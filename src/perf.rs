use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use radius::core::{
    avp::AVP, code::Code, packet::Packet, rfc2865, rfc2869::add_message_authenticator,
};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::{
    acct::AcctSession,
    config::{AcctStatusKind, AppConfig, AuthMethod, PacketCode},
    eap::{self, EapOutcome},
    error::AppError,
    mschapv2::{self, Mschapv2Exchange, VENDOR_SPECIFIC_TYPE},
    utils::fix_message_authenticator,
};

pub struct PerfTest {
    config: Arc<AppConfig>,
    /// One counter set per connection (worker).
    stats: Vec<Arc<PerfStats>>,
}

impl PerfTest {
    pub fn new(config: AppConfig) -> Self {
        let stats = (0..config.connections)
            .map(|_| Arc::new(PerfStats::default()))
            .collect();
        PerfTest {
            config: Arc::new(config),
            stats,
        }
    }

    /// Spawns the workers and the stats reporter, and waits until `cancel` is
    /// triggered (or all workers die). Returns once everything shut down.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), AppError> {
        info!(
            "starting {} workers against {} (timeout: {:?}, report interval: {:?})",
            self.config.connections, self.config.server, self.config.timeout, self.config.interval,
        );

        let mut tasks = JoinSet::new();
        for (worker_id, stats) in self.stats.iter().enumerate() {
            tasks.spawn(Self::worker(
                worker_id,
                self.config.clone(),
                stats.clone(),
                cancel.clone(),
            ));
        }
        tasks.spawn(Self::reporter(
            self.stats.clone(),
            self.config.interval,
            cancel.clone(),
        ));

        while let Some(res) = tasks.join_next().await {
            if let Err(e) = res {
                error!("task failed: {e}");
            }
        }
        Ok(())
    }

    /// Prints the aggregated totals and per-second averages: a line per
    /// connection plus the overall total.
    pub fn print_summary(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64().max(f64::EPSILON);
        println!();
        println!("--- summary after {:.2}s ---", secs);

        let mut total = StatsSnapshot::default();
        for (i, stats) in self.stats.iter().enumerate() {
            let s = stats.snapshot();
            total.add(&s);
            println!(
                "conn {:>4}: requests: {:>10} | success: {:>10} | rejected: {:>10} | failed: {:>10}",
                i, s.requests, s.success, s.rejected, s.failure
            );
        }

        let rate = |n: u64| n as f64 / secs;
        let pct = |n: u64| {
            if total.requests == 0 {
                0.0
            } else {
                100.0 * n as f64 / total.requests as f64
            }
        };
        println!("-------------------------------------------------");
        println!(
            "requests:  {:>10} total, {:>10.1}/s",
            total.requests,
            rate(total.requests)
        );
        println!(
            "success:   {:>10} total, {:>10.1}/s ({:.2}%)",
            total.success,
            rate(total.success),
            pct(total.success)
        );
        println!(
            "rejected:  {:>10} total, {:>10.1}/s ({:.2}%)",
            total.rejected,
            rate(total.rejected),
            pct(total.rejected)
        );
        println!(
            "failed:    {:>10} total, {:>10.1}/s ({:.2}%)",
            total.failure,
            rate(total.failure),
            pct(total.failure)
        );
    }

    async fn worker(
        worker_id: usize,
        config: Arc<AppConfig>,
        stats: Arc<PerfStats>,
        cancel: CancellationToken,
    ) {
        if config.auth.method == AuthMethod::PeapMschapv2 {
            // EAP is driven by external eapol_test processes; no UDP socket
            // of our own is needed.
            return Self::eap_worker(worker_id, config, stats, cancel).await;
        }

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                error!("worker {worker_id}: failed to bind UDP socket: {e}");
                return;
            }
        };
        if let Err(e) = socket.connect(config.server).await {
            error!(
                "worker {worker_id}: failed to connect to {}: {e}",
                config.server
            );
            return;
        }

        if config.packet_type == PacketCode::AccountingRequest {
            return Self::acct_worker(worker_id, config, stats, cancel, socket).await;
        }

        let mut buf = vec![0u8; 4096];
        loop {
            // A fresh packet per request: FreeRADIUS' duplicate cache keys on
            // (source addr/port, identifier, request authenticator), so reusing
            // the same bytes would hit the cache ("Sending duplicate reply")
            // instead of measuring real auth work. Packet::new() draws a new
            // random identifier + request authenticator; the User-Password
            // hiding and Message-Authenticator (both depend on the request
            // authenticator) are recomputed accordingly.
            let packet = match RadiusPacket::build(&config) {
                Ok(packet) => packet,
                Err(e) => {
                    error!("worker {worker_id}: failed to build request packet: {e}");
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                }
            };

            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                outcome = Self::round_trip(&socket, &packet.payload, packet.mschap.as_ref(), config.secret.as_bytes(), config.timeout, &mut buf) => {
                    stats.record(outcome);
                    if matches!(outcome, RoundTrip::SendError | RoundTrip::RecvError) {
                        // transport errors (e.g. ICMP port unreachable) return
                        // immediately; back off briefly to avoid a hot loop
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                        }
                    }
                }
            }
        }
    }

    /// Sends one request and waits for the response (one outstanding request
    /// per connection). `mschap` is set for MS-CHAPv2 Access-Requests so that
    /// the `MS-CHAP2-Success` in an Access-Accept can be verified.
    async fn round_trip(
        socket: &UdpSocket,
        payload: &[u8],
        mschap: Option<&Mschapv2Exchange>,
        secret: &[u8],
        timeout_dur: Duration,
        buf: &mut [u8],
    ) -> RoundTrip {
        if let Err(e) = socket.send(payload).await {
            debug!("send error: {e}");
            return RoundTrip::SendError;
        }

        match tokio::time::timeout(timeout_dur, socket.recv(buf)).await {
            Err(_) => RoundTrip::Timeout,
            Ok(Err(e)) => {
                debug!("recv error: {e}");
                RoundTrip::RecvError
            }
            Ok(Ok(n)) => {
                let raw = &buf[..n];
                if raw.len() < 2
                    || raw[1] != payload[1] // identifier mismatch
                    || !Packet::is_authentic_response(raw, payload, secret)
                {
                    return RoundTrip::InvalidResponse;
                }
                match Code::from(raw[0]) {
                    Code::AccessAccept => match mschap {
                        Some(exchange) => Self::verify_mschap_success(raw, secret, exchange),
                        None => RoundTrip::Success,
                    },
                    Code::AccessChallenge | Code::AccountingResponse => RoundTrip::Success,
                    Code::AccessReject => RoundTrip::Rejected,
                    _ => RoundTrip::UnexpectedResponse,
                }
            }
        }
    }

    /// Accounting worker. Behaviour depends on `accounting.status_type`:
    /// `start`/`interim`/`stop` flood that single record type as fast as
    /// possible; `cycle` simulates full user sessions (Start, paced
    /// Interim-Updates, Stop, then a fresh session).
    async fn acct_worker(
        worker_id: usize,
        config: Arc<AppConfig>,
        stats: Arc<PerfStats>,
        cancel: CancellationToken,
        socket: UdpSocket,
    ) {
        let acct = &config.accounting;
        match acct.status_type {
            AcctStatusKind::Cycle => {
                // session pacing: Start -> Interim every interim_interval ->
                // Stop at session_length -> new session
                'sessions: loop {
                    let session = AcctSession::new(worker_id, acct.framed_ip);
                    if !Self::acct_send(
                        &config,
                        &session,
                        AcctStatusKind::Start,
                        &socket,
                        &stats,
                        &cancel,
                    )
                    .await
                    {
                        return;
                    }
                    let stop_at = Instant::now() + acct.session_length;
                    let mut next_interim = Instant::now() + acct.interim_interval;
                    while next_interim < stop_at {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break 'sessions,
                            _ = tokio::time::sleep_until(next_interim) => {}
                        }
                        if !Self::acct_send(
                            &config,
                            &session,
                            AcctStatusKind::Interim,
                            &socket,
                            &stats,
                            &cancel,
                        )
                        .await
                        {
                            return;
                        }
                        next_interim += acct.interim_interval;
                    }
                    let remaining = stop_at.saturating_duration_since(Instant::now());
                    if !remaining.is_zero() {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break 'sessions,
                            _ = tokio::time::sleep(remaining) => {}
                        }
                    }
                    if !Self::acct_send(
                        &config,
                        &session,
                        AcctStatusKind::Stop,
                        &socket,
                        &stats,
                        &cancel,
                    )
                    .await
                    {
                        return;
                    }
                }
            }
            kind => {
                // flood a single record type
                let mut fixed_session: Option<AcctSession> = None;
                loop {
                    // Start/Stop need a fresh session per record; Interim keeps
                    // one session alive so counters/timers stay monotonic.
                    let session = match kind {
                        AcctStatusKind::Interim => fixed_session
                            .get_or_insert_with(|| AcctSession::new(worker_id, acct.framed_ip)),
                        AcctStatusKind::Stop => &*fixed_session.insert(AcctSession::new_aged(
                            worker_id,
                            acct.framed_ip,
                            Duration::from_secs_f64(
                                rand::random::<f64>() * acct.session_length.as_secs_f64(),
                            ),
                        )),
                        _ => &*fixed_session.insert(AcctSession::new(worker_id, acct.framed_ip)),
                    };
                    if !Self::acct_send(&config, session, kind, &socket, &stats, &cancel).await {
                        return;
                    }
                }
            }
        }
    }

    /// Builds one accounting record, sends it and records the outcome.
    /// Returns false when the worker should stop (cancelled or fatal error).
    async fn acct_send(
        config: &AppConfig,
        session: &AcctSession,
        kind: AcctStatusKind,
        socket: &UdpSocket,
        stats: &PerfStats,
        cancel: &CancellationToken,
    ) -> bool {
        let payload = match session.build_packet(config, kind) {
            Ok(payload) => payload,
            Err(e) => {
                error!("failed to build accounting packet: {e}");
                return false;
            }
        };
        let mut buf = vec![0u8; 4096];
        tokio::select! {
            biased;
            _ = cancel.cancelled() => false,
            outcome = Self::round_trip(socket, &payload, None, config.secret.as_bytes(), config.timeout, &mut buf) => {
                stats.record(outcome);
                if matches!(outcome, RoundTrip::SendError | RoundTrip::RecvError) {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return false,
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    }
                }
                true
            }
        }
    }

    /// EAP worker: repeatedly runs one full PEAP/MSCHAPv2 authentication via
    /// an external eapol_test process and records the outcome.
    async fn eap_worker(
        worker_id: usize,
        config: std::sync::Arc<AppConfig>,
        stats: std::sync::Arc<PerfStats>,
        cancel: CancellationToken,
    ) {
        let runner = match eap::EapolTest::prepare(&config, worker_id) {
            Ok(runner) => runner,
            Err(e) => {
                error!("worker {worker_id}: failed to prepare eapol_test: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                outcome = runner.authenticate(config.timeout, &cancel) => {
                    let round_trip = match outcome {
                        EapOutcome::Success => RoundTrip::Success,
                        EapOutcome::Rejected => RoundTrip::Rejected,
                        EapOutcome::Timeout => RoundTrip::Timeout,
                        // backs off below like other transport errors
                        EapOutcome::Error => RoundTrip::RecvError,
                        EapOutcome::Cancelled => break,
                    };
                    stats.record(round_trip);
                    if round_trip == RoundTrip::RecvError {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                        }
                    }
                }
            }
        }
    }

    /// An Access-Accept to a MS-CHAPv2 request only counts as success if the
    /// `MS-CHAP2-Success` authenticator response is valid (i.e. it proves the
    /// server knew the password).
    fn verify_mschap_success(raw: &[u8], secret: &[u8], exchange: &Mschapv2Exchange) -> RoundTrip {
        match Packet::decode(raw, secret) {
            Ok(response)
                if mschapv2::verify_success(
                    &response,
                    exchange.ident,
                    &exchange.expected_success_message,
                ) =>
            {
                RoundTrip::Success
            }
            _ => RoundTrip::InvalidResponse,
        }
    }

    /// Prints per-connection rates every `interval`: requests/s, success/s,
    /// rejected/s and failed/s since the previous tick, plus a total line.
    async fn reporter(
        all_stats: Vec<Arc<PerfStats>>,
        interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let started_at = Instant::now();
        let mut prev = vec![StatsSnapshot::default(); all_stats.len()];
        let mut prev_at = started_at;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let now = Instant::now();
                    let secs = now.duration_since(prev_at).as_secs_f64().max(f64::EPSILON);
                    let rate = |n: u64| n as f64 / secs;

                    let mut total = StatsSnapshot::default();
                    let mut total_prev = StatsSnapshot::default();
                    for (i, stats) in all_stats.iter().enumerate() {
                        let cur = stats.snapshot();
                        let d = cur.since(&prev[i]);
                        total.add(&cur);
                        total_prev.add(&prev[i]);
                        println!(
                            "[conn {:>4}] req/s: {:>9.1} | ok/s: {:>9.1} | rej/s: {:>9.1} | fail/s: {:>9.1} | total: {}",
                            i, rate(d.requests), rate(d.success), rate(d.rejected), rate(d.failure), cur.requests
                        );
                        prev[i] = cur;
                    }
                    prev_at = now;

                    let d = total.since(&total_prev);
                    println!(
                        "[t+{:.0}s total] req/s: {:>9.1} | ok/s: {:>9.1} | rej/s: {:>9.1} | fail/s: {:>9.1} | total req: {}",
                        started_at.elapsed().as_secs_f64(),
                        rate(d.requests), rate(d.success), rate(d.rejected), rate(d.failure), total.requests,
                    );
                }
            }
        }
    }
}

pub struct RadiusPacket {
    pub payload: Vec<u8>,
    /// Present for `AuthMethod::Mschapv2`; used to verify `MS-CHAP2-Success`.
    pub mschap: Option<Mschapv2Exchange>,
}

impl RadiusPacket {
    /// Builds one encoded request packet. Must be called once per request (not
    /// reused) so that every request has a unique identifier and request
    /// authenticator — see the comment in `worker`.
    pub fn build(config: &AppConfig) -> Result<RadiusPacket, AppError> {
        let mut req_packet = Packet::new(config.packet_type.into(), config.secret.as_bytes());

        rfc2865::add_user_name(&mut req_packet, config.auth.username.as_str());
        let mschap = match config.auth.method {
            AuthMethod::Pap => {
                rfc2865::add_user_password(&mut req_packet, config.auth.password.as_bytes())?;
                None
            }
            AuthMethod::Mschapv2 => {
                let exchange = Mschapv2Exchange::new(&config.auth.username, &config.auth.password);
                req_packet.add(AVP::from_bytes(
                    VENDOR_SPECIFIC_TYPE,
                    &exchange.challenge_vsa,
                ));
                req_packet.add(AVP::from_bytes(
                    VENDOR_SPECIFIC_TYPE,
                    &exchange.response_vsa,
                ));
                Some(exchange)
            }
            AuthMethod::PeapMschapv2 => {
                return Err(AppError::RadiusPacketError(
                    "PEAP/MSCHAPv2 runs via external eapol_test; no packet to build".to_owned(),
                ));
            }
        };
        if let Some(nas_identifier) = &config.nas_identifier {
            rfc2865::add_nas_identifier(&mut req_packet, nas_identifier.as_str());
        }
        rfc2865::add_nas_port(&mut req_packet, 0);
        // 16 zero bytes as a placeholder; recomputed below like radclient does
        // with `Message-Authenticator = 0x00` in the input file.
        add_message_authenticator(&mut req_packet, &[0u8; 16]);

        let mut encoded = req_packet.encode()?;
        fix_message_authenticator(&mut encoded, config.secret.as_bytes())?;

        Ok(RadiusPacket {
            payload: encoded,
            mschap,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundTrip {
    Success,
    Rejected,
    Timeout,
    InvalidResponse,
    UnexpectedResponse,
    SendError,
    RecvError,
}

#[derive(Debug, Default)]
pub struct PerfStats {
    pub requests: AtomicU64,
    pub success: AtomicU64,
    pub rejected: AtomicU64,
    pub failure: AtomicU64,
}

impl PerfStats {
    fn record(&self, outcome: RoundTrip) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        match outcome {
            RoundTrip::Success => {
                self.success.fetch_add(1, Ordering::Relaxed);
            }
            RoundTrip::Rejected => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.failure.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            failure: self.failure.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSnapshot {
    pub requests: u64,
    pub success: u64,
    pub rejected: u64,
    pub failure: u64,
}

impl StatsSnapshot {
    fn since(&self, prev: &StatsSnapshot) -> StatsSnapshot {
        StatsSnapshot {
            requests: self.requests.saturating_sub(prev.requests),
            success: self.success.saturating_sub(prev.success),
            rejected: self.rejected.saturating_sub(prev.rejected),
            failure: self.failure.saturating_sub(prev.failure),
        }
    }

    fn add(&mut self, other: &StatsSnapshot) {
        self.requests += other.requests;
        self.success += other.success;
        self.rejected += other.rejected;
        self.failure += other.failure;
    }
}

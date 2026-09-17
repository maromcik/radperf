//! RADIUS accounting (RFC 2866/2869): per-worker session state and packet
//! building for Start / Interim-Update / Stop records.

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use chrono::Utc;
use radius::core::{
    code::Code,
    packet::Packet,
    rfc2865,
    rfc2865::NAS_PORT_TYPE_WIRELESS_802_11,
    rfc2866,
    rfc2866::{
        ACCT_AUTHENTIC_RADIUS, ACCT_STATUS_TYPE_INTERIM_UPDATE, ACCT_STATUS_TYPE_START,
        ACCT_STATUS_TYPE_STOP, ACCT_TERMINATE_CAUSE_USER_REQUEST,
    },
    rfc2869,
};
use rand::Rng;

use crate::{
    config::{AcctStatusKind, AppConfig},
    error::AppError,
    utils::fix_accounting_authenticator,
};

/// State of one simulated user session. The FreeRADIUS SQL module correlates
/// records by (NAS, Acct-Session-Id), so the id is fixed per session and all
/// counters/timers are monotonic within it.
pub struct AcctSession {
    /// Acct-Session-Id (44): printable, unique per session (random so that
    /// re-running the tool doesn't collide with rows already in radacct).
    pub id: String,
    started_at: Instant,
    framed_ip: Ipv4Addr,
    calling_station_id: String,
    /// synthetic traffic rates (octets/s) used to grow the counters
    rate_in: u32,
    rate_out: u32,
}

impl AcctSession {
    /// A fresh session starting now.
    pub fn new(worker_id: usize, framed_ip: Option<Ipv4Addr>) -> Self {
        Self::new_aged(worker_id, framed_ip, Duration::ZERO)
    }

    /// A session that already `age` worth of traffic when the first record is
    /// sent (used for standalone Stop records, which end a session that was
    /// never started on this client).
    pub fn new_aged(worker_id: usize, framed_ip: Option<Ipv4Addr>, age: Duration) -> Self {
        let mut rng = rand::thread_rng();
        let calling_station_id = (0..6)
            .map(|_| format!("{:02X}", rand::random::<u8>()))
            .collect::<Vec<_>>()
            .join("-");
        AcctSession {
            id: format!(
                "{:04X}{:012X}",
                worker_id,
                rand::random::<u64>() & 0xFFFF_FFFF_FFFF
            ),
            started_at: Instant::now() - age,
            framed_ip: framed_ip.unwrap_or_else(|| {
                Ipv4Addr::new(
                    10,
                    rand::random::<u8>(),
                    rand::random::<u8>(),
                    rand::random::<u8>(),
                )
            }),
            calling_station_id,
            rate_in: rng.gen_range(1_000..100_000),
            rate_out: rng.gen_range(1_000..100_000),
        }
    }

    /// Acct-Session-Time (46): seconds since the session started.
    pub fn session_time(&self) -> u32 {
        self.started_at.elapsed().as_secs().min(u32::MAX as u64) as u32
    }

    /// Acct-Input-Octets (42), cumulative since session start.
    pub fn input_octets(&self) -> u32 {
        (self.session_time() as u64 * self.rate_in as u64) as u32
    }

    /// Acct-Output-Octets (43), cumulative since session start.
    pub fn output_octets(&self) -> u32 {
        (self.session_time() as u64 * self.rate_out as u64) as u32
    }

    fn packets(octets: u32) -> u32 {
        octets / 1500
    }

    /// Encodes one Accounting-Request for this session of the given kind.
    /// `kind` must not be `Cycle` (that is a worker scheduling mode, not a
    /// record type).
    pub fn build_packet(
        &self,
        config: &AppConfig,
        kind: AcctStatusKind,
    ) -> Result<Vec<u8>, AppError> {
        let status_type = match kind {
            AcctStatusKind::Start => ACCT_STATUS_TYPE_START,
            AcctStatusKind::Interim => ACCT_STATUS_TYPE_INTERIM_UPDATE,
            AcctStatusKind::Stop => ACCT_STATUS_TYPE_STOP,
            AcctStatusKind::Cycle => {
                return Err(AppError::RadiusPacketError(
                    "Cycle is a scheduling mode, not a record type".to_owned(),
                ));
            }
        };

        let mut p = Packet::new(Code::AccountingRequest, config.secret.as_bytes());
        rfc2865::add_user_name(&mut p, &config.auth.username);
        rfc2865::add_nas_port(&mut p, 0);
        rfc2865::add_nas_port_type(&mut p, NAS_PORT_TYPE_WIRELESS_802_11);
        if let Some(nas_identifier) = &config.nas_identifier {
            rfc2865::add_nas_identifier(&mut p, nas_identifier);
        }
        rfc2866::add_acct_status_type(&mut p, status_type);
        rfc2866::add_acct_delay_time(&mut p, 0);
        rfc2869::add_event_timestamp(&mut p, &Utc::now());
        rfc2866::add_acct_session_id(&mut p, &self.id);
        rfc2866::add_acct_authentic(&mut p, ACCT_AUTHENTIC_RADIUS);
        rfc2865::add_framed_ip_address(&mut p, &self.framed_ip);
        rfc2865::add_calling_station_id(&mut p, &self.calling_station_id);
        if let Some(called) = &config.accounting.called_station_id {
            rfc2865::add_called_station_id(&mut p, called);
        }
        if kind != AcctStatusKind::Start {
            rfc2866::add_acct_session_time(&mut p, self.session_time());
            rfc2866::add_acct_input_octets(&mut p, self.input_octets());
            rfc2866::add_acct_output_octets(&mut p, self.output_octets());
            rfc2866::add_acct_input_packets(&mut p, Self::packets(self.input_octets()));
            rfc2866::add_acct_output_packets(&mut p, Self::packets(self.output_octets()));
        }
        if kind == AcctStatusKind::Stop {
            rfc2866::add_acct_terminate_cause(&mut p, ACCT_TERMINATE_CAUSE_USER_REQUEST);
        }

        let mut encoded = p.encode()?;
        // Accounting-Requests carry no Message-Authenticator (FreeRADIUS does
        // not require one here), but the Request Authenticator must be the
        // MD5 signature defined by RFC 2866.
        fix_accounting_authenticator(&mut encoded, config.secret.as_bytes())?;
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use radius::core::packet::Packet;

    use super::*;
    use crate::config::{AcctConfig, AppConfig, AuthConfig, AuthMethod, PacketCode};

    fn fixture_config() -> AppConfig {
        AppConfig {
            log_level: "info".to_owned(),
            connections: 1,
            timeout: Duration::from_secs(1),
            interval: Duration::from_secs(1),
            server: "127.0.0.1:1813".parse().unwrap(),
            secret: "testing123".to_owned(),
            nas_identifier: Some("radperf".to_owned()),
            packet_type: PacketCode::AccountingRequest,
            auth: AuthConfig {
                username: "radperf-test".to_owned(),
                password: "not-used-for-acct".to_owned(),

                method: AuthMethod::Pap,
            },
            accounting: AcctConfig {
                status_type: AcctStatusKind::Cycle,
                interim_interval: Duration::from_secs(10),
                session_length: Duration::from_secs(300),
                called_station_id: Some("02-00-00-00-00-01:eduroam".to_owned()),
                framed_ip: None,
            },
        }
    }

    /// The Request Authenticator must satisfy the RFC 2866 MD5 formula, or
    /// FreeRADIUS drops the packet with "invalid signature". The radius
    /// crate's own `is_authentic_request` implements exactly that check.
    #[test]
    fn accounting_request_authenticator_is_valid() {
        let config = fixture_config();
        let session = AcctSession::new(0, None);
        for kind in [
            AcctStatusKind::Start,
            AcctStatusKind::Interim,
            AcctStatusKind::Stop,
        ] {
            let payload = session.build_packet(&config, kind).unwrap();
            assert_eq!(payload[0], Code::AccountingRequest as u8);
            assert!(
                Packet::is_authentic_request(&payload, config.secret.as_bytes()),
                "invalid signature for {kind:?}"
            );
        }
    }

    /// Counters and session time must be monotonic within a session.
    #[test]
    fn counters_are_monotonic() {
        let session = AcctSession::new_aged(0, None, Duration::from_secs(60));
        assert!(session.session_time() >= 60);
        assert!(session.input_octets() >= 60_000);
        assert!(session.output_octets() >= 60_000);
    }
}

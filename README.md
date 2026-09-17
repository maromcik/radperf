# radperf

A RADIUS load- and performance-testing tool, written in Rust on tokio.
Think of it as `radclient`/`radtest` or `eapol_test` wired into a
multi-connection benchmarking harness: N parallel connections keep one
request in flight each, and the tool reports requests/s, successful/s,
rejected/s and failed/s — per connection every interval, and as an
aggregated summary on exit (Ctrl+C).

Primary use case: benchmarking FreeRADIUS servers (auth paths, EAP paths,
and the accounting write path, which usually hits a SQL bottleneck first).

## Features

- **PAP** — plain `User-Password` access requests (like `radtest`)
- **MS-CHAPv2** — plain RADIUS MS-CHAPv2 via Microsoft VSAs
  (like `radtest -t mschap`), including verification of the server's
  `MS-CHAP2-Success` authenticator, so a success means the server proved
  it knows the password
- **PEAP/MSCHAPv2 (EAP)** — full EAP sessions driven by external
  `eapol_test` processes: one complete authentication (full PEAP TLS
  handshake + inner MS-CHAPv2) per invocation, no session resumption
- **Accounting** — Start / Interim-Update / Stop records, either as a
  flood of a single record type or as realistic simulated sessions
  (Start → paced Interim-Update → Stop → new session)
- fresh random packet Identifier + Request Authenticator per request, so
  FreeRADIUS' duplicate cache never short-circuits the measurements
- correct protocol details out of the box: `Message-Authenticator`
  (HMAC-MD5, RFC 3579) on access requests, the MD5 request authenticator
  required on accounting requests (RFC 2866), FreeRADIUS-compatible
  MS-CHAPv2 attribute layouts

## Requirements

- Rust toolchain (edition 2024)
- `eapol_test` (from wpa_supplicant/hostapd) — only needed for the
  PEAP/MSCHAPv2 mode
- network reachability to the RADIUS server. Mind the ports: FreeRADIUS
  listeners are strict — auth packets only on the auth port (usually
  1812), accounting only on the accounting port (usually 1813)

## Building

```sh
cargo build --release
# binary: target/release/radperf
```

## Running

```sh
radperf -c myconfig        # reads myconfig.yaml (relative to the CWD)
```

Stop with Ctrl+C — the tool cancels all workers, waits for in-flight
requests, and prints the aggregated summary.

`log_level` in the config is a tracing filter (`info`, `debug`, …).
At `debug`, internal details (e.g. eapol_test output of failed runs) are
logged.

## Configuration

See `radperf-example.yaml` for a fully commented template; the
`radperf-eduroam.yaml` in this repo shows a real PEAP/MSCHAPv2 scenario.

```yaml
log_level: "info"
connections: 100          # parallel workers; one request in flight each
timeout: "2s"             # response timeout => request counts as failed
interval: "1s"            # per-connection stats period

server: "192.0.2.1:1812"  # auth=AccessRequest, acct=AccountingRequest(1813)
secret: "<shared secret>"
# nas_identifier: "my-nas"   # optional NAS-Identifier attribute
packet_type: "AccessRequest" # or "AccountingRequest"

auth:
  username: "radtest"
  password: "<password>"
  method: "pap"              # pap | mschapv2 | peap-mschapv2

accounting:                  # only for packet_type: AccountingRequest
  status_type: "cycle"       # start | interim | stop | cycle
  interim_interval: "10s"
  session_length: "5m"
  # called_station_id: "02-00-00-00-00-01:eduroam"
  # framed_ip: "10.0.0.1"    # fixed; random 10.x.y.z per session otherwise

eap:                         # only for auth.method: peap-mschapv2
  binary: "eapol_test"
  anonymous_identity: "anonymous@example.org"
  # phase2: "auth=MSCHAPV2"  # default
  # phase1: "peapver=0"      # if TLS negotiation quirks appear
  attrs:                     # extra RADIUS attributes (eapol_test -N syntax)
    - "32:s:wlan:eduroam:test"     # NAS-Identifier
  # NOTE: Calling-Station-Id is set automatically (-M, distinct MAC per
  # connection); don't add attribute 31 here or it is sent twice.
```

Flat keys can also be overridden with `APP_*` environment variables
(e.g. `APP_CONNECTIONS=20`).

## Modes

### PAP (`method: pap`)

Access-Request with `User-Name` + `User-Password` (RFC 2865 hiding),
`NAS-Port`, optional `NAS-Identifier`, `Message-Authenticator`. Success =
Access-Accept, Rejected = Access-Reject.

### MS-CHAPv2 (`method: mschapv2`)

Access-Request with `MS-CHAP-Challenge` + `MS-CHAP2-Response` (fresh
random challenges per request), plus `Message-Authenticator`. An
Access-Accept only counts as success if the `MS-CHAP2-Success` attribute
carries the expected `S=<40 hex>` authenticator (RFC 2759 §8.7). The
crypto is unit-tested against the RFC 2759 §9 test vectors.

Caveat that is baked into the code: FreeRADIUS' `rlm_mschap` expects the
MS-CHAP2-Response value as `Ident + Flags + Peer-Challenge + 8×0x00 +
NT-Response`, which is *not* the RFC 2548 octet order — get this wrong
and every request fails with `MS-CHAP2-Response is incorrect`.

### PEAP/MSCHAPv2 (`method: peap-mschapv2`)

Each worker runs `eapol_test` in a loop; every invocation performs one
**full** authentication (EAPOL-Start → PEAP TLS handshake → inner
EAP-MSCHAPv2 → Access-Accept). This deliberately avoids re-authentication
shortcuts, so the TLS cost on the server equals real supplicants.

Outcome classification: `SUCCESS` → success, `FAILURE` → rejected, no
response within `timeout` → timeout, spawn/other errors → failed.

The per-worker supplicant config (username/password from `auth`, identity
etc. from `eap`) is written to `/tmp/radperf-eap-<pid>-<worker>.conf` with
mode `0600` and deleted on exit.

Note that in this mode the tool spawns many short-lived processes; CPU
load on the testing machine is higher than in the pure-RADIUS modes.

### Accounting (`packet_type: AccountingRequest`)

Point `server` at the accounting port (usually `:1813`).
`accounting.status_type`:

- `start` / `interim` / `stop` — flood that single record type as fast as
  possible. Use these to benchmark the respective SQL paths
  (`radacct` INSERT vs. UPDATE/close)
- `cycle` — simulate full sessions: Start, Interim-Update every
  `interim_interval`, Stop after `session_length`, then a new session.
  Each worker ≈ one concurrent user. Shrink the pacing values
  (`interim_interval: "200ms"`, `session_length: "2s"`) for a
  high-rate full-lifecycle benchmark.

Session correlation is RFC 2866-correct: a stable random
`Acct-Session-Id` per session, monotonic `Acct-Session-Time` and
octet/packet counters, `Event-Timestamp`, `Acct-Delay-Time=0`,
`Acct-Terminate-Cause` on Stop, and the MD5 Request Authenticator
(verified at build time against the radius crate's own validator — this
is the part that makes or breaks accounting delivery).

## Metrics and throughput model

Per interval, one line per connection plus a total line:

```
[conn    0] req/s:     9.9 | ok/s:   9.9 | rej/s: 0.0 | fail/s: 0.0 | total: 10
[t+1s total] req/s:  987.2 | ok/s: 987.2 | rej/s: 0.0 | fail/s: 0.0 | total req: 988
```

On Ctrl+C, an aggregated summary with totals, per-second rates and
percentages.

Classification:

| counter   | meaning                                                        |
|-----------|----------------------------------------------------------------|
| requests  | every completed request attempt                                |
| success   | Access-Accept (for MSCHAPv2 additionally valid S=), or Accounting-Response |
| rejected  | Access-Reject, or EAP-Failure                                  |
| failed    | timeout, invalid/spoofed response, transport or build errors   |

This is a **closed-loop** benchmark: each connection has at most one
request in flight, so

```
requests/s ≈ connections / average_response_time
```

There is no rate limiter; `connections` is the throttle. To find a
server's sustainable ceiling, sweep `connections` (10, 20, 50, 100, …)
and watch where `fail/s` first appears.

With many connections the per-connection lines get noisy — increase
`interval` or redirect stdout; the final summary always aggregates
everything.

## Limitations

- one request in flight per connection (closed loop); no asynchronous
  pipelining
- UDP only; no RADIUS/TLS (RadSec) for the native paths. `eapol_test`
  itself could do RadSec, but radperf only drives its UDP mode
- EAP support is PEAP + inner MS-CHAPv2 only (that's the eduroam scenario
  it was built for); no EAP-TLS/TTLS/PAP
- accounting packets carry no `Message-Authenticator` (not required by
  FreeRADIUS accounting listeners by default)
- a timed-out request counts as failed even though the server may still
  process it — at high overload, effective server-side work can exceed
  what `success/s` reports
- accounting counters are 32-bit on the wire (per RFC); with absurdly
  long/fast simulated sessions they wrap
- per-connection stat lines are printed regardless of connection count

## Verifying results against FreeRADIUS

Run the server with `-X` and check that the work you intend is actually
happening:

- auth: `Login OK`, for MSCHAPv2 `mschap: Client is using MS-CHAPv2`
  followed by `Sent Access-Accept` with `MS-CHAP2-Success`
- PEAP: full inner-tunnel EAP exchange per authentication (Look for
  inner-tunnel `mschap` module lines, not a resumed outer tunnel)
- accounting: `sql: ... INSERT/UPDATE radacct` per record
- you should never see `Sending duplicate reply` (if you do, requests are
  being short-circuited by the duplicate cache and you're measuring
  cache, not server work)

Typical failure signatures and their causes:

| server log / symptom                                   | cause                                   |
|--------------------------------------------------------|-----------------------------------------|
| `Message-Authenticator has invalid length 32`          | hex string sent instead of 16 computed bytes |
| `invalid Message-Authenticator! (Shared secret is incorrect.)` | wrong shared secret             |
| `Invalid packet code 1 sent to a accounting port`      | `packet_type` vs. port mismatch (1812 ↔ 1813) |
| `mschap: MS-CHAP2-Response is incorrect`               | MS-CHAPv2 attribute layout/secret issue  |
| radacct row count frozen + `rlm_sql ... at max connection limit` | SQL write path saturated — the accounting benchmark's bottleneck: tune the sql pool (`pool { max }`), Postgres (`max_connections`, `synchronous_commit`), or decouple via buffered-sql (detail files) |

## Repository layout

- `src/perf.rs` — worker/reporter/stats core, protocol dispatch
- `src/acct.rs` — accounting session state + packet building
- `src/eap.rs` — eapol_test process driver
- `src/mschapv2.rs` — MS-CHAPv2 crypto (RFC 2759), RFC-vector unit tests
- `src/utils.rs` — post-encode authenticator fixes (Message-Authenticator
  HMAC-MD5, accounting MD5 signature)
- `src/config.rs` — YAML config schema
- `radperf-example.yaml` — annotated template

## Security notes

- configs contain the shared secret and credentials — do not commit them
  (this repo's example files use placeholders; keep real configs local)
- generated eapol_test configs are `0600` and cleaned up on exit
- this is a load generator; pointed at a production server it *will* load
  the production server, including downstream LDAP/SQL. Start with a
  small `connections` value.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use config::Config;
use serde::Deserialize;

use crate::error::AppError;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub connections: usize,
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(default = "default_interval")]
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub server: SocketAddr,
    pub secret: String,
    pub nas_identifier: Option<String>,
    pub packet_type: PacketCode,
    pub auth: AuthConfig,
    #[serde(default)]
    pub accounting: AcctConfig,
    #[serde(default)]
    pub eap: EapConfig,
}

impl AppConfig {
    pub fn parse_config(settings_path: &str) -> Result<AppConfig, AppError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(settings_path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        let config = settings.try_deserialize::<AppConfig>()?;

        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub method: AuthMethod,
}

/// Accounting behaviour (used when `auth.packet_type` is `AccountingRequest`).
#[derive(Debug, Clone, Deserialize)]
pub struct AcctConfig {
    /// Which records to emit:
    /// `start` / `interim` / `stop` flood that single record type as fast as
    /// possible; `cycle` simulates full sessions (Start -> paced Interim-Update
    /// every `interim_interval` -> Stop after `session_length`, then a new
    /// session).
    #[serde(default)]
    pub status_type: AcctStatusKind,
    #[serde(default = "default_interim_interval")]
    #[serde(with = "humantime_serde")]
    pub interim_interval: Duration,
    #[serde(default = "default_session_length")]
    #[serde(with = "humantime_serde")]
    pub session_length: Duration,
    /// Called-Station-Id (e.g. "02-00-00-00-00-01:eduroam"); omitted when unset.
    pub called_station_id: Option<String>,
    /// Fixed Framed-IP-Address for all sessions; random 10.x.y.z per session
    /// when unset.
    pub framed_ip: Option<Ipv4Addr>,
}

impl Default for AcctConfig {
    fn default() -> Self {
        AcctConfig {
            status_type: AcctStatusKind::default(),
            interim_interval: default_interim_interval(),
            session_length: default_session_length(),
            called_station_id: None,
            framed_ip: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AcctStatusKind {
    Start,
    Interim,
    Stop,
    #[default]
    Cycle,
}

fn default_interim_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_session_length() -> Duration {
    Duration::from_secs(300)
}

/// Authentication method to put into the request.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// PAP: plain `User-Password` attribute (RFC 2865 hiding).
    #[default]
    Pap,
    /// MS-CHAPv2 in plain RADIUS via Microsoft VSAs (RFC 2548/2759).
    Mschapv2,
    /// Full EAP session: PEAP with inner MS-CHAPv2, driven by external
    /// eapol_test processes (see the `eap` section).
    #[serde(rename = "peap-mschapv2")]
    PeapMschapv2,
}

/// Settings for `AuthMethod::PeapMschapv2` (external eapol_test).
#[derive(Debug, Clone, Deserialize)]
pub struct EapConfig {
    /// Path/name of the eapol_test binary.
    #[serde(default = "default_eap_binary")]
    pub binary: String,
    /// Outer (anonymous) identity; omitted when unset.
    pub anonymous_identity: Option<String>,
    /// PEAP phase2, e.g. "auth=MSCHAPV2".
    #[serde(default = "default_eap_phase2")]
    pub phase2: String,
    /// Optional PEAP phase1, e.g. "peapver=0".
    pub phase1: Option<String>,
    /// Extra RADIUS attributes in eapol_test -N syntax, e.g.
    /// "32:s:my-nas" (NAS-Identifier) or "77:d:123".
    #[serde(default)]
    pub attrs: Vec<String>,
}

impl Default for EapConfig {
    fn default() -> Self {
        EapConfig {
            binary: default_eap_binary(),
            anonymous_identity: None,
            phase2: default_eap_phase2(),
            phase1: None,
            attrs: Vec::new(),
        }
    }
}

fn default_eap_binary() -> String {
    "eapol_test".to_owned()
}

fn default_eap_phase2() -> String {
    "auth=MSCHAPV2".to_owned()
}

fn default_interval() -> std::time::Duration {
    Duration::from_secs(1)
}

fn default_timeout() -> std::time::Duration {
    Duration::from_secs(5)
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum PacketCode {
    AccessRequest,
    AccountingRequest,
    DisconnectRequest,
    CoARequest,
}

impl From<PacketCode> for radius::core::code::Code {
    fn from(packet_type: PacketCode) -> Self {
        match packet_type {
            PacketCode::AccessRequest => radius::core::code::Code::AccessRequest,
            PacketCode::AccountingRequest => radius::core::code::Code::AccountingRequest,
            PacketCode::DisconnectRequest => radius::core::code::Code::DisconnectRequest,
            PacketCode::CoARequest => radius::core::code::Code::CoARequest,
        }
    }
}

use std::{net::SocketAddr, time::Duration};

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
    pub auth: AuthConfig,
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
    pub server: SocketAddr,
    pub secret: String,
    pub username: String,
    pub password: String,
    pub nas_identifier: Option<String>,
    pub packet_type: PacketCode,
    #[serde(default)]
    pub method: AuthMethod,
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
}

fn default_interval() -> std::time::Duration {
    Duration::from_secs(1)
}

fn default_timeout() -> std::time::Duration {
    Duration::from_secs(5)
}

#[derive(Debug, Clone, Deserialize)]
pub enum PacketCode {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccountingRequest,
    AccountingResponse,
    AccessChallenge,
    StatusServer,
    StatusClient,
    DisconnectRequest,
    DisconnectACK,
    DisconnectNAK,
    CoARequest,
    CoAACK,
    CoANAK,
    Reserved,
    Invalid,
}

impl From<PacketCode> for radius::core::code::Code {
    fn from(packet_type: PacketCode) -> Self {
        match packet_type {
            PacketCode::AccessRequest => radius::core::code::Code::AccessRequest,
            PacketCode::AccessAccept => radius::core::code::Code::AccessAccept,
            PacketCode::AccessReject => radius::core::code::Code::AccessReject,
            PacketCode::AccountingRequest => radius::core::code::Code::AccountingRequest,
            PacketCode::AccountingResponse => radius::core::code::Code::AccountingResponse,
            PacketCode::AccessChallenge => radius::core::code::Code::AccessChallenge,
            PacketCode::StatusServer => radius::core::code::Code::StatusServer,
            PacketCode::StatusClient => radius::core::code::Code::StatusClient,
            PacketCode::DisconnectRequest => radius::core::code::Code::DisconnectRequest,
            PacketCode::DisconnectACK => radius::core::code::Code::DisconnectACK,
            PacketCode::DisconnectNAK => radius::core::code::Code::DisconnectNAK,
            PacketCode::CoARequest => radius::core::code::Code::CoARequest,
            PacketCode::CoAACK => radius::core::code::Code::CoAACK,
            PacketCode::CoANAK => radius::core::code::Code::CoANAK,
            PacketCode::Reserved => radius::core::code::Code::Reserved,
            PacketCode::Invalid => radius::core::code::Code::Invalid,
        }
    }
}

use radius::core::{avp::AVPError, packet::PacketError};
use std::fmt::Debug;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Clone, PartialEq, Eq)]
pub enum AppError {
    #[error("request error: {0}")]
    RequestError(String),
    #[error("file error: {0}")]
    FileError(String),
    #[error("could not parse IP address: {0}")]
    ParseError(String),
    #[error("could not parse json: {0}")]
    DeserializeError(String),
    #[error("io error: {0}")]
    IoError(String),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("radius packet error: {0}")]
    RadiusPacketError(String),
}

impl Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(value: std::num::ParseIntError) -> Self {
        AppError::ParseError(value.to_string())
    }
}

impl From<::config::ConfigError> for AppError {
    fn from(value: ::config::ConfigError) -> Self {
        AppError::ConfigError(value.to_string())
    }
}
impl From<AVPError> for AppError {
    fn from(value: AVPError) -> Self {
        AppError::RadiusPacketError(value.to_string())
    }
}

impl From<PacketError> for AppError {
    fn from(value: PacketError) -> Self {
        AppError::RadiusPacketError(value.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        AppError::IoError(value.to_string())
    }
}

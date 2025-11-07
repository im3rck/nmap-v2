//! Error types for ApexScan

use thiserror::Error;

/// ApexScan Result type
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for ApexScan operations
#[derive(Error, Debug)]
pub enum Error {
    /// Network operation error
    #[error("Network error: {0}")]
    Network(String),

    /// Packet parsing error
    #[error("Packet parse error: {0}")]
    PacketParse(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Permission error (e.g., CAP_NET_RAW required)
    #[error("Permission denied: {0}")]
    Permission(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Script execution error
    #[error("Script error: {0}")]
    Script(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// DNS error kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    Bug,
    InvalidPacket,
    InvalidConfig,
    InvalidArgument,
    /// The remote peer refused the request — most often a non-retryable
    /// HTTP status from a DoH server (401, 403, 406, 415, ...). Distinct from
    /// [`ErrorKind::InvalidPacket`]: the server received and understood a
    /// well-formed DNS message but chose not to answer it.
    Rejected,
    Timeout,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Bug => write!(f, "bug"),
            ErrorKind::InvalidPacket => write!(f, "invalid_packet"),
            ErrorKind::InvalidArgument => write!(f, "invalid_argument"),
            ErrorKind::InvalidConfig => {
                write!(f, "invalid_config")
            }
            ErrorKind::Rejected => write!(f, "rejected"),
            ErrorKind::Timeout => write!(f, "timeout"),
        }
    }
}

/// DNS parsing/serialization errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MudzError {
    pub kind: ErrorKind,
    pub message: String,
}

impl MudzError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for MudzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for MudzError {}

impl From<std::io::Error> for MudzError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::InvalidConfig, format!("std::io::IoError: {e}"))
    }
}

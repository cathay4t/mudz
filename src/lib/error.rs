// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// DNS error kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    BufferTooShort,
    InvalidCompressionPointer,
    InvalidDomainName,
    InvalidRecordType,
    InvalidRdata,
    LabelTooLong,
    DomainNameTooLong,
    CompressionPointerCycle,
    IoError(String),
    Timeout,
    InvalidResponse,
    InvalidConfig,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::BufferTooShort => write!(f, "buffer_too_short"),
            ErrorKind::InvalidCompressionPointer => {
                write!(f, "invalid_compression_pointer")
            }
            ErrorKind::InvalidDomainName => write!(f, "invalid_domain_name"),
            ErrorKind::InvalidRecordType => write!(f, "invalid_record_type"),
            ErrorKind::InvalidRdata => write!(f, "invalid_rdata"),
            ErrorKind::LabelTooLong => write!(f, "label_too_long"),
            ErrorKind::DomainNameTooLong => write!(f, "domain_name_too_long"),
            ErrorKind::CompressionPointerCycle => {
                write!(f, "compression_pointer_cycle")
            }
            ErrorKind::IoError(msg) => write!(f, "io_error: {msg}"),
            ErrorKind::Timeout => write!(f, "timeout"),
            ErrorKind::InvalidResponse => write!(f, "invalid_response"),
            ErrorKind::InvalidConfig => write!(f, "invalid_config"),
        }
    }
}

/// DNS parsing/serialization errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError {
    pub kind: ErrorKind,
    pub message: String,
}

impl DnsError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for DnsError {}

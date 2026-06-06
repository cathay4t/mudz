// SPDX-License-Identifier: Apache-2.0

use crate::{ErrorKind, MudzError};

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl From<DnsResponseCode> for u8 {
    fn from(rcode: DnsResponseCode) -> u8 {
        match rcode {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormErr => 1,
            DnsResponseCode::ServFail => 2,
            DnsResponseCode::NxDomain => 3,
            DnsResponseCode::NotImp => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::Other(c) => c,
        }
    }
}

impl From<u8> for DnsResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            _ => Self::Other(value),
        }
    }
}

/// DNS Header structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u16,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u16,
    pub rcode: DnsResponseCode,
    /// Question count
    pub qdcount: u16,
    /// Answer count
    pub ancount: u16,
    /// Authority record count
    pub nscount: u16,
    /// Additional record count
    pub arcount: u16,
}

impl DnsHeader {
    pub const LEN: usize = 12;

    pub fn is_query(&self) -> bool {
        !self.qr
    }

    pub fn parse(data: &[u8]) -> Result<Self, MudzError> {
        if data.len() < Self::LEN {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                format!(
                    "DNS header is too short, expecting {}, got {}",
                    Self::LEN,
                    data.len()
                ),
            ));
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        Ok(Self {
            id,
            qr: (flags & 0x8000) != 0,
            opcode: ((flags & 0x7800) >> 11),
            aa: (flags & 0x0400) != 0,
            tc: (flags & 0x0200) != 0,
            rd: (flags & 0x0100) != 0,
            ra: (flags & 0x0080) != 0,
            z: ((flags & 0x0070) >> 4),
            rcode: ((flags & 0x000F) as u8).into(),
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);

        // ID
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Flags
        let mut flags = 0u16;
        if self.qr {
            flags |= 1u16 << 15;
        }
        flags |= self.opcode << 11;
        if self.aa {
            flags |= 1u16 << 10;
        }
        if self.tc {
            flags |= 1u16 << 9;
        }
        if self.rd {
            flags |= 1u16 << 8;
        }
        if self.ra {
            flags |= 1u16 << 7;
        }
        flags |= self.z << 4;
        flags |= u8::from(self.rcode) as u16;

        buf.extend_from_slice(&flags.to_be_bytes());

        // Counts
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
    }

    pub fn new_response(id: u16, rcode: DnsResponseCode) -> Self {
        Self {
            id,
            qr: true,
            rcode,
            qdcount: 1,
            ..Default::default()
        }
    }

    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            qr: false,
            rd: true,
            qdcount: 1,
            ..Default::default()
        }
    }

    pub fn set_response(&mut self, value: bool) {
        self.qr = value;
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: DnsResponseCode::NoError,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

mod error;
mod header;
mod packet;
mod record;

pub use self::{
    error::{ErrorKind, MudzError},
    header::{DnsHeader, DnsResponseCode},
    packet::{DnsPacket, DnsType},
    record::{DnsClass, DnsDomainName, DnsQuestion, DnsResourceRecord},
};

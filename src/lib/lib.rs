// SPDX-License-Identifier: Apache-2.0

mod client;
mod error;
mod header;
mod packet;
mod record;

pub use self::{
    client::DnsUdpClient,
    error::{ErrorKind, MudzError},
    header::{DnsHeader, DnsResponseCode},
    packet::{DnsPacket, DnsType},
    record::{DnsClass, DnsDomainName, DnsQuestion, DnsResourceRecord},
};

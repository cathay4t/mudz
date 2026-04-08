// SPDX-License-Identifier: Apache-2.0

mod dns;
mod error;
mod https_client;
mod udp_client;
#[cfg(test)]
mod unit_tests;

pub use self::{
    dns::{
        DnsDomainName, DnsHeader, DnsMessage, DnsMessageType, DnsQueryType,
        DnsQuestion, DnsRecordClass, DnsResourceRecord, DnsResponseCode,
    },
    error::{DnsError, ErrorKind},
    https_client::DnsHttpsClient,
    udp_client::DnsUdpClient,
};

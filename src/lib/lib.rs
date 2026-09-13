// SPDX-License-Identifier: Apache-2.0

//! DNS cache library.
//!
//! Besides the DNS packet codec, the crate provides an embeddable caching
//! resolver through [`MudzServer`], configured by [`MudzConfig`]:
//!
//! ```no_run
//! use mudz::{MudzConfig, MudzServer};
//!
//! # async fn run() -> Result<(), mudz::MudzError> {
//! let config = MudzConfig::from_file("/etc/mudz/mudz.conf")?;
//! let server = MudzServer::new(config).await?;
//! server.run().await
//! # }
//! ```
//!
//! [`MudzConfig`] can also be built from plain struct literals (all fields
//! are public and have defaults) when the embedder stores its configuration
//! in another format.
//!
//! [`MudzServer::new`] validates the configuration, binds the listening
//! sockets and resolves the DoH bootstrap hostnames, so an error means
//! nothing is listening. [`MudzServer::run`] then serves queries until
//! `SIGINT`/`SIGTERM`; embedders that own their shutdown path use
//! [`MudzServer::run_with_shutdown`] instead. Both take the server by value
//! and release the sockets before returning, so a configuration change is
//! handled by stopping the running server and creating a new one. Live
//! reconfiguration is not supported.

mod cache;
mod client;
mod config;
mod doh;
mod error;
mod group;
mod header;
mod host;
mod listener;
mod packet;
mod record;
mod resolver;
mod retry;
mod server;
mod suspend;

pub use self::{
    client::DnsUdpClient,
    config::{
        MudzConfig, MudzDohConfig, MudzFallbackConfig, MudzGroupConfig,
        MudzMainConfig,
    },
    error::{ErrorKind, MudzError},
    header::{DnsHeader, DnsResponseCode},
    packet::{DnsPacket, DnsType},
    record::{
        DnsClass, DnsDomainName, DnsNameCompressionMap, DnsQuestion,
        DnsResourceRecord,
    },
    server::MudzServer,
};

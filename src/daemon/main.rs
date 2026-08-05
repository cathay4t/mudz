// SPDX-License-Identifier: Apache-2.0

mod cache;
mod config;
mod doh;
mod group;
mod host;
mod listener;
mod resolver;
mod retry;
mod server;

#[cfg(test)]
mod tests;

use std::cmp::min;

use env_logger::Builder;
use log::LevelFilter;
use mudz::{ErrorKind, MudzError};

use self::{config::MudzConfig, server::DnsUdpServer};

const DEFAULT_CONFIG_PATH: &str = "/etc/mudz/mudz.conf";

/// Builds the daemon's log filter.
///
/// The configured `log_level` applies to mudz's own crates (`mudz`,
/// `mudzd`) only. Third-party crates (reqwest, hyper, rustls, ...) are
/// capped at `info` — or at the configured level when it is below `info` —
/// so their TRACE/DEBUG chatter (e.g. `reqwest::retry` "shouldn't retry!")
/// does not pollute the daemon log when `debug`/`trace` is configured.
///
/// `RUST_LOG` (when set) overrides these defaults entirely.
fn build_logger(log_level: &str, rust_log: Option<&str>) -> Builder {
    let own = log_level
        .parse::<LevelFilter>()
        .unwrap_or(LevelFilter::Error);
    let mut builder = Builder::new();
    builder
        .filter(Some("mudz"), own)
        .filter(Some("mudzd"), own)
        .filter(None, min(own, LevelFilter::Info));
    if let Some(rust_log) = rust_log {
        builder.parse_filters(rust_log);
    }
    builder
}

fn main() -> Result<(), MudzError> {
    let config = MudzConfig::from_file(DEFAULT_CONFIG_PATH)?;
    let log_level = &config.main.log_level;

    build_logger(
        log_level,
        std::env::var(env_logger::DEFAULT_FILTER_ENV)
            .ok()
            .as_deref(),
    )
    .init();

    log::info!(
        "Starting DNS Caching Server on {} (fallback: {:?})",
        config.main.udp_bind,
        config.fallback.nameservers,
    );

    // Run the server in a Tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        // We only have two threads
        .worker_threads(2)
        .thread_name("mudz-worker")
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| {
            MudzError::new(ErrorKind::Bug, "Failed to create Tokio runtime")
        })?;

    rt.block_on(async move { DnsUdpServer::new(config).await?.run().await })
}

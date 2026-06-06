// SPDX-License-Identifier: Apache-2.0

mod cache;
mod config;
mod doh;
mod group;
mod host;
mod listener;
mod resolver;
mod server;

#[cfg(test)]
mod tests;

use mudz::{ErrorKind, MudzError};

use self::{config::MudzConfig, server::DnsUdpServer};

const DEFAULT_CONFIG_PATH: &str = "/etc/mudz/mudz.conf";

fn main() -> Result<(), MudzError> {
    let config = MudzConfig::from_file(DEFAULT_CONFIG_PATH)?;
    let log_level = &config.main.log_level;

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level),
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

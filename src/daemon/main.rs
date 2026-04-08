// SPDX-License-Identifier: Apache-2.0

use mudz::DnsError;

mod cache;
mod config;
mod dns_server;
mod host;

use self::{config::MudzConfig, dns_server::DnsUdpServer};

fn main() -> Result<(), DnsError> {
    let config = MudzConfig::from_file(config::DEFAULT_CONFIG_PATH)?;
    let cache_size = config.main.max_cache_size;
    let log_level = &config.main.log_level;

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level),
    )
    .init();

    let server = DnsUdpServer::from_config(&config, cache_size)?;

    log::info!(
        "Starting DNS Caching Server on {} (fallback: {:?})",
        server.listen_addr(),
        config.fallback.nameservers,
    );

    if !config.groups.is_empty() {
        for (name, group) in &config.groups {
            log::info!(
                "Domain group '{}': {:?} -> {:?}",
                name,
                group.domains,
                group.nameservers
            );
        }
    }

    // Run the server in a Tokio runtime
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        DnsError::new(
            mudz::ErrorKind::IoError(e.to_string()),
            "Failed to create Tokio runtime",
        )
    })?;

    rt.block_on(async { server.run().await })
}

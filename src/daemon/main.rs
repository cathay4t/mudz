// SPDX-License-Identifier: Apache-2.0

use clap::{Arg, ArgAction, Command};
use mudz::DnsError;

mod dns_server;
use self::dns_server::DnsUdpServer;

fn main() -> Result<(), DnsError> {
    env_logger::init();

    let matches = Command::new("mudzd")
        .version("0.1.0")
        .about("Linux DNS Caching Daemon")
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .value_name("ADDRESS")
                .help("Address to listen on (default: 127.0.0.1:53)")
                .default_value("127.0.0.1:53"),
        )
        .arg(
            Arg::new("upstream")
                .short('u')
                .long("upstream")
                .value_name("DNS_SERVER")
                .help("Upstream DNS server or DoH URL (default: 8.8.8.8)")
                .default_value("8.8.8.8"),
        )
        .arg(
            Arg::new("https")
                .short('H')
                .long("https")
                .help("Use DNS-over-HTTPS instead of UDP")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("cache-size")
                .short('c')
                .long("cache-size")
                .value_name("SIZE")
                .help("Maximum cache entries (default: 1000)")
                .default_value("1000")
                .value_parser(clap::value_parser!(usize)),
        )
        .get_matches();

    let listen_addr = matches.get_one::<String>("listen").unwrap();
    let upstream = matches.get_one::<String>("upstream").unwrap();
    let use_https = matches.get_flag("https");
    let cache_size = *matches.get_one::<usize>("cache-size").unwrap();

    let server =
        DnsUdpServer::new(listen_addr, upstream, use_https, cache_size)?;

    log::info!(
        "Starting DNS Caching Server on {} (upstream: {}, HTTPS: {})",
        server.listen_addr(),
        upstream,
        use_https
    );

    // Run the server in a Tokio runtime
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        DnsError::new(
            mudz::ErrorKind::IoError(e.to_string()),
            "Failed to create Tokio runtime",
        )
    })?;

    rt.block_on(async { server.run().await })
}

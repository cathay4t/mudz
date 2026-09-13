# DNS cache daemon in Rust -- mudz

## Features

- Support DNS over UDP, TCP and HTTPs.
- Domain based DNS name server selecting.
- Embeddable: the whole cache server is a library crate.
- Pure rust code with memory safe guarantee.
- High performance.

## Usage

```bash
sudo mkdir /etc/mudz
sudo cp -fv mudz.conf.example /etc/mudz/mudz.conf
cargo build --release
sudo systemctl stop mudz.service
sudo cp -fv target/release/mudzd /usr/bin/
sudo cp -fv mudz.service /etc/systemd/system/
sudo systemctl enable mudz.service --now
```

## Embedding

The `mudz` library crate contains the cache server itself, so another daemon
can run it without the `mudzd` binary. Build a `MudzConfig` in code (or load
it with `MudzConfig::from_file()`) and hand it to `MudzServer`:

```rust,no_run
use mudz::{MudzConfig, MudzServer};

# async fn run() -> Result<(), mudz::MudzError> {
let config = MudzConfig::from_file("/etc/mudz/mudz.conf")?;
let server = MudzServer::new(config).await?; // validates, binds, bootstraps DoH
server.run().await // blocks until SIGINT/SIGTERM
# }
```

`MudzServer::new()` fails if the configuration is invalid or the UDP socket
cannot be bound. `run()` blocks until the process gets `SIGINT`/`SIGTERM`;
embedders that own their shutdown path call
`run_with_shutdown(shutdown_future)` instead. Both take the server by value
and release the listening sockets before returning, so a configuration
change is handled by dropping the old server and creating a new one. Live
reconfiguration is not supported.

## Configuration

```toml
[main]
# Which UDP socket to listen
udp_bind = "127.0.0.1:53"
# Which TCP socket to listen (optional; defaults to udp_bind). DNS over TCP
# is required by RFC 7766: clients retry over TCP when a UDP reply is
# truncated (TC bit), e.g. bind-utils `host` with answers over 512 bytes.
tcp_bind = "127.0.0.1:53"
# Maximum number of cache entries. 0 disables caching, queries are still
# forwarded to the upstream nameservers.
max_cache_size = 4096
# Answer A/AAAA queries from /etc/hosts before forwarding them.
load_etc_hosts = true
# Log level (trace, debug, info, warn, error)
log_level = "info"

[fallback]
# Send out DNS request to all nameservers simultaneously, and reply to user
# once got any valid reply
nameservers = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]
disable_ipv6 = true

# To resolve DoH server hostnames via plain UDP, use the [doh] section.
# Mandatory if any nameserver is a DoH URL.
[doh]
nameservers = ["223.5.5.5", "119.29.29.29"]
disable_ipv6 = false

# Redirect user's request on these domains to specified nameservers instead of
# fallback ones
[group.google]
nameservers = ["8.8.8.8", "https://dns.google/dns-query"]
domains = [
    "google.com",
    "youtube.com",
]

[group.company]
nameservers = ["10.0.0.1"]
domains = [
    "fish-touching.net",
]
# Don't send AAAA queries to this nameserver
disable_ipv6 = true

# Return NXDOMAIN for these domains without sending any upstream query
# (useful for blocking domains)
[group.blocked]
nameservers = []
domains = [
    "ads.example.com",
]
```

## License

Apache License Version 2.0
http://www.apache.org/licenses/

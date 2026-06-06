# DNS cache daemon in Rust -- mudz

## Features
 * Support DNS over UDP and HTTPs.
 * Domain based DNS name server selecting.
 * Pure rust code with memory safe guarantee.
 * Lock free concurrency and high performance.

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

## Configuration

```toml
[main]
# Which UDP socket to listen
udp_bind = "127.0.0.1:53"
# Maximum number of cache entries
max_cache_size = 4096
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

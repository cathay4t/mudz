# DNS cache daemon in Rust -- mudz

## Features
 * Support DNS over UDP and HTTPs.
 * Domain based DNS name server selecting.
 * Pure rust code with memory safe guarantee.

## Usage

```bash
sudo mkdir /etc/mudz
sudo cp -fv mudz.conf.example /etc/mudz/mudz.conf
cargo build --release
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
nameservers = ["223.5.5.5", "119.29.29.29"]

# Redirect user's request on these domains to specified nameservers instead of
# fallback ones
[nameservers.google]
nameservers = ["8.8.8.8"]
domains = [
    "google.com",
    "youtube.com",
]

[nameserver.company]
nameservers = ["10.0.0.1"]
domains = [
    "fish-touching.net",
]
```

## License

Apache License Version 2.0
http://www.apache.org/licenses/

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

## License

Apache License Version 2.0
http://www.apache.org/licenses/

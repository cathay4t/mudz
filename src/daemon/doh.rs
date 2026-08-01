// SPDX-License-Identifier: Apache-2.0

//! DNS over HTTPS (DoH) client implementation per RFC 8484.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use data_encoding::BASE64URL_NOPAD;
use mudz::{DnsPacket, DnsResponseCode, ErrorKind, MudzError};
use reqwest::{Client, Url};

const DEFAULT_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const DNS_MEDIA_TYPE: &str = "application/dns-message";

#[derive(Clone)]
pub(crate) struct DohClient {
    url_prefix: String,
    http_client: Client,
    timeout: std::time::Duration,
}

impl DohClient {
    pub(crate) fn new(
        server_url: &str,
        cache: Arc<DohResolvCache>,
    ) -> Result<Self, MudzError> {
        if !server_url.starts_with("https://") {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                "DoH server URL must use https:// scheme",
            ));
        }

        let http_client = Client::builder()
            .timeout(DEFAULT_TIMEOUT_SEC)
            .dns_resolver(cache)
            .build()
            .map_err(|e| {
                MudzError::new(
                    ErrorKind::Bug,
                    format!("Failed to create HTTP client: {e}",),
                )
            })?;

        let url_prefix = if server_url.contains('?') {
            format!("{server_url}&dns=")
        } else {
            format!("{server_url}?dns=")
        };

        Ok(Self {
            url_prefix,
            http_client,
            timeout: DEFAULT_TIMEOUT_SEC,
        })
    }

    pub(crate) async fn request(
        &self,
        packet: &DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        let dns_param = BASE64URL_NOPAD.encode(&packet.to_bytes());

        let url = format!("{}{}", self.url_prefix, dns_param);
        let url = Url::parse(&url).map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Invalid DoH server URL: {e}"),
            )
        })?;

        let response = self
            .http_client
            .get(url)
            .header("Accept", DNS_MEDIA_TYPE)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                MudzError::new(
                    ErrorKind::Bug,
                    format!("Failed to send DoH request: {e}"),
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                format!(
                    "DoH server returned HTTP status {}: {}",
                    status,
                    status.canonical_reason().unwrap_or("Unknown")
                ),
            ));
        }

        let response_bytes = response
            .bytes()
            .await
            .map_err(|_| {
                MudzError::new(
                    ErrorKind::Bug,
                    "Failed to read DoH response body",
                )
            })?
            .to_vec();

        if response_bytes.len() > DnsPacket::MAX_DOH_PACKET_SIZE {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                format!(
                    "DoH response exceeds maximum(65535) DNS message size: {} \
                     bytes",
                    response_bytes.len()
                ),
            ));
        }

        let packet = DnsPacket::parse(&response_bytes)?;

        match packet.header.rcode {
            DnsResponseCode::FormErr => {
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
                    "DNS server returned error code: FormErr",
                ));
            }
            DnsResponseCode::ServFail => {
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
                    "DNS server returned error code: ServFail",
                ));
            }
            _ => {}
        }

        Ok(packet)
    }
}

pub(crate) struct DohResolvCache {
    store: HashMap<String, Vec<IpAddr>>,
}

impl DohResolvCache {
    pub(crate) fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, domain: &str, ips: Vec<IpAddr>) {
        self.store.insert(domain.to_string(), ips);
    }
}

impl reqwest::dns::Resolve for DohResolvCache {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        if let Some(ips) = self.store.get(name.as_str()) {
            let addrs: Vec<SocketAddr> =
                ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect();
            Box::pin(async move {
                Ok(Box::new(addrs.into_iter())
                    as Box<dyn Iterator<Item = SocketAddr> + Send>)
            })
        } else {
            Box::pin(async move {
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Domain not found in static registry",
                ))
                    as Box<dyn std::error::Error + Send + Sync>)
            })
        }
    }
}

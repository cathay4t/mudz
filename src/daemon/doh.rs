// SPDX-License-Identifier: Apache-2.0

//! DNS over HTTPS (DoH) client implementation per RFC 8484.
//!
//! This module provides `DohClient` which performs DNS queries over HTTPS
//! using the GET method with base64url-encoded DNS wire format queries.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use data_encoding::BASE64URL_NOPAD;
use mudz::{DnsPacket, DnsResponseCode, ErrorKind, MudzError};
use reqwest::{Client, Url};

/// Default query timeout: 5 seconds
const DEFAULT_TIMEOUT_SEC: Duration = Duration::from_secs(5);
/// DNS media type per RFC 8484
const DNS_MEDIA_TYPE: &str = "application/dns-message";

/// DNS over HTTPS client per RFC 8484.
///
/// This client performs DNS queries over HTTPS using the GET method.
/// The DNS query is base64url-encoded (without padding) and passed as
/// the `dns` query parameter.
#[derive(Clone)]
pub(crate) struct DohClient {
    /// DoH server URL (e.g., "https://dns.google/dns-query")
    server_url: String,
    /// HTTP client
    http_client: Client,
    /// Query timeout
    timeout: std::time::Duration,
}

impl DohClient {
    /// Create a new DoH client with a specific server URL.
    ///
    /// # Arguments
    /// * `server_url` - DoH server URL (e.g., "https://dns.google/dns-query",
    ///   "https://cloudflare-dns.com/dns-query")
    pub(crate) fn new(
        server_url: &str,
        cache: Arc<DohResolvCache>,
    ) -> Result<Self, MudzError> {
        // Validate URL format
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

        Ok(Self {
            server_url: server_url.to_string(),
            http_client,
            timeout: DEFAULT_TIMEOUT_SEC,
        })
    }

    pub(crate) async fn request(
        &self,
        packet: &DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        // Base64url-encode without padding (RFC 8484 Section 4.1)
        let dns_param = BASE64URL_NOPAD.encode(&packet.to_bytes());

        // Build URL with dns query parameter
        let mut url = Url::parse(&self.server_url).map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Invalid DoH server URL: {e}"),
            )
        })?;
        url.query_pairs_mut().append_pair("dns", &dns_param);

        // Send HTTP GET request
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

        // Check HTTP status - 2xx means success
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

        // Read response body
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

        // Validate response size
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

        // Return the response even if it contains NxDomain or other non-error
        // rcodes. NxDomain is a valid DNS response meaning "this domain
        // doesn't exist" and should be passed through to the client.
        // Only treat FormErr and ServFail as actual errors.
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
            _ => {} /* NoError, NxDomain, NotImp, Refused, Other are all
                     * valid responses to pass through */
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

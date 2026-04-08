// SPDX-License-Identifier: Apache-2.0

//! DNS over HTTPS (DoH) client implementation per RFC 8484.
//!
//! This module provides `DnsHttpsClient` which performs DNS queries over HTTPS
//! using the GET method with base64url-encoded DNS wire format queries.

use std::net::{Ipv4Addr, Ipv6Addr};

use data_encoding::BASE64URL_NOPAD;
use reqwest::Client;

use crate::{
    dns::{DnsDomainName, DnsMessage, DnsQueryType, DnsResourceRecord},
    error::{DnsError, ErrorKind},
};

/// Default DoH server URL (Google's public DNS over HTTPS)
const DEFAULT_DOH_SERVER: &str = "https://dns.google/dns-query";
/// Default query timeout
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Maximum CNAME chain depth to prevent infinite loops
const MAX_CNAME_DEPTH: usize = 10;
/// DNS media type per RFC 8484
const DNS_MEDIA_TYPE: &str = "application/dns-message";
/// Maximum DNS message size over HTTPS
const MAX_DNS_MESSAGE_SIZE: usize = 65535;

/// Trait for parsing DNS record types from RDATA
trait DnsRecordType: Sized {
    const QUERY_TYPE: DnsQueryType;
    fn parse_rdata(rdata: &[u8]) -> Option<Self>;
}

impl DnsRecordType for Ipv4Addr {
    const QUERY_TYPE: DnsQueryType = DnsQueryType::A;

    fn parse_rdata(rdata: &[u8]) -> Option<Self> {
        if rdata.len() == 4 {
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
        } else {
            None
        }
    }
}

impl DnsRecordType for Ipv6Addr {
    const QUERY_TYPE: DnsQueryType = DnsQueryType::AAAA;

    fn parse_rdata(rdata: &[u8]) -> Option<Self> {
        if rdata.len() == 16 {
            Some(Ipv6Addr::new(
                u16::from_be_bytes([rdata[0], rdata[1]]),
                u16::from_be_bytes([rdata[2], rdata[3]]),
                u16::from_be_bytes([rdata[4], rdata[5]]),
                u16::from_be_bytes([rdata[6], rdata[7]]),
                u16::from_be_bytes([rdata[8], rdata[9]]),
                u16::from_be_bytes([rdata[10], rdata[11]]),
                u16::from_be_bytes([rdata[12], rdata[13]]),
                u16::from_be_bytes([rdata[14], rdata[15]]),
            ))
        } else {
            None
        }
    }
}

/// Result of a DNS query that may include CNAME redirection
enum QueryResult<T> {
    FoundRecords(Vec<T>),
    CNAMEredirect(String),
    NoRecords,
}

/// DNS over HTTPS client per RFC 8484.
///
/// This client performs DNS queries over HTTPS using the GET method.
/// The DNS query is base64url-encoded (without padding) and passed as
/// the `dns` query parameter.
#[derive(Clone)]
pub struct DnsHttpsClient {
    /// DoH server URL (e.g., "https://dns.google/dns-query")
    server_url: String,
    /// HTTP client
    http_client: Client,
    /// Query timeout
    timeout: std::time::Duration,
}

impl DnsHttpsClient {
    /// Create a new DoH client using the default server (Google's DNS over
    /// HTTPS).
    pub fn new() -> Result<Self, DnsError> {
        Self::with_server(DEFAULT_DOH_SERVER)
    }

    /// Create a new DoH client with a specific server URL.
    ///
    /// # Arguments
    /// * `server_url` - DoH server URL (e.g., "https://dns.google/dns-query",
    ///   "https://cloudflare-dns.com/dns-query")
    pub fn with_server(server_url: &str) -> Result<Self, DnsError> {
        // Validate URL format
        if !server_url.starts_with("https://") {
            return Err(DnsError::new(
                ErrorKind::InvalidDomainName,
                "DoH server URL must use https:// scheme",
            ));
        }

        let http_client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to create HTTP client",
                )
            })?;

        Ok(Self {
            server_url: server_url.to_string(),
            http_client,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Set the query timeout.
    pub fn set_timeout(&mut self, timeout: std::time::Duration) {
        self.timeout = timeout;
    }

    /// Get the DoH server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Query A records for a domain name.
    ///
    /// This function handles CNAME redirection by following CNAME chains
    /// to find the final A record(s).
    ///
    /// # Arguments
    /// * `domain_name` - The domain name to query (e.g., "example.com")
    ///
    /// # Returns
    /// A vector of IPv4 addresses, or an error if the query fails
    pub async fn query_a_record(
        &self,
        domain_name: &str,
    ) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.query_records_internal(domain_name).await
    }

    /// Query AAAA records for a domain name.
    ///
    /// This function handles CNAME redirection by following CNAME chains
    /// to find the final AAAA record(s).
    ///
    /// # Arguments
    /// * `domain_name` - The domain name to query (e.g., "example.com")
    ///
    /// # Returns
    /// A vector of IPv6 addresses, or an error if the query fails
    pub async fn query_aaaa_record(
        &self,
        domain_name: &str,
    ) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.query_records_internal(domain_name).await
    }

    /// Generic internal query handler with CNAME following support
    async fn query_records_internal<T: DnsRecordType>(
        &self,
        domain_name: &str,
    ) -> Result<Vec<T>, DnsError> {
        let mut current_domain = domain_name.to_string();

        for _depth in 0..=MAX_CNAME_DEPTH {
            let result = self.query_dns::<T>(&current_domain).await?;

            match result {
                QueryResult::FoundRecords(records) => return Ok(records),
                QueryResult::CNAMEredirect(target) => {
                    current_domain = target;
                }
                QueryResult::NoRecords => {
                    // No records of this type exist for this domain
                    return Ok(Vec::new());
                }
            }
        }

        Err(DnsError::new(
            ErrorKind::InvalidResponse,
            "CNAME chain too deep, possible infinite loop",
        ))
    }

    /// Perform a single DNS query over HTTPS per RFC 8484.
    ///
    /// Uses the GET method with base64url-encoded DNS query.
    /// Per RFC 8484 Section 4.1:
    /// - DNS header ID SHOULD be 0 to maximize HTTP cache hit rates
    /// - DNS wire format is base64url-encoded without padding
    /// - Accept header SHOULD specify supported media types
    async fn query_dns<T: DnsRecordType>(
        &self,
        domain: &str,
    ) -> Result<QueryResult<T>, DnsError> {
        // Create the DNS query message with ID=0 for HTTP caching
        let query = DnsMessage::new_query(0, domain, T::QUERY_TYPE)?;
        let query_bytes = query.to_bytes()?;

        // Base64url-encode without padding (RFC 8484 Section 4.1)
        let dns_param = BASE64URL_NOPAD.encode(&query_bytes);

        // Build URL with dns query parameter
        let url = format!("{}?dns={}", self.server_url, dns_param);

        // Send HTTP GET request
        let response = self
            .http_client
            .get(&url)
            .header("Accept", DNS_MEDIA_TYPE)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to send DoH request",
                )
            })?;

        // Check HTTP status - 2xx means success
        let status = response.status();
        if !status.is_success() {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
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
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to read DoH response body",
                )
            })?
            .to_vec();

        // Validate response size
        if response_bytes.len() > MAX_DNS_MESSAGE_SIZE {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                format!(
                    "DoH response too large: {} bytes (max {})",
                    response_bytes.len(),
                    MAX_DNS_MESSAGE_SIZE
                ),
            ));
        }

        // Parse the DNS response
        let response_message = DnsMessage::from_bytes(&response_bytes)?;

        // Extract records and CNAME records from the answer section
        let mut records = Vec::new();
        let mut first_cname_target: Option<String> = None;

        for record in &response_message.answers {
            Self::extract_record_or_cname::<T>(
                record,
                &mut records,
                &mut first_cname_target,
            );
        }

        log::trace!(
            "HTTPS response for {} {:?}: {} records, {} CNAMEs",
            domain,
            T::QUERY_TYPE,
            records.len(),
            if first_cname_target.is_some() { 1 } else { 0 }
        );

        // If we found records, return them
        if !records.is_empty() {
            return Ok(QueryResult::FoundRecords(records));
        }

        // If no records but we have a CNAME, follow the redirect
        if let Some(cname_target) = first_cname_target {
            log::trace!(
                "HTTPS CNAME redirect for {} {:?} -> {}",
                domain,
                T::QUERY_TYPE,
                cname_target
            );
            return Ok(QueryResult::CNAMEredirect(cname_target));
        }

        // No records and no CNAMEs
        log::trace!("HTTPS no records for {} {:?}", domain, T::QUERY_TYPE);
        Ok(QueryResult::NoRecords)
    }

    /// Query an arbitrary record type and return the raw response bytes.
    ///
    /// This method forwards the query to the upstream DoH server and returns
    /// the raw DNS response bytes without parsing specific record types.
    /// The caller is responsible for parsing the response.
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `query_type` - The type of DNS record to query
    ///
    /// # Returns
    /// Raw DNS response bytes, or an error if the query fails
    pub async fn query_raw(
        &self,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        log::trace!(
            "query_raw HTTPS: querying {} {:?} for {}",
            self.server_url,
            query_type,
            domain
        );
        // Create the DNS query message with ID=0 for HTTP caching
        let query = DnsMessage::new_query(0, domain, query_type)?;
        let query_bytes = query.to_bytes()?;

        // Base64url-encode without padding (RFC 8484 Section 4.1)
        let dns_param = BASE64URL_NOPAD.encode(&query_bytes);

        // Build URL with dns query parameter
        let url = format!("{}?dns={}", self.server_url, dns_param);

        // Send HTTP GET request
        let response = self
            .http_client
            .get(&url)
            .header("Accept", DNS_MEDIA_TYPE)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to send DoH request",
                )
            })?;

        // Check HTTP status - 2xx means success
        let status = response.status();
        if !status.is_success() {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
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
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to read DoH response body",
                )
            })?
            .to_vec();

        // Validate response size
        if response_bytes.len() > MAX_DNS_MESSAGE_SIZE {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                format!(
                    "DoH response too large: {} bytes (max {})",
                    response_bytes.len(),
                    MAX_DNS_MESSAGE_SIZE
                ),
            ));
        }

        // Parse and validate the response
        let response_message = DnsMessage::from_bytes(&response_bytes)?;

        // Return the response even if it contains NXDomain or other non-error
        // rcodes. NXDomain is a valid DNS response meaning "this domain
        // doesn't exist" and should be passed through to the client.
        // Only treat FormErr and ServFail as actual errors.
        match response_message.header.rcode {
            crate::dns::DnsResponseCode::FormErr => {
                return Err(DnsError::new(
                    ErrorKind::InvalidResponse,
                    "DNS server returned error code: FormErr",
                ));
            }
            crate::dns::DnsResponseCode::ServFail => {
                return Err(DnsError::new(
                    ErrorKind::InvalidResponse,
                    "DNS server returned error code: ServFail",
                ));
            }
            _ => {} /* NoError, NXDomain, NotImp, Refused, OTHER are all
                     * valid responses to pass through */
        }

        Ok(response_bytes)
    }

    /// Helper to extract a specific record type or CNAME from a DNS resource
    /// record
    fn extract_record_or_cname<T: DnsRecordType>(
        record: &DnsResourceRecord,
        records: &mut Vec<T>,
        first_cname_target: &mut Option<String>,
    ) {
        // Try to parse as the target record type
        if record.record_type == T::QUERY_TYPE {
            if let Some(ip) = T::parse_rdata(&record.rdata) {
                records.push(ip);
            }
        }
        // Try to parse as CNAME
        else if record.record_type == DnsQueryType::CNAME
            && !record.rdata.is_empty()
            && first_cname_target.is_none()
            && let Ok(cname_domain) =
                DnsDomainName::parse_from(&record.rdata, &mut 0usize)
        {
            *first_cname_target = Some(cname_domain.to_string());
        }
    }
}

impl Default for DnsHttpsClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DnsHttpsClient")
    }
}

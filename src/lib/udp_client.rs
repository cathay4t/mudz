// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::Rng;
use tokio::{
    net::UdpSocket,
    time::{Duration, timeout},
};

use crate::{
    dns::{DnsDomainName, DnsMessage, DnsQueryType, DnsResourceRecord},
    error::{DnsError, ErrorKind},
};

/// Default DNS server address (Google's public DNS)
const DEFAULT_DNS_SERVER: &str = "8.8.8.8";
/// Default DNS port
const DNS_PORT: u16 = 53;
/// Default query timeout
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum CNAME chain depth to prevent infinite loops
const MAX_CNAME_DEPTH: usize = 10;

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

/// UDP client for DNS queries
pub struct DnsUdpClient {
    /// DNS server address
    server_addr: SocketAddr,
    /// Query timeout
    timeout: Duration,
}

impl DnsUdpClient {
    /// Create a new DNS UDP client using the default DNS server (8.8.8.8:53)
    pub fn new() -> Result<Self, DnsError> {
        Self::with_server(DEFAULT_DNS_SERVER)
    }

    /// Create a new DNS UDP client with a specific server address
    ///
    /// # Arguments
    /// * `server` - DNS server address (e.g., "8.8.8.8", "1.1.1.1:5353")
    pub fn with_server(server: &str) -> Result<Self, DnsError> {
        // Parse server address, adding default port if not specified
        let server_addr = if server.contains(':') {
            server.parse::<SocketAddr>().map_err(|e| {
                DnsError::new(ErrorKind::InvalidDomainName, e.to_string())
            })?
        } else {
            format!("{}:{}", server, DNS_PORT)
                .parse::<SocketAddr>()
                .map_err(|e| {
                    DnsError::new(ErrorKind::InvalidDomainName, e.to_string())
                })?
        };

        Ok(Self {
            server_addr,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Set the query timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Query A records for a domain name
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

    /// Query AAAA records for a domain name
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

        for depth in 0..=MAX_CNAME_DEPTH {
            let result = self.query_dns::<T>(&current_domain).await?;

            match result {
                QueryResult::FoundRecords(records) => return Ok(records),
                QueryResult::CNAMEredirect(target) => {
                    current_domain = target;
                }
                QueryResult::NoRecords => {
                    if depth == MAX_CNAME_DEPTH {
                        return Err(DnsError::new(
                            ErrorKind::InvalidResponse,
                            "CNAME chain too deep, possible infinite loop",
                        ));
                    }
                    // Continue loop with next domain
                }
            }
        }

        // Should not reach here, but handle gracefully
        Ok(Vec::new())
    }

    /// Generic helper to perform a single DNS query and parse records
    async fn query_dns<T: DnsRecordType>(
        &self,
        domain: &str,
    ) -> Result<QueryResult<T>, DnsError> {
        // Generate a random transaction ID
        let id = rand::rng().random::<u16>();

        // Create the DNS query message
        let query = DnsMessage::new_query(id, domain, T::QUERY_TYPE)?;
        let query_bytes = query.to_bytes()?;

        // Create UDP socket (unbound, let OS choose)
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            DnsError::new(
                ErrorKind::IoError(e.to_string()),
                "Failed to bind UDP socket",
            )
        })?;

        // Send the query
        socket
            .send_to(&query_bytes, self.server_addr)
            .await
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to send DNS query",
                )
            })?;

        // Receive the response with timeout
        let mut response_buf = [0u8; 512]; // Standard DNS UDP size limit

        let response =
            timeout(self.timeout, socket.recv_from(&mut response_buf))
                .await
                .map_err(|_| {
                    DnsError::new(ErrorKind::Timeout, "DNS query timed out")
                })?
                .map_err(|e| {
                    DnsError::new(
                        ErrorKind::IoError(e.to_string()),
                        "Failed to receive DNS response",
                    )
                })?;

        let (bytes_received, _from_addr) = response;
        let response_bytes = &response_buf[..bytes_received];

        // Parse the DNS response
        let response_message = DnsMessage::from_bytes(response_bytes)?;

        // Validate the response
        if response_message.header.id != id {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "Response ID does not match query ID",
            ));
        }

        if !response_message.header.qr {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "Received a query instead of a response",
            ));
        }

        // Check for error response codes
        if response_message.header.rcode != crate::dns::DnsResponseCode::NoError
        {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                format!(
                    "DNS server returned error code: {:?}",
                    response_message.header.rcode
                ),
            ));
        }

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

        // If we found records, return them
        if !records.is_empty() {
            return Ok(QueryResult::FoundRecords(records));
        }

        // If no records but we have a CNAME, follow the redirect
        if let Some(cname_target) = first_cname_target {
            return Ok(QueryResult::CNAMEredirect(cname_target));
        }

        // No records and no CNAMEs
        Ok(QueryResult::NoRecords)
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

impl Default for DnsUdpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DnsUdpClient")
    }
}

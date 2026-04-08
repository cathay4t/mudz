// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use mudz::{
    DnsDomainName, DnsError, DnsHeader, DnsHttpsClient, DnsMessage,
    DnsMessageType, DnsQueryType, DnsQuestion, DnsRecordClass,
    DnsResourceRecord, DnsResponseCode, DnsUdpClient, ErrorKind,
};
use tokio::{net::UdpSocket, sync::RwLock};

/// Minimum TTL to cache (seconds)
const MIN_CACHE_TTL: u32 = 60;
/// Maximum TTL to cache (seconds, 1 day)
const MAX_CACHE_TTL: u32 = 86400;

/// Cache entry for a DNS query result
struct CacheEntry {
    /// Cached DNS message bytes (response format)
    response_bytes: Vec<u8>,
    /// Expiry time based on record TTL
    expires_at: Instant,
}

/// DNS cache storage
struct DnsCache {
    /// Map of (domain, query_type) -> cache entry
    entries: HashMap<(String, DnsQueryType), CacheEntry>,
    /// Maximum number of cache entries
    max_size: usize,
}

impl DnsCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    /// Get a cached response if it exists and hasn't expired
    fn get(
        &self,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Option<&CacheEntry> {
        self.entries
            .get(&(domain.to_string(), query_type))
            .filter(|entry| entry.expires_at > Instant::now())
    }

    /// Insert or update a cache entry
    fn insert(
        &mut self,
        domain: String,
        query_type: DnsQueryType,
        response: Vec<u8>,
        ttl: u32,
    ) {
        // Clamp TTL to reasonable bounds
        let effective_ttl = ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL);

        // Evict old entries if cache is full
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            // If still full, remove first entry
            if let Some(oldest_key) = self.entries.keys().next().cloned()
                && self.entries.len() >= self.max_size
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            (domain, query_type),
            CacheEntry {
                response_bytes: response,
                expires_at: Instant::now()
                    + Duration::from_secs(effective_ttl as u64),
            },
        );
    }

    /// Remove all expired entries
    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Get current cache size
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Upstream resolver type
#[derive(Clone)]
enum ResolverType {
    Udp,
    Https,
}

/// DNS UDP server with caching support
pub struct DnsUdpServer {
    /// Cache for DNS responses
    cache: Arc<RwLock<DnsCache>>,
    /// Listen address
    listen_addr: String,
    /// Upstream DNS UDP client
    udp_client: Option<DnsUdpClient>,
    /// Upstream DNS HTTPS client
    https_client: Option<DnsHttpsClient>,
    /// Resolver type
    resolver_type: ResolverType,
    /// Socket receive buffer size
    recv_buf_size: usize,
}

impl DnsUdpServer {
    /// Create a new DNS UDP server with caching
    ///
    /// # Arguments
    /// * `listen_addr` - Address to listen on (e.g., "127.0.0.1:5353")
    /// * `upstream_dns` - Upstream DNS server address or DoH server URL
    /// * `use_https` - If true, use DNS-over-HTTPS, otherwise use UDP
    /// * `max_cache_size` - Maximum number of cache entries
    pub fn new(
        listen_addr: &str,
        upstream_dns: &str,
        use_https: bool,
        max_cache_size: usize,
    ) -> Result<Self, DnsError> {
        let (udp_client, https_client, resolver_type) = if use_https {
            (
                None,
                Some(DnsHttpsClient::with_server(upstream_dns)?),
                ResolverType::Https,
            )
        } else {
            (
                Some(DnsUdpClient::with_server(upstream_dns)?),
                None,
                ResolverType::Udp,
            )
        };

        Ok(Self {
            cache: Arc::new(RwLock::new(DnsCache::new(max_cache_size))),
            listen_addr: listen_addr.to_string(),
            udp_client,
            https_client,
            resolver_type,
            recv_buf_size: 4096,
        })
    }

    /// Start the DNS server and handle requests
    pub async fn run(&self) -> Result<(), DnsError> {
        let socket = Arc::new(
            UdpSocket::bind(&self.listen_addr).await.map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    format!("Failed to bind to {}", self.listen_addr),
                )
            })?,
        );

        log::info!("DNS UDP server listening on {}", self.listen_addr);

        let mut buf = vec![0u8; self.recv_buf_size];

        loop {
            let (size, client_addr) =
                socket.recv_from(&mut buf).await.map_err(|e| {
                    DnsError::new(
                        ErrorKind::IoError(e.to_string()),
                        "Failed to receive DNS query",
                    )
                })?;

            let query_bytes = buf[..size].to_vec();
            let cache = Arc::clone(&self.cache);
            let socket = Arc::clone(&socket);
            let resolver_type = self.resolver_type.clone();
            let udp_client = self.udp_client.clone();
            let https_client = self.https_client.clone();

            // Handle each query in a separate task
            tokio::spawn(async move {
                match Self::handle_query(
                    query_bytes,
                    client_addr,
                    &cache,
                    &socket,
                    resolver_type,
                    udp_client.as_ref(),
                    https_client.as_ref(),
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error handling query: {}", e);
                        // Send SERVFAIL response on error
                        if let Err(send_err) =
                            Self::send_error_response(client_addr, &socket)
                                .await
                        {
                            log::error!(
                                "Failed to send error response: {}",
                                send_err
                            );
                        }
                    }
                }
            });
        }
    }

    /// Handle a single DNS query
    async fn handle_query(
        query_bytes: Vec<u8>,
        client_addr: SocketAddr,
        cache: &RwLock<DnsCache>,
        socket: &UdpSocket,
        resolver_type: ResolverType,
        udp_client: Option<&DnsUdpClient>,
        https_client: Option<&DnsHttpsClient>,
    ) -> Result<(), DnsError> {
        // Parse the incoming query
        let query = DnsMessage::from_bytes(&query_bytes)?;

        // We only support queries
        if query.header.message_type != DnsMessageType::Query {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "Expected a query message",
            ));
        }

        // Check if there's a question in the query
        if query.questions.is_empty() {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "DNS query has no questions",
            ));
        }

        let question = &query.questions[0];
        let domain = question.domain.to_string();
        let query_type = question.query_type;
        let transaction_id = query.header.id;

        log::debug!(
            "Received query: {} {:?} from {}",
            domain,
            query_type,
            client_addr
        );

        // Check cache first
        {
            let cache_read = cache.read().await;
            if let Some(cached) = cache_read.get(&domain, query_type) {
                log::debug!("Cache hit for {} {:?}", domain, query_type);
                let mut response =
                    DnsMessage::from_bytes(&cached.response_bytes)?;
                // Update the transaction ID to match the client's query
                response.header.id = transaction_id;
                let response_bytes = response.to_bytes()?;
                socket.send_to(&response_bytes, client_addr).await.map_err(
                    |e| {
                        DnsError::new(
                            ErrorKind::IoError(e.to_string()),
                            "Failed to send cached response",
                        )
                    },
                )?;
                return Ok(());
            }
        }

        log::debug!(
            "Cache miss for {} {:?}, querying upstream",
            domain,
            query_type
        );

        // Query upstream resolver
        let response_message = Self::resolve_upstream(
            resolver_type,
            udp_client,
            https_client,
            &domain,
            query_type,
        )
        .await?;

        // Extract TTL from response
        let response = DnsMessage::from_bytes(&response_message)?;
        let ttl =
            Self::extract_ttl_from_response(&response).unwrap_or(MAX_CACHE_TTL);

        // Cache the response
        {
            let mut cache_write = cache.write().await;
            cache_write.insert(
                domain.clone(),
                query_type,
                response_message.clone(),
                ttl,
            );
        }

        // Update transaction ID and send response
        let mut response = DnsMessage::from_bytes(&response_message)?;
        response.header.id = transaction_id;
        let response_bytes = response.to_bytes()?;

        socket
            .send_to(&response_bytes, client_addr)
            .await
            .map_err(|e| {
                DnsError::new(
                    ErrorKind::IoError(e.to_string()),
                    "Failed to send upstream response",
                )
            })?;

        log::debug!(
            "Sent response for {} {:?} to {}",
            domain,
            query_type,
            client_addr
        );

        Ok(())
    }

    /// Resolve using upstream resolver
    async fn resolve_upstream(
        resolver_type: ResolverType,
        udp_client: Option<&DnsUdpClient>,
        https_client: Option<&DnsHttpsClient>,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        match (resolver_type, udp_client, https_client) {
            (ResolverType::Udp, Some(client), _) => {
                Self::resolve_udp(client, domain, query_type).await
            }
            (ResolverType::Https, _, Some(client)) => {
                Self::resolve_https(client, domain, query_type).await
            }
            _ => Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "No upstream resolver configured",
            )),
        }
    }

    /// Resolve using UDP upstream
    async fn resolve_udp(
        client: &DnsUdpClient,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        match query_type {
            DnsQueryType::A => {
                let ips = client.query_a_record(domain).await?;
                Self::build_response(domain, query_type, &ips)
            }
            DnsQueryType::AAAA => {
                let ips = client.query_aaaa_record(domain).await?;
                Self::build_response(domain, query_type, &ips)
            }
            _ => {
                // For all other query types, forward and cache raw response
                client.query_raw(domain, query_type).await
            }
        }
    }

    /// Resolve using HTTPS upstream
    async fn resolve_https(
        client: &DnsHttpsClient,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        match query_type {
            DnsQueryType::A => {
                let ips = client.query_a_record(domain).await?;
                Self::build_response(domain, query_type, &ips)
            }
            DnsQueryType::AAAA => {
                let ips = client.query_aaaa_record(domain).await?;
                Self::build_response(domain, query_type, &ips)
            }
            _ => {
                // For all other query types, forward and cache raw response
                client.query_raw(domain, query_type).await
            }
        }
    }

    /// Build a DNS response message from IP addresses
    fn build_response<T: IpRecord>(
        domain: &str,
        query_type: DnsQueryType,
        records: &[T],
    ) -> Result<Vec<u8>, DnsError> {
        let domain_obj = DnsDomainName {
            labels: domain
                .split('.')
                .filter(|l| !l.is_empty())
                .map(|l| l.as_bytes().to_vec())
                .collect(),
            raw_offset: 0,
            compression_pointer: None,
        };

        let mut response = DnsMessage {
            header: DnsHeader {
                id: 0, // Will be set by caller
                message_type: DnsMessageType::Response,
                qr: true,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                z: 0,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                ancount: records.len() as u16,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                domain: domain_obj.clone(),
                query_type,
                query_class: DnsRecordClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        for record in records {
            response.answers.push(DnsResourceRecord {
                domain: domain_obj.clone(),
                record_type: query_type,
                record_class: DnsRecordClass::IN,
                ttl: record.ttl(),
                rdlength: record.rdata_len() as u16,
                rdata: record.to_rdata(),
            });
        }

        response.to_bytes()
    }

    /// Extract TTL from a DNS response message
    fn extract_ttl_from_response(response: &DnsMessage) -> Option<u32> {
        response.answers.first().map(|r| r.ttl)
    }

    /// Send a SERVFAIL error response
    async fn send_error_response(
        client_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<(), DnsError> {
        let error_response = DnsMessage {
            header: DnsHeader {
                id: 0,
                message_type: DnsMessageType::Response,
                qr: true,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                z: 0,
                rcode: DnsResponseCode::ServFail,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let bytes = error_response.to_bytes()?;
        socket.send_to(&bytes, client_addr).await.map_err(|e| {
            DnsError::new(
                ErrorKind::IoError(e.to_string()),
                "Failed to send error response",
            )
        })?;
        Ok(())
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    /// Get current cache size
    #[allow(dead_code)]
    pub async fn cache_size(&self) -> usize {
        let cache_read = self.cache.read().await;
        cache_read.len()
    }
}

/// Helper trait for IP record types
trait IpRecord {
    fn ttl(&self) -> u32;
    fn rdata_len(&self) -> usize;
    fn to_rdata(&self) -> Vec<u8>;
}

impl IpRecord for Ipv4Addr {
    fn ttl(&self) -> u32 {
        MAX_CACHE_TTL
    }

    fn rdata_len(&self) -> usize {
        4
    }

    fn to_rdata(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl IpRecord for Ipv6Addr {
    fn ttl(&self) -> u32 {
        MAX_CACHE_TTL
    }

    fn rdata_len(&self) -> usize {
        16
    }

    fn to_rdata(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

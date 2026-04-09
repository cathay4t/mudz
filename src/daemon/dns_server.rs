// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use futures::stream::{FuturesUnordered, StreamExt};
use mudz::{
    DnsDomainName, DnsError, DnsHeader, DnsHttpsClient, DnsMessage,
    DnsMessageType, DnsQueryType, DnsQuestion, DnsRecordClass,
    DnsResourceRecord, DnsResponseCode, DnsUdpClient, ErrorKind,
};
use tokio::{net::UdpSocket, sync::RwLock};

use crate::{
    cache::{DnsCache, MAX_CACHE_TTL},
    config::MudzConfig,
    host::HostsFile,
};

/// Named upstream resolver clients
#[derive(Clone)]
struct UpstreamClients {
    /// DNS UDP clients (one per nameserver address)
    udp_clients: Vec<DnsUdpClient>,
    /// DNS HTTPS clients (one per DoH server URL)
    https_clients: Vec<DnsHttpsClient>,
    /// Disable AAAA queries for this group
    disable_ipv6: bool,
    /// Group has no nameservers configured -- return NXDOMAIN immediately
    empty_nameservers: bool,
}

impl UpstreamClients {
    /// Create upstream clients from server addresses (auto-detect UDP vs HTTPS)
    fn from_server_addrs(
        addrs: &[String],
        disable_ipv6: bool,
    ) -> Result<Self, DnsError> {
        let mut udp_clients: Vec<DnsUdpClient> = Vec::new();
        let mut https_clients: Vec<DnsHttpsClient> = Vec::new();

        for addr in addrs {
            if addr.starts_with("https://") {
                https_clients.push(DnsHttpsClient::with_server(addr)?);
            } else {
                udp_clients.push(DnsUdpClient::with_server(addr)?);
            }
        }

        let empty_nameservers = addrs.is_empty();

        Ok(Self {
            udp_clients,
            https_clients,
            disable_ipv6,
            empty_nameservers,
        })
    }

    /// Check if this group has any clients configured
    fn has_clients(&self) -> bool {
        !self.udp_clients.is_empty() || !self.https_clients.is_empty()
    }
}

/// DNS UDP server with caching and per-domain routing support
pub(crate) struct DnsUdpServer {
    /// Cache for DNS responses
    cache: Arc<RwLock<DnsCache>>,
    /// Listen address
    listen_addr: String,
    /// Fallback upstream clients
    fallback: UpstreamClients,
    /// Named upstream client groups (for per-domain routing)
    named_groups: HashMap<String, UpstreamClients>,
    /// Domain to group name mapping: (domain_pattern, group_name)
    domain_routes: Vec<(String, String)>,
    /// Socket receive buffer size
    recv_buf_size: usize,
    /// /etc/hosts entries
    hosts_file: HostsFile,
}

impl DnsUdpServer {
    /// Create a new DNS UDP server with caching and config-based routing
    ///
    /// # Arguments
    /// * `config` - The mudz configuration
    /// * `max_cache_size` - Maximum number of cache entries
    pub fn from_config(
        config: &MudzConfig,
        max_cache_size: usize,
    ) -> Result<Self, DnsError> {
        // Create fallback clients from config (auto-detect UDP vs HTTPS)
        let fallback = UpstreamClients::from_server_addrs(
            &config.fallback.nameservers,
            false,
        )?;

        // Create named groups and domain routes
        let mut named_groups: HashMap<String, UpstreamClients> = HashMap::new();
        let mut domain_routes: Vec<(String, String)> = Vec::new();
        for (name, group) in &config.groups {
            let clients = UpstreamClients::from_server_addrs(
                &group.nameservers,
                group.disable_ipv6,
            )?;
            // Always register the group (even with no clients, so we can
            // return NXDOMAIN for groups with empty nameservers)
            for domain in &group.domains {
                domain_routes.push((domain.clone(), name.clone()));
            }
            if clients.has_clients() || clients.empty_nameservers {
                named_groups.insert(name.clone(), clients);
            }
        }

        Ok(Self {
            cache: Arc::new(RwLock::new(DnsCache::new(max_cache_size))),
            listen_addr: config.main.udp_bind.clone(),
            fallback,
            named_groups,
            domain_routes,
            recv_buf_size: 4096,
            hosts_file: HostsFile::new(),
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
            let fallback = self.fallback.clone();
            let named_groups = self.named_groups.clone();
            let domain_routes = self.domain_routes.clone();
            let hosts_file = self.hosts_file.clone();

            // Extract transaction ID early for error responses
            let transaction_id = if query_bytes.len() >= 2 {
                u16::from_be_bytes([query_bytes[0], query_bytes[1]])
            } else {
                0
            };

            // Handle each query in a separate task
            tokio::spawn(async move {
                match Self::handle_query(
                    query_bytes,
                    client_addr,
                    &cache,
                    &socket,
                    &fallback,
                    &named_groups,
                    &domain_routes,
                    &hosts_file,
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error handling query: {}", e);
                        // Send SERVFAIL response on error
                        if let Err(send_err) = Self::send_error_response(
                            client_addr,
                            &socket,
                            transaction_id,
                        )
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
    #[allow(clippy::too_many_arguments)]
    async fn handle_query(
        query_bytes: Vec<u8>,
        client_addr: SocketAddr,
        cache: &RwLock<DnsCache>,
        socket: &UdpSocket,
        fallback: &UpstreamClients,
        named_groups: &HashMap<String, UpstreamClients>,
        domain_routes: &[(String, String)],
        hosts_file: &HostsFile,
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

        log::trace!(
            "Received query: {} {:?} from {}",
            domain,
            query_type,
            client_addr
        );

        // Check /etc/hosts first
        if let Some(response_bytes) =
            Self::resolve_from_hosts(hosts_file, &domain, query_type)
        {
            log::trace!("Hosts hit for {} {:?}", domain, query_type);
            let response_bytes =
                Self::update_transaction_id(&response_bytes, transaction_id)?;
            socket.send_to(&response_bytes, client_addr).await.map_err(
                |e| {
                    DnsError::new(
                        ErrorKind::IoError(e.to_string()),
                        "Failed to send hosts response",
                    )
                },
            )?;
            return Ok(());
        }

        // Check cache first
        {
            let cache_read = cache.read().await;
            if let Some(cached) = cache_read.get(&domain, query_type) {
                log::trace!("Cache hit for {} {:?}", domain, query_type);
                let response_bytes = Self::update_transaction_id(
                    &cached.response_bytes,
                    transaction_id,
                )?;
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

        log::trace!(
            "Cache miss for {} {:?}, querying upstream",
            domain,
            query_type
        );

        // Select upstream based on domain
        let upstream = if let Some(group_name) =
            Self::find_group_for_domain(&domain, domain_routes)
        {
            log::trace!(
                "Routing {} {:?} to group '{}'",
                domain,
                query_type,
                group_name
            );
            named_groups.get(&group_name).unwrap_or(fallback)
        } else {
            log::trace!("Routing {} {:?} to fallback", domain, query_type);
            fallback
        };

        // If this group has no nameservers configured, return NXDOMAIN
        if upstream.empty_nameservers {
            log::trace!(
                "Returning NXDOMAIN for {} (empty nameservers group)",
                domain
            );
            let response =
                DnsMessage::new_nxdomain(transaction_id, &domain, query_type)?;
            socket
                .send_to(&response.to_bytes()?, client_addr)
                .await
                .map_err(|e| {
                    DnsError::new(
                        ErrorKind::IoError(e.to_string()),
                        "Failed to send NXDOMAIN response",
                    )
                })?;
            return Ok(());
        }

        // If this group disables IPv6 and the query is for AAAA,
        // return an empty NoError response immediately
        if upstream.disable_ipv6 && query_type == DnsQueryType::AAAA {
            log::trace!(
                "Blocking AAAA query for {} (disable_ipv6 group)",
                domain
            );
            let response_bytes = Self::build_empty_response(
                transaction_id,
                &domain,
                query_type,
            )?;
            socket.send_to(&response_bytes, client_addr).await.map_err(
                |e| {
                    DnsError::new(
                        ErrorKind::IoError(e.to_string()),
                        "Failed to send empty response",
                    )
                },
            )?;
            return Ok(());
        }

        // Query upstream resolver
        let response_bytes =
            Self::resolve_upstream(upstream, &domain, query_type).await?;

        // Parse once to extract TTL
        let response = DnsMessage::from_bytes(&response_bytes)?;
        let ttl =
            Self::extract_ttl_from_response(&response).unwrap_or(MAX_CACHE_TTL);

        // Update transaction ID and cache in one pass
        let response_bytes =
            Self::update_transaction_id(&response_bytes, transaction_id)?;

        // Cache the final response bytes
        {
            let mut cache_write = cache.write().await;
            cache_write.insert(
                domain.clone(),
                query_type,
                response_bytes.clone(),
                ttl,
            );
        }

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

        log::trace!(
            "Response sent for {} {:?} to {}",
            domain,
            query_type,
            client_addr
        );

        Ok(())
    }

    /// Update the transaction ID in a DNS response without full re-parsing.
    /// Directly modifies the ID bytes at offset 0-1.
    fn update_transaction_id(
        response_bytes: &[u8],
        transaction_id: u16,
    ) -> Result<Vec<u8>, DnsError> {
        let mut bytes = response_bytes.to_vec();
        if bytes.len() < 12 {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "Response too short",
            ));
        }
        let id_bytes = transaction_id.to_be_bytes();
        bytes[0] = id_bytes[0];
        bytes[1] = id_bytes[1];
        Ok(bytes)
    }

    /// Build an empty DNS response with NoError and no answers
    fn build_empty_response(
        transaction_id: u16,
        domain: &str,
        query_type: DnsQueryType,
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

        let response = DnsMessage {
            header: DnsHeader {
                id: transaction_id,
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
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                domain: domain_obj,
                query_type,
                query_class: DnsRecordClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        response.to_bytes()
    }

    /// Find the named group that matches a domain
    fn find_group_for_domain(
        domain: &str,
        domain_routes: &[(String, String)],
    ) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        for (route_domain, group_name) in domain_routes {
            let route_domain_lower = route_domain.to_lowercase();
            // Match exact domain or subdomain (e.g., "google.com" matches
            // "foo.google.com")
            if domain_lower == route_domain_lower
                || domain_lower.ends_with(&format!(".{route_domain_lower}"))
            {
                return Some(group_name.clone());
            }
        }
        None
    }

    /// Try to resolve from /etc/hosts, returning DNS response bytes or None
    fn resolve_from_hosts(
        hosts_file: &HostsFile,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Option<Vec<u8>> {
        match query_type {
            DnsQueryType::A => {
                let ips = hosts_file.lookup_a(domain)?;
                Self::build_response(domain, query_type, ips.as_slice()).ok()
            }
            DnsQueryType::AAAA => {
                let ips = hosts_file.lookup_aaaa(domain)?;
                Self::build_response(domain, query_type, ips.as_slice()).ok()
            }
            _ => None, // /etc/hosts only supports A and AAAA
        }
    }

    /// Resolve using upstream resolver with all clients in the group
    /// Returns the first successful response
    async fn resolve_upstream(
        upstream: &UpstreamClients,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        let num_clients =
            upstream.udp_clients.len() + upstream.https_clients.len();

        if num_clients == 0 {
            return Err(DnsError::new(
                ErrorKind::InvalidResponse,
                "No upstream clients configured",
            ));
        }

        type ResolveFuture =
            Pin<Box<dyn Future<Output = Result<Vec<u8>, DnsError>> + Send>>;
        let mut futures = FuturesUnordered::<ResolveFuture>::new();

        // Create futures for all UDP clients
        for client in &upstream.udp_clients {
            let server = client.server_addr().to_string();
            let domain_str = domain.to_string();
            log::trace!(
                "Querying upstream UDP {} for {} {:?}",
                server,
                domain,
                query_type
            );
            let client = client.clone();
            futures.push(Box::pin(async move {
                let result =
                    Self::resolve_udp_single(&client, &domain_str, query_type)
                        .await;
                if result.is_ok() {
                    log::trace!(
                        "Upstream UDP {} responded for {} {:?}",
                        server,
                        domain_str,
                        query_type
                    );
                } else if let Err(ref e) = result {
                    log::trace!(
                        "Upstream UDP {} failed for {} {:?}: {}",
                        server,
                        domain_str,
                        query_type,
                        e
                    );
                }
                result
            }));
        }

        // Create futures for all HTTPS clients
        for client in &upstream.https_clients {
            let server = client.server_url().to_string();
            let domain_str = domain.to_string();
            log::trace!(
                "Querying upstream HTTPS {} for {} {:?}",
                server,
                domain,
                query_type
            );
            let client = client.clone();
            futures.push(Box::pin(async move {
                let result = Self::resolve_https_single(
                    &client,
                    &domain_str,
                    query_type,
                )
                .await;
                if result.is_ok() {
                    log::trace!(
                        "Upstream HTTPS {} responded for {} {:?}",
                        server,
                        domain_str,
                        query_type
                    );
                } else if let Err(ref e) = result {
                    log::trace!(
                        "Upstream HTTPS {} failed for {} {:?}: {}",
                        server,
                        domain_str,
                        query_type,
                        e
                    );
                }
                result
            }));
        }

        // Poll futures, return first success
        while let Some(result) = futures.next().await {
            if result.is_ok() {
                return result;
            }
        }

        Err(DnsError::new(
            ErrorKind::InvalidResponse,
            format!("All upstream DNS servers failed for domain: {}", domain),
        ))
    }

    /// Resolve using a single UDP upstream client
    async fn resolve_udp_single(
        client: &DnsUdpClient,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        // Use query_raw for all query types to properly handle NXDOMAIN
        // and other response codes
        client.query_raw(domain, query_type).await
    }

    /// Resolve using a single HTTPS upstream client
    async fn resolve_https_single(
        client: &DnsHttpsClient,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Result<Vec<u8>, DnsError> {
        // Use query_raw for all query types to properly handle NXDOMAIN
        // and other response codes
        client.query_raw(domain, query_type).await
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
                id: 0, // Will be set by caller via update_transaction_id
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
        transaction_id: u16,
    ) -> Result<(), DnsError> {
        let bytes = DnsMessage::new_servfail(transaction_id).to_bytes()?;
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

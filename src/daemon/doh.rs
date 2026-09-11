// SPDX-License-Identifier: Apache-2.0

//! DNS over HTTPS (DoH) client implementation per RFC 8484.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use data_encoding::BASE64URL_NOPAD;
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use mudz::{DnsPacket, DnsResponseCode, DnsType, ErrorKind, MudzError};
use reqwest::{Client, Url};
use tokio::net::UdpSocket;

use super::{config::MudzConfig, host::HostsFile};

const DEFAULT_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const BOOTSTRAP_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const DOH_NAMESERVER_PORT: u16 = 53;
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

/// Resolver for DoH server hostnames, pinned at startup.
///
/// The mapping is resolved once before the daemon starts serving (see
/// [`bootstrap_doh_cache`]) and never changes, so no lock or refresh task is
/// involved. `[doh]` bootstrap nameservers exist precisely because the
/// system resolver cannot be used for these hostnames.
pub(crate) struct DohResolvCache {
    store: HashMap<String, Vec<IpAddr>>,
}

impl DohResolvCache {
    pub(crate) fn new(store: HashMap<String, Vec<IpAddr>>) -> Self {
        Self { store }
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

/// Collect the unique DoH server hostnames from the fallback and named group
/// nameserver lists.
fn doh_hostnames(config: &MudzConfig) -> Result<BTreeSet<String>, MudzError> {
    let mut hostnames = BTreeSet::new();
    let nameservers = config
        .fallback
        .nameservers
        .iter()
        .chain(config.groups.values().flat_map(|g| g.nameservers.iter()));
    for srv in nameservers {
        if !srv.starts_with("https://") {
            continue;
        }
        let hostname =
            super::config::extract_doh_hostname(srv).ok_or_else(|| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!("Invalid DoH URL: {srv}"),
                )
            })?;
        hostnames.insert(hostname);
    }
    Ok(hostnames)
}

/// Resolve every configured DoH hostname and pin it for the process
/// lifetime.
///
/// Called before the daemon starts serving. Failure aborts startup: reqwest
/// uses [`DohResolvCache`] instead of the system resolver, so without the
/// bootstrap addresses no DoH query could ever succeed. Returns `None` when
/// no DoH nameserver is configured.
pub(crate) async fn bootstrap_doh_cache(
    config: &MudzConfig,
    hosts: &HostsFile,
) -> Result<Option<Arc<DohResolvCache>>, MudzError> {
    let hostnames = doh_hostnames(config)?;
    if hostnames.is_empty() {
        return Ok(None);
    }

    let doh_cfg = config.doh.as_ref().ok_or_else(|| {
        MudzError::new(
            ErrorKind::InvalidConfig,
            "DoH servers are configured but no [doh] section found",
        )
    })?;
    if doh_cfg.nameservers.is_empty() {
        return Err(MudzError::new(
            ErrorKind::InvalidConfig,
            "[doh] section must have at least one nameserver",
        ));
    }
    let nameservers: Vec<SocketAddr> = doh_cfg
        .nameservers
        .iter()
        .map(|ip| SocketAddr::new(*ip, DOH_NAMESERVER_PORT))
        .collect();

    let hostnames: Vec<String> = hostnames.into_iter().collect();
    let results = join_all(hostnames.iter().map(|hostname| {
        resolve_hostname(hostname, &nameservers, doh_cfg.disable_ipv6, hosts)
    }))
    .await;

    let mut store = HashMap::with_capacity(hostnames.len());
    for (hostname, result) in hostnames.into_iter().zip(results) {
        let ips = result?;
        log::info!("DoH hostname {} resolved to {:?}", hostname, ips);
        store.insert(hostname, ips);
    }

    Ok(Some(Arc::new(DohResolvCache::new(store))))
}

/// Resolve one DoH hostname through the plain-IP `[doh]` nameservers.
///
/// `/etc/hosts` entries win over DNS, mirroring the resolver's own query
/// handling. AAAA queries are skipped when `disable_ipv6` is set.
async fn resolve_hostname(
    host_name: &str,
    nameservers: &[SocketAddr],
    disable_ipv6: bool,
    hosts: &HostsFile,
) -> Result<Vec<IpAddr>, MudzError> {
    log::info!("Resolving DoH hostname {}", host_name);

    let hosts_ips = hosts.lookup_ips(host_name);
    if !hosts_ips.is_empty() {
        log::info!(
            "Resolved DoH hostname {} from /etc/hosts: {:?}",
            host_name,
            hosts_ips
        );
        return Ok(hosts_ips);
    }

    let mut ret = Vec::new();

    let query_packet = DnsPacket::new_query(host_name, DnsType::A)?;
    match send_request_and_wait_first_reply(nameservers, &query_packet).await {
        Ok(ips) => ret.extend_from_slice(&ips),
        Err(e) => {
            log::debug!(
                "Failed to resolve DoH hostname {} to A record: {e}",
                host_name
            );
        }
    }

    if disable_ipv6 {
        if ret.is_empty() {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "Failed to resolve DoH hostname {} to A record",
                    host_name
                ),
            ));
        }
        return Ok(ret);
    }

    let query_packet = DnsPacket::new_query(host_name, DnsType::AAAA)?;
    match send_request_and_wait_first_reply(nameservers, &query_packet).await {
        Ok(ips) => ret.extend_from_slice(&ips),
        Err(e) => {
            log::debug!(
                "Failed to resolve DoH hostname {} to AAAA record: {e}",
                host_name
            );
        }
    }

    if ret.is_empty() {
        Err(MudzError::new(
            ErrorKind::InvalidConfig,
            format!("Failed to resolve DoH hostname {}", host_name),
        ))
    } else {
        Ok(ret)
    }
}

async fn send_request_and_wait_first_reply(
    nameservers: &[SocketAddr],
    query_packet: &DnsPacket,
) -> Result<Vec<IpAddr>, MudzError> {
    let mut sockets = Vec::new();
    let mut ret = Vec::new();

    for nameserver in nameservers {
        let bind_addr = if nameserver.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to bind UDP socket: {e}"),
            )
        })?;
        log::debug!("Connecting to UDP nameserver {}", nameserver);
        socket.connect(*nameserver).await.map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Failed to connect to nameserver {}: {e}", nameserver),
            )
        })?;
        sockets.push(socket);
    }

    // Send queries with a timeout so a stuck UDP socket cannot block
    // startup (or a refresh) indefinitely.
    for socket in &sockets {
        let send_bytes = query_packet.to_bytes();
        match tokio::time::timeout(
            BOOTSTRAP_TIMEOUT_SEC,
            socket.send(&send_bytes),
        )
        .await
        {
            Ok(Ok(_n)) => {}
            Ok(Err(e)) => {
                log::warn!("Failed to send DNS query to nameserver: {e}");
            }
            Err(_) => {
                log::warn!("Timed out sending DNS query to nameserver");
            }
        }
    }

    let mut futures = FuturesUnordered::new();
    for socket in &sockets {
        futures.push(get_udp_dns_reply(socket));
    }
    while let Some(result) = futures.next().await {
        let packet = match result {
            Ok(packet) => packet,
            Err(e) => {
                log::debug!("Failed to get DNS reply: {e}");
                continue;
            }
        };
        log::debug!("Received DNS reply: {}", packet.display_brief());

        if packet.header.id != query_packet.header.id {
            log::debug!(
                "DNS reply TXID mismatch: expected {:#06x}, got {:#06x}",
                query_packet.header.id,
                packet.header.id,
            );
            continue;
        }
        if !packet.header.qr {
            log::debug!("Ignoring non-response DNS packet");
            continue;
        }
        if packet.header.rcode != DnsResponseCode::NoError {
            log::debug!("DNS reply rcode {:?}, ignoring", packet.header.rcode,);
            continue;
        }

        for record in packet
            .answers
            .into_iter()
            .filter(|r| r.kind == DnsType::A || r.kind == DnsType::AAAA)
        {
            if record.kind == DnsType::A
                && record.rdata.len() >= Ipv4Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V4(Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                )));
            } else if record.kind == DnsType::AAAA
                && record.rdata.len() >= Ipv6Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V6(Ipv6Addr::from([
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                    record.rdata[4],
                    record.rdata[5],
                    record.rdata[6],
                    record.rdata[7],
                    record.rdata[8],
                    record.rdata[9],
                    record.rdata[10],
                    record.rdata[11],
                    record.rdata[12],
                    record.rdata[13],
                    record.rdata[14],
                    record.rdata[15],
                ])));
            }
        }
        if !ret.is_empty() {
            break;
        }
    }

    Ok(ret)
}

async fn get_udp_dns_reply(socket: &UdpSocket) -> Result<DnsPacket, MudzError> {
    let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
    match tokio::time::timeout(BOOTSTRAP_TIMEOUT_SEC, socket.recv(&mut buf))
        .await
    {
        Ok(Ok(len)) => {
            let packet = DnsPacket::parse(&buf[..len])?;
            Ok(packet)
        }
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("Error receiving DNS response: {e}"),
        )),
        Err(_) => Err(MudzError::new(
            ErrorKind::Timeout,
            "Timed out waiting for DNS response",
        )),
    }
}

#[cfg(test)]
#[path = "unit_tests/doh.rs"]
mod tests;

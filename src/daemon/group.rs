// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr as _,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures_util::{StreamExt, future::Either, stream::FuturesUnordered};
use mudz::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
    DnsType, ErrorKind, MudzError,
};
use tokio::net::UdpSocket;

use super::{
    config::MudzConfig,
    doh::{DohClient, DohResolvCache},
    host::HostsFile,
};

const DNS_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const IPV6_BLOCKED_HINFO_CPU: &str =
    "AAAA queries have been locally blocked by mudz";
const IPV6_BLOCKED_HINFO_OS: &str =
    "Set disable_ipv6 to false to allow IPv6 DNS queries";
const IPV6_BLOCKED_HINFO_TTL: u32 = 86_400;

pub(crate) struct DnsGroups {
    fallback: DnsGroup,
    groups: HashMap<String, DnsGroup>,
    search_index: HashMap<Vec<String>, String>,
}

impl DnsGroups {
    pub(crate) async fn new(
        mut config: MudzConfig,
        doh_config: Option<super::config::MudzDohConfig>,
        hosts: Arc<HostsFile>,
    ) -> Result<Self, MudzError> {
        let fallback = DnsGroup::new(
            "fallback".to_string(),
            config.fallback.nameservers,
            config.fallback.disable_ipv6,
            doh_config.clone(),
            hosts.clone(),
        );

        let mut groups = HashMap::new();
        let mut search_index = HashMap::new();
        for (group_name, group_config) in config.groups.drain() {
            let dns_group = DnsGroup::new(
                group_name.to_string(),
                group_config.nameservers,
                group_config.disable_ipv6,
                doh_config.clone(),
                hosts.clone(),
            );
            groups.insert(group_name.to_string(), dns_group);

            for domain in group_config.domains {
                let domain_split: Vec<String> =
                    domain.split('.').map(|s| s.to_lowercase()).collect();
                search_index.insert(domain_split, group_name.to_string());
            }
        }

        Ok(Self {
            fallback,
            groups,
            search_index,
        })
    }

    pub(crate) async fn request(
        &self,
        request: DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        if let Some(domain) = request.domain_name() {
            log::debug!("Searching for DNS group matching domain '{}'", domain);
            let domain_split: Vec<String> =
                domain.split('.').map(|s| s.to_string()).collect();
            for possible_suffix in 0..domain_split.len() {
                let suffix = &domain_split[possible_suffix..];
                if let Some(group_name) = self.search_index.get(suffix)
                    && let Some(group) = self.groups.get(group_name)
                {
                    log::debug!(
                        "Found matching DNS group '{}' for domain '{}'",
                        group_name,
                        domain
                    );

                    if group.is_blocking() {
                        log::debug!(
                            "Group '{}' is blocking, returning NXDOMAIN for \
                             '{}'",
                            group_name,
                            domain
                        );
                        let mut packet = request;
                        packet.header.set_response(true);
                        packet.header.rcode = DnsResponseCode::NxDomain;
                        return Ok(packet);
                    } else {
                        return group.request(request).await;
                    }
                }
            }
            // fallback
            self.fallback.request(request).await
        } else {
            Err(MudzError::new(
                ErrorKind::InvalidArgument,
                "DNS request does not contain a domain",
            ))
        }
    }
}

struct DnsGroupConnections {
    sockets: Vec<UdpSocket>,
    doh_conns: Vec<DohClient>,
}

struct DnsGroup {
    name: String,
    srvs: Vec<String>,
    conns: RwLock<Option<Arc<DnsGroupConnections>>>,
    disable_ipv6: bool,
    doh_config: Option<super::config::MudzDohConfig>,
    hosts: Arc<HostsFile>,
}

impl DnsGroup {
    fn new(
        name: String,
        srvs: Vec<String>,
        disable_ipv6: bool,
        doh_config: Option<super::config::MudzDohConfig>,
        hosts: Arc<HostsFile>,
    ) -> Self {
        Self {
            name,
            srvs,
            conns: RwLock::new(None),
            disable_ipv6,
            doh_config,
            hosts,
        }
    }

    fn is_blocking(&self) -> bool {
        self.srvs.is_empty()
    }

    async fn request(
        &self,
        request: DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        if self.disable_ipv6
            && request.first_question().map(|q| q.kind) == Some(DnsType::AAAA)
        {
            log::debug!(
                "AAAA query blocked for group '{}', returning synthetic \
                 NOERROR",
                self.name
            );
            return Ok(make_ipv6_blocked_response(&request));
        }

        let conns = self.get_or_init_conns_async().await?;

        log::debug!("Sending DNS request to group '{}'", self.name);
        for socket in &conns.sockets {
            if let Err(e) = socket.send(&request.to_bytes()).await {
                log::debug!("Error sending DNS request to socket: {e}");
            }
        }

        let mut futures = FuturesUnordered::new();
        for socket in &conns.sockets {
            futures.push(Either::Left(get_socket_reply(socket)));
        }
        for doh_conn in &conns.doh_conns {
            futures.push(Either::Right(doh_conn.request(&request)));
        }

        while let Some(result) = futures.next().await {
            match result {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => {
                    log::debug!("Error processing DNS response: {e}");
                }
            }
        }

        log::warn!(
            "All upstream requests failed for group '{}', freeing \
             connections for retry on next query",
            self.name
        );
        *self.conns.write().unwrap() = None;
        tokio::time::sleep(Duration::from_secs(1)).await;
        Err(MudzError::new(
            ErrorKind::InvalidPacket,
            "All DNS requests failed or returned invalid responses",
        ))
    }

    async fn get_or_init_conns_async(
        &self,
    ) -> Result<Arc<DnsGroupConnections>, MudzError> {
        // Check again under lock
        if let Some(conns) = self.conns.read().unwrap().as_ref() {
            return Ok(Arc::clone(conns));
        }

        // Create connections (I/O, no lock held)
        let new_conns = self.create_connections().await?;
        let new_arc = Arc::new(new_conns);

        // Store (lock held for ~ns)
        let mut guard = self.conns.write().unwrap();
        match &*guard {
            Some(existing) => {
                // Race: another request initialized while we were creating.
                // Use the existing connections, drop ours.
                Ok(Arc::clone(existing))
            }
            None => {
                *guard = Some(Arc::clone(&new_arc));
                Ok(new_arc)
            }
        }
    }

    async fn create_connections(
        &self,
    ) -> Result<DnsGroupConnections, MudzError> {
        let mut sockets = Vec::new();
        let mut doh_conns = Vec::new();

        for srv in &self.srvs {
            if srv.starts_with("https://") {
                match create_doh_client(srv, &self.doh_config, &self.hosts)
                    .await
                {
                    Ok(client) => doh_conns.push(client),
                    Err(e) => log::warn!(
                        "Failed to create DoH client for '{}' in group '{}': \
                         {e}",
                        srv,
                        self.name
                    ),
                }
            } else {
                match create_udp_socket(srv).await {
                    Ok(socket) => sockets.push(socket),
                    Err(e) => log::warn!(
                        "Failed to create UDP socket for '{}' in group '{}': \
                         {e}",
                        srv,
                        self.name
                    ),
                }
            }
        }

        if sockets.is_empty() && doh_conns.is_empty() {
            return Err(MudzError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to create any upstream connections for group '{}'",
                    self.name
                ),
            ));
        }

        Ok(DnsGroupConnections {
            sockets,
            doh_conns,
        })
    }
}

fn make_ipv6_blocked_response(request: &DnsPacket) -> DnsPacket {
    let question = request
        .questions
        .first()
        .expect("request has at least one question");
    let domain = question.domain.clone();

    let mut hinfo_rdata = Vec::new();
    hinfo_rdata.push(IPV6_BLOCKED_HINFO_CPU.len() as u8);
    hinfo_rdata.extend_from_slice(IPV6_BLOCKED_HINFO_CPU.as_bytes());
    hinfo_rdata.push(IPV6_BLOCKED_HINFO_OS.len() as u8);
    hinfo_rdata.extend_from_slice(IPV6_BLOCKED_HINFO_OS.as_bytes());
    let hinfo = DnsResourceRecord {
        domain: domain.clone(),
        kind: DnsType::HINFO,
        class: DnsClass::IN,
        ttl: IPV6_BLOCKED_HINFO_TTL,
        rdlength: hinfo_rdata.len() as u16,
        rdata: hinfo_rdata,
    };

    DnsPacket {
        header: DnsHeader {
            id: request.header.id,
            qr: true,
            opcode: request.header.opcode,
            rd: request.header.rd,
            ra: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
            ..Default::default()
        },
        questions: vec![question.clone()],
        answers: vec![hinfo],
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

async fn create_udp_socket(srv: &str) -> Result<UdpSocket, MudzError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        MudzError::new(
            ErrorKind::Bug,
            format!("Failed to bind UDP socket: {e}"),
        )
    })?;
    let addr = if srv.contains(':') {
        SocketAddr::from_str(srv)
    } else {
        SocketAddr::from_str(&format!("{srv}:53"))
    }
    .map_err(|e| {
        MudzError::new(
            ErrorKind::InvalidConfig,
            format!("Invalid nameserver address '{srv}': {e}"),
        )
    })?;
    socket.connect(addr).await.map_err(|e| {
        MudzError::new(
            ErrorKind::Bug,
            format!("Failed to connect UDP socket to {addr}: {e}"),
        )
    })?;
    Ok(socket)
}

async fn create_doh_client(
    srv: &str,
    doh_config: &Option<super::config::MudzDohConfig>,
    hosts: &HostsFile,
) -> Result<DohClient, MudzError> {
    let hostname =
        super::config::extract_doh_hostname(srv).ok_or_else(|| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Invalid DoH URL: {srv}"),
            )
        })?;

    let doh_cfg = doh_config.as_ref().ok_or_else(|| {
        MudzError::new(
            ErrorKind::InvalidConfig,
            format!(
                "DoH server '{}' configured but no [doh] section with IP \
                 nameservers found",
                srv
            ),
        )
    })?;

    let ips = resolve_hostname(
        &hostname,
        &doh_cfg.nameservers,
        doh_cfg.disable_ipv6,
        hosts,
    )
    .await?;

    let mut cache = DohResolvCache::new();
    cache.insert(&hostname, ips);
    let cache = Arc::new(cache);

    DohClient::new(srv, cache)
}

async fn resolve_hostname(
    host_name: &str,
    nameservers: &[IpAddr],
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
        } else {
            return Ok(ret);
        }
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
    nameservers: &[IpAddr],
    query_packet: &DnsPacket,
) -> Result<Vec<IpAddr>, MudzError> {
    let mut sockets = Vec::new();
    let mut ret = Vec::new();

    for nameserver in nameservers {
        let bind_addr = match nameserver {
            ip if ip.is_ipv4() => {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
            _ => {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            }
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to bind UDP socket: {e}"),
            )
        })?;
        log::debug!("Connecting to UDP nameserver {}:53", nameserver);
        socket.connect((*nameserver, 53)).await.map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "Failed to connect to nameserver {}: {e}",
                    nameserver
                ),
            )
        })?;
        sockets.push(socket);
    }

    for socket in &sockets {
        if let Err(e) = socket.send(&query_packet.to_bytes()).await {
            log::warn!("Failed to send DNS query to nameserver: {e}");
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

        for record in packet
            .answers
            .into_iter()
            .filter(|r| r.kind == DnsType::A || r.kind == DnsType::AAAA)
        {
            if record.kind == DnsType::A
                && record.rdata.len() >= Ipv4Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                )));
            } else if record.kind == DnsType::AAAA
                && record.rdata.len() >= Ipv6Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V6(std::net::Ipv6Addr::from([
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
    match tokio::time::timeout(DNS_TIMEOUT_SEC, socket.recv(&mut buf)).await {
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

async fn get_socket_reply(socket: &UdpSocket) -> Result<DnsPacket, MudzError> {
    let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
    match tokio::time::timeout(DNS_TIMEOUT_SEC, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => {
            let packet = DnsPacket::parse(&buf[..len])?;
            Ok(packet)
        }
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("Error receiving DNS response from socket: {e}"),
        )),
        Err(_) => Err(MudzError::new(
            ErrorKind::Timeout,
            "Timed out waiting for DNS response from socket",
        )),
    }
}

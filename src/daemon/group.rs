// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{StreamExt, future::Either, stream::FuturesUnordered};
use mudz::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
    DnsType, ErrorKind, MudzError,
};
use tokio::{net::UdpSocket, sync::oneshot};

use super::{
    config::MudzConfig,
    doh::{DohClient, DohResolvCache},
    host::HostsFile,
};

const DNS_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const DNS_RETRY_COOLDOWN: Duration = Duration::from_secs(5);
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
            false, // fallback is never intentionally blocking
            doh_config.clone(),
            hosts.clone(),
        )
        .await;

        let mut groups = HashMap::new();
        let mut search_index = HashMap::new();
        for (group_name, group_config) in config.groups.drain() {
            let blocking = group_config.nameservers.is_empty();
            let dns_group = DnsGroup::new(
                group_name.to_string(),
                group_config.nameservers,
                group_config.disable_ipv6,
                blocking,
                doh_config.clone(),
                hosts.clone(),
            )
            .await;
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
                        return synthetic_reply(
                            &request,
                            DnsResponseCode::NxDomain,
                        );
                    }

                    if !group.ensure_transports().await {
                        // All transports failed and cooldown hasn't
                        // elapsed — reply SERVFAIL so the client will
                        // retry rather than silently timing out.
                        return synthetic_reply(
                            &request,
                            DnsResponseCode::ServFail,
                        );
                    }
                    return group.request(request).await;
                }
            }
            // fallback
            if !self.fallback.ensure_transports().await {
                // The fallback group follows the same retry policy as named
                // groups: if its transports failed at startup (e.g. the
                // network was not up yet), try to recreate them, and reply
                // SERVFAIL while they are unavailable.
                log::debug!(
                    "Fallback group has no available transports, replying \
                     SERVFAIL"
                );
                return synthetic_reply(&request, DnsResponseCode::ServFail);
            }
            self.fallback.request(request).await
        } else {
            Err(MudzError::new(
                ErrorKind::InvalidArgument,
                "DNS request does not contain a domain",
            ))
        }
    }
}

/// Build a synthetic response for `request` with the given RCODE, echoing
/// the question section and the request's ID and RD bit.
fn synthetic_reply(
    request: &DnsPacket,
    code: DnsResponseCode,
) -> Result<DnsPacket, MudzError> {
    let question = request.first_question().ok_or_else(|| {
        MudzError::new(
            ErrorKind::InvalidArgument,
            "DNS request has no question section",
        )
    })?;
    Ok(DnsPacket::new_reply(
        request.header.id,
        code,
        question.domain.clone(),
        question.kind,
        question.class,
        request.header.rd,
    ))
}

/// A per-upstream-server UDP transport that fans out responses to the
/// correct caller via a background recv loop and oneshot channels.
struct DnsUdpTransport {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<PendingMap>>,
}

/// Key for matching an upstream UDP response to its waiter: the question's
/// (domain, type, class) plus the DNS transaction ID. The ID — echoed by every
/// compliant response (RFC 1035 §4.1.1) — disambiguates concurrent in-flight
/// queries for the same name/type/class (e.g. a DO=0 and a DO=1 resolution),
/// so they are never cross-delivered.
type PendingKey = (String, DnsType, DnsClass, u16);
type PendingMap = HashMap<PendingKey, Vec<oneshot::Sender<DnsPacket>>>;

impl DnsUdpTransport {
    async fn new(server_addr: &str) -> Result<Self, MudzError> {
        let socket = Arc::new(create_udp_socket(server_addr).await?);
        let pending: Arc<Mutex<PendingMap>> =
            Arc::new(Mutex::new(HashMap::new()));

        let recv_socket = socket.clone();
        let recv_pending = pending.clone();
        tokio::spawn(Self::recv_loop(recv_socket, recv_pending));

        Ok(Self { socket, pending })
    }

    async fn send_query(&self, bytes: &[u8]) -> Result<(), MudzError> {
        self.socket.send(bytes).await.map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to send DNS query via UDP: {e}"),
            )
        })?;
        Ok(())
    }

    /// Register interest in a response matching `key`. The sender is
    /// inserted synchronously under a lock, so it is guaranteed to be
    /// visible to `recv_loop` before `send_query` can complete.
    fn register(&self, key: PendingKey) -> oneshot::Receiver<DnsPacket> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending map lock poisoned")
            .entry(key)
            .or_default()
            .push(tx);
        rx
    }

    async fn recv_loop(
        socket: Arc<UdpSocket>,
        pending: Arc<Mutex<PendingMap>>,
    ) {
        let mut recv_buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
        let mut cleanup = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                result = socket.recv(&mut recv_buf) => {
                    let len = match result {
                        Ok(n) => n,
                        Err(e) => {
                            log::debug!("UDP recv error on upstream socket: {e}");
                            if is_fatal_io_error(&e) {
                                break;
                            }
                            continue;
                        }
                    };
                    match DnsPacket::parse(&recv_buf[..len]) {
                        Ok(packet) => {
                            if let Some(question) = packet.first_question() {
                                let key: PendingKey = (
                                    question.domain.to_string(),
                                    question.kind,
                                    question.class,
                                    packet.header.id,
                                );
                                let senders = pending
                                    .lock()
                                    .expect("pending map lock poisoned")
                                    .remove(&key);
                                if let Some(senders) = senders {
                                    for sender in senders {
                                        let _ = sender.send(packet.clone());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!(
                                "Failed to parse upstream DNS response: {e}"
                            );
                        }
                    }
                }
                _ = cleanup.tick() => {
                    pending
                        .lock()
                        .expect("pending map lock poisoned")
                        .retain(|_, senders| {
                            senders.retain(|s| !s.is_closed());
                            !senders.is_empty()
                        });
                }
            }
        }
    }
}

struct DnsGroup {
    name: String,
    state: tokio::sync::RwLock<GroupState>,
    /// Unix timestamp (seconds) of the last transport-retry attempt.
    /// Used for the [`DNS_RETRY_COOLDOWN`] gap between recreations.
    last_attempt: AtomicU64,
    disable_ipv6: bool,
    /// `true` when the group was explicitly configured with an empty
    /// nameserver list — callers should return NXDOMAIN.
    blocking: bool,
    /// Configuration for recreating transports at runtime.
    nameservers: Vec<String>,
    doh_config: Option<super::config::MudzDohConfig>,
    hosts: Arc<HostsFile>,
}

struct GroupState {
    udp_transports: Vec<Arc<DnsUdpTransport>>,
    doh_clients: Vec<DohClient>,
}

impl DnsGroup {
    async fn new(
        name: String,
        nameservers: Vec<String>,
        disable_ipv6: bool,
        blocking: bool,
        doh_config: Option<super::config::MudzDohConfig>,
        hosts: Arc<HostsFile>,
    ) -> Self {
        let state = Self::create_state(
            &nameservers,
            &doh_config,
            &hosts,
            &name,
            blocking,
        )
        .await;

        Self {
            name,
            state: tokio::sync::RwLock::new(state),
            last_attempt: AtomicU64::new(0),
            disable_ipv6,
            blocking,
            nameservers,
            doh_config,
            hosts,
        }
    }

    /// Build `GroupState` from the given nameserver list.  When
    /// `blocking` is false and all connections fail, a warning is
    /// logged and an empty state is returned — the caller will retry.
    async fn create_state(
        nameservers: &[String],
        doh_config: &Option<super::config::MudzDohConfig>,
        hosts: &HostsFile,
        group_name: &str,
        blocking: bool,
    ) -> GroupState {
        let mut udp_transports = Vec::new();
        let mut doh_clients = Vec::new();

        for srv in nameservers {
            if srv.starts_with("https://") {
                match create_doh_client(srv, doh_config, hosts).await {
                    Ok(client) => doh_clients.push(client),
                    Err(e) => log::warn!(
                        "Failed to create DoH client for '{}' in group '{}': \
                         {e}",
                        srv,
                        group_name
                    ),
                }
            } else {
                match DnsUdpTransport::new(srv).await {
                    Ok(transport) => {
                        udp_transports.push(Arc::new(transport));
                    }
                    Err(e) => log::warn!(
                        "Failed to create UDP transport for '{}' in group \
                         '{}': {e}",
                        srv,
                        group_name
                    ),
                }
            }
        }

        if udp_transports.is_empty() && doh_clients.is_empty() && !blocking {
            log::warn!(
                "No upstream connections available for group '{}', will retry \
                 on next request",
                group_name
            );
        }

        GroupState {
            udp_transports,
            doh_clients,
        }
    }

    /// Ensure this group has working transports.  If they were
    /// previously empty (e.g. the p2p interface was not up at startup),
    /// try to recreate them — but only if at least
    /// [`DNS_RETRY_COOLDOWN`] have passed since the last attempt.
    ///
    /// Returns `true` if one or more transports are now available.
    async fn ensure_transports(&self) -> bool {
        if self.blocking {
            return false;
        }

        // Fast path: already ready — just a read-lock.
        {
            let state = self.state.read().await;
            if !state.udp_transports.is_empty() || !state.doh_clients.is_empty()
            {
                return true;
            }
        }

        // Cooldown check.
        let now = now_secs();
        let prev = self.last_attempt.load(Ordering::Acquire);
        if now.wrapping_sub(prev) < DNS_RETRY_COOLDOWN.as_secs() {
            log::debug!(
                "Group '{}' transport retry cooldown ({:.1}s remaining)",
                self.name,
                (DNS_RETRY_COOLDOWN.as_secs() - now.wrapping_sub(prev)) as f32
            );
            return false;
        }
        let _ = self.last_attempt.compare_exchange(
            prev,
            now,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        let mut state = self.state.write().await;
        // Double-check: another request may have recreated them already.
        if !state.udp_transports.is_empty() || !state.doh_clients.is_empty() {
            return true;
        }
        *state = Self::create_state(
            &self.nameservers,
            &self.doh_config,
            &self.hosts,
            &self.name,
            false,
        )
        .await;
        let ok =
            !state.udp_transports.is_empty() || !state.doh_clients.is_empty();
        if !ok {
            log::debug!(
                "Group '{}' transport recreation failed, will retry later",
                self.name
            );
        }
        ok
    }

    fn is_blocking(&self) -> bool {
        self.blocking
    }

    async fn request(
        &self,
        request: DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        // Wrap the entire request with a timeout.  A stuck UDP transport
        // (e.g. a connected socket on a point-to-point interface whose
        // send never completes) would otherwise stall the request
        // indefinitely because `send_query` is called outside the
        // per-future timeout that only protects the receive side.
        tokio::time::timeout(DNS_TIMEOUT_SEC, self.request_inner(request))
            .await
            .unwrap_or_else(|_elapsed| {
                Err(MudzError::new(ErrorKind::Timeout, "DNS request timed out"))
            })
    }

    /// Implementation of [`Self::request`] – the actual work, called inside
    /// a timeout guard.
    async fn request_inner(
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

        let question = request.first_question().ok_or_else(|| {
            MudzError::new(
                ErrorKind::InvalidArgument,
                "DNS request has no question section",
            )
        })?;
        let key = (
            question.domain.to_string(),
            question.kind,
            question.class,
            request.header.id,
        );
        let query_bytes = request.to_bytes();

        let state = self.state.read().await;
        let mut futures = FuturesUnordered::new();

        for transport in &state.udp_transports {
            let rx = transport.register(key.clone());
            if let Err(e) = transport.send_query(&query_bytes).await {
                log::debug!(
                    "Error sending DNS query to group '{}': {e}",
                    self.name
                );
                continue;
            }
            let udp_future = async move {
                match tokio::time::timeout(DNS_TIMEOUT_SEC, rx).await {
                    Ok(Ok(packet)) => Ok(packet),
                    Ok(Err(_)) => Err(MudzError::new(
                        ErrorKind::Timeout,
                        "UDP response channel closed",
                    )),
                    Err(_) => Err(MudzError::new(
                        ErrorKind::Timeout,
                        "UDP DNS query timed out",
                    )),
                }
            };
            futures.push(Either::Left(udp_future));
        }

        // Send to all DoH clients
        for doh_client in &state.doh_clients {
            futures.push(Either::Right(doh_client.request(&request)));
        }

        if futures.is_empty() {
            return Err(MudzError::new(
                ErrorKind::Bug,
                format!(
                    "No upstream connections available for group '{}'",
                    self.name
                ),
            ));
        }

        while let Some(result) = futures.next().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::debug!("Error processing DNS response: {e}");
                }
            }
        }

        Err(MudzError::new(
            ErrorKind::Timeout,
            "All upstream DNS requests failed or timed out",
        ))
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
            ancount: 0,
            nscount: 0,
            arcount: 1,
            ..Default::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![hinfo],
    }
}

async fn create_udp_socket(srv: &str) -> Result<UdpSocket, MudzError> {
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
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        MudzError::new(
            ErrorKind::Bug,
            format!("Failed to bind UDP socket: {e}"),
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
                format!("Failed to connect to nameserver {}: {e}", nameserver),
            )
        })?;
        sockets.push(socket);
    }

    // Send queries with a timeout so a stuck UDP socket cannot
    // block startup indefinitely.
    for socket in &sockets {
        let send_bytes = query_packet.to_bytes();
        match tokio::time::timeout(DNS_TIMEOUT_SEC, socket.send(&send_bytes))
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_fatal_io_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionRefused
            | ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::atomic::Ordering};

    use mudz::{DnsPacket, DnsResponseCode, DnsType};

    use super::*;
    use crate::config::{MudzConfig, MudzFallbackConfig, MudzMainConfig};

    fn test_config(fallback_ns: &str) -> MudzConfig {
        MudzConfig {
            main: MudzMainConfig::default(),
            fallback: MudzFallbackConfig {
                nameservers: vec![fallback_ns.to_string()],
                disable_ipv6: false,
            },
            doh: None,
            groups: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_fallback_servfail_when_no_transports() {
        // An unparseable nameserver address always fails transport creation,
        // leaving the fallback group with no upstream connections.
        let config = test_config("not-an-address");
        let groups = DnsGroups::new(config, None, Arc::new(HostsFile::new()))
            .await
            .expect("create groups");
        let query = DnsPacket::new_query("example.com", DnsType::A)
            .expect("build query");

        // Must be a SERVFAIL reply, not an error: the resolver turns the
        // former into a reply to the client.
        let resp = groups
            .request(query)
            .await
            .expect("request must return a reply");
        assert_eq!(resp.header.rcode, DnsResponseCode::ServFail);
        assert!(resp.header.qr);
        assert_eq!(resp.questions[0].domain.to_string(), "example.com");
    }

    #[tokio::test]
    async fn test_ensure_transports_recovers_after_cooldown() {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let group = DnsGroup::new(
            "test".to_string(),
            vec![addr.to_string()],
            false,
            false,
            None,
            Arc::new(HostsFile::new()),
        )
        .await;
        assert!(group.ensure_transports().await);

        // Simulate a failed startup: no transports and a recent retry
        // attempt, so ensure_transports must respect the cooldown.
        *group.state.write().await = GroupState {
            udp_transports: Vec::new(),
            doh_clients: Vec::new(),
        };
        group.last_attempt.store(now_secs(), Ordering::Release);
        assert!(
            !group.ensure_transports().await,
            "retry must be refused during the cooldown window"
        );

        // Once the cooldown has elapsed, the transports are recreated.
        group.last_attempt.store(0, Ordering::Release);
        assert!(
            group.ensure_transports().await,
            "transports must be recreated after the cooldown"
        );
        let state = group.state.read().await;
        assert_eq!(state.udp_transports.len(), 1);
    }
}

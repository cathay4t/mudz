// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::Duration,
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
    retry::{Attempt, CooldownGate, DNS_RETRY_COOLDOWN, UpstreamState},
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
    pub(crate) fn new(
        mut config: MudzConfig,
        doh_config: Option<super::config::MudzDohConfig>,
        hosts: Arc<HostsFile>,
    ) -> Self {
        let fallback = DnsGroup::new(
            "fallback".to_string(),
            config.fallback.nameservers,
            config.fallback.disable_ipv6,
            false, // fallback is never intentionally blocking
            doh_config.clone(),
            hosts.clone(),
        );

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
            );
            groups.insert(group_name.to_string(), dns_group);

            for domain in group_config.domains {
                let domain_split: Vec<String> =
                    domain.split('.').map(|s| s.to_lowercase()).collect();
                search_index.insert(domain_split, group_name.to_string());
            }
        }

        Self {
            fallback,
            groups,
            search_index,
        }
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

                    if !ensure_transports_with_timeout(group).await {
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
            if !ensure_transports_with_timeout(&self.fallback).await {
                // The fallback group follows the same retry policy as named
                // groups: transports are created on demand, and if they are
                // unavailable (e.g. the network is not up yet) we reply
                // SERVFAIL and retry after the cooldown.
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

/// Ensure `group` has transports, bounding the (potentially blocking)
/// transport-creation work with the same per-upstream timeout used for DNS
/// requests. A group whose upstreams are unreachable must fail fast with
/// SERVFAIL instead of stalling the client while sockets or DoH bootstrap
/// queries time out.
async fn ensure_transports_with_timeout(group: &DnsGroup) -> bool {
    match tokio::time::timeout(DNS_TIMEOUT_SEC, group.ensure_transports()).await
    {
        Ok(ready) => ready,
        Err(_elapsed) => {
            log::warn!(
                "Timed out creating transports for group '{}', replying \
                 SERVFAIL",
                group.name
            );
            false
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
    /// Fail-cooldown-retry state (see [`super::retry`]). Shared with
    /// `recv_loop`, which marks it broken when it exits on a fatal socket
    /// error; `request_inner` consults it before sending and records the
    /// outcome, and `ensure_transports` evicts broken transports.
    state: Arc<UpstreamState>,
    /// Handle to the background `recv_loop` task. The loop never exits on
    /// its own except on a fatal socket error (which marks the transport
    /// broken) or a panic; either way the task finishes. A finished handle
    /// therefore means the transport can never dispatch responses again and
    /// must be recreated - even when the panic path failed to mark it
    /// broken (`tokio::spawn` catches panics silently).
    recv_task: tokio::task::JoinHandle<()>,
}

/// Key for matching an upstream UDP response to its waiter: the question's
/// (domain, type, class) plus the DNS transaction ID. The ID — echoed by every
/// compliant response (RFC 1035 §4.1.1) — disambiguates concurrent in-flight
/// queries for the same name/type/class (e.g. a DO=0 and a DO=1 resolution),
/// so they are never cross-delivered.
type PendingKey = (String, DnsType, DnsClass, u16);
type PendingMap = HashMap<PendingKey, Vec<oneshot::Sender<DnsPacket>>>;

impl DnsUdpTransport {
    async fn new(
        server_addr: &str,
        group_name: &str,
    ) -> Result<Self, MudzError> {
        let socket = Arc::new(create_udp_socket(server_addr).await?);
        let pending: Arc<Mutex<PendingMap>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(UpstreamState::new(server_addr, group_name));

        let recv_socket = socket.clone();
        let recv_pending = pending.clone();
        let recv_state = Arc::clone(&state);
        let recv_task = tokio::spawn(Self::recv_loop(
            recv_socket,
            recv_pending,
            recv_state,
        ));

        Ok(Self {
            socket,
            pending,
            state,
            recv_task,
        })
    }

    /// Whether this transport can still dispatch upstream responses. True
    /// when the receive loop marked the transport broken on a fatal socket
    /// error, or when the receive loop task has finished for any other
    /// reason (e.g. a panic) - `recv_loop` only exits on those two events.
    fn is_broken(&self) -> bool {
        self.state.is_broken() || self.recv_task.is_finished()
    }

    async fn send_query(
        &self,
        bytes: &[u8],
        key: &PendingKey,
    ) -> Result<oneshot::Receiver<DnsPacket>, MudzError> {
        // Rewrite the transaction ID to a fresh random value so that
        // concurrent queries for the same (domain, type, class) — e.g. a
        // DO=0 and a DO=1 resolution, or a retried query reusing the
        // client's ID — carry distinct wire IDs and can never be
        // cross-delivered. The response echoes the rewritten ID and is
        // matched against it; the caller restores the client's original ID.
        let mut buf = bytes.to_vec();
        let mut wire_key: PendingKey = (key.0.clone(), key.1, key.2, 0);
        let mut rx = None;
        while rx.is_none() {
            wire_key.3 = rand::random::<u16>();
            // Check-and-insert under one lock: if another in-flight query
            // already uses this wire ID, re-roll instead of registering a
            // duplicate key, which would cross-deliver both responses.
            let mut pending =
                self.pending.lock().expect("pending map lock poisoned");
            if pending.contains_key(&wire_key) {
                continue;
            }
            let (tx, receiver) = oneshot::channel();
            pending.entry(wire_key.clone()).or_default().push(tx);
            rx = Some(receiver);
        }
        buf[0..2].copy_from_slice(&wire_key.3.to_be_bytes());
        self.socket.send(&buf).await.map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to send DNS query via UDP: {e}"),
            )
        })?;
        Ok(rx.expect("wire key registered"))
    }

    async fn recv_loop(
        socket: Arc<UdpSocket>,
        pending: Arc<Mutex<PendingMap>>,
        state: Arc<UpstreamState>,
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
                                log::warn!(
                                    "Upstream '{}' in group '{}' receive loop \
                                     exiting on fatal socket error: {e}; \
                                     transport marked broken",
                                    state.name(),
                                    state.group()
                                );
                                state.mark_broken();
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

fn record_upstream_success(transport: Option<Arc<DnsUdpTransport>>) {
    if let Some(transport) = transport {
        transport.state.record_success();
    }
}

fn record_upstream_failure(
    transport: Option<Arc<DnsUdpTransport>>,
    error: &MudzError,
    is_probe: bool,
) {
    if let Some(transport) = transport {
        if is_probe {
            // The probe failed: the upstream has been unresponsive for a
            // whole cooldown window. Evict and recreate the transport so a
            // fresh socket (no latched errors, clean ARP/route state) is
            // used instead of probing forever.
            log::warn!(
                "Upstream '{}' in group '{}' failed a probe, marking \
                 transport broken for recreation",
                transport.state.name(),
                transport.state.group()
            );
            transport.state.mark_broken();
        } else {
            transport.state.record_failure();
        }
    }
    log::debug!("Error processing DNS response: {error}");
}

struct DnsGroup {
    name: String,
    state: tokio::sync::RwLock<GroupState>,
    /// Throttles transport recreation to at most one attempt per
    /// [`DNS_RETRY_COOLDOWN`].
    recreate_gate: CooldownGate,
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
    fn new(
        name: String,
        nameservers: Vec<String>,
        disable_ipv6: bool,
        blocking: bool,
        doh_config: Option<super::config::MudzDohConfig>,
        hosts: Arc<HostsFile>,
    ) -> Self {
        Self {
            name,
            // Upstream transports are created lazily on the first request
            // for this group, so an unreachable fallback (or any other
            // group) never blocks daemon startup or unrelated groups.
            state: tokio::sync::RwLock::new(GroupState {
                udp_transports: Vec::new(),
                doh_clients: Vec::new(),
            }),
            recreate_gate: CooldownGate::new(DNS_RETRY_COOLDOWN),
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
                match DnsUdpTransport::new(srv, group_name).await {
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

    /// Ensure this group has working transports. Transports are created
    /// lazily on the first request; if creation failed (e.g. the p2p
    /// interface was not up), retry — but only if at least
    /// [`DNS_RETRY_COOLDOWN`] has passed since the last attempt.
    ///
    /// Returns `true` if one or more transports are now available.
    async fn ensure_transports(&self) -> bool {
        if self.blocking {
            return false;
        }

        // Fast path: every transport is live and at least one exists.
        {
            let state = self.state.read().await;
            let has_broken = state.udp_transports.iter().any(|t| t.is_broken());
            let has_live = !state.udp_transports.is_empty()
                || !state.doh_clients.is_empty();
            if !has_broken && has_live {
                return true;
            }
        }

        let mut state = self.state.write().await;
        // Evict transports whose receive loop died (fatal socket error or a
        // silent panic) or that failed a probe: they can never dispatch
        // responses again, and keeping them around would block recreation.
        let before = state.udp_transports.len();
        state.udp_transports.retain(|t| !t.is_broken());
        if state.udp_transports.len() != before {
            log::warn!(
                "Group '{}': evicted {} broken upstream transport(s)",
                self.name,
                before - state.udp_transports.len()
            );
        }
        // Double-check: another request may have recreated them already.
        if !state.udp_transports.is_empty() || !state.doh_clients.is_empty() {
            return true;
        }

        // Cooldown check: at most one recreation attempt per window.
        if !self.recreate_gate.try_acquire() {
            log::debug!(
                "Group '{}' transport retry cooldown ({}s remaining)",
                self.name,
                self.recreate_gate.remaining_secs()
            );
            return false;
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
        //
        // The guard must outlive the per-upstream timers: when both share
        // one deadline they race, and if this outer guard wins,
        // `request_inner` is dropped before it records the upstream
        // failure, leaving the upstream health state stale.
        tokio::time::timeout(
            DNS_TIMEOUT_SEC + Duration::from_secs(1),
            self.request_inner(request),
        )
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
        let mut skipped_dead = 0usize;
        let mut pending_udp = 0usize;

        for transport in &state.udp_transports {
            // Dead upstreams are skipped so clients fail fast with
            // SERVFAIL; the retry policy lets one probe through per
            // cooldown window. Broken ones (receive loop dead, e.g. a
            // fatal socket error or a silent panic) are never usable again
            // and wait for eviction by `ensure_transports`.
            if transport.is_broken() {
                skipped_dead += 1;
                continue;
            }
            let attempt = transport.state.may_attempt();
            match attempt {
                Attempt::Ready | Attempt::Probing => {}
                Attempt::Dead | Attempt::Broken => {
                    skipped_dead += 1;
                    continue;
                }
            }
            let rx = match transport.send_query(&query_bytes, &key).await {
                Ok(rx) => rx,
                Err(e) => {
                    log::debug!(
                        "Error sending DNS query to group '{}': {e}",
                        self.name
                    );
                    if matches!(attempt, Attempt::Probing) {
                        // A failed probe means the upstream has been
                        // unresponsive for a whole cooldown window. Recreate
                        // the transport instead of probing the same (possibly
                        // stuck) socket forever - a fresh socket clears any
                        // latched kernel error state.
                        transport.state.mark_broken();
                    } else {
                        transport.state.record_failure();
                    }
                    continue;
                }
            };
            let client_id = key.3;
            let transport = Arc::clone(transport);
            let is_probe = matches!(attempt, Attempt::Probing);
            let udp_future = async move {
                let result = match tokio::time::timeout(DNS_TIMEOUT_SEC, rx)
                    .await
                {
                    Ok(Ok(mut packet)) => {
                        // The upstream echoed the rewritten wire ID; restore
                        // the client's original transaction ID.
                        packet.header.id = client_id;
                        Ok(packet)
                    }
                    Ok(Err(_)) => Err(MudzError::new(
                        ErrorKind::Timeout,
                        "UDP response channel closed",
                    )),
                    Err(_) => Err(MudzError::new(
                        ErrorKind::Timeout,
                        "UDP DNS query timed out",
                    )),
                };
                (Some(transport), result, is_probe)
            };
            futures.push(Either::Left(udp_future));
            pending_udp += 1;
        }

        // Send to all DoH clients
        for doh_client in &state.doh_clients {
            let doh_client = doh_client.clone();
            let doh_request = request.clone();
            let doh_future = async move {
                (None, doh_client.request(&doh_request).await, false)
            };
            futures.push(Either::Right(doh_future));
        }

        if futures.is_empty() {
            return Err(if skipped_dead > 0 {
                MudzError::new(
                    ErrorKind::Timeout,
                    format!(
                        "All {skipped_dead} upstream(s) of group '{}' are \
                         dead, failing fast",
                        self.name
                    ),
                )
            } else {
                MudzError::new(
                    ErrorKind::Bug,
                    format!(
                        "No upstream connections available for group '{}'",
                        self.name
                    ),
                )
            });
        }

        while let Some((transport, result, is_probe)) = futures.next().await {
            if transport.is_some() {
                pending_udp -= 1;
            }
            match result {
                Ok(response) => {
                    record_upstream_success(transport);
                    if pending_udp > 0 {
                        // Keep accounting for the upstreams that did not win
                        // this request: their replies may still arrive (or
                        // time out), and their health state must not go stale
                        // just because another upstream answered first.
                        tokio::spawn(async move {
                            while let Some((transport, result, is_probe)) =
                                futures.next().await
                            {
                                match result {
                                    Ok(_) => {
                                        record_upstream_success(transport);
                                    }
                                    Err(e) => {
                                        record_upstream_failure(
                                            transport, &e, is_probe,
                                        );
                                    }
                                }
                            }
                        });
                    }
                    return Ok(response);
                }
                Err(e) => {
                    record_upstream_failure(transport, &e, is_probe);
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
    use std::collections::HashMap;

    use mudz::{DnsPacket, DnsResponseCode, DnsType};

    use super::*;
    use crate::{
        config::{
            DnsUpstreamGroup, MudzConfig, MudzFallbackConfig, MudzMainConfig,
        },
        retry::now_secs,
    };

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

    /// Nothing listens on the upstream port, so the kernel answers with
    /// ICMP port-unreachable; the latched socket error must reach the recv
    /// loop (tokio >= 1.51.1, see tokio#8001) and mark the transport
    /// broken. Uses its own port so it never collides with the end-to-end
    /// tests.
    #[tokio::test]
    async fn test_transport_broken_on_icmp_refused() {
        let transport = DnsUdpTransport::new("127.0.0.1:53537", "test")
            .await
            .expect("create transport to dead port");
        let query =
            DnsPacket::new_query("example.com", DnsType::A).expect("query");
        let key = (
            "example.com".to_string(),
            DnsType::A,
            DnsClass::IN,
            query.header.id,
        );
        // Let the receive loop park in recv before triggering the ICMP
        // error, exactly like the running daemon.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rx = transport
            .send_query(&query.to_bytes(), &key)
            .await
            .expect("send query");
        // The reply never comes; the rx oneshot only ends when it is
        // dropped after the timeout future gives up.
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(rx);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            transport.state.is_broken(),
            "recv loop must consume the latched ICMP error and mark the \
             transport broken"
        );
        assert!(
            transport.is_broken(),
            "a broken transport must be detected via the transport itself so \
             ensure_transports can evict it"
        );
    }

    #[tokio::test]
    async fn test_transport_is_broken_when_recv_loop_panics() {
        // A transport whose receive loop exits for any reason other than a
        // fatal socket error (here: a panic) must still be detected as
        // broken. `recv_loop` only exits on a fatal error or a panic, so a
        // finished task handle is a reliable liveness signal even when the
        // panic path never ran `mark_broken`.
        let transport = DnsUdpTransport::new("127.0.0.1:53538", "test")
            .await
            .expect("create transport");
        assert!(
            !transport.is_broken(),
            "a freshly created transport must be live"
        );

        // Abort the receive loop to simulate a silent exit (e.g. a panic
        // in `recv_loop` being caught by tokio). The transport must then
        // be detected as broken without any fatal socket error.
        transport.recv_task.abort();
        // Allow the abort to take effect.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !transport.is_broken() && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert!(
            transport.is_broken(),
            "a transport whose receive loop exited silently must be detected \
             as broken so it is evicted and recreated"
        );
    }

    #[tokio::test]
    async fn test_fallback_servfail_when_no_transports() {
        // An unparseable nameserver address always fails transport creation,
        // leaving the fallback group with no upstream connections.
        let config = test_config("not-an-address");
        let groups = DnsGroups::new(config, None, Arc::new(HostsFile::new()));
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
    async fn test_group_transports_created_on_demand() {
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
        );

        {
            let state = group.state.read().await;
            assert!(
                state.udp_transports.is_empty(),
                "no upstream transport should be created until first request"
            );
        }

        assert!(group.ensure_transports().await);
        let state = group.state.read().await;
        assert_eq!(state.udp_transports.len(), 1);
    }

    #[tokio::test]
    async fn test_named_group_resolves_when_fallback_unavailable() {
        let upstream =
            Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = upstream.local_addr().unwrap();
        let server = upstream.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = tokio::time::timeout(
                Duration::from_secs(5),
                server.recv_from(&mut buf),
            )
            .await
            .expect("named group must query its upstream")
            .unwrap();
            let query = DnsPacket::parse(&buf[..len]).unwrap();
            let question = query.first_question().unwrap();
            let reply = DnsPacket::new_reply(
                query.header.id,
                DnsResponseCode::NoError,
                question.domain.clone(),
                question.kind,
                question.class,
                true,
            );
            server.send_to(&reply.to_bytes(), peer).await.unwrap();
        });

        let mut groups = HashMap::new();
        groups.insert(
            "corp".to_string(),
            DnsUpstreamGroup {
                nameservers: vec![upstream_addr.to_string()],
                domains: vec!["corp.example".to_string()],
                disable_ipv6: false,
            },
        );
        let config = MudzConfig {
            main: MudzMainConfig::default(),
            fallback: MudzFallbackConfig {
                nameservers: vec!["not-an-address".to_string()],
                disable_ipv6: false,
            },
            doh: None,
            groups,
        };
        let groups = DnsGroups::new(config, None, Arc::new(HostsFile::new()));

        let resp = groups
            .request(
                DnsPacket::new_query("host.corp.example", DnsType::A)
                    .expect("build query"),
            )
            .await
            .expect("named group request must succeed");
        assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
        server_task.await.unwrap();
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
        );
        assert!(group.ensure_transports().await);

        // Simulate a failed startup: no transports and a recent retry
        // attempt, so ensure_transports must respect the cooldown.
        *group.state.write().await = GroupState {
            udp_transports: Vec::new(),
            doh_clients: Vec::new(),
        };
        group.recreate_gate.set_last_attempt(now_secs());
        assert!(
            !group.ensure_transports().await,
            "retry must be refused during the cooldown window"
        );

        // Once the cooldown has elapsed, the transports are recreated.
        group.recreate_gate.set_last_attempt(0);
        assert!(
            group.ensure_transports().await,
            "transports must be recreated after the cooldown"
        );
        let state = group.state.read().await;
        assert_eq!(state.udp_transports.len(), 1);
    }

    /// Concurrent queries for the same (domain, type, class) with the same
    /// client transaction ID but different DNSSEC OK bits must each receive
    /// their own response. Before per-query wire ID rewriting, the first
    /// response was delivered to every waiter under the shared key, so one
    /// caller received the other query's response.
    #[tokio::test]
    async fn test_concurrent_same_id_queries_not_cross_delivered() {
        // Fake upstream: reply to each query echoing the received ID and the
        // query's DO bit, so the two responses are distinguishable.
        let upstream =
            Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = upstream.local_addr().unwrap();
        let server = upstream.clone();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let query = DnsPacket::parse(&buf[..n]).unwrap();
                let question = &query.questions[0];
                let mut reply = DnsPacket::new_reply(
                    query.header.id,
                    DnsResponseCode::NoError,
                    question.domain.clone(),
                    question.kind,
                    question.class,
                    true,
                );
                reply.add_opt_record(1232, query.dnssec_ok());
                server.send_to(&reply.to_bytes(), peer).await.unwrap();
            }
        });

        let transport =
            DnsUdpTransport::new(&upstream_addr.to_string(), "test")
                .await
                .unwrap();

        // Two queries for the same name/type/class with the same client ID,
        // one with the DNSSEC OK bit set and one without.
        let mut query_do0 =
            DnsPacket::new_query("example.com", DnsType::A).unwrap();
        query_do0.add_opt_record(1232, false);
        let mut query_do1 =
            DnsPacket::new_query("example.com", DnsType::A).unwrap();
        query_do1.add_opt_record(1232, true);
        query_do1.header.id = query_do0.header.id;
        let client_id = query_do0.header.id;
        let question = query_do0.questions[0].clone();
        let key = (
            question.domain.to_string(),
            question.kind,
            question.class,
            client_id,
        );

        let bytes_do0 = query_do0.to_bytes();
        let bytes_do1 = query_do1.to_bytes();
        let (rx_do0, rx_do1) = tokio::join!(
            transport.send_query(&bytes_do0, &key),
            transport.send_query(&bytes_do1, &key),
        );
        let rx_do0 = rx_do0.expect("send DO=0 query");
        let rx_do1 = rx_do1.expect("send DO=1 query");

        let (resp_do0, resp_do1) = tokio::join!(rx_do0, rx_do1);
        let mut resp_do0 = resp_do0.expect("DO=0 response");
        let mut resp_do1 = resp_do1.expect("DO=1 response");
        // Restore the client ID, as `DnsGroup::request_inner` does.
        resp_do0.header.id = client_id;
        resp_do1.header.id = client_id;

        assert_eq!(resp_do0.header.id, client_id);
        assert_eq!(resp_do1.header.id, client_id);
        assert!(
            !resp_do0.dnssec_ok(),
            "DO=0 caller must not receive the DO=1 response"
        );
        assert!(
            resp_do1.dnssec_ok(),
            "DO=1 caller must not receive the DO=0 response"
        );

        server_task.await.unwrap();
    }
}

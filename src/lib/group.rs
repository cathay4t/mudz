// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{
    StreamExt,
    future::{join_all, select_ok},
    stream::FuturesUnordered,
};
use tokio::{net::UdpSocket, sync::oneshot};

use super::{
    config::MudzConfig,
    doh::{DohClient, DohOptions, DohResolvCache, is_transport_error},
    endpoint::{NameserverAddress, NameserverEndpoint, NameserverScheme},
    retry::{Attempt, CooldownGate, DNS_RETRY_COOLDOWN, UpstreamState},
    stream::{DOT_PORT, DnsDotTransport, DnsTcpTransport},
};
use crate::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
    DnsType, ErrorKind, MudzError,
};

const DNS_TIMEOUT_SEC: Duration = Duration::from_secs(5);
/// Standard plaintext DNS port (RFC 1035), used for `tcp://`, `udp://` and
/// the plaintext fallbacks of a bare IP nameserver.
const DNS_PORT: u16 = 53;
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
        doh_cache: Option<Arc<DohResolvCache>>,
    ) -> Self {
        let doh_options = config
            .doh
            .as_ref()
            .map(DohOptions::from_config)
            .unwrap_or_default();
        let fallback = DnsGroup::new(
            "fallback".to_string(),
            config.fallback.nameservers,
            config.fallback.disable_ipv6,
            false, // fallback is never intentionally blocking
            doh_cache.clone(),
            doh_options,
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
                doh_cache.clone(),
                doh_options,
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

    /// Drop pooled DoH connections and clear upstream failure state after
    /// the system resumed from suspend. UDP transports are connectionless
    /// and need no reset.
    pub(crate) async fn handle_resume(&self) {
        self.fallback.handle_resume().await;
        for group in self.groups.values() {
            group.handle_resume().await;
        }
    }

    /// Clear upstream failure state and drop every pooled transport after
    /// the embedder reported a network change, such as a new default
    /// gateway. Cached DNS replies are kept.
    pub(crate) async fn handle_network_change(&self) {
        self.fallback.handle_network_change().await;
        for group in self.groups.values() {
            group.handle_network_change().await;
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

impl Drop for DnsUdpTransport {
    fn drop(&mut self) {
        // The receive loop owns a clone of the socket. Dropping a
        // `JoinHandle` does not cancel the task, so without this abort an
        // evicted transport would keep its socket and its waiters alive.
        self.recv_task.abort();
    }
}

impl DnsUdpTransport {
    async fn new(
        nameserver: &str,
        addr: SocketAddr,
        group_name: &str,
    ) -> Result<Self, MudzError> {
        let socket = Arc::new(create_udp_socket(addr).await?);
        let pending: Arc<Mutex<PendingMap>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(UpstreamState::new(nameserver, group_name));

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
                                // Fail every in-flight waiter immediately
                                // instead of letting each one wait for the
                                // full per-query timeout on a transport that
                                // can never answer again.
                                pending
                                    .lock()
                                    .expect("pending map lock poisoned")
                                    .clear();
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

fn record_upstream_success(upstream: Option<Upstream>) {
    match upstream {
        Some(Upstream::Udp(transport)) => transport.state.record_success(),
        Some(Upstream::Tcp(transport)) => transport.state.record_success(),
        Some(Upstream::Dot(transport)) => transport.state.record_success(),
        Some(Upstream::Doh(upstream)) => upstream.state.record_success(),
        None => {}
    }
}

/// Record a failed attempt for a connection-oriented transport.
///
/// A failed probe means the transport has been silent for a whole cooldown
/// window. A framed stream (plain TCP or DoT) or a connected UDP socket can
/// be half-open without ever producing a read or write error, so probing the
/// same transport forever would never recover; tear it down and let the next
/// repair reconnect according to the configured scheme.
fn record_transport_probe_failure(state: &UpstreamState) {
    log::warn!(
        "Upstream '{}' in group '{}' failed a probe, marking transport broken \
         for recreation",
        state.name(),
        state.group()
    );
    state.mark_broken();
}

async fn record_upstream_failure(
    upstream: Option<Upstream>,
    error: &MudzError,
    is_probe: bool,
) {
    match upstream {
        Some(Upstream::Udp(transport)) => {
            if is_probe {
                record_transport_probe_failure(&transport.state);
            } else {
                transport.state.record_failure();
            }
        }
        Some(Upstream::Tcp(transport)) => {
            if is_probe {
                record_transport_probe_failure(&transport.state);
            } else {
                transport.state.record_failure();
            }
        }
        Some(Upstream::Dot(transport)) => {
            if is_probe {
                record_transport_probe_failure(&transport.state);
            } else {
                transport.state.record_failure();
            }
        }
        Some(Upstream::Doh(upstream)) if is_transport_error(error) => {
            if is_probe {
                log::debug!(
                    "DoH upstream '{}' in group '{}' failed a probe; \
                     rebuilding its connection pool",
                    upstream.state.name(),
                    upstream.state.group()
                );
                upstream.client.invalidate_pool().await;
            }
            upstream.state.record_failure();
        }
        Some(Upstream::Doh(_)) => {
            // Protocol errors (SERVFAIL, HTTP 4xx, malformed replies) do not
            // indicate a broken transport; they must not affect health.
        }
        None => {}
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
    /// DoH hostname-to-IP mapping resolved at startup. `None` when the
    /// daemon has no DoH nameserver configured.
    doh_cache: Option<Arc<DohResolvCache>>,
    /// DoH retry/timeout policy configured in the `[doh]` section.
    doh_options: DohOptions,
}

struct GroupState {
    udp_transports: Vec<Arc<DnsUdpTransport>>,
    tcp_transports: Vec<Arc<DnsTcpTransport>>,
    dot_transports: Vec<Arc<DnsDotTransport>>,
    doh_clients: Vec<Arc<DohUpstream>>,
}

/// A transport created for one configured nameserver by
/// [`DnsGroup::create_upstream`].
enum CreatedUpstream {
    Udp(Arc<DnsUdpTransport>),
    Tcp(Arc<DnsTcpTransport>),
    Dot(Arc<DnsDotTransport>),
    Doh(Arc<DohUpstream>),
}

/// A DoH upstream plus the shared health/cooldown state used to skip it
/// while it is failing and to probe it for recovery.
struct DohUpstream {
    client: DohClient,
    state: Arc<UpstreamState>,
}

impl DohUpstream {
    fn new(client: DohClient, server: &str, group: &str) -> Self {
        Self {
            client,
            state: Arc::new(UpstreamState::new(server, group)),
        }
    }
}

/// Handle to the upstream a request future was sent to, so success and
/// failure can be recorded in the right health state.
#[derive(Clone)]
enum Upstream {
    Udp(Arc<DnsUdpTransport>),
    Tcp(Arc<DnsTcpTransport>),
    Dot(Arc<DnsDotTransport>),
    Doh(Arc<DohUpstream>),
}

/// A live framed-stream upstream (plain TCP or DoT). The two transports
/// share their framing, demultiplexing, and health policy, so the fan-out
/// drives both through this one handle.
enum StreamTransport {
    Tcp(Arc<DnsTcpTransport>),
    Dot(Arc<DnsDotTransport>),
}

impl StreamTransport {
    fn is_broken(&self) -> bool {
        match self {
            Self::Tcp(transport) => transport.is_broken(),
            Self::Dot(transport) => transport.is_broken(),
        }
    }

    fn state(&self) -> &Arc<UpstreamState> {
        match self {
            Self::Tcp(transport) => &transport.state,
            Self::Dot(transport) => &transport.state,
        }
    }

    async fn send_query(
        &self,
        bytes: &[u8],
        key: &PendingKey,
    ) -> Result<oneshot::Receiver<DnsPacket>, MudzError> {
        match self {
            Self::Tcp(transport) => transport.send_query(bytes, key).await,
            Self::Dot(transport) => transport.send_query(bytes, key).await,
        }
    }

    fn into_upstream(self) -> Upstream {
        match self {
            Self::Tcp(transport) => Upstream::Tcp(transport),
            Self::Dot(transport) => Upstream::Dot(transport),
        }
    }
}

/// A single upstream lookup future: the upstream it was sent to (for health
/// accounting), its result, and whether it was the cooldown-window probe.
/// Boxed so the UDP, DoT, and DoH branches of the fan-out all share one
/// `FuturesUnordered` element type.
type UpstreamResult = (Option<Upstream>, Result<DnsPacket, MudzError>, bool);
type UpstreamQueryFuture =
    Pin<Box<dyn Future<Output = UpstreamResult> + Send + 'static>>;

impl DnsGroup {
    fn new(
        name: String,
        nameservers: Vec<String>,
        disable_ipv6: bool,
        blocking: bool,
        doh_cache: Option<Arc<DohResolvCache>>,
        doh_options: DohOptions,
    ) -> Self {
        Self {
            name,
            // Upstream transports are created lazily on the first request
            // for this group, so an unreachable fallback (or any other
            // group) never blocks daemon startup or unrelated groups.
            state: tokio::sync::RwLock::new(GroupState {
                udp_transports: Vec::new(),
                tcp_transports: Vec::new(),
                dot_transports: Vec::new(),
                doh_clients: Vec::new(),
            }),
            recreate_gate: CooldownGate::new(DNS_RETRY_COOLDOWN),
            disable_ipv6,
            blocking,
            nameservers,
            doh_cache,
            doh_options,
        }
    }

    /// Build `GroupState` from the given nameserver list.  When
    /// `blocking` is false and all connections fail, a warning is
    /// logged and an empty state is returned — the caller will retry.
    ///
    /// Nameservers are probed concurrently: the callers bound transport
    /// creation with the per-request timeout, and probing sequentially would
    /// let a couple of unreachable DoT endpoints consume that budget and
    /// discard every already-created transport.
    async fn create_state(
        nameservers: &[String],
        doh_cache: &Option<Arc<DohResolvCache>>,
        group_name: &str,
        blocking: bool,
        doh_options: DohOptions,
    ) -> GroupState {
        let created = join_all(nameservers.iter().map(|srv| {
            Self::create_upstream(srv, doh_cache, group_name, doh_options)
        }))
        .await;

        let mut udp_transports = Vec::new();
        let mut tcp_transports = Vec::new();
        let mut dot_transports = Vec::new();
        let mut doh_clients = Vec::new();

        for upstream in created.into_iter().flatten() {
            match upstream {
                CreatedUpstream::Udp(transport) => {
                    udp_transports.push(transport);
                }
                CreatedUpstream::Tcp(transport) => {
                    tcp_transports.push(transport);
                }
                CreatedUpstream::Dot(transport) => {
                    dot_transports.push(transport);
                }
                CreatedUpstream::Doh(upstream) => {
                    doh_clients.push(upstream);
                }
            }
        }

        if udp_transports.is_empty()
            && tcp_transports.is_empty()
            && dot_transports.is_empty()
            && doh_clients.is_empty()
            && !blocking
        {
            log::warn!(
                "No upstream connections available for group '{}', will retry \
                 on next request",
                group_name
            );
        }

        GroupState {
            udp_transports,
            tcp_transports,
            dot_transports,
            doh_clients,
        }
    }

    /// Create the transport for one configured nameserver.
    ///
    /// A `https://` URL uses DoH. An IP literal prefixed with `tls://`,
    /// `tcp://` or `udp://` uses exactly that transport, with no fallback. A
    /// bare IP address tries DoT, then DNS over TCP, then UDP, so the
    /// ordering is also the preference order.
    async fn create_upstream(
        srv: &str,
        doh_cache: &Option<Arc<DohResolvCache>>,
        group_name: &str,
        doh_options: DohOptions,
    ) -> Option<CreatedUpstream> {
        if srv.starts_with("https://") {
            return match create_doh_client(srv, doh_cache, doh_options) {
                Ok(client) => Some(CreatedUpstream::Doh(Arc::new(
                    DohUpstream::new(client, srv, group_name),
                ))),
                Err(e) => {
                    log::warn!(
                        "Failed to create DoH client for '{}' in group '{}': \
                         {e}",
                        srv,
                        group_name
                    );
                    None
                }
            };
        }

        let nameserver = match NameserverEndpoint::parse(srv) {
            Ok(nameserver) => nameserver,
            Err(e) => {
                log::warn!(
                    "Failed to create upstream for '{}' in group '{}': {e}",
                    srv,
                    group_name
                );
                return None;
            }
        };

        // A forced transport never falls back: a failure leaves the upstream
        // unavailable until the group retries after the cooldown.
        match nameserver.scheme {
            NameserverScheme::Tls => {
                match Self::create_dot_transport(
                    srv,
                    &nameserver,
                    doh_cache,
                    group_name,
                )
                .await
                {
                    Ok(transport) => {
                        log::info!(
                            "Upstream '{}' in group '{}' uses DNS over TLS",
                            srv,
                            group_name
                        );
                        Some(CreatedUpstream::Dot(Arc::new(transport)))
                    }
                    Err(e) => {
                        log::warn!(
                            "Forced DNS over TLS upstream '{}' in group '{}' \
                             is unavailable: {e}",
                            srv,
                            group_name
                        );
                        None
                    }
                }
            }
            NameserverScheme::Tcp => {
                let Some(ip) = nameserver.address.ip() else {
                    log::warn!(
                        "DNS over TCP upstream '{}' in group '{}' requires an \
                         IP literal",
                        srv,
                        group_name
                    );
                    return None;
                };
                let addr = SocketAddr::new(ip, nameserver.port_or(DNS_PORT));
                match DnsTcpTransport::new_tcp(srv, addr, group_name).await {
                    Ok(transport) => {
                        log::info!(
                            "Upstream '{}' in group '{}' uses DNS over TCP",
                            srv,
                            group_name
                        );
                        Some(CreatedUpstream::Tcp(Arc::new(transport)))
                    }
                    Err(e) => {
                        log::warn!(
                            "Forced DNS over TCP upstream '{}' in group '{}' \
                             is unavailable: {e}",
                            srv,
                            group_name
                        );
                        None
                    }
                }
            }
            NameserverScheme::Udp => {
                let Some(ip) = nameserver.address.ip() else {
                    log::warn!(
                        "DNS over UDP upstream '{}' in group '{}' requires an \
                         IP literal",
                        srv,
                        group_name
                    );
                    return None;
                };
                let addr = SocketAddr::new(ip, nameserver.port_or(DNS_PORT));
                match DnsUdpTransport::new(srv, addr, group_name).await {
                    Ok(transport) => {
                        log::debug!(
                            "Upstream '{}' in group '{}' uses plain UDP",
                            srv,
                            group_name
                        );
                        Some(CreatedUpstream::Udp(Arc::new(transport)))
                    }
                    Err(e) => {
                        log::warn!(
                            "Forced DNS over UDP upstream '{}' in group '{}' \
                             is unavailable: {e}",
                            srv,
                            group_name
                        );
                        None
                    }
                }
            }
            NameserverScheme::Auto => {
                // `Auto` is only produced for an IP literal: a bare
                // hostname stays unsupported and a hostname endpoint is
                // always `tls://`.
                let Some(ip) = nameserver.address.ip() else {
                    log::warn!(
                        "Bare nameserver '{}' in group '{}' must be an IP \
                         literal",
                        srv,
                        group_name
                    );
                    return None;
                };
                match Self::create_dot_transport(
                    srv,
                    &nameserver,
                    doh_cache,
                    group_name,
                )
                .await
                {
                    Ok(transport) => {
                        log::info!(
                            "Upstream '{}' in group '{}' uses DNS over TLS",
                            srv,
                            group_name
                        );
                        return Some(CreatedUpstream::Dot(Arc::new(transport)));
                    }
                    Err(e) => log::debug!(
                        "DoT not available for '{}' in group '{}': {e}; \
                         trying DNS over TCP",
                        srv,
                        group_name
                    ),
                }

                let tcp_addr =
                    SocketAddr::new(ip, nameserver.port_or(DNS_PORT));
                match DnsTcpTransport::new_tcp(srv, tcp_addr, group_name).await
                {
                    Ok(transport) => {
                        log::info!(
                            "Upstream '{}' in group '{}' uses DNS over TCP",
                            srv,
                            group_name
                        );
                        return Some(CreatedUpstream::Tcp(Arc::new(transport)));
                    }
                    Err(e) => log::debug!(
                        "DNS over TCP not available for '{}' in group '{}': \
                         {e}; using plain UDP",
                        srv,
                        group_name
                    ),
                }

                let udp_addr =
                    SocketAddr::new(ip, nameserver.port_or(DNS_PORT));
                match DnsUdpTransport::new(srv, udp_addr, group_name).await {
                    Ok(transport) => {
                        Some(CreatedUpstream::Udp(Arc::new(transport)))
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to create UDP transport for '{}' in group \
                             '{}': {e}",
                            srv,
                            group_name
                        );
                        None
                    }
                }
            }
        }
    }

    /// Create a DoT transport for `endpoint`.
    ///
    /// An IP endpoint verifies the certificate against the IP literal. A
    /// hostname endpoint (`tls://hostname`) connects to the addresses pinned
    /// during bootstrap and verifies the certificate against the hostname
    /// (sent as SNI); the pinned addresses are raced, so one blackholed
    /// address cannot consume the whole transport-creation budget.
    async fn create_dot_transport(
        srv: &str,
        endpoint: &NameserverEndpoint,
        doh_cache: &Option<Arc<DohResolvCache>>,
        group_name: &str,
    ) -> Result<DnsDotTransport, MudzError> {
        let port = endpoint.port_or(DOT_PORT);
        let NameserverAddress::Hostname(hostname) = &endpoint.address else {
            let ip = endpoint
                .address
                .ip()
                .expect("IP endpoint has an IP address");
            let addr = SocketAddr::new(ip, port);
            return DnsDotTransport::new_dot(
                srv,
                addr,
                &ip.to_string(),
                group_name,
            )
            .await;
        };

        let cache = doh_cache.as_ref().ok_or_else(|| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "DoT hostname '{hostname}' requires a [doh] section with \
                     plain IP nameservers for resolution"
                ),
            )
        })?;
        let ips = cache.lookup(hostname).ok_or_else(|| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "DoT hostname '{hostname}' was not resolved at startup"
                ),
            )
        })?;

        if ips.is_empty() {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!("DoT hostname '{hostname}' has no resolved addresses"),
            ));
        }
        let attempts = ips.iter().map(|ip| {
            let addr = SocketAddr::new(*ip, port);
            Box::pin(async move {
                match DnsDotTransport::new_dot(srv, addr, hostname, group_name)
                    .await
                {
                    Ok(transport) => Ok(transport),
                    Err(e) => {
                        log::debug!(
                            "DoT to {addr} for hostname '{hostname}' failed: \
                             {e}"
                        );
                        Err(e)
                    }
                }
            })
        });
        select_ok(attempts)
            .await
            .map(|(transport, _losers)| transport)
    }

    /// Ensure this group has working transports. Transports are created
    /// lazily on the first request; if creation failed (e.g. the p2p
    /// interface was not up), retry — but only if at least
    /// [`DNS_RETRY_COOLDOWN`] has passed since the last attempt.
    ///
    /// UDP transports and the framed-stream transports (plain TCP and DoT)
    /// are all tracked by `is_broken`; the DoH `clients` are always live as
    /// far as this fast path is concerned (their pool is rebuilt on demand
    /// and the per-request timeout catches any stale connection).
    async fn ensure_transports(&self) -> bool {
        if self.blocking {
            return false;
        }

        // Fast path: every transport is live and at least one exists.
        {
            let state = self.state.read().await;
            if !Self::state_has_broken(&state) && Self::state_has_live(&state) {
                return true;
            }
        }

        let mut state = self.state.write().await;
        // Another request may have repaired the state while this task waited
        // for the write lock.
        if !Self::state_has_broken(&state) && Self::state_has_live(&state) {
            return true;
        }

        // Transports whose receive loop died (fatal socket/TLS error or a
        // silent panic) or that failed a probe can never dispatch again and
        // must be replaced. They are collected here but evicted only after
        // the recreation below succeeded: this method is cancelled by the
        // caller's timeout, and removing them before the await would forget
        // them for good whenever another transport keeps the group alive.
        let broken_udp: Vec<Arc<DnsUdpTransport>> = state
            .udp_transports
            .iter()
            .filter(|t| t.is_broken())
            .cloned()
            .collect();
        let broken_dot: Vec<Arc<DnsDotTransport>> = state
            .dot_transports
            .iter()
            .filter(|t| t.is_broken())
            .cloned()
            .collect();
        let broken_tcp: Vec<Arc<DnsTcpTransport>> = state
            .tcp_transports
            .iter()
            .filter(|t| t.is_broken())
            .cloned()
            .collect();

        if !broken_udp.is_empty()
            || !broken_dot.is_empty()
            || !broken_tcp.is_empty()
        {
            if !self.recreate_gate.try_acquire() {
                log::debug!(
                    "Group '{}' transport retry cooldown ({}s remaining)",
                    self.name,
                    self.recreate_gate.remaining_secs()
                );
                // Broken transports stay in the state so a later request
                // retries them after the cooldown; requests skip them and
                // use whatever is still live meanwhile.
                return Self::state_has_live(&state);
            }

            // Recreate only the broken members, leaving healthy transports
            // (and their streams/pools) untouched. Without this, a group
            // that still has one live upstream would drop the broken UDP,
            // TCP or DoT member forever instead of reconnecting it.
            let nameservers: Vec<String> = broken_udp
                .iter()
                .map(|t| t.state.name().to_string())
                .chain(broken_dot.iter().map(|t| t.state.name().to_string()))
                .chain(broken_tcp.iter().map(|t| t.state.name().to_string()))
                .collect();
            log::warn!(
                "Group '{}': recreating {} broken upstream transport(s)",
                self.name,
                nameservers.len()
            );
            let rebuilt = Self::create_state(
                &nameservers,
                &self.doh_cache,
                &self.name,
                false,
                self.doh_options,
            )
            .await;
            // Evict exactly the transports collected above. A peer that
            // broke while the recreation was in flight is left in the state
            // for the next pass instead of being dropped without a
            // replacement.
            state
                .udp_transports
                .retain(|t| !broken_udp.iter().any(|b| Arc::ptr_eq(b, t)));
            state
                .dot_transports
                .retain(|t| !broken_dot.iter().any(|b| Arc::ptr_eq(b, t)));
            state
                .tcp_transports
                .retain(|t| !broken_tcp.iter().any(|b| Arc::ptr_eq(b, t)));
            state.udp_transports.extend(rebuilt.udp_transports);
            state.dot_transports.extend(rebuilt.dot_transports);
            state.tcp_transports.extend(rebuilt.tcp_transports);
            state.doh_clients.extend(rebuilt.doh_clients);

            let ok = Self::state_has_live(&state);
            if !ok {
                log::debug!(
                    "Group '{}' transport recreation failed, will retry later",
                    self.name
                );
            }
            return ok;
        }

        if Self::state_has_live(&state) {
            return true;
        }

        // No transport exists at all: try the complete nameserver list after
        // the cooldown window.
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
            &self.doh_cache,
            &self.name,
            false,
            self.doh_options,
        )
        .await;
        let ok = Self::state_has_live(&state);
        if !ok {
            log::debug!(
                "Group '{}' transport recreation failed, will retry later",
                self.name
            );
        }
        ok
    }

    /// Whether the group has at least one transport that can still answer.
    /// Broken transports are excluded: they are only kept until the
    /// recreation gate allows replacing them.
    fn state_has_live(state: &GroupState) -> bool {
        state.udp_transports.iter().any(|t| !t.is_broken())
            || state.tcp_transports.iter().any(|t| !t.is_broken())
            || state.dot_transports.iter().any(|t| !t.is_broken())
            || !state.doh_clients.is_empty()
    }

    /// Whether any attached transport must be replaced.
    fn state_has_broken(state: &GroupState) -> bool {
        state.udp_transports.iter().any(|t| t.is_broken())
            || state.tcp_transports.iter().any(|t| t.is_broken())
            || state.dot_transports.iter().any(|t| t.is_broken())
    }

    /// Drop pooled DoH connections and clear upstream failure state after
    /// the system resumed from suspend.
    async fn handle_resume(&self) {
        let state = self.state.read().await;
        for upstream in &state.doh_clients {
            upstream.client.invalidate_pool().await;
            upstream.state.reset();
        }
        // Plain TCP and DoT are persistent streams like the DoH pool: after
        // suspend the connection is likely half-open. Mark them broken so
        // the next `ensure_transports` evicts the transport and
        // `create_upstream` reconnects (or falls back according to the
        // configured scheme). Plain UDP is connectionless and needs no reset
        // here.
        for tcp in &state.tcp_transports {
            tcp.state.mark_broken();
        }
        for dot in &state.dot_transports {
            dot.state.mark_broken();
        }
    }

    /// Clear upstream failure state and drop every pooled transport after
    /// the embedder reported a network change - for example a new default
    /// gateway or a new address on the interface carrying the upstream
    /// traffic.
    ///
    /// Unlike [`Self::handle_resume`], the connected UDP sockets are
    /// marked broken too: the kernel picks and caches the source address
    /// of a connected UDP socket when the route is first resolved, so a
    /// moved gateway or a renumbered interface leaves it sending from a
    /// stale source address. Marking the transports broken makes
    /// `ensure_transports` rebuild them on the next request, and the
    /// recreation gate is cleared so that happens immediately instead of
    /// after the retry cooldown.
    async fn handle_network_change(&self) {
        let state = self.state.read().await;
        for upstream in &state.doh_clients {
            upstream.client.invalidate_pool().await;
            upstream.state.reset();
        }
        for transport in &state.udp_transports {
            transport.state.mark_broken();
            transport.state.reset();
        }
        for transport in &state.tcp_transports {
            transport.state.mark_broken();
            transport.state.reset();
        }
        for transport in &state.dot_transports {
            transport.state.mark_broken();
            transport.state.reset();
        }
        self.recreate_gate.reset();
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
        let mut futures: FuturesUnordered<UpstreamQueryFuture> =
            FuturesUnordered::new();
        let mut skipped_dead = 0usize;

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
                (Some(Upstream::Udp(transport)), result, is_probe)
            };
            futures.push(Box::pin(udp_future));
        }

        // Send to every live framed-stream transport (plain TCP and DoT),
        // mirroring the UDP branches above: same wire-ID rewriting, same
        // response matching, same liveness and cooldown policy. The only
        // difference is the length framing handled inside the transport.
        let stream_transports = state
            .tcp_transports
            .iter()
            .map(|t| StreamTransport::Tcp(Arc::clone(t)))
            .chain(
                state
                    .dot_transports
                    .iter()
                    .map(|t| StreamTransport::Dot(Arc::clone(t))),
            );
        for transport in stream_transports {
            if transport.is_broken() {
                skipped_dead += 1;
                continue;
            }
            let attempt = transport.state().may_attempt();
            match attempt {
                Attempt::Ready | Attempt::Probing => {}
                Attempt::Dead | Attempt::Broken => {
                    skipped_dead += 1;
                    continue;
                }
            }
            let protocol = match &transport {
                StreamTransport::Tcp(_) => "TCP",
                StreamTransport::Dot(_) => "DoT",
            };
            let rx = match transport.send_query(&query_bytes, &key).await {
                Ok(rx) => rx,
                Err(e) => {
                    log::debug!(
                        "Error sending DNS query over {} to group '{}': {e}",
                        protocol,
                        self.name
                    );
                    if matches!(attempt, Attempt::Probing) {
                        // A failed probe on a stream means the write failed,
                        // i.e. the stream is gone: force a fresh
                        // connection on the next recreation.
                        transport.state().mark_broken();
                    } else {
                        transport.state().record_failure();
                    }
                    continue;
                }
            };
            let client_id = key.3;
            let upstream = transport.into_upstream();
            let is_probe = matches!(attempt, Attempt::Probing);
            let stream_future = async move {
                let result =
                    match tokio::time::timeout(DNS_TIMEOUT_SEC, rx).await {
                        Ok(Ok(mut packet)) => {
                            packet.header.id = client_id;
                            Ok(packet)
                        }
                        Ok(Err(_)) => Err(MudzError::new(
                            ErrorKind::Timeout,
                            format!("{protocol} response channel closed"),
                        )),
                        Err(_) => Err(MudzError::new(
                            ErrorKind::Timeout,
                            format!("{protocol} DNS query timed out"),
                        )),
                    };
                (Some(upstream), result, is_probe)
            };
            futures.push(Box::pin(stream_future));
        }

        // Send to all live DoH clients. Dead upstreams are skipped; the
        // cooldown policy lets one probe through per window.
        for doh in &state.doh_clients {
            if doh.state.is_broken() {
                skipped_dead += 1;
                continue;
            }
            let attempt = doh.state.may_attempt();
            match attempt {
                Attempt::Ready | Attempt::Probing => {}
                Attempt::Dead | Attempt::Broken => {
                    skipped_dead += 1;
                    continue;
                }
            }
            let is_probe = matches!(attempt, Attempt::Probing);
            let upstream = Arc::clone(doh);
            let doh_request = request.clone();
            let doh_future = async move {
                let result = upstream.client.request(&doh_request).await;
                (Some(Upstream::Doh(upstream)), result, is_probe)
            };
            futures.push(Box::pin(doh_future));
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

        while let Some((upstream, result, is_probe)) = futures.next().await {
            match result {
                Ok(response) => {
                    record_upstream_success(upstream);
                    if !futures.is_empty() {
                        // Keep accounting for the upstreams that did not win
                        // this request: their replies may still arrive (or
                        // time out), and their health state must not go stale
                        // just because another upstream answered first.
                        tokio::spawn(async move {
                            while let Some((upstream, result, is_probe)) =
                                futures.next().await
                            {
                                match result {
                                    Ok(_) => {
                                        record_upstream_success(upstream);
                                    }
                                    Err(e) => {
                                        record_upstream_failure(
                                            upstream, &e, is_probe,
                                        )
                                        .await;
                                    }
                                }
                            }
                        });
                    }
                    return Ok(response);
                }
                Err(e) => {
                    record_upstream_failure(upstream, &e, is_probe).await;
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

async fn create_udp_socket(addr: SocketAddr) -> Result<UdpSocket, MudzError> {
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

fn create_doh_client(
    srv: &str,
    doh_cache: &Option<Arc<DohResolvCache>>,
    options: DohOptions,
) -> Result<DohClient, MudzError> {
    let cache = doh_cache.clone().ok_or_else(|| {
        MudzError::new(
            ErrorKind::InvalidConfig,
            format!(
                "DoH server '{}' configured but no startup bootstrap from \
                 [doh] nameservers available",
                srv
            ),
        )
    })?;
    DohClient::new(srv, cache, options)
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
impl DnsGroup {
    /// Test helper: report the number of live UDP / TCP / DoT / DoH
    /// transports.
    async fn transport_counts(&self) -> (usize, usize, usize, usize) {
        let s = self.state.read().await;
        (
            s.udp_transports.len(),
            s.tcp_transports.len(),
            s.dot_transports.len(),
            s.doh_clients.len(),
        )
    }
}

#[cfg(test)]
#[path = "unit_tests/group.rs"]
mod tests;

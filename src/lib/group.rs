// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{StreamExt, future::Either, stream::FuturesUnordered};
use tokio::{net::UdpSocket, sync::oneshot};

use super::{
    config::MudzConfig,
    doh::{DohClient, DohOptions, DohResolvCache, is_transport_error},
    retry::{Attempt, CooldownGate, DNS_RETRY_COOLDOWN, UpstreamState},
};
use crate::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
    DnsType, ErrorKind, MudzError,
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

fn record_upstream_success(upstream: Option<Upstream>) {
    match upstream {
        Some(Upstream::Udp(transport)) => transport.state.record_success(),
        Some(Upstream::Doh(upstream)) => upstream.state.record_success(),
        None => {}
    }
}

async fn record_upstream_failure(
    upstream: Option<Upstream>,
    error: &MudzError,
    is_probe: bool,
) {
    match upstream {
        Some(Upstream::Udp(transport)) => {
            if is_probe {
                // The probe failed: the upstream has been unresponsive for a
                // whole cooldown window. Evict and recreate the transport so
                // a fresh socket (no latched errors, clean ARP/route state)
                // is used instead of probing forever.
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
    doh_clients: Vec<Arc<DohUpstream>>,
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
    Doh(Arc<DohUpstream>),
}

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
    async fn create_state(
        nameservers: &[String],
        doh_cache: &Option<Arc<DohResolvCache>>,
        group_name: &str,
        blocking: bool,
        doh_options: DohOptions,
    ) -> GroupState {
        let mut udp_transports = Vec::new();
        let mut doh_clients = Vec::new();

        for srv in nameservers {
            if srv.starts_with("https://") {
                match create_doh_client(srv, doh_cache, doh_options) {
                    Ok(client) => doh_clients.push(Arc::new(DohUpstream::new(
                        client, srv, group_name,
                    ))),
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
            &self.doh_cache,
            &self.name,
            false,
            self.doh_options,
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

    /// Drop pooled DoH connections and clear upstream failure state after
    /// the system resumed from suspend.
    async fn handle_resume(&self) {
        let state = self.state.read().await;
        for upstream in &state.doh_clients {
            upstream.client.invalidate_pool().await;
            upstream.state.reset();
        }
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
            futures.push(Either::Left(udp_future));
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
#[path = "unit_tests/group.rs"]
mod tests;

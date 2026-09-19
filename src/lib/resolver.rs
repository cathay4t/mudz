// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, hash_map::Entry},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver};

use super::{
    cache::{CACHE_GC_INTERVAL, DnsCacheStore},
    config::MudzConfig,
    doh::DohResolvCache,
    group::DnsGroups,
    host::HostsFile,
    server::{DnsQueryPacket, DnsReplyTarget},
    suspend::ResumeDetector,
};
use crate::{
    DnsClass, DnsDomainName, DnsHeader, DnsNameCompressionMap, DnsPacket,
    DnsResponseCode, DnsType, MudzError,
};

/// Pending client: (reply target, transaction ID, RD flag, EDNS payload
/// size). The payload size is `None` for non-EDNS clients, which are
/// limited to 512 bytes per RFC 1035 §4.2.1 over UDP; TCP replies are not
/// size-limited (RFC 7766 §7).
type PendingClient = (DnsReplyTarget, u16, bool, Option<u16>);
/// (domain, query-type, query-class, DNSSEC-OK bit). The DO bit is part of
/// the key so DO=0 and DO=1 resolutions stay separate (see `CacheKey`).
type CliIndexKey = (String, DnsType, DnsClass, bool);
/// Result of one upstream lookup: query key plus the upstream reply.
type ResolvedQuery = (
    String,
    DnsType,
    DnsClass,
    bool,
    Result<DnsPacket, MudzError>,
);

/// UDP payload size advertised in synthesized OPT acks (RFC 6891 §6.2.4).
/// Matches the listener's receive buffer so we never promise more than we can
/// deliver over UDP.
const EDNS_RESPONDER_PAYLOAD_SIZE: u16 =
    DnsPacket::MAX_UDP_EDNS_PACKET_SIZE as u16;
/// Non-EDNS UDP response size limit (RFC 1035 §4.2.1).
const NON_EDNS_UDP_LIMIT: usize = 512;
/// Serialized size of the OPT ack appended by `build_client_reply`
/// (1 byte root name + 2 type + 2 class + 4 TTL + 2 RDLENGTH).
const OPT_ACK_LEN: usize = 11;
/// How often to check for a suspend/resume cycle.
const RESUME_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct DnsResolver;

impl DnsResolver {
    pub(crate) async fn run(
        mut receiver: UnboundedReceiver<DnsQueryPacket>,
        config: MudzConfig,
        socket: Arc<UdpSocket>,
        hosts: Arc<HostsFile>,
        doh_cache: Option<Arc<DohResolvCache>>,
    ) {
        let mut cache = DnsCacheStore::new(config.main.max_cache_size);
        if !cache.is_enabled() {
            log::info!(
                "Response caching is disabled (max_cache_size = 0), queries \
                 are still forwarded"
            );
        }
        let mut cli_index: HashMap<CliIndexKey, Vec<PendingClient>> =
            HashMap::new();
        let groups = Arc::new(DnsGroups::new(config, doh_cache));

        let mut cache_gc = tokio::time::interval(CACHE_GC_INTERVAL);
        // The first tick of a tokio interval completes immediately; skip it
        // so GC only runs after a full interval.
        cache_gc.tick().await;

        let mut resume_check = tokio::time::interval(RESUME_CHECK_INTERVAL);
        resume_check.tick().await;
        let mut resume_detector = ResumeDetector::new();

        let mut futures = FuturesUnordered::new();
        loop {
            if !futures.is_empty() && log::log_enabled!(log::Level::Debug) {
                log::debug!("Pending DNS reply count {}", futures.len());
            }
            if futures.is_empty() && !cli_index.is_empty() {
                reply_servfail_all(&socket, &mut cli_index).await;
            }

            tokio::select! {
                result = receiver.recv() => {
                    let Some(query_packet) = result else { break };
                    if let Some((packet, key)) = handle_client_query(
                        query_packet,
                        &socket,
                        &hosts,
                        &mut cache,
                        &mut cli_index,
                    )
                    .await
                    {
                        let groups = Arc::clone(&groups);
                        futures.push(async move {
                            let (domain, dns_type, dns_class, dnssec_ok) =
                                key;
                            let result = groups.request(packet).await;
                            (domain, dns_type, dns_class, dnssec_ok, result)
                        });
                    }
                }
                Some(resolved) = futures.next() => {
                    handle_upstream_result(
                        resolved, &socket, &mut cache, &mut cli_index,
                    )
                    .await;
                }
                _ = cache_gc.tick() => {
                    cache.gc();
                }
                _ = resume_check.tick() => {
                    if let Some(suspended) = resume_detector.poll() {
                        log::info!(
                            "Detected resume from suspend after {}s; \
                             resetting DoH connections",
                            suspended.as_secs()
                        );
                        groups.handle_resume().await;
                    }
                }
                else => {
                    break;
                }
            }
        }
    }
}

/// Reply SERVFAIL to every client still waiting once no upstream lookup can
/// answer them anymore.
async fn reply_servfail_all(
    socket: &Arc<UdpSocket>,
    cli_index: &mut HashMap<CliIndexKey, Vec<PendingClient>>,
) {
    let count: usize = cli_index.values().map(|v| v.len()).sum();
    log::debug!(
        "All pending DNS queries failed to resolve, replying SERVFAIL to \
         remaining {count} clients",
    );
    for ((domain, dns_type, dns_class, dnssec_ok), cli_addrs) in
        cli_index.drain()
    {
        reply_servfail(
            socket, cli_addrs, &domain, dns_type, dns_class, dnssec_ok,
        )
        .await;
    }
}

/// Reply SERVFAIL to the clients waiting on one failed query.
async fn reply_servfail(
    socket: &Arc<UdpSocket>,
    cli_addrs: Vec<PendingClient>,
    domain: &str,
    dns_type: DnsType,
    dns_class: DnsClass,
    dnssec_ok: bool,
) {
    let Ok(domain_obj) = DnsDomainName::from_str(domain) else {
        log::warn!(
            "Failed to parse domain name {}: invalid format, skipping reply",
            domain
        );
        return;
    };
    let packet = DnsPacket::new_reply(
        0,
        DnsResponseCode::ServFail,
        domain_obj,
        dns_type,
        dns_class,
        true,
    );
    let neutral = packet.to_bytes();
    for (reply, id, rd, edns_payload) in cli_addrs {
        reply_client(socket, reply, &neutral, id, rd, edns_payload, dnssec_ok)
            .await;
    }
}

/// Serve one client query from `/etc/hosts` or the cache. When the query is
/// not cached, the client joins `cli_index`; the packet and key are returned
/// only for the first client of a key so the caller can start the upstream
/// lookup.
async fn handle_client_query(
    query_packet: DnsQueryPacket,
    socket: &Arc<UdpSocket>,
    hosts: &HostsFile,
    cache: &mut DnsCacheStore,
    cli_index: &mut HashMap<CliIndexKey, Vec<PendingClient>>,
) -> Option<(DnsPacket, CliIndexKey)> {
    let DnsQueryPacket { packet, reply } = query_packet;

    if let Some(reply_packet) = hosts.get(&packet) {
        let neutral = reply_packet.to_bytes();
        reply_client(
            socket,
            reply,
            &neutral,
            packet.header.id,
            packet.header.rd,
            packet.edns_udp_payload_size(),
            packet.dnssec_ok(),
        )
        .await;
        return None;
    }

    let question = packet.first_question()?;
    let domain = question.domain.to_string();
    let dns_type = question.kind;
    let dns_class = question.class;
    let id = packet.header.id;
    let rd = packet.header.rd;
    let edns_payload = packet.edns_udp_payload_size();
    let dnssec_ok = packet.dnssec_ok();
    let key = (domain, dns_type, dns_class, dnssec_ok);

    if let Some(cached) = cache.get(&key) {
        // The cache stores parsed packets; the caller owns the wire-format
        // conversion.
        let neutral = cached.to_bytes_without_opt(None);
        reply_client(socket, reply, &neutral, id, rd, edns_payload, dnssec_ok)
            .await;
        return None;
    }

    log::debug!("Received DNS query from {}", packet.display_brief());
    match cli_index.entry(key.clone()) {
        Entry::Occupied(pending) => {
            log::debug!(
                "Already has pending request for {}",
                packet.display_brief()
            );
            pending.into_mut().push((reply, id, rd, edns_payload));
            None
        }
        Entry::Vacant(vacant) => {
            vacant.insert(vec![(reply, id, rd, edns_payload)]);
            Some((packet, key))
        }
    }
}

/// Validate one finished upstream lookup, then cache and dispatch the reply
/// or answer SERVFAIL to every waiting client.
async fn handle_upstream_result(
    resolved: ResolvedQuery,
    socket: &Arc<UdpSocket>,
    cache: &mut DnsCacheStore,
    cli_index: &mut HashMap<CliIndexKey, Vec<PendingClient>>,
) {
    let (domain, dns_type, dns_class, dnssec_ok, result) = resolved;
    let key = (domain.clone(), dns_type, dns_class, dnssec_ok);

    let reply_packet = match result {
        Ok(packet) => {
            if validate_upstream_response(&packet, &domain, dns_type, dns_class)
            {
                log::debug!(
                    "Got DNS reply from upstream for {}",
                    packet.display_brief()
                );
                Some(packet)
            } else {
                log::warn!(
                    "Upstream response question mismatch for {}/{}/{:?}",
                    domain,
                    dns_type,
                    dns_class,
                );
                None
            }
        }
        Err(e) => {
            log::debug!(
                "Upstream DNS query for {}/{} failed: {e}",
                domain,
                dns_type,
            );
            None
        }
    };

    let Some(reply_packet) = reply_packet else {
        if let Some(cli_addrs) = cli_index.remove(&key) {
            reply_servfail(
                socket, cli_addrs, &domain, dns_type, dns_class, dnssec_ok,
            )
            .await;
        }
        return;
    };

    let neutral = reply_packet.to_bytes_without_opt(None);
    // Cache the validated upstream reply before replying, so a follow-up
    // query for this key is a cache hit.
    cache.add(key.clone(), reply_packet);
    let Some(cli_addrs) = cli_index.remove(&key) else {
        return;
    };
    for (reply, id, rd, edns_payload) in cli_addrs {
        reply_client(socket, reply, &neutral, id, rd, edns_payload, dnssec_ok)
            .await;
    }
}

/// Build and deliver a reply to one pending client: rewrite the transaction
/// ID and RD bit, truncate to the transport's limits (UDP only), append the
/// OPT ack when the client queried with EDNS, and send it over the client's
/// chosen transport.
async fn reply_client(
    socket: &Arc<UdpSocket>,
    reply: DnsReplyTarget,
    neutral: &[u8],
    id: u16,
    rd: bool,
    edns_payload: Option<u16>,
    dnssec_ok: bool,
) {
    let tcp = reply.is_tcp();
    let buf = build_client_reply(neutral, id, rd, edns_payload, dnssec_ok, tcp);
    reply.send(socket, buf).await;
}

/// Set or clear the RD (Recursion Desired) bit in a serialized DNS
/// packet header. RD is bit 8 of the 16-bit flags field (byte 2,
/// bit 0). RFC 1035 §4.1.1: the response copies the query's RD.
fn set_rd_bit(buf: &mut [u8], rd: bool) {
    if buf.len() > 2 {
        if rd {
            buf[2] |= 0x01;
        } else {
            buf[2] &= !0x01;
        }
    }
}

/// Turn neutral response bytes (no OPT record, as stored in the cache or
/// synthesized for SERVFAIL) into the final reply for a single client:
/// rewrite the transaction ID and RD bit, truncate to the client's
/// advertised UDP payload size (setting TC as required by RFC 6891 §6.2.5),
/// and append an EDNS(0) OPT ack when the client queried with EDNS. RFC 6891
/// §6.1.1 requires a response to an EDNS query to carry an OPT record; a
/// non-EDNS client gets none (§6.1.1). When `tcp` is set the reply is never
/// truncated: RFC 7766 §7 removes the size limit for TCP transport.
fn build_client_reply(
    neutral: &[u8],
    id: u16,
    rd: bool,
    edns_payload: Option<u16>,
    dnssec_ok: bool,
    tcp: bool,
) -> Vec<u8> {
    let mut buf = neutral.to_vec();
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
    set_rd_bit(&mut buf, rd);
    // Over TCP there is no message size limit (RFC 7766 §7): never
    // truncate and never set TC. Over UDP, truncate to the client's
    // advertised payload size, 512 bytes for non-EDNS clients (RFC 1035
    // §4.2.1).
    if !tcp {
        let opt_len = if edns_payload.is_some() {
            OPT_ACK_LEN
        } else {
            0
        };
        let limit = edns_payload.map_or(NON_EDNS_UDP_LIMIT, usize::from);
        truncate_response(&mut buf, limit, opt_len);
    }
    if edns_payload.is_some() {
        DnsPacket::append_opt_ack(
            &mut buf,
            EDNS_RESPONDER_PAYLOAD_SIZE,
            dnssec_ok,
        );
    }
    buf
}

/// Truncate a serialized DNS message to fit within `limit` bytes once
/// `opt_len` bytes of a trailing OPT record are accounted for, setting the
/// TC bit as required by RFC 6891 §6.2.5. RFC 1035 §4.2.1: the server
/// SHOULD include as many RRs as possible in a truncated response. Records
/// are included in section order (answer, authority, additional); once a
/// section does not fit, all subsequent sections are dropped and TC is set.
/// OPT records in the additional section are skipped (the caller appends a
/// per-client OPT ack separately). If the message cannot be parsed or the
/// question would not fit even on its own, a header-only reply (QDCOUNT 0)
/// is emitted rather than a corrupt message. Returns whether truncation was
/// needed.
fn truncate_response(buf: &mut Vec<u8>, limit: usize, opt_len: usize) -> bool {
    if buf.len() < DnsHeader::LEN || buf.len() + opt_len <= limit {
        return false;
    }
    let Ok(packet) = DnsPacket::parse(buf) else {
        let mut new_buf = buf[..DnsHeader::LEN].to_vec();
        new_buf[2] |= 0x02;
        new_buf[4..12].fill(0);
        *buf = new_buf;
        return true;
    };

    let mut new_buf = packet.header.to_bytes();
    let mut cmap = DnsNameCompressionMap::new();
    let mut truncated = false;

    // Question section: emit directly into new_buf so compression offsets
    // are relative to the final message. Always kept if it fits.
    let before_questions = new_buf.len();
    for question in &packet.questions {
        question.emit_to_compressed(&mut new_buf, &mut cmap);
    }
    let qdcount = if new_buf.len() + opt_len <= limit {
        packet.questions.len() as u16
    } else {
        new_buf.truncate(before_questions);
        cmap = DnsNameCompressionMap::new();
        0u16
    };

    // Answer section: include as many RRs as fit (RFC 1035 §4.2.1).
    let mut ancount = 0u16;
    for answer in &packet.answers {
        let before = new_buf.len();
        answer.emit_to_with_ttl_compressed(&mut new_buf, &mut None, &mut cmap);
        if new_buf.len() + opt_len > limit {
            new_buf.truncate(before);
            truncated = true;
            break;
        }
        ancount += 1;
    }
    if ancount < packet.answers.len() as u16 {
        truncated = true;
    }

    // Authority section: include only if all answers fit.
    let mut nscount = 0u16;
    if !truncated {
        for authority in &packet.authorities {
            let before = new_buf.len();
            authority.emit_to_with_ttl_compressed(
                &mut new_buf,
                &mut None,
                &mut cmap,
            );
            if new_buf.len() + opt_len > limit {
                new_buf.truncate(before);
                truncated = true;
                break;
            }
            nscount += 1;
        }
        if nscount < packet.authorities.len() as u16 {
            truncated = true;
        }
    }

    // Additional section (non-OPT): include only if all above fit.
    let mut arcount = 0u16;
    if !truncated {
        for additional in &packet.additionals {
            if u16::from(additional.kind) == 41 {
                continue;
            }
            let before = new_buf.len();
            additional.emit_to_with_ttl_compressed(
                &mut new_buf,
                &mut None,
                &mut cmap,
            );
            if new_buf.len() + opt_len > limit {
                new_buf.truncate(before);
                truncated = true;
                break;
            }
            arcount += 1;
        }
    }

    if truncated {
        new_buf[2] |= 0x02;
    }
    new_buf[4..6].copy_from_slice(&qdcount.to_be_bytes());
    new_buf[6..8].copy_from_slice(&ancount.to_be_bytes());
    new_buf[8..10].copy_from_slice(&nscount.to_be_bytes());
    new_buf[10..12].copy_from_slice(&arcount.to_be_bytes());

    *buf = new_buf;
    true
}

/// Validate an upstream response against the query we sent: the question
/// must match (domain/type/class, case-insensitively), and the server must
/// not have signalled an extended RCODE (RFC 6891 §6.1.3) — BADVERS,
/// BADCOOKIE, etc. — which the header's low 4 RCODE bits would otherwise
/// mask as NoError.
fn validate_upstream_response(
    packet: &DnsPacket,
    domain: &str,
    dns_type: DnsType,
    dns_class: DnsClass,
) -> bool {
    packet.extended_rcode() == 0
        && packet.first_question().is_some_and(|q| {
            q.domain.to_string() == domain
                && q.kind == dns_type
                && q.class == dns_class
        })
}

#[cfg(test)]
#[path = "unit_tests/resolver.rs"]
mod tests;

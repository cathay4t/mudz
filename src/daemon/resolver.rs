// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use mudz::{
    DnsClass, DnsDomainName, DnsHeader, DnsNameCompressionMap, DnsPacket,
    DnsResponseCode, DnsType,
};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver};

use super::{
    cache::DnsCacheStore, config::MudzConfig, group::DnsGroups,
    host::HostsFile, server::DnsQueryPacket,
};

/// Pending client: (address, transaction ID, RD flag, EDNS payload size).
/// The payload size is `None` for non-EDNS clients, which are limited to
/// 512 bytes per RFC 1035 §4.2.1.
type PendingClient = (SocketAddr, u16, bool, Option<u16>);
/// (domain, query-type, query-class, DNSSEC-OK bit). The DO bit is part of
/// the key so DO=0 and DO=1 resolutions stay separate (see `CacheKey`).
type CliIndexKey = (String, DnsType, DnsClass, bool);

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

pub(crate) struct DnsResolver;

impl DnsResolver {
    pub(crate) async fn run(
        mut receiver: UnboundedReceiver<DnsQueryPacket>,
        config: MudzConfig,
        socket: Arc<UdpSocket>,
    ) {
        let hosts = Arc::new(HostsFile::new());
        let mut cache = DnsCacheStore::new(config.main.max_cache_size);
        let mut cli_index: HashMap<CliIndexKey, Vec<PendingClient>> =
            HashMap::new();

        let doh_config = config.doh.clone();
        let groups =
            match DnsGroups::new(config, doh_config, hosts.clone()).await {
                Ok(groups) => Arc::new(groups),
                Err(e) => {
                    log::error!("Failed to initialize DNS groups: {e}");
                    return;
                }
            };

        let mut futures = FuturesUnordered::new();
        loop {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!("Pending DNS reply count {}", futures.len());
            }
            if futures.is_empty() && !cli_index.is_empty() {
                let count: usize = cli_index.values().map(|v| v.len()).sum();
                log::debug!(
                    "All pending DNS queries failed to resolve, replying \
                     SERVFAIL to remaining {count} clients",
                );
                for ((domain, kind, class, dnssec_ok), cli_addrs) in
                    cli_index.drain()
                {
                    let Ok(domain_obj) = DnsDomainName::from_str(&domain)
                    else {
                        log::warn!(
                            "Failed to parse domain name {}: invalid format, \
                             skipping reply",
                            domain
                        );
                        continue;
                    };
                    let packet = DnsPacket::new_reply(
                        0,
                        DnsResponseCode::ServFail,
                        domain_obj,
                        kind,
                        class,
                        true,
                    );
                    let neutral = packet.to_bytes();
                    for (cli_addr, id, rd, edns_payload) in cli_addrs {
                        let buf = build_client_reply(
                            &neutral,
                            id,
                            rd,
                            edns_payload,
                            dnssec_ok,
                        );
                        send_bytes(&socket, &buf, cli_addr).await;
                    }
                }
            }
            tokio::select! {
                result = receiver.recv() => {
                    if let Some(query_packet) = result {
                        let packet = query_packet.packet;
                        let cli_addr = query_packet.cli_addr;
                        if let Some(reply_packet) = hosts.get(&packet) {
                            let neutral = reply_packet.to_bytes();
                            let buf = build_client_reply(
                                &neutral,
                                packet.header.id,
                                packet.header.rd,
                                packet.edns_udp_payload_size(),
                                packet.dnssec_ok(),
                            );
                            send_bytes(&socket, &buf, cli_addr).await;
                            continue;
                        }

                        let question = packet.first_question();
                        let Some(question) = question else { continue };
                        let domain = question.domain.to_string();
                        let dns_type = question.kind;
                        let dns_class = question.class;
                        let id = packet.header.id;
                        let rd = packet.header.rd;
                        let edns_payload = packet.edns_udp_payload_size();
                        let dnssec_ok = packet.dnssec_ok();

                        if let Some(neutral) = cache.get(&packet) {
                            let buf = build_client_reply(
                                &neutral, id, rd, edns_payload, dnssec_ok,
                            );
                            send_bytes(&socket, &buf, cli_addr).await;
                            continue;
                        }

                        if log::log_enabled!(log::Level::Debug) {
                            log::debug!(
                                "Received DNS query from {}",
                                packet.display_brief()
                            );
                        }
                        let domain_key = domain.clone();
                        match cli_index.entry((
                            domain_key,
                            dns_type,
                            dns_class,
                            dnssec_ok,
                        )) {
                            Entry::Occupied(pending) => {
                                if log::log_enabled!(log::Level::Debug) {
                                    log::debug!(
                                        "Already has pending request for {}",
                                        packet.display_brief()
                                    );
                                }
                                pending
                                    .into_mut()
                                    .push((cli_addr, id, rd, edns_payload));
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(vec![(
                                    cli_addr, id, rd, edns_payload,
                                )]);
                                let groups = Arc::clone(&groups);
                                futures.push(async move {
                                    match groups.request(packet).await {
                                        Ok(reply) => (domain,
                                                      dns_type,
                                                      dns_class,
                                                      dnssec_ok,
                                                      Ok(reply)),
                                        Err(e) => (domain,
                                                   dns_type,
                                                   dns_class,
                                                   dnssec_ok,
                                                   Err(e)),
                                    }
                                });
                            }
                        }
                    } else {
                        break;
                    }
                }
                Some((domain, dns_type, dns_class, dnssec_ok, result)) =
                    futures.next() =>
                {
                    let reply_packet = match result {
                        Ok(packet) => {
                            if validate_upstream_response(
                                &packet, &domain, dns_type, dns_class,
                            ) {
                                if log::log_enabled!(log::Level::Debug) {
                                    log::debug!(
                                        "Got DNS reply from upstream for {}",
                                        packet.display_brief()
                                    );
                                }
                                Some(packet)
                            } else {
                                log::warn!(
                                    "Upstream response question mismatch \
                                     for {}/{}/{:?}",
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
                        let Ok(domain_obj) =
                            DnsDomainName::from_str(&domain)
                        else {
                            log::warn!(
                                "Failed to parse domain name {}: \
                                 invalid format",
                                domain,
                            );
                            let _ = cli_index.remove(&(
                                domain, dns_type, dns_class, dnssec_ok,
                            ));
                            continue;
                        };
                        let Some(cli_addrs) = cli_index.remove(&(
                            domain, dns_type, dns_class, dnssec_ok,
                        )) else {
                            continue;
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
                        for (cli_addr, id, rd, edns_payload) in cli_addrs {
                            let buf = build_client_reply(
                                &neutral, id, rd, edns_payload, dnssec_ok,
                            );
                            send_bytes(&socket, &buf, cli_addr).await;
                        }
                        continue;
                    };

                    let neutral = match cache.insert(&reply_packet, dnssec_ok)
                    {
                        Some(bytes) => bytes,
                        None => {
                            log::debug!(
                                "Cache insert failed for {}, \
                                 forwarding without caching",
                                reply_packet.display_brief(),
                            );
                            reply_packet.to_bytes_without_opt(None)
                        }
                    };
                    let Some(cli_addrs) = cli_index.remove(&(
                        domain, dns_type, dns_class, dnssec_ok,
                    )) else {
                        continue;
                    };
                    for (cli_addr, id, rd, edns_payload) in cli_addrs {
                        let buf = build_client_reply(
                            &neutral, id, rd, edns_payload, dnssec_ok,
                        );
                        send_bytes(&socket, &buf, cli_addr).await;
                    }
                }
                else => {
                    break;
                }
            }
        }
    }
}

async fn send_bytes(socket: &Arc<UdpSocket>, buf: &[u8], cli_addr: SocketAddr) {
    if let Err(e) = socket.send_to(buf, cli_addr).await {
        log::warn!("Failed to send DNS reply to {}: {e}", cli_addr);
    }
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
/// non-EDNS client gets none (§6.1.1).
fn build_client_reply(
    neutral: &[u8],
    id: u16,
    rd: bool,
    edns_payload: Option<u16>,
    dnssec_ok: bool,
) -> Vec<u8> {
    let mut buf = neutral.to_vec();
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
    set_rd_bit(&mut buf, rd);
    let opt_len = if edns_payload.is_some() {
        OPT_ACK_LEN
    } else {
        0
    };
    let limit = edns_payload.map_or(NON_EDNS_UDP_LIMIT, usize::from);
    truncate_response(&mut buf, limit, opt_len);
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
mod tests {
    use std::str::FromStr;

    use mudz::{
        DnsClass, DnsDomainName, DnsHeader, DnsPacket, DnsQuestion,
        DnsResourceRecord, DnsResponseCode, DnsType,
    };

    use super::{build_client_reply, validate_upstream_response};

    /// A NOERROR response to `example.com A` carrying an OPT record whose
    /// TTL encodes the given extended RCODE in its high byte.
    fn response_with_ext_rcode(ext_rcode: u8) -> DnsPacket {
        let domain = DnsDomainName::from_str("example.com").unwrap();
        let opt_ttl: u32 = (ext_rcode as u32) << 24;
        DnsPacket {
            header: DnsHeader {
                id: 0x1234,
                qr: true,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                arcount: 1,
                ..Default::default()
            },
            questions: vec![DnsQuestion {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
            }],
            answers: vec![DnsResourceRecord {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 4,
                rdata: vec![1, 2, 3, 4],
            }],
            authorities: Vec::new(),
            additionals: vec![DnsResourceRecord {
                domain: DnsDomainName::default(),
                kind: DnsType::Other(41),
                class: DnsClass::Other(1232),
                ttl: opt_ttl,
                rdlength: 0,
                rdata: Vec::new(),
            }],
        }
    }

    #[test]
    fn test_validate_accepts_matching_response() {
        let packet = response_with_ext_rcode(0);
        assert!(validate_upstream_response(
            &packet,
            "example.com",
            DnsType::A,
            DnsClass::IN,
        ));
    }

    #[test]
    fn test_validate_rejects_extended_rcode() {
        // BADVERS = 16 (ext-rcode 1): the header says NoError, but the
        // response is an error and must not be treated as a valid answer.
        let packet = response_with_ext_rcode(1);
        assert_eq!(packet.extended_rcode(), 1);
        assert!(!validate_upstream_response(
            &packet,
            "example.com",
            DnsType::A,
            DnsClass::IN,
        ));
    }

    #[test]
    fn test_validate_rejects_question_mismatch() {
        let packet = response_with_ext_rcode(0);
        assert!(!validate_upstream_response(
            &packet,
            "other.com",
            DnsType::A,
            DnsClass::IN,
        ));
        assert!(!validate_upstream_response(
            &packet,
            "example.com",
            DnsType::AAAA,
            DnsClass::IN,
        ));
    }

    /// A NOERROR response to `example.com A` with 100 answers, serialized to
    /// well over 512 bytes.
    fn large_response() -> Vec<u8> {
        let domain = DnsDomainName::from_str("example.com").unwrap();
        let packet = DnsPacket {
            header: DnsHeader {
                id: 0x1234,
                qr: true,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                ancount: 100,
                ..Default::default()
            },
            questions: vec![DnsQuestion {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
            }],
            answers: (0..100u8)
                .map(|i| DnsResourceRecord {
                    domain: domain.clone(),
                    kind: DnsType::A,
                    class: DnsClass::IN,
                    ttl: 300,
                    rdlength: 4,
                    rdata: vec![10, 0, 0, i],
                })
                .collect(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let bytes = packet.to_bytes();
        assert!(bytes.len() > 512, "test response must exceed 512 bytes");
        bytes
    }

    #[test]
    fn test_build_client_reply_truncates_large_response_for_non_edns() {
        let reply =
            build_client_reply(&large_response(), 0x1111, true, None, false);
        assert!(
            reply.len() <= 512,
            "non-EDNS reply must fit in 512 bytes, got {}",
            reply.len()
        );
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc, "TC bit must be set on truncation");
        assert_eq!(parsed.header.id, 0x1111);
        assert_eq!(parsed.questions[0].domain.to_string(), "example.com");
        // RFC 1035 §4.2.1: as many RRs as possible must be kept.
        assert!(
            !parsed.answers.is_empty(),
            "truncated reply must keep as many answers as fit"
        );
        assert!(
            parsed.answers.len() < 100,
            "not all 100 answers can fit in 512 bytes"
        );
        assert!(!parsed.has_edns());
    }

    #[test]
    fn test_build_client_reply_truncates_to_edns_payload() {
        let reply = build_client_reply(
            &large_response(),
            0x2222,
            false,
            Some(512),
            false,
        );
        assert!(
            reply.len() <= 512,
            "reply must fit within the advertised payload, got {}",
            reply.len()
        );
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc, "TC bit must be set on truncation");
        assert_eq!(parsed.header.id, 0x2222);
        assert_eq!(parsed.questions[0].domain.to_string(), "example.com");
        assert!(
            !parsed.answers.is_empty(),
            "truncated reply must keep as many answers as fit"
        );
        assert!(parsed.answers.len() < 100);
        // An EDNS client still gets its OPT ack.
        assert!(parsed.has_edns());
    }

    #[test]
    fn test_build_client_reply_tiny_advertised_payload() {
        // A client advertising an absurdly small payload (below the 512
        // octet EDNS minimum) must still receive a reply that fits, even if
        // that means dropping the question section entirely.
        let reply = build_client_reply(
            &large_response(),
            0x4444,
            false,
            Some(40),
            false,
        );
        assert!(
            reply.len() <= 40,
            "reply must fit within the tiny advertised payload, got {}",
            reply.len()
        );
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc, "TC bit must be set on truncation");
        assert_eq!(parsed.header.id, 0x4444);
    }

    #[test]
    fn test_build_client_reply_malformed_neutral() {
        // Garbage neutral bytes: must not panic and must yield a parseable
        // header-only reply with TC set instead of a corrupt message.
        let garbage = vec![0xAA; 600];
        let reply = build_client_reply(&garbage, 0x5555, true, None, false);
        assert!(reply.len() <= 512);
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc);
        assert_eq!(parsed.header.id, 0x5555);
        assert!(parsed.questions.is_empty());
    }

    #[test]
    fn test_build_client_reply_keeps_small_response() {
        let domain = DnsDomainName::from_str("example.com").unwrap();
        let packet = DnsPacket {
            header: DnsHeader {
                id: 0x3333,
                qr: true,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                ancount: 1,
                ..Default::default()
            },
            questions: vec![DnsQuestion {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
            }],
            answers: vec![DnsResourceRecord {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 4,
                rdata: vec![1, 2, 3, 4],
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let neutral = packet.to_bytes();

        // Small response for a non-EDNS client: no truncation, no OPT ack.
        let reply = build_client_reply(&neutral, 0x3333, true, None, false);
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(!parsed.header.tc);
        assert_eq!(parsed.answers.len(), 1);
        assert!(!parsed.has_edns());

        // Small response for an EDNS client with DO=1: intact, with OPT ack
        // echoing the DO bit.
        let reply =
            build_client_reply(&neutral, 0x3333, true, Some(4096), true);
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(!parsed.header.tc);
        assert_eq!(parsed.answers.len(), 1);
        assert!(parsed.has_edns());
        assert!(parsed.dnssec_ok());
    }

    #[test]
    fn test_truncation_keeps_maximum_answers() {
        // With RFC 1035 §4.1.4 compression, each A record for "example.com"
        // serializes to 16 bytes (2-byte pointer to the question name +
        // 2 type + 2 class + 4 TTL + 2 rdlength + 4 rdata).
        // Header(12) + question(17) = 29 bytes overhead.
        // Non-EDNS limit 512: (512 - 29) / 16 = 30 answers fit.
        let reply =
            build_client_reply(&large_response(), 0x6666, true, None, false);
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc);
        assert_eq!(parsed.answers.len(), 30);
        assert!(reply.len() <= 512);
        // Adding one more answer would exceed 512: 29 + 31 * 16 = 525.
    }

    /// A CNAME chain response similar to `finance.sina.com.cn`: 3 CNAMEs
    /// plus multiple A records, exceeding 512 bytes when serialized without
    /// compression.
    fn cname_chain_response() -> Vec<u8> {
        let domain = DnsDomainName::from_str("finance.sina.com.cn").unwrap();
        let cname1 =
            DnsDomainName::from_str("financesina.gslb.sinaedge.com").unwrap();
        let cname2 =
            DnsDomainName::from_str("acksmall.grid.sinaedge.com").unwrap();
        let cname3 =
            DnsDomainName::from_str("ww1.sinaimg.cn.w.alikunlun.com").unwrap();
        let mut answers = vec![
            DnsResourceRecord {
                domain: domain.clone(),
                kind: DnsType::CNAME,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 0,
                rdata: {
                    let mut b = Vec::new();
                    cname1.emit_to(&mut b);
                    b
                },
            },
            DnsResourceRecord {
                domain: cname1.clone(),
                kind: DnsType::CNAME,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 0,
                rdata: {
                    let mut b = Vec::new();
                    cname2.emit_to(&mut b);
                    b
                },
            },
            DnsResourceRecord {
                domain: cname2.clone(),
                kind: DnsType::CNAME,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 0,
                rdata: {
                    let mut b = Vec::new();
                    cname3.emit_to(&mut b);
                    b
                },
            },
        ];
        for i in 0..20u8 {
            answers.push(DnsResourceRecord {
                domain: cname3.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 37,
                rdlength: 4,
                rdata: vec![121, 17, 122, 56 + i],
            });
        }
        let packet = DnsPacket {
            header: DnsHeader {
                id: 0x7777,
                qr: true,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                ancount: answers.len() as u16,
                ..Default::default()
            },
            questions: vec![DnsQuestion {
                domain,
                kind: DnsType::A,
                class: DnsClass::IN,
            }],
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let bytes = packet.to_bytes();
        assert!(bytes.len() > 512, "CNAME chain must exceed 512 bytes");
        bytes
    }

    #[test]
    fn test_truncation_keeps_cname_chain_and_some_answers() {
        // A non-EDNS client querying a CNAME chain with many A records
        // (like `host finance.sina.com.cn`) must receive as many records
        // as fit within 512 bytes, not an empty truncated reply.
        let reply = build_client_reply(
            &cname_chain_response(),
            0x7777,
            true,
            None,
            false,
        );
        assert!(reply.len() <= 512);
        let parsed = DnsPacket::parse(&reply).unwrap();
        assert!(parsed.header.tc);
        assert_eq!(parsed.header.id, 0x7777);
        // The 3 CNAME records plus a few A records must fit; at minimum the
        // CNAME chain is preserved.
        assert!(
            parsed.answers.len() >= 3,
            "CNAME chain must survive truncation, got {} answers",
            parsed.answers.len()
        );
        assert!(
            parsed.answers.len() < 23,
            "not all 23 records can fit in 512 bytes"
        );
        // First three answers must be the CNAME chain in order.
        assert_eq!(parsed.answers[0].kind, DnsType::CNAME);
        assert_eq!(parsed.answers[1].kind, DnsType::CNAME);
        assert_eq!(parsed.answers[2].kind, DnsType::CNAME);
    }
}

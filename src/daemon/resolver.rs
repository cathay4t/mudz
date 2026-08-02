// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use mudz::{DnsClass, DnsDomainName, DnsPacket, DnsResponseCode, DnsType};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver};

use super::{
    cache::DnsCacheStore, config::MudzConfig, group::DnsGroups,
    host::HostsFile, server::DnsQueryPacket,
};

/// Pending client: (address, transaction ID, RD flag, query carried EDNS).
type PendingClient = (SocketAddr, u16, bool, bool);
/// (domain, query-type, query-class, DNSSEC-OK bit). The DO bit is part of
/// the key so DO=0 and DO=1 resolutions stay separate (see `CacheKey`).
type CliIndexKey = (String, DnsType, DnsClass, bool);

/// UDP payload size advertised in synthesized OPT acks (RFC 6891 §6.2.4).
/// Matches the listener's receive buffer so we never promise more than we can
/// deliver over UDP.
const EDNS_RESPONDER_PAYLOAD_SIZE: u16 =
    DnsPacket::MAX_UDP_EDNS_PACKET_SIZE as u16;

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
                    for (cli_addr, id, rd, has_edns) in cli_addrs {
                        let buf = build_client_reply(
                            &neutral, id, rd, has_edns, dnssec_ok,
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
                                packet.has_edns(),
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
                        let has_edns = packet.has_edns();
                        let dnssec_ok = packet.dnssec_ok();

                        if let Some(neutral) = cache.get(&packet) {
                            let buf = build_client_reply(
                                &neutral, id, rd, has_edns, dnssec_ok,
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
                                    .push((cli_addr, id, rd, has_edns));
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(vec![(
                                    cli_addr, id, rd, has_edns,
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
                        for (cli_addr, id, rd, has_edns) in cli_addrs {
                            let buf = build_client_reply(
                                &neutral, id, rd, has_edns, dnssec_ok,
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
                    for (cli_addr, id, rd, has_edns) in cli_addrs {
                        let buf = build_client_reply(
                            &neutral, id, rd, has_edns, dnssec_ok,
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
/// rewrite the transaction ID and RD bit, and append an EDNS(0) OPT ack when
/// the client queried with EDNS. RFC 6891 §6.1.1 requires a response to an
/// EDNS query to carry an OPT record; a non-EDNS client gets none (§6.1.1).
fn build_client_reply(
    neutral: &[u8],
    id: u16,
    rd: bool,
    has_edns: bool,
    dnssec_ok: bool,
) -> Vec<u8> {
    let mut buf = neutral.to_vec();
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
    set_rd_bit(&mut buf, rd);
    if has_edns {
        DnsPacket::append_opt_ack(
            &mut buf,
            EDNS_RESPONDER_PAYLOAD_SIZE,
            dnssec_ok,
        );
    }
    buf
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

    use super::validate_upstream_response;

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
}

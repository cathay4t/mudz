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

/// Pending client: (address, transaction ID, RD flag).
type PendingClient = (SocketAddr, u16, bool);
type CliIndexKey = (String, DnsType, DnsClass);

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
                for ((domain, kind, class), cli_addrs) in cli_index.drain() {
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
                    let reply_bytes = packet.to_bytes();
                    for (cli_addr, id, rd) in cli_addrs {
                        let mut buf = reply_bytes.clone();
                        buf[0..2].copy_from_slice(&id.to_be_bytes());
                        set_rd_bit(&mut buf, rd);
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
                            let reply_bytes = reply_packet.to_bytes();
                            send_bytes(
                                &socket, &reply_bytes, cli_addr,
                            ).await;
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

                        if !has_edns
                            && let Some(reply_bytes) = cache.get(&packet)
                        {
                            send_bytes(
                                &socket, &reply_bytes, cli_addr,
                            ).await;
                            continue;
                        }

                        if log::log_enabled!(log::Level::Debug) {
                            log::debug!(
                                "Received DNS query from {}",
                                packet.display_brief()
                            );
                        }
                        let domain_key = domain.clone();
                        match cli_index
                            .entry((domain_key, dns_type, dns_class))
                        {
                            Entry::Occupied(pending) => {
                                if log::log_enabled!(log::Level::Debug) {
                                    log::debug!(
                                        "Already has pending request for {}",
                                        packet.display_brief()
                                    );
                                }
                                pending.into_mut().push((cli_addr, id, rd));
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(vec![(cli_addr, id, rd)]);
                                let groups = Arc::clone(&groups);
                                futures.push(async move {
                                    match groups.request(packet).await {
                                        Ok(reply) => (domain,
                                                      dns_type,
                                                      dns_class,
                                                      has_edns,
                                                      Ok(reply)),
                                        Err(e) => (domain,
                                                   dns_type,
                                                   dns_class,
                                                   has_edns,
                                                   Err(e)),
                                    }
                                });
                            }
                        }
                    } else {
                        break;
                    }
                }
                Some((domain, dns_type, dns_class, has_edns, result)) =
                    futures.next() =>
                {
                    let reply_packet = match result {
                        Ok(packet) => {
                            let question_ok =
                                packet.first_question().is_some_and(|q| {
                                    q.domain.to_string() == domain
                                        && q.kind == dns_type
                                        && q.class == dns_class
                                });
                            if question_ok {
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
                            let _ = cli_index
                                .remove(&(domain, dns_type, dns_class));
                            continue;
                        };
                        let Some(cli_addrs) = cli_index
                            .remove(&(domain, dns_type, dns_class))
                        else {
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
                        let reply_bytes = packet.to_bytes();
                        for (cli_addr, id, rd) in cli_addrs {
                            let mut buf = reply_bytes.clone();
                            buf[0..2].copy_from_slice(&id.to_be_bytes());
                            set_rd_bit(&mut buf, rd);
                            send_bytes(&socket, &buf, cli_addr).await;
                        }
                        continue;
                    };

                    let reply_bytes = if has_edns {
                        reply_packet.to_bytes()
                    } else {
                        match cache.insert(&reply_packet)
                        {
                            Some(bytes) => bytes,
                            None => {
                                log::debug!(
                                    "Cache insert failed for {}, \
                                     forwarding without caching",
                                    reply_packet.display_brief(),
                                );
                                reply_packet.to_bytes()
                            }
                        }
                    };
                    let Some(cli_addrs) = cli_index
                        .remove(&(domain, dns_type, dns_class))
                    else {
                        continue;
                    };
                    for (cli_addr, id, rd) in cli_addrs {
                        let mut buf = reply_bytes.clone();
                        buf[0..2].copy_from_slice(&id.to_be_bytes());
                        set_rd_bit(&mut buf, rd);
                        send_bytes(
                            &socket, &buf, cli_addr,
                        ).await;
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

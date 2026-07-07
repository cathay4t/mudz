// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use mudz::{DnsDomainName, DnsPacket, DnsResponseCode, DnsType};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver};

use super::{
    cache::DnsCacheStore,
    config::MudzConfig,
    group::DnsGroups,
    host::HostsFile,
    server::DnsQueryPacket,
};

pub(crate) struct DnsResolver;

impl DnsResolver {
    pub(crate) async fn run(
        mut receiver: UnboundedReceiver<DnsQueryPacket>,
        config: MudzConfig,
        socket: Arc<UdpSocket>,
    ) {
        let hosts = Arc::new(HostsFile::new());
        let mut cache = DnsCacheStore::new(config.main.max_cache_size);
        let mut cli_index: HashMap<(String, DnsType), Vec<(SocketAddr, u16)>> =
            HashMap::new();

        let doh_config = config.doh.clone();
        let groups = match DnsGroups::new(config, doh_config, hosts.clone())
            .await
        {
            Ok(groups) => groups,
            Err(e) => {
                log::error!("Failed to initialize DNS groups: {e}");
                return;
            }
        };

        let mut futures = FuturesUnordered::new();
        loop {
            log::debug!("Pending DNS reply count {}", futures.len());
            if futures.is_empty() && !cli_index.is_empty() {
                log::debug!(
                    "All pending DNS queries failed to resolve, replying \
                     SERVFAIL to remaining {} clients",
                    cli_index.values().map(|v| v.len()).sum::<usize>()
                );
                for ((domain, kind), cli_addrs) in cli_index.drain() {
                    let Ok(domain_obj) = DnsDomainName::from_str(&domain)
                    else {
                        log::warn!(
                            "Failed to parse domain name {}: invalid format, \
                             skipping reply",
                            domain
                        );
                        continue;
                    };
                    let mut packet = DnsPacket::new_reply(
                        0,
                        DnsResponseCode::ServFail,
                        domain_obj,
                        kind,
                    );
                    for (cli_addr, id) in cli_addrs {
                        packet.header.id = id;
                        reply(&socket, &packet, cli_addr).await;
                    }
                }
            }
            tokio::select! {
                result = receiver.recv() => {
                    if let Some(query_packet) = result {
                        let packet = query_packet.packet;
                        let cli_addr = query_packet.cli_addr;
                        if let Some(reply_packet) = hosts.get(&packet) {
                                reply(
                                    &socket,
                                    &reply_packet,
                                    cli_addr,
                                ).await;
                                continue;
                        } else if let Some(reply_packet) = cache.get(&packet) {
                            reply(
                                &socket,
                                &reply_packet,
                                cli_addr,
                            ).await;
                        } else {
                            let Some(domain) = packet
                                .first_question()
                                .map(|q|q.domain.to_string()) else {continue};
                            let Some(dns_type) = packet
                                .first_question()
                                .map(|q|q.kind) else {continue};
                            log::debug!(
                                "Received DNS query from {}",
                                packet.display_brief()
                            );
                            let id = packet.header.id;
                            match cli_index.entry((domain, dns_type)) {
                                Entry::Occupied(pending) => {
                                    log::debug!(
                                        "Already has pending request for {}",
                                        packet.display_brief()
                                    );
                                    pending.into_mut().push((cli_addr, id));
                                }
                                Entry::Vacant(vacant) => {
                                    vacant.insert(vec![(cli_addr, id)]);
                                    futures.push(groups.request(packet));
                                }
                            }
                        }
                    } else {
                        // DNS query channel closed, shutting down
                        break;
                    }
                }
                Some(result) = futures.next() => {
                    if let Ok(reply_packet) = result {
                        log::debug!(
                            "Got DNS reply from upstream for {}",
                            reply_packet.display_brief());
                        cache.insert(reply_packet.clone());
                        let Some(domain) = reply_packet
                            .first_question()
                            .map(|q|q.domain.to_string()) else {continue};
                        let Some(dns_type) = reply_packet
                            .first_question()
                            .map(|q|q.kind) else {continue};
                        let Some(cli_addrs) = cli_index
                            .remove(&(domain, dns_type)) else {continue};
                        for (cli_addr, id) in cli_addrs {
                            let mut packet = reply_packet.clone();
                            packet.header.id = id;
                            reply(
                                &socket,
                                &packet,
                                cli_addr,
                            ).await;
                        }
                    }
                }
                else => {
                    break;
                }
            }
        }
    }
}

async fn reply(
    socket: &Arc<UdpSocket>,
    packet: &DnsPacket,
    cli_addr: SocketAddr,
) {
    if let Err(e) = socket.send_to(&packet.to_bytes(), cli_addr).await {
        log::warn!("Failed to send DNS reply to {}: {e}", cli_addr);
    }
    log::debug!("Sent DNS {}", packet.display_brief());
}

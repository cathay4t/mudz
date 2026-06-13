// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use mudz::{
    DnsDomainName, DnsPacket, DnsResponseCode, DnsType, ErrorKind, MudzError,
};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver, time::timeout};

use super::{
    cache::DnsCacheStore,
    config::{MudzConfig, MudzDohConfig},
    doh::DohResolvCache,
    group::DnsGroups,
    host::HostsFile,
    server::DnsQueryPacket,
};

const TIMEOUT_DOH_RESOLVE_SEC: Duration = Duration::from_secs(2);
const MAX_RETRIES_DOH_RESOLVE: usize = 5;

pub(crate) struct DnsResolver;

impl DnsResolver {
    pub(crate) async fn run(
        mut receiver: UnboundedReceiver<DnsQueryPacket>,
        config: MudzConfig,
        socket: Arc<UdpSocket>,
    ) {
        let hosts = HostsFile::new();
        let mut cache = DnsCacheStore::new(config.main.max_cache_size);
        let config_clone = config.clone();
        let mut cli_index: HashMap<(String, DnsType), Vec<(SocketAddr, u16)>> =
            HashMap::new();

        // FIXME: This DohResolvCache is never updated after initialized.
        //        In most cases, DoH server never change its IP.
        //        Will fix later or never.
        let mut doh_resolv_cache = DohResolvCache::new();

        // DoH hostname should be resolved before processing any DNS
        // query, otherwise, it may cause a deadlock because reqwest
        // is using blocking way on resolve DNS.
        if let Err(e) = ensure_doh_hostnames_resolved(
            &config_clone,
            &hosts,
            &mut doh_resolv_cache,
        )
        .await
        {
            log::error!("Failed to resolve DoH hostnames: {e}");
            return;
        }

        doh_resolv_cache.log();

        let groups = match DnsGroups::new(config, doh_resolv_cache).await {
            Ok(groups) => groups,
            Err(e) => {
                log::error!("Failed to initialize DNS groups: {e}");
                return;
            }
        };

        let mut futures = FuturesUnordered::new();
        loop {
            log::debug!("Pending DNS reply count {}", futures.len());
            // When some resolve future fails, we should inform all pending
            // client on SERVFAIL.
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
                                    // Already has pending request, no need to
                                    // request again.
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

async fn ensure_doh_hostnames_resolved(
    config: &MudzConfig,
    hosts: &HostsFile,
    doh_cache: &mut DohResolvCache,
) -> Result<(), MudzError> {
    if let Some(doh_config) = config.doh.as_ref() {
        let doh_hostnames = config.get_doh_hostnames();
        if doh_hostnames.is_empty() {
            return Ok(());
        }

        let mut retry_count = 0;
        while retry_count < MAX_RETRIES_DOH_RESOLVE {
            match resolve_doh_hostnames(
                hosts,
                doh_config,
                &doh_hostnames,
                doh_cache,
            )
            .await
            {
                Ok(_) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "Failed to resolve DoH hostnames (attempt {}/{}): {e}",
                        retry_count + 1,
                        MAX_RETRIES_DOH_RESOLVE
                    );
                    retry_count += 1;
                }
            }
        }
        Err(MudzError::new(
            ErrorKind::InvalidConfig,
            "Failed to resolve DoH hostnames after multiple attempts"
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn resolve_doh_hostnames(
    hosts: &HostsFile,
    doh_config: &MudzDohConfig,
    doh_hostnames: &[String],
    doh_cache: &mut DohResolvCache,
) -> Result<(), MudzError> {
    for host_name in doh_hostnames {
        let host_ips = hosts.get_ips(host_name);

        if !host_ips.is_empty() {
            log::info!(
                "DoH hostname {} resolved to IPs from hosts file: {:?}",
                host_name,
                host_ips
            );
            doh_cache.insert(host_name, host_ips);
        } else {
            let mut ips = timeout(
                TIMEOUT_DOH_RESOLVE_SEC,
                resolve_hostname(
                    host_name,
                    doh_config.nameservers.as_slice(),
                    doh_config.disable_ipv6,
                ),
            )
            .await
            .map_err(|_| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!(
                        "Timeout while resolving DoH hostname {}",
                        host_name
                    ),
                )
            })??;
            log::info!("Resolved DoH hostname {} to IPs: {:?}", host_name, ips);
            ips.dedup();
            doh_cache.insert(host_name, ips);
        }
    }
    Ok(())
}

async fn resolve_hostname(
    host_name: &str,
    nameservers: &[IpAddr],
    disable_ipv6: bool,
) -> Result<Vec<IpAddr>, MudzError> {
    log::info!("Resolving DoH hostname {}", host_name);
    let mut ret = Vec::new();

    let query_packet = DnsPacket::new_query(host_name, DnsType::A)?;

    match send_request_and_wait_first_reply(
        host_name,
        nameservers,
        &query_packet,
    )
    .await
    {
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

    match send_request_and_wait_first_reply(
        host_name,
        nameservers,
        &query_packet,
    )
    .await
    {
        Ok(ips) => ret.extend_from_slice(&ips),
        Err(e) => {
            log::debug!(
                "Failed to resolve DoH hostname {} to AAAA record: {e}",
                host_name
            );
        }
    }

    // If we can't get both A and AAAA records, it's still considered as
    // resolved, because some DoH hostnames may not have AAAA records.
    if ret.is_empty() {
        Err(MudzError::new(
            ErrorKind::InvalidConfig,
            format!("Failed to resolve DoH hostname {}", host_name),
        ))
    } else {
        Ok(ret)
    }
}

async fn get_udp_dns_reply(socket: &UdpSocket) -> Result<DnsPacket, MudzError> {
    let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
    let len = socket.recv(&mut buf).await.map_err(|e| {
        MudzError::new(
            ErrorKind::Bug,
            format!("Failed to receive DNS reply from upstream: {e}"),
        )
    })?;
    let packet = DnsPacket::parse(&buf[..len]).map_err(|e| {
        MudzError::new(
            ErrorKind::InvalidPacket,
            format!("Failed to parse DNS reply from upstream: {e}"),
        )
    })?;
    Ok(packet)
}

async fn send_request_and_wait_first_reply(
    host_name: &str,
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

    for socket in &sockets {
        if let Err(e) = socket.send(&query_packet.to_bytes()).await {
            log::warn!(
                "Failed to send A record DNS query for DoH hostname {}: {e}",
                host_name
            );
            continue;
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
                log::warn!(
                    "Failed to get DNS reply for DoH hostname {}: {e}",
                    host_name
                );
                continue;
            }
        };
        log::debug!(
            "Received DNS reply for DoH hostname {}: {}",
            host_name,
            packet.display_brief()
        );

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

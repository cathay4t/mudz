// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap, net::SocketAddr, str::FromStr as _, sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, future::Either, stream::FuturesUnordered};
use mudz::{DnsPacket, DnsResponseCode, DnsType, ErrorKind, MudzError};
use tokio::net::UdpSocket;

use super::{
    config::MudzConfig,
    doh::{DohClient, DohResolvCache},
};

const DNS_TIMEOUT_SEC: Duration = Duration::from_secs(5);

pub(crate) struct DnsGroups {
    fallback: DnsGroup,
    // HashMap<group_name, DnsGroup>
    groups: HashMap<String, DnsGroup>,
    // HashMap<domain_suffix, group_name>
    search_index: HashMap<Vec<String>, String>,
}

impl DnsGroups {
    pub(crate) async fn new(
        mut config: MudzConfig,
        doh_cache: DohResolvCache,
    ) -> Result<Self, MudzError> {
        let doh_cache = Arc::new(doh_cache);
        let fallback = DnsGroup::new(
            "fallback".to_string(),
            config.fallback.nameservers,
            doh_cache.clone(),
            config.fallback.disable_ipv6,
        )
        .await?;

        let mut groups = HashMap::new();
        let mut search_index = HashMap::new();
        for (group_name, group_config) in config.groups.drain() {
            let dns_group = DnsGroup::new(
                group_name.to_string(),
                group_config.nameservers,
                doh_cache.clone(),
                group_config.disable_ipv6,
            )
            .await?;
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
                            "Group '{}' is blocking group, returning NXDOMAIN \
                             for domain '{}'",
                            group_name,
                            domain
                        );
                        let mut packet = request;
                        packet.header.set_response(true);
                        packet.header.rcode = DnsResponseCode::NxDomain;
                        return Ok(packet);
                    } else {
                        return group.request(request).await;
                    }
                }
            }
            // fallback
            self.fallback.request(request).await
        } else {
            Err(MudzError::new(
                ErrorKind::InvalidArgument,
                "DNS request does not contain a domain",
            ))
        }
    }
}

struct DnsGroup {
    name: String,
    sockets: Vec<UdpSocket>,
    doh_conns: Vec<DohClient>,
    disable_ipv6: bool,
}

impl DnsGroup {
    async fn new(
        name: String,
        srvs: Vec<String>,
        doh_cache: Arc<DohResolvCache>,
        disable_ipv6: bool,
    ) -> Result<Self, MudzError> {
        let mut sockets = Vec::new();
        let mut doh_conns = Vec::new();
        for srv in srvs {
            if srv.starts_with("https://") {
                doh_conns.push(DohClient::new(&srv, doh_cache.clone())?);
            } else {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let addr = if srv.contains(':') {
                    SocketAddr::from_str(&srv)
                } else {
                    SocketAddr::from_str(&format!("{srv}:53"))
                }
                .map_err(|e| {
                    MudzError::new(
                        ErrorKind::InvalidConfig,
                        format!("Invalid nameserver address '{srv}': {e}"),
                    )
                })?;
                socket.connect(addr).await?;
                sockets.push(socket);
            }
        }

        Ok(Self {
            name,
            sockets,
            doh_conns,
            disable_ipv6,
        })
    }

    fn is_blocking(&self) -> bool {
        self.sockets.is_empty() && self.doh_conns.is_empty()
    }

    async fn request(
        &self,
        request: DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        // Return NoError immediately if the request is for AAAA and IPv6 is
        // disabled for this
        if self.disable_ipv6
            && request.first_question().map(|q| q.kind) == Some(DnsType::AAAA)
        {
            log::debug!(
                "Received AAAA query but IPv6 is disabled for group '{}', \
                 returning NOERROR",
                self.name
            );
            let mut response = request;
            response.header.set_response(true);
            response.header.rcode = DnsResponseCode::NoError;
            return Ok(response);
        }

        log::debug!("Sending DNS request to group '{}'", self.name);
        for socket in &self.sockets {
            if let Err(e) = socket.send(&request.to_bytes()).await {
                log::debug!("Error sending DNS request to socket: {e}");
            }
        }

        let mut futures = FuturesUnordered::new();
        for socket in &self.sockets {
            futures.push(Either::Left(get_socket_reply(socket)));
        }

        for doh_conn in &self.doh_conns {
            futures.push(Either::Right(doh_conn.request(&request)));
        }

        // return on first valid response to come back
        while let Some(result) = futures.next().await {
            match result {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => {
                    log::debug!("Error processing DoH response: {e}");
                }
            }
        }
        Err(MudzError::new(
            ErrorKind::InvalidPacket,
            "All DNS requests failed or returned invalid responses",
        ))
    }
}

async fn get_socket_reply(socket: &UdpSocket) -> Result<DnsPacket, MudzError> {
    let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
    match tokio::time::timeout(DNS_TIMEOUT_SEC, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => {
            let packet = DnsPacket::parse(&buf[..len])?;
            Ok(packet)
        }
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("Error receiving DNS response from socket: {e}"),
        )),
        Err(_) => Err(MudzError::new(
            ErrorKind::Timeout,
            "Timed out waiting for DNS response from socket",
        )),
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use mudz::{DnsHeader, DnsPacket};
use tokio::{net::UdpSocket, sync::mpsc::UnboundedSender};

use super::server::DnsQueryPacket;

pub(crate) struct DnsUdpListener;

impl DnsUdpListener {
    pub(crate) async fn run(
        sender: UnboundedSender<DnsQueryPacket>,
        socket: Arc<UdpSocket>,
    ) {
        let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
        loop {
            if let Ok((size, cli_addr)) = socket.recv_from(&mut buf).await {
                handle_dns_query(&buf, size, cli_addr, &sender);
            }
        }
    }
}

fn handle_dns_query(
    buf: &[u8],
    size: usize,
    cli_addr: std::net::SocketAddr,
    sender: &UnboundedSender<DnsQueryPacket>,
) {
    if size < DnsHeader::LEN {
        log::warn!(
            "Received packet too small to be a valid DNS query from {}",
            cli_addr
        );
        return;
    }

    let packet = match DnsPacket::parse(&buf[..size]) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse DNS query from {}: {}", cli_addr, e);
            return;
        }
    };
    log::debug!(
        "Received DNS query from {} for {}",
        cli_addr,
        packet.display_brief()
    );

    // only allow DNS query.
    if !packet.is_query() {
        return;
    }

    let query = DnsQueryPacket { packet, cli_addr };

    if let Err(e) = sender.send(query) {
        log::error!("Failed to send DNS query to resolver: {}", e);
    }
}

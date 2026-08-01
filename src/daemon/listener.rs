// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use mudz::{DnsHeader, DnsPacket, DnsResponseCode};
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
            match socket.recv_from(&mut buf).await {
                Ok((size, cli_addr)) => {
                    handle_dns_query(&buf, size, cli_addr, &sender, &socket)
                        .await;
                }
                Err(e) => {
                    log::error!("Error receiving DNS query: {e}");
                    if is_listener_fatal_error(&e) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100))
                        .await;
                }
            }
        }
    }
}

async fn handle_dns_query(
    buf: &[u8],
    size: usize,
    cli_addr: std::net::SocketAddr,
    sender: &UnboundedSender<DnsQueryPacket>,
    socket: &Arc<UdpSocket>,
) {
    if size < DnsHeader::LEN {
        log::warn!(
            "Received packet too small to be a valid DNS query from {}",
            cli_addr
        );
        let id = if size >= 2 {
            u16::from_be_bytes([buf[0], buf[1]])
        } else {
            0
        };
        send_formerr(id, socket, cli_addr).await;
        return;
    }

    let packet = match DnsPacket::parse(&buf[..size]) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse DNS query from {}: {}", cli_addr, e,);
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            send_formerr(id, socket, cli_addr).await;
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

async fn send_formerr(
    id: u16,
    socket: &Arc<UdpSocket>,
    cli_addr: std::net::SocketAddr,
) {
    let packet = DnsPacket {
        header: DnsHeader {
            id,
            qr: true,
            ra: true,
            rcode: DnsResponseCode::FormErr,
            ..Default::default()
        },
        questions: vec![],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };
    let reply_bytes = packet.to_bytes();
    if let Err(e) = socket.send_to(&reply_bytes, cli_addr).await {
        log::warn!("Failed to send FormErr reply to {}: {}", cli_addr, e,);
    }
}

fn is_listener_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionRefused
    )
}

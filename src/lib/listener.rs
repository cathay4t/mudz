// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc::UnboundedSender, oneshot},
    task::JoinSet,
};

use super::server::{DnsQueryPacket, DnsReplyTarget};
use crate::{DnsHeader, DnsPacket, DnsResponseCode};

/// Idle timeout for reading the next query on a TCP connection. RFC 7766
/// §6.2.1 permits servers to close idle connections; this sheds dead peers
/// without timing out slow upstream resolutions (the reply wait is not
/// subject to this timeout).
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn handle_dns_query(
    buf: &[u8],
    size: usize,
    cli_addr: SocketAddr,
    sender: &UnboundedSender<DnsQueryPacket>,
    socket: &Arc<UdpSocket>,
) {
    match classify_query(&buf[..size], cli_addr) {
        Ok(Some(packet)) => {
            log::debug!(
                "Received DNS query from {} for {}",
                cli_addr,
                packet.display_brief()
            );
            let query = DnsQueryPacket {
                packet,
                reply: DnsReplyTarget::Udp(cli_addr),
            };
            if let Err(e) = sender.send(query) {
                log::error!("Failed to send DNS query to resolver: {}", e);
            }
        }
        Ok(None) => {}
        Err(formerr) => {
            let reply_bytes = formerr.to_bytes();
            if let Err(e) = socket.send_to(&reply_bytes, cli_addr).await {
                log::warn!(
                    "Failed to send FormErr reply to {}: {}",
                    cli_addr,
                    e,
                );
            }
        }
    }
}

/// TCP listener: accepts connections and serves each with its own task.
/// RFC 7766 §6.2.1.1: connections are reused across queries rather than
/// opened per query.
pub(crate) struct DnsTcpListener;

impl DnsTcpListener {
    pub(crate) async fn run(
        sender: UnboundedSender<DnsQueryPacket>,
        listener: Arc<TcpListener>,
    ) {
        // Connection tasks are tracked so that aborting this listener (which
        // happens on server shutdown) also aborts the connections it spawned.
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            log::debug!(
                                "Accepted TCP DNS connection from {peer}"
                            );
                            let sender = sender.clone();
                            connections.spawn(async move {
                                handle_tcp_connection(sender, stream).await;
                            });
                        }
                        Err(e) => {
                            log::error!(
                                "Error accepting TCP DNS connection: {e}"
                            );
                            if is_listener_fatal_error(&e) {
                                break;
                            }
                            tokio::time::sleep(
                                Duration::from_millis(100)
                            ).await;
                        }
                    }
                }
                Some(result) = connections.join_next(),
                    if !connections.is_empty() =>
                {
                    if let Err(e) = result {
                        log::warn!("DNS TCP connection task failed: {e}");
                    }
                }
            }
        }
    }
}

/// Serve one client connection. Queries on a connection are handled one at a
/// time (RFC 7766 §6.2.1.1): read a length-prefixed query (RFC 1035 §4.2.2),
/// hand it to the resolver, write the framed reply, then read the next
/// query. Waiting for the resolver's reply keeps responses in query order.
async fn handle_tcp_connection(
    sender: UnboundedSender<DnsQueryPacket>,
    mut stream: TcpStream,
) {
    let peer = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::warn!("Failed to read TCP peer address: {e}");
            return;
        }
    };
    loop {
        // Read the 2-byte length prefix (RFC 1035 §4.2.2).
        let mut len_buf = [0u8; 2];
        match read_tcp_exact(&mut stream, &mut len_buf).await {
            Ok(()) => {}
            Err(e) => {
                log::debug!("TCP client {peer} disconnected before query: {e}");
                return;
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            log::warn!(
                "TCP client {peer} sent a zero-length DNS frame, closing"
            );
            return;
        }
        let mut buf = vec![0u8; len];
        if read_tcp_exact(&mut stream, &mut buf).await.is_err() {
            log::debug!("TCP client {peer} closed mid-message, closing");
            return;
        }

        match classify_query(&buf, peer) {
            Ok(Some(packet)) => {
                log::debug!(
                    "Received TCP DNS query from {} for {}",
                    peer,
                    packet.display_brief()
                );
                let (reply_tx, reply_rx) = oneshot::channel();
                let query = DnsQueryPacket {
                    packet,
                    reply: DnsReplyTarget::Tcp {
                        reply: reply_tx,
                        peer,
                    },
                };
                if sender.send(query).is_err() {
                    log::debug!(
                        "Resolver shut down, closing TCP connection from \
                         {peer}"
                    );
                    return;
                }
                match reply_rx.await {
                    Ok(reply) => {
                        if let Err(e) =
                            write_tcp_reply(&mut stream, &reply).await
                        {
                            log::debug!(
                                "Failed to write TCP DNS reply to {peer}: {e}"
                            );
                            return;
                        }
                    }
                    Err(_) => {
                        log::debug!(
                            "Resolver dropped reply for {peer}, closing"
                        );
                        return;
                    }
                }
            }
            Ok(None) => {}
            Err(formerr) => {
                let reply_bytes = formerr.to_bytes();
                if let Err(e) = write_tcp_reply(&mut stream, &reply_bytes).await
                {
                    log::debug!(
                        "Failed to write TCP FormErr reply to {peer}: {e}"
                    );
                    return;
                }
            }
        }
    }
}

/// Read exactly `buf.len()` bytes over TCP, or fail. An idle connection
/// waiting for its next query times out after [`TCP_IDLE_TIMEOUT`] (RFC
/// 7766 §6.2.1); mid-message stalls are treated as client disconnects.
async fn read_tcp_exact(
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), std::io::Error> {
    let _ = tcp_io_with_timeout(stream.read_exact(buf)).await?;
    Ok(())
}

/// Write exactly `buf.len()` bytes over TCP, or fail. The timeout bounds how
/// long a stalled peer can pin a connection task (RFC 7766 §6.2.1).
async fn write_tcp_exact(
    stream: &mut TcpStream,
    buf: &[u8],
) -> Result<(), std::io::Error> {
    tcp_io_with_timeout(stream.write_all(buf)).await
}

async fn tcp_io_with_timeout<T>(
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T, std::io::Error> {
    match tokio::time::timeout(TCP_IDLE_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TCP I/O timed out",
        )),
    }
}

/// Write a DNS message prefixed with its RFC 1035 §4.2.2 2-byte length.
async fn write_tcp_reply(
    stream: &mut TcpStream,
    reply: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(reply.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "DNS reply too large for TCP framing: {} bytes",
                reply.len()
            ),
        )
    })?;
    write_tcp_exact(stream, &len.to_be_bytes()).await?;
    write_tcp_exact(stream, reply).await?;
    Ok(())
}

/// Validate a raw DNS query, shared by the UDP and TCP listeners. Returns:
/// - `Ok(Some(packet))`: a well-formed query to forward to the resolver.
/// - `Ok(None)`: not a query (e.g. a response); drop it silently.
/// - `Err(formerr)`: a FORMERR reply to send back to the client.
fn classify_query(
    buf: &[u8],
    peer: SocketAddr,
) -> Result<Option<DnsPacket>, DnsPacket> {
    if buf.len() < DnsHeader::LEN {
        log::warn!(
            "Received packet too small to be a valid DNS query from {}",
            peer
        );
        return Err(formerr_packet(query_id(buf)));
    }
    let packet = match DnsPacket::parse(buf) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse DNS query from {}: {}", peer, e,);
            return Err(formerr_packet(query_id(buf)));
        }
    };
    if !packet.is_query() {
        return Ok(None);
    }
    // RFC 1035 §4.1.1: a query must contain at least one question. A
    // qdcount=0 query cannot be answered, so reject it with FORMERR instead
    // of silently dropping it and letting the client time out.
    if packet.questions.is_empty() {
        log::warn!("Received DNS query without question section from {}", peer);
        return Err(formerr_packet(packet.header.id));
    }
    Ok(Some(packet))
}

/// Transaction ID of a raw message, or 0 if it is too short to hold one.
fn query_id(buf: &[u8]) -> u16 {
    if buf.len() >= 2 {
        u16::from_be_bytes([buf[0], buf[1]])
    } else {
        0
    }
}

fn formerr_packet(id: u16) -> DnsPacket {
    DnsPacket {
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
    }
}

fn is_listener_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionRefused
    )
}

#[cfg(test)]
#[path = "unit_tests/listener.rs"]
mod tests;

// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc, time::Duration};

use mudz::{DnsHeader, DnsPacket, DnsResponseCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc::UnboundedSender, oneshot},
};

use super::server::{DnsQueryPacket, DnsReplyTarget};

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
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    log::debug!("Accepted TCP DNS connection from {peer}");
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        handle_tcp_connection(sender, stream).await;
                    });
                }
                Err(e) => {
                    log::error!("Error accepting TCP DNS connection: {e}");
                    if is_listener_fatal_error(&e) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
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
                                "Failed to write TCP DNS reply to {peer}: \
                                 {e}"
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
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use mudz::{
        DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
        DnsType,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        sync::mpsc,
    };

    use super::{DnsTcpListener, DnsUdpListener, classify_query};
    use crate::server::{DnsQueryPacket, DnsReplyTarget};

    #[tokio::test]
    async fn test_query_without_question_gets_formerr() {
        let (tx, mut rx) = mpsc::unbounded_channel::<DnsQueryPacket>();
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0").await.expect("bind listener"),
        );
        let listen_socket = socket.clone();
        let handle = tokio::spawn(async move {
            DnsUdpListener::run(tx, listen_socket).await;
        });

        // A well-formed 12-byte header with qdcount = 0: not parseable into a
        // question, but a perfectly valid DNS packet otherwise.
        let query = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: QR=0, opcode=0, RD=1
            0x00, 0x00, // qdcount = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
        ];
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client
            .send_to(&query, socket.local_addr().unwrap())
            .await
            .expect("send query");

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("no FORMERR reply received")
        .expect("recv failed");
        let resp = DnsPacket::parse(&buf[..n]).expect("parse FORMERR reply");
        assert!(resp.header.qr);
        assert_eq!(resp.header.id, 0x1234);
        assert_eq!(resp.header.rcode, DnsResponseCode::FormErr);

        // The malformed query must not reach the resolver.
        assert!(rx.try_recv().is_err());
        handle.abort();
    }

    fn test_peer() -> SocketAddr {
        "127.0.0.1:12345".parse().expect("parse test peer")
    }

    #[test]
    fn test_classify_query_short_buffer_yields_formerr() {
        let formerr = classify_query(&[0x12, 0x34, 0x01], test_peer())
            .expect_err("short buffer must be rejected");
        assert_eq!(formerr.header.id, 0x1234);
        assert_eq!(formerr.header.rcode, DnsResponseCode::FormErr);
    }

    #[test]
    fn test_classify_query_ignores_responses() {
        let mut query =
            DnsPacket::new_query("example.com", DnsType::A).expect("query");
        query.header.qr = true; // a response, not a query
        let bytes = query.to_bytes();
        assert!(
            classify_query(&bytes, test_peer())
                .expect("classify")
                .is_none()
        );
    }

    #[test]
    fn test_classify_query_accepts_valid_query() {
        let query =
            DnsPacket::new_query("example.com", DnsType::A).expect("query");
        let packet = classify_query(&query.to_bytes(), test_peer())
            .expect("classify")
            .expect("valid query must be accepted");
        assert!(packet.is_query());
        assert_eq!(
            packet.first_question().unwrap().domain.to_string(),
            "example.com"
        );
    }

    /// A NOERROR reply to the given query carrying one A record.
    fn build_reply(query: &DnsPacket, address: [u8; 4]) -> DnsPacket {
        let domain = query.first_question().unwrap().domain.clone();
        DnsPacket {
            header: DnsHeader {
                id: query.header.id,
                qr: true,
                rcode: DnsResponseCode::NoError,
                qdcount: 1,
                ancount: 1,
                ..Default::default()
            },
            questions: query.questions.clone(),
            answers: vec![DnsResourceRecord {
                domain,
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 60,
                rdlength: 4,
                rdata: address.to_vec(),
            }],
            authorities: vec![],
            additionals: vec![],
        }
    }

    /// Drive the TCP listener as a fake resolver: read one query from the
    /// channel and answer it on its oneshot.
    async fn answer_one(rx: &mut mpsc::UnboundedReceiver<DnsQueryPacket>) {
        let query = rx.recv().await.expect("no query received");
        let reply = build_reply(&query.packet, [192, 0, 2, 1]).to_bytes();
        match query.reply {
            DnsReplyTarget::Tcp { reply: tx, .. } => {
                tx.send(reply).expect("connection closed early")
            }
            DnsReplyTarget::Udp(_) => panic!("expected a TCP reply target"),
        }
    }

    /// Send one length-prefixed frame on `stream`.
    async fn send_frame(stream: &mut TcpStream, bytes: &[u8]) {
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .expect("write frame length");
        stream.write_all(bytes).await.expect("write frame body");
    }

    /// Read one length-prefixed reply from `stream`.
    async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .expect("read reply length");
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut reply = vec![0u8; len];
        stream
            .read_exact(&mut reply)
            .await
            .expect("read reply body");
        reply
    }

    /// Send a query, have the fake resolver answer it, then read the reply.
    async fn query_roundtrip(
        stream: &mut TcpStream,
        rx: &mut mpsc::UnboundedReceiver<DnsQueryPacket>,
        query: &DnsPacket,
    ) -> DnsPacket {
        send_frame(stream, &query.to_bytes()).await;
        // Answer before reading: the connection task writes the reply only
        // after the resolver sends it on the oneshot.
        answer_one(rx).await;
        DnsPacket::parse(&read_frame(stream).await).expect("parse reply")
    }

    #[tokio::test]
    async fn test_tcp_framing_reuse_and_formerr() {
        let listener =
            Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind"));
        let addr = listener.local_addr().expect("listener address");
        let (tx, mut rx) = mpsc::unbounded_channel::<DnsQueryPacket>();
        let handle = tokio::spawn(async move {
            DnsTcpListener::run(tx, listener).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("tcp connect");

        // Query 1: answered by the fake resolver over the same connection.
        let query = DnsPacket::new_query("example.com", DnsType::A)
            .expect("build query");
        let reply = query_roundtrip(&mut stream, &mut rx, &query).await;
        assert_eq!(reply.header.id, query.header.id);
        assert_eq!(reply.answers.len(), 1);

        // Query 2: same connection is reused (RFC 7766 §6.2.1.1).
        let query = DnsPacket::new_query("example.org", DnsType::A)
            .expect("build query");
        let reply = query_roundtrip(&mut stream, &mut rx, &query).await;
        assert_eq!(reply.header.id, query.header.id);
        assert_eq!(reply.answers.len(), 1);

        // A too-short frame gets a framed FORMERR reply, connection stays up.
        send_frame(&mut stream, &[0x12, 0x34, 0x01, 0x00]).await;
        let formerr = DnsPacket::parse(&read_frame(&mut stream).await)
            .expect("parse formerr");
        assert_eq!(formerr.header.id, 0x1234);
        assert_eq!(formerr.header.rcode, DnsResponseCode::FormErr);

        // A zero-length frame is a protocol violation: the server closes the
        // connection (EOF).
        stream
            .write_all(&0u16.to_be_bytes())
            .await
            .expect("write zero-length frame");
        let mut buf = [0u8; 4];
        assert_eq!(
            stream.read(&mut buf).await.expect("read after close"),
            0,
            "server must close on a zero-length frame"
        );

        handle.abort();
    }
}

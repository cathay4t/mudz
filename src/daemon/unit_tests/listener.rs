// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc};

use mudz::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode, DnsType,
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
    let socket =
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind listener"));
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
    let query = DnsPacket::new_query("example.com", DnsType::A).expect("query");
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
    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    let reply = query_roundtrip(&mut stream, &mut rx, &query).await;
    assert_eq!(reply.header.id, query.header.id);
    assert_eq!(reply.answers.len(), 1);

    // Query 2: same connection is reused (RFC 7766 §6.2.1.1).
    let query =
        DnsPacket::new_query("example.org", DnsType::A).expect("build query");
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

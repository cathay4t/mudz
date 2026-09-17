// SPDX-License-Identifier: Apache-2.0

//! Tests for the framed stream transports (RFC 7766 TCP and RFC 7858 DoT).
//!
//! * The framing decode (`read_frame`) is hermetic: it is generic over any
//!   `AsyncRead`, verified against an in-memory `tokio::io::duplex` pair and
//!   edge cases (zero length, EOF mid-body).
//! * `test_dot_upstream_end_to_end` is a real network exercise against the
//!   public Alidns DoT endpoint (`223.5.5.5:853`); it is `#[ignore]`d so `cargo
//!   test` stays hermetic. Run with `cargo test -- --ignored` when network
//!   access to port 853 is available.

use super::*;
use crate::DnsResponseCode;

// --- framing decode -------------------------------------------------------

/// A round-trip: a correctly framed DNS message read back byte-for-byte.
#[tokio::test]
async fn test_read_frame_roundtrip() {
    let payload = DnsPacket::new_query("example.com", DnsType::A)
        .expect("query")
        .to_bytes();

    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);

    let (mut writer, mut reader) = tokio::io::duplex(1024);
    writer.write_all(&frame).await.expect("frame into duplex");

    let got = read_frame(&mut reader).await.expect("decode frame");
    assert_eq!(got, payload, "decoded frame must match the sent payload");
}

/// A zero byte length is not a valid RFC 7766/7858 frame and must be rejected.
#[tokio::test]
async fn test_read_frame_rejects_zero_length() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&[0u8, 0u8])
        .await
        .expect("zero length into duplex");
    let got = read_frame(&mut reader).await.expect_err("zero length");
    assert_eq!(
        got.kind(),
        std::io::ErrorKind::InvalidData,
        "zero-length frames must fail as InvalidData"
    );
}

/// A frame whose 2-byte length promise exceeds the bytes actually written
/// surfaces as a read failure (the caller tears the transport down).
#[tokio::test]
async fn test_read_frame_eof_in_body() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&[0u8, 16u8])
        .await
        .expect("length prefix into duplex");
    // Close the write end: the read half will get EOF after 0 body bytes.
    drop(writer);
    // read_exact expects 16 more bytes; only 0 will ever arrive, so it must
    // fail (not hang).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let got = tokio::time::timeout_at(deadline, read_frame(&mut reader))
        .await
        .expect("read_frame must not hang")
        .expect_err("mid-body EOF");
    assert!(matches!(
        got.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    ));
}

// --- plain DNS over TCP (hermetic) ----------------------------------------

/// A local RFC 7766 server: framed query in, framed reply out. Unlike the
/// DoT test this needs no certificate or network access, so the plain-TCP
/// transport is covered by the default test run.
#[tokio::test]
async fn test_tcp_upstream_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        loop {
            let mut prefix = [0u8; 2];
            if socket.read_exact(&mut prefix).await.is_err() {
                return;
            }
            let mut message = vec![0u8; u16::from_be_bytes(prefix) as usize];
            if socket.read_exact(&mut message).await.is_err() {
                return;
            }
            let Ok(query) = DnsPacket::parse(&message) else {
                return;
            };
            let question = &query.questions[0];
            let reply = DnsPacket::new_reply(
                query.header.id,
                DnsResponseCode::NoError,
                question.domain.clone(),
                question.kind,
                question.class,
                true,
            );
            let bytes = reply.to_bytes();
            if socket
                .write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .is_err()
                || socket.write_all(&bytes).await.is_err()
            {
                return;
            }
            socket.flush().await.ok();
        }
    });

    let name = format!("tcp://{server_addr}");
    let transport = DnsTcpTransport::new_tcp(&name, server_addr, "test")
        .await
        .expect("plain TCP connect must succeed");
    assert!(!transport.is_broken());

    let query = DnsPacket::new_query("example.com", DnsType::A).expect("query");
    let key = (
        "example.com".to_string(),
        DnsType::A,
        DnsClass::IN,
        query.header.id,
    );
    let rx = transport
        .send_query(&query.to_bytes(), &key)
        .await
        .expect("send over TCP");
    let resp = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("TCP reply must not hang")
        .expect("TCP reply must deliver");
    assert!(resp.header.qr, "response must have the QR bit set");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);

    drop(transport);
    server.abort();
}

// --- end-to-end over a real DoT server (network-required) ------------------

/// Exercise the transport end-to-end against Alidns's public DoT endpoint
/// (223.5.5.5:853), mirroring `dig @223.5.5.5 bing.com +tls`. Requires a
/// working network to that host and an Alidns cert that webpki-roots trusts.
///
/// `#[ignore]`d so the default `cargo test` stays hermetic; run only when
/// the environment has such access (e.g. on a corporate/dev machine):
///   cargo test -- --ignored test_dot_upstream_end_to_end
///
/// The test is written against the crate-internal `DnsDotTransport` API
/// (unlike `client::DnsUdpClient`, which has no TLS) to keep it in the same
/// module as `DnsDotTransport` without exposing it in the public API.
#[tokio::test]
#[ignore = "requires outbound connectivity to 223.5.5.5:853 and a trusted cert"]
async fn test_dot_upstream_end_to_end() {
    let dot_addr: SocketAddr = "223.5.5.5:853".parse().expect("literal");
    let transport = DnsDotTransport::new_dot(
        "tls://223.5.5.5",
        dot_addr,
        "223.5.5.5",
        "test",
    )
    .await
    .expect("DoT probe to 223.5.5.5 must succeed (TLS handshake)");
    assert!(
        !transport.is_broken(),
        "a freshly established DoT transport must be live"
    );

    let query = DnsPacket::new_query("bing.com", DnsType::A).expect("query");
    let key = (
        "bing.com".to_string(),
        DnsType::A,
        DnsClass::IN,
        query.header.id,
    );
    let rx = transport
        .send_query(&query.to_bytes(), &key)
        .await
        .expect("send over DoT");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let resp = tokio::time::timeout_at(deadline, rx)
        .await
        .expect("upstream reply must not hang")
        .expect("upstream reply must deliver");
    assert!(resp.header.qr, "response must have the QR bit set");
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "Alidns should answer bing.com A with NoError"
    );
    assert!(
        !resp.answers.is_empty(),
        "bing.com should resolve to at least one A record"
    );
}

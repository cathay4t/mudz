// SPDX-License-Identifier: Apache-2.0

//! End-to-end test: run [`mudz::MudzServer`] in a background thread on a
//! non-privileged port and drive it with the blocking [`mudz::DnsUdpClient`],
//! covering traditional (non-EDNS) and EDNS queries against a stable domain,
//! for both a plain-UDP fallback and a DoH fallback.

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, TcpStream, UdpSocket},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use mudz::{
    DnsClass, DnsHeader, DnsPacket, DnsResourceRecord, DnsResponseCode,
    DnsType, DnsUdpClient, MudzConfig, MudzServer,
};

const CONF_PATH: &str = "/tmp/test_mudz.conf";
const BIND: &str = "127.0.0.1:53530";

/// All end-to-end tests bind the same `BIND` port, so they must not run
/// concurrently. Hold this lock for the whole test body.
static SERVER_LOCK: Mutex<()> = Mutex::new(());

// i.root-servers.net has stable A/AAAA records that never change.
const DOMAIN: &str = "i.root-servers.net";
const EXPECTED_A: &str = "192.36.148.17";
const EXPECTED_AAAA: &str = "2001:7fe::53";

fn write_config(fallback_nameservers: &str, doh_section: &str) {
    let content = format!(
        "[main]\nudp_bind = \"{BIND}\"\nmax_cache_size = 1024\nlog_level = \
         \"error\"\n\n[fallback]\nnameservers = \
         [{fallback_nameservers}]\n{doh_section}"
    );
    fs::write(CONF_PATH, content).expect("failed to write test config");
}

/// A running daemon instance; shutting down (and joining the thread) happens
/// on drop.
struct ServerHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Removes the test config file on drop so it is cleaned up even when a test
/// assertion panics.
struct ConfigGuard;

impl Drop for ConfigGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(CONF_PATH);
    }
}

fn start_server() -> ServerHandle {
    let config =
        MudzConfig::from_file(CONF_PATH).expect("failed to load test config");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to build test runtime");
        rt.block_on(async move {
            let server = MudzServer::new(config)
                .await
                .expect("failed to start DNS server");
            server
                .run_with_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .expect("DNS server exited with error");
        });
    });
    wait_until_listening();
    ServerHandle {
        shutdown: Some(tx),
        thread: Some(handle),
    }
}

/// Poll the bound port with a short-timeout probe query (resolved from
/// /etc/hosts, so no upstream dependency) until the daemon answers.
fn wait_until_listening() {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
    probe.connect(BIND).expect("connect probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set probe timeout");
    let query =
        DnsPacket::new_query("localhost", DnsType::A).expect("build probe");
    let bytes = query.to_bytes();
    let mut buf = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let _ = probe.send(&bytes);
        if probe.recv(&mut buf).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("daemon did not start listening on {BIND} within 15s");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn first_a(resp: &DnsPacket) -> Option<String> {
    resp.answers
        .iter()
        .find(|r| r.kind == DnsType::A)
        .and_then(|r| <[u8; 4]>::try_from(r.rdata.as_slice()).ok())
        .map(|octets| Ipv4Addr::from(octets).to_string())
}

fn first_aaaa(resp: &DnsPacket) -> Option<String> {
    resp.answers
        .iter()
        .find(|r| r.kind == DnsType::AAAA)
        .and_then(|r| <[u8; 16]>::try_from(r.rdata.as_slice()).ok())
        .map(|octets| Ipv6Addr::from(octets).to_string())
}

/// Send one query over TCP (RFC 1035 §4.2.2 framing: 2-byte length prefix)
/// and parse the reply.
fn tcp_query(query: &DnsPacket) -> DnsPacket {
    let mut stream = TcpStream::connect(BIND).expect("tcp connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set tcp timeout");
    let bytes = query.to_bytes();
    let len = u16::try_from(bytes.len()).expect("query too large for TCP");
    stream
        .write_all(&len.to_be_bytes())
        .expect("write tcp length prefix");
    stream.write_all(&bytes).expect("write tcp query");
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .expect("read tcp reply length");
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).expect("read tcp reply body");
    DnsPacket::parse(&reply).expect("parse tcp reply")
}

/// Run the full query suite against whatever fallback the current
/// `/tmp/test_mudz.conf` selects.
fn run_query_suite() {
    let server = start_server();
    let client = DnsUdpClient::new(BIND).expect("failed to create client");

    // Traditional (non-EDNS) A query: correct answer, no OPT record.
    let query = DnsPacket::new_query(DOMAIN, DnsType::A).expect("build query");
    let resp = client.query(&query).expect("A query failed");
    assert_eq!(first_a(&resp).as_deref(), Some(EXPECTED_A));
    assert!(
        !resp.has_edns(),
        "non-EDNS query must not be answered with an OPT record"
    );

    // Traditional AAAA query.
    let query =
        DnsPacket::new_query(DOMAIN, DnsType::AAAA).expect("build query");
    let resp = client.query(&query).expect("AAAA query failed");
    assert_eq!(first_aaaa(&resp).as_deref(), Some(EXPECTED_AAAA));

    // EDNS A query: correct answer and an OPT ack must be present.
    let mut query =
        DnsPacket::new_query(DOMAIN, DnsType::A).expect("build query");
    query.add_opt_record(1232, false);
    let resp = client.query(&query).expect("EDNS A query failed");
    assert_eq!(first_a(&resp).as_deref(), Some(EXPECTED_A));
    assert!(
        resp.has_edns(),
        "EDNS query must be answered with an OPT record"
    );
    assert!(
        !resp.dnssec_ok(),
        "DO bit must stay clear when not requested"
    );

    // EDNS query with the DNSSEC OK bit set: DO must be echoed back.
    let mut query =
        DnsPacket::new_query(DOMAIN, DnsType::A).expect("build query");
    query.add_opt_record(1232, true);
    let resp = client.query(&query).expect("EDNS DO query failed");
    assert_eq!(first_a(&resp).as_deref(), Some(EXPECTED_A));
    assert!(resp.dnssec_ok(), "DO bit must be echoed in the OPT ack");

    // A repeat traditional query still resolves (cache replay path).
    let query = DnsPacket::new_query(DOMAIN, DnsType::A).expect("build query");
    let resp = client.query(&query).expect("repeat A query failed");
    assert_eq!(first_a(&resp).as_deref(), Some(EXPECTED_A));

    drop(server);
}

/// Start a fake upstream that answers every query with 100 A records, so a
/// non-EDNS UDP client gets a truncated reply with TC set and retries over
/// TCP (RFC 1035 §4.2.2). The daemon must answer that TCP retry with the
/// full, untruncated answer (RFC 7766 §7) instead of refusing the
/// connection.
fn start_large_upstream() -> std::net::SocketAddr {
    let socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind fake upstream");
    let addr = socket.local_addr().expect("fake upstream address");
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buf) else {
                return;
            };
            let Ok(query) = DnsPacket::parse(&buf[..size]) else {
                continue;
            };
            let Some(question) = query.first_question() else {
                continue;
            };
            let domain = question.domain.clone();
            let answers = (0..100u8)
                .map(|i| DnsResourceRecord {
                    domain: domain.clone(),
                    kind: DnsType::A,
                    class: DnsClass::IN,
                    ttl: 300,
                    rdlength: 4,
                    rdata: vec![10, 0, 0, i],
                })
                .collect();
            let response = DnsPacket {
                header: DnsHeader {
                    id: query.header.id,
                    qr: true,
                    rcode: DnsResponseCode::NoError,
                    qdcount: 1,
                    ancount: 100,
                    ..Default::default()
                },
                questions: vec![question.clone()],
                answers,
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let bytes = response.to_bytes();
            assert!(
                bytes.len() > 512,
                "fake upstream answer must exceed 512 bytes"
            );
            let _ = socket.send_to(&bytes, peer);
        }
    });
    addr
}

#[test]
fn test_daemon_resolves_over_tcp() {
    let _lock = SERVER_LOCK.lock().expect("server lock poisoned");
    let _config_guard = ConfigGuard;
    let upstream = start_large_upstream();
    write_config(&format!("\"127.0.0.1:{}\"", upstream.port()), "");
    let server = start_server();

    // Basic TCP resolution: correct answer, never truncated.
    let query =
        DnsPacket::new_query("large.example", DnsType::A).expect("build query");
    let tcp_resp = tcp_query(&query);
    assert!(
        !tcp_resp.header.tc,
        "TCP reply must not be truncated (RFC 7766 §7)"
    );
    assert_eq!(
        tcp_resp.answers.len(),
        100,
        "TCP reply must carry the full answer"
    );

    // The large-answer case that forces the TCP fallback.
    let udp_resp = DnsUdpClient::new(BIND)
        .expect("udp client")
        .query(&query)
        .expect("udp query");
    assert!(
        udp_resp.header.tc,
        "precondition: the non-EDNS UDP reply is truncated to 512 bytes"
    );
    let tcp_resp = tcp_query(&query);
    assert!(
        !tcp_resp.header.tc,
        "TCP reply must carry the full answer, not TC"
    );
    assert!(
        tcp_resp.answers.len() > udp_resp.answers.len(),
        "TCP reply must keep more records than the truncated UDP reply \
         (udp={}, tcp={})",
        udp_resp.answers.len(),
        tcp_resp.answers.len()
    );
    assert!(
        tcp_resp.answers.iter().any(|r| r.kind == DnsType::A),
        "TCP reply must include the final A record"
    );

    drop(server);
}

#[test]
fn test_daemon_resolves_via_udp_then_doh_fallback() {
    // Declared first so it is dropped last, removing the config file only
    // after both phases (and their servers) have finished.
    let _lock = SERVER_LOCK.lock().expect("server lock poisoned");
    let _config_guard = ConfigGuard;

    // Phase 1: plain UDP fallback nameserver.
    write_config("\"223.5.5.5\"", "");
    run_query_suite();

    // Phase 2: DoH fallback (bootstrapped through a plain IP nameserver).
    write_config(
        "\"https://dns.alidns.com/dns-query\"",
        "[doh]\nnameservers = [\"223.5.5.5\"]\n",
    );
    run_query_suite();
}

/// Regression test: `news.sina.com.cn` resolves to a CNAME chain plus a
/// dozen A records. The upstream answer uses DNS name compression and fits
/// in ~270 bytes, but re-serializing without compression bloats it past the
/// 512-byte non-EDNS UDP limit, setting TC and forcing clients such as
/// `host` to retry over TCP. With RFC 1035 §4.1.4 compression in the
/// emitter the reply stays under 512 bytes and must not be truncated.
#[test]
fn test_daemon_large_cname_response_not_truncated_for_non_edns() {
    let _lock = SERVER_LOCK.lock().expect("server lock poisoned");
    let _config_guard = ConfigGuard;
    write_config("\"223.5.5.5\"", "");
    let server = start_server();
    let client = DnsUdpClient::new(BIND).expect("failed to create client");

    // A plain (non-EDNS) query, exactly what `host` sends.
    let query = DnsPacket::new_query("news.sina.com.cn", DnsType::A)
        .expect("build query");
    let resp = client.query(&query).expect("news.sina.com.cn query failed");

    assert!(
        !resp.header.tc,
        "compressed reply must fit in 512 bytes and not set TC (got {} bytes)",
        resp.to_bytes().len()
    );
    assert!(
        !resp.answers.is_empty(),
        "reply must carry the CNAME chain and A records"
    );
    // The answer must contain at least one A record (the final target of the
    // CNAME chain) so the client can actually connect.
    assert!(
        resp.answers.iter().any(|r| r.kind == DnsType::A),
        "reply must contain at least one A record"
    );

    drop(server);
}

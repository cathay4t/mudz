// SPDX-License-Identifier: Apache-2.0

//! End-to-end test: run the daemon in a background thread on a non-privileged
//! port and drive it with the blocking [`mudz::DnsUdpClient`], covering
//! traditional (non-EDNS) and EDNS queries against a stable domain, for both a
//! plain-UDP fallback and a DoH fallback.

use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use mudz::{DnsPacket, DnsType, DnsUdpClient};

use crate::{config::MudzConfig, server::DnsUdpServer};

const CONF_PATH: &str = "/tmp/test_mudz.conf";
const BIND: &str = "127.0.0.1:53530";

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
            let server = DnsUdpServer::new(config)
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

#[test]
fn test_daemon_resolves_via_udp_then_doh_fallback() {
    // Declared first so it is dropped last, removing the config file only
    // after both phases (and their servers) have finished.
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

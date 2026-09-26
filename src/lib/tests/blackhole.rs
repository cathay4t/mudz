// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for dead upstreams at server start: the node boots, the
//! embedded [`mudz::MudzServer`] starts, and a group's upstream server is not
//! reachable yet (or is blackholed). Clients querying that group must get
//! SERVFAIL instead of waiting forever, and the server must recover on its
//! own once the upstream becomes reachable — no restart.
//!
//! `test_blackhole_upstream_at_boot` reproduces the boot scenario with a
//! kernel blackhole route (`ip route blackhole`, RFC 5737 TEST-NET-1
//! address) and therefore needs root; it is `#[ignore]`d. Run it with:
//!
//! ```text
//! cargo test --package mudz --no-run
//! sudo target/debug/deps/blackhole-* blackhole --ignored --nocapture
//! ```
//!
//! `test_silent_upstream_fails_fast_after_repeated_timeouts` reproduces the
//! worse, silent variant: the upstream address is reachable at L2/L4 (a bound
//! UDP socket) but never answers — exactly what a firewall DROP or a
//! blackholing router looks like to DNS. No root required.

use std::{
    fs, io,
    net::{Ipv4Addr, UdpSocket},
    process::Command,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use mudz::{
    DnsClass, DnsPacket, DnsResourceRecord, DnsResponseCode, DnsType,
    MudzConfig, MudzServer,
};

/// RFC 5737 TEST-NET-1: guaranteed never to be routed anywhere real.
const UPSTREAM: &str = "192.0.2.153";
/// The A record the fake upstream answers with after recovery.
const FAKE_ANSWER: [u8; 4] = [192, 0, 2, 200];

const BLACKHOLE_CONF: &str = "/tmp/test_mudz_blackhole.conf";
const BLACKHOLE_BIND: &str = "127.0.0.1:53531";
const SILENT_CONF: &str = "/tmp/test_mudz_silent.conf";
const SILENT_BIND: &str = "127.0.0.1:53532";
/// Deaf UDP socket acting as a silent (never answering) upstream.
const SILENT_UPSTREAM: &str = "127.0.0.1:53533";
const REFUSED_CONF: &str = "/tmp/test_mudz_refused.conf";
const REFUSED_BIND: &str = "127.0.0.1:53534";
/// Upstream port with nothing listening: the kernel answers every datagram
/// with ICMP port-unreachable, latching ECONNREFUSED on the transport
/// socket, which is fatal for its receive loop.
const REFUSED_UPSTREAM: &str = "127.0.0.1:53535";

/// The daemon's per-upstream timeout (`DNS_TIMEOUT_SEC` in group.rs) is 5s,
/// so the first failure may legitimately take the full timeout plus
/// overhead; anything beyond this budget means a client-visible hang.
const FIRST_FAILURE_BUDGET: Duration = Duration::from_secs(8);
/// Once the daemon has seen the upstream fail repeatedly, it must fail fast:
/// no client should sit waiting for the upstream timeout again.
const FAST_FAIL_BUDGET: Duration = Duration::from_secs(2);

static LOGGER: Once = Once::new();

fn init_logger() {
    LOGGER.call_once(|| {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("debug"),
        )
        .try_init();
    });
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute 'ip': {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Removes the blackhole route and the loopback address on drop so the host
/// network state is restored even when a test assertion panics.
struct NetGuard;

impl Drop for NetGuard {
    fn drop(&mut self) {
        let _ = run_ip(&["route", "del", "blackhole", UPSTREAM]);
        let addr = format!("{UPSTREAM}/32");
        let _ = run_ip(&["addr", "del", addr.as_str(), "dev", "lo"]);
    }
}

/// Removes the test config file on drop.
struct ConfigGuard(&'static str);

impl Drop for ConfigGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// A running daemon instance; shutdown (and thread join) happens on drop.
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

fn start_server(conf_path: &str, bind: &str) -> ServerHandle {
    let config =
        MudzConfig::from_file(conf_path).expect("failed to load test config");
    let bind = bind.to_string();
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
    wait_until_listening(&bind);
    ServerHandle {
        shutdown: Some(tx),
        thread: Some(handle),
    }
}

/// Probe with a query that is answered from /etc/hosts (no upstream
/// dependency) until the daemon answers.
fn wait_until_listening(bind: &str) {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
    probe.connect(bind).expect("connect probe socket");
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
            panic!("daemon did not start listening on {bind} within 15s");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Send one query and wait for its reply, returning the reply and how long
/// the client waited for it.
fn udp_query(
    bind: &str,
    domain: &str,
    budget: Duration,
) -> Result<(DnsPacket, Duration), String> {
    let socket =
        UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    socket
        .connect(bind)
        .map_err(|e| format!("connect to {bind}: {e}"))?;
    let query = DnsPacket::new_query(domain, DnsType::A)
        .map_err(|e| format!("build query: {e}"))?;
    socket
        .send(&query.to_bytes())
        .map_err(|e| format!("send query: {e}"))?;
    let start = Instant::now();
    socket
        .set_read_timeout(Some(budget))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut buf = [0u8; 4096];
    loop {
        match socket.recv(&mut buf) {
            Ok(n) => {
                if let Ok(packet) = DnsPacket::parse(&buf[..n])
                    && packet.header.id == query.header.id
                    && packet.header.qr
                {
                    return Ok((packet, start.elapsed()));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(format!(
                    "no DNS reply for {domain} within {budget:?}"
                ));
            }
            Err(e) => return Err(format!("recv: {e}")),
        }
        if start.elapsed() > budget {
            return Err(format!("no DNS reply for {domain} within {budget:?}"));
        }
    }
}

fn first_a(resp: &DnsPacket) -> Option<String> {
    resp.answers
        .iter()
        .find(|r| r.kind == DnsType::A)
        .and_then(|r| <[u8; 4]>::try_from(r.rdata.as_slice()).ok())
        .map(Ipv4Addr::from)
        .map(|ip| ip.to_string())
}

/// A UDP server bound to `bind` that answers every query with NOERROR and a
/// single A record of [`FAKE_ANSWER`] — the "upstream comes back to life"
/// side of the recovery phase.
struct FakeUpstream {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeUpstream {
    fn start(bind: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(300)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                let (len, peer) = match socket.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let Ok(query) = DnsPacket::parse(&buf[..len]) else {
                    continue;
                };
                let Some(question) = query.first_question() else {
                    continue;
                };
                let mut reply = DnsPacket::new_reply(
                    query.header.id,
                    DnsResponseCode::NoError,
                    question.domain.clone(),
                    question.kind,
                    question.class,
                    query.header.rd,
                );
                reply.answers.push(DnsResourceRecord::new(
                    question.domain.clone(),
                    DnsType::A,
                    DnsClass::IN,
                    60,
                    FAKE_ANSWER.to_vec(),
                ));
                reply.header.ancount = 1;
                let _ = socket.send_to(&reply.to_bytes(), peer);
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn write_blackhole_config() {
    let content = format!(
        "[main]\nudp_bind = \"{BLACKHOLE_BIND}\"\nmax_cache_size = \
         1024\nlog_level = \"debug\"\n\n[fallback]\nnameservers = \
         [\"{UPSTREAM}\"]\n\n[group.corp]\nnameservers = \
         [\"{UPSTREAM}\"]\ndomains = [\"corp.example\"]\n"
    );
    fs::write(BLACKHOLE_CONF, content).expect("write blackhole config");
}

fn write_silent_config() {
    let content = format!(
        "[main]\nudp_bind = \"{SILENT_BIND}\"\nmax_cache_size = \
         1024\nlog_level = \"debug\"\n\n[fallback]\nnameservers = \
         [\"{SILENT_UPSTREAM}\"]\n\n[group.silent]\nnameservers = \
         [\"{SILENT_UPSTREAM}\"]\ndomains = [\"silent.example\"]\n"
    );
    fs::write(SILENT_CONF, content).expect("write silent config");
}

fn write_refused_config() {
    let content = format!(
        "[main]\nudp_bind = \"{REFUSED_BIND}\"\nmax_cache_size = \
         1024\nlog_level = \"debug\"\n\n[fallback]\nnameservers = \
         [\"{REFUSED_UPSTREAM}\"]\n\n[group.refused]\nnameservers = \
         [\"{REFUSED_UPSTREAM}\"]\ndomains = [\"refused.example\"]\n"
    );
    fs::write(REFUSED_CONF, content).expect("write refused config");
}

/// Boot scenario: the upstream is unreachable the moment the server starts.
///
/// Phase 1 — a kernel blackhole route covers the upstream, so the server starts
/// with a dead upstream. Queries for the group's domains must be answered
/// SERVFAIL (never hang), and after the server has seen the upstream fail
/// repeatedly it must fail fast.
///
/// Phase 2 — the blackhole route is removed and the upstream address comes
/// up on loopback with a live DNS server behind it. The server must recover
/// by itself (no restart) once the transport retry cooldown has passed.
#[test]
#[ignore = "requires root: installs a kernel blackhole route"]
fn test_blackhole_upstream_at_boot() {
    init_logger();
    if !is_root() {
        eprintln!("SKIP: test_blackhole_upstream_at_boot requires root");
        return;
    }

    // Declared first so it is dropped last, after the server has stopped.
    let _config_guard = ConfigGuard(BLACKHOLE_CONF);
    let _net_guard = NetGuard;

    // The upstream is already blackholed when the server starts, exactly like a
    // group whose nameserver is not reachable at node boot.
    run_ip(&["route", "replace", "blackhole", UPSTREAM])
        .expect("install blackhole route");
    write_blackhole_config();
    let server = start_server(BLACKHOLE_CONF, BLACKHOLE_BIND);

    // The first failure may legitimately consume the upstream timeout; the
    // client must still get a SERVFAIL reply instead of waiting forever.
    let (resp, elapsed) =
        udp_query(BLACKHOLE_BIND, "host1.corp.example", FIRST_FAILURE_BUDGET)
            .expect("query must receive a reply, not hang");
    log::info!(
        "blackholed query 1: rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::ServFail,
        "blackholed upstream must produce SERVFAIL"
    );

    // Once the upstream has failed repeatedly, answers must be fast — a
    // client should not sit through the upstream timeout on every lookup.
    for i in [2, 3] {
        let domain = format!("host{i}.corp.example");
        let (resp, elapsed) =
            udp_query(BLACKHOLE_BIND, &domain, FAST_FAIL_BUDGET)
                .unwrap_or_else(|e| panic!("query {i} must fail fast: {e}"));
        log::info!(
            "blackholed query {i}: rcode {:?} after {elapsed:?}",
            resp.header.rcode
        );
        assert_eq!(
            resp.header.rcode,
            DnsResponseCode::ServFail,
            "blackholed upstream must produce SERVFAIL"
        );
    }

    // Bring the upstream back: drop the blackhole route, put the address on
    // loopback, and start a live DNS server behind it.
    run_ip(&["route", "del", "blackhole", UPSTREAM])
        .expect("remove blackhole route");
    let addr = format!("{UPSTREAM}/32");
    run_ip(&["addr", "replace", addr.as_str(), "dev", "lo"])
        .expect("add upstream address to loopback");
    let _upstream = FakeUpstream::start(&format!("{UPSTREAM}:53"))
        .expect("start fake upstream");

    // Wait out the transport retry cooldown, then the daemon must resolve
    // through the recovered upstream without any restart.
    thread::sleep(Duration::from_secs(6));
    let (resp, elapsed) = udp_query(
        BLACKHOLE_BIND,
        "recovered.corp.example",
        Duration::from_secs(10),
    )
    .expect("query must resolve after the upstream recovers");
    log::info!(
        "recovered query: rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "daemon must recover automatically once the upstream is reachable"
    );
    assert_eq!(first_a(&resp).as_deref(), Some("192.0.2.200"));

    drop(server);
}

/// Silent-blackhole scenario: the upstream socket exists and accepts
/// datagrams but never answers — what a firewall DROP or a blackholing
/// router looks like to DNS. The daemon must track upstream health: once
/// the upstream has failed repeatedly it must fail fast with SERVFAIL
/// instead of burning the upstream timeout on every lookup, and probe the
/// upstream back to life once the cooldown has passed.
#[test]
fn test_silent_upstream_fails_fast_after_repeated_timeouts() {
    init_logger();
    let _config_guard = ConfigGuard(SILENT_CONF);

    // The deaf upstream: bound, reachable, never answers.
    let deaf_upstream =
        UdpSocket::bind(SILENT_UPSTREAM).expect("bind deaf upstream socket");

    write_silent_config();
    let server = start_server(SILENT_CONF, SILENT_BIND);

    // The first failure may legitimately consume the upstream timeout, but
    // the client must still get a SERVFAIL instead of hanging.
    let (resp, elapsed) =
        udp_query(SILENT_BIND, "one.silent.example", FIRST_FAILURE_BUDGET)
            .expect("query must receive a reply, not hang");
    log::info!(
        "silent query 1: rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::ServFail,
        "silent upstream must produce SERVFAIL"
    );

    // Second failure: still allowed to take the upstream timeout.
    let (resp, elapsed) =
        udp_query(SILENT_BIND, "two.silent.example", FIRST_FAILURE_BUDGET)
            .expect("query must receive a reply, not hang");
    log::info!(
        "silent query 2: rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(resp.header.rcode, DnsResponseCode::ServFail);

    // The upstream has now failed repeatedly: the daemon must answer
    // SERVFAIL immediately instead of stalling clients on the upstream
    // timeout for every lookup.
    for i in [3, 4] {
        let domain = format!("q{i}.silent.example");
        let (resp, elapsed) = udp_query(SILENT_BIND, &domain, FAST_FAIL_BUDGET)
            .unwrap_or_else(|e| panic!("query {i} must fail fast: {e}"));
        log::info!(
            "silent query {i}: rcode {:?} after {elapsed:?}",
            resp.header.rcode
        );
        assert_eq!(resp.header.rcode, DnsResponseCode::ServFail);
    }

    // The silent upstream comes back to life on the same address. Once the
    // dead-upstream cooldown has passed, the next query must probe it and
    // recover — a dead upstream must not stay dead forever.
    drop(deaf_upstream);
    let _upstream = FakeUpstream::start(SILENT_UPSTREAM)
        .expect("start fake upstream on the silent address");
    thread::sleep(Duration::from_secs(6));
    let (resp, elapsed) =
        udp_query(SILENT_BIND, "five.silent.example", Duration::from_secs(10))
            .expect("query must resolve after the silent upstream comes back");
    log::info!(
        "silent query 5 (recovery): rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "daemon must probe a dead upstream after the cooldown and recover"
    );
    assert_eq!(first_a(&resp).as_deref(), Some("192.0.2.200"));

    drop(server);
}

/// ICMP-refusing upstream: nothing listens on the upstream port, so the
/// kernel answers every datagram with ICMP port-unreachable. The latched
/// ECONNREFUSED is fatal for the transport's receive loop — the transport
/// becomes a zombie that can never dispatch a response again. The daemon
/// must evict such broken transports and recreate them, recovering without
/// a restart once a real server appears on that port.
#[test]
fn test_refused_upstream_recovers_after_comeback() {
    init_logger();
    let _config_guard = ConfigGuard(REFUSED_CONF);

    write_refused_config();
    let server = start_server(REFUSED_CONF, REFUSED_BIND);

    // Nothing listens on REFUSED_UPSTREAM yet.
    let (resp, elapsed) =
        udp_query(REFUSED_BIND, "one.refused.example", FIRST_FAILURE_BUDGET)
            .expect("query must receive a reply, not hang");
    log::info!(
        "refused query 1: rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::ServFail,
        "ICMP-refusing upstream must produce SERVFAIL"
    );

    // The upstream comes up on the same address:port. Once the transport
    // retry cooldown has passed, the daemon must resolve through it.
    let _upstream = FakeUpstream::start(REFUSED_UPSTREAM)
        .expect("start fake upstream on the refused port");
    thread::sleep(Duration::from_secs(6));
    let (resp, elapsed) =
        udp_query(REFUSED_BIND, "two.refused.example", Duration::from_secs(10))
            .expect("query must resolve after the upstream comes up");
    log::info!(
        "refused query 2 (recovery): rcode {:?} after {elapsed:?}",
        resp.header.rcode
    );
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "daemon must evict the broken transport and recover"
    );
    assert_eq!(first_a(&resp).as_deref(), Some("192.0.2.200"));

    drop(server);
}

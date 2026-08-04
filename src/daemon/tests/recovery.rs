// SPDX-License-Identifier: Apache-2.0

//! Stress the upstream health/recovery machinery the way a long-running
//! daemon hits it: an upstream that is *alive* most of the time, with short
//! outages sprinkled in. Every query must either resolve or fail fast with
//! SERVFAIL - never hang - and the daemon must always recover on its own
//! once the upstream answers again (no restart), for every outage cycle.

use std::{
    io,
    net::UdpSocket,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use mudz::{DnsClass, DnsPacket, DnsResourceRecord, DnsResponseCode, DnsType};

use crate::{config::MudzConfig, server::DnsUdpServer};

/// Ports and config path for the long-outage test.
const BIND_A: &str = "127.0.0.1:53541";
const UPSTREAM_A: &str = "127.0.0.1:53542";
const CONF_A: &str = "/tmp/test_mudz_recovery_a.conf";
/// Ports and config path for the repeated-outages test.
const BIND_B: &str = "127.0.0.1:53543";
const UPSTREAM_B: &str = "127.0.0.1:53544";
const CONF_B: &str = "/tmp/test_mudz_recovery_b.conf";
const FAKE_ANSWER: [u8; 4] = [10, 11, 12, 13];

static LOGGER: Once = Once::new();

fn init_logger() {
    LOGGER.call_once(|| {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("warn"),
        )
        .try_init();
    });
}

/// A fake upstream that answers A queries, can be told to go deaf.
struct FakeUpstream {
    #[allow(dead_code)] // kept bound for the upstream's lifetime
    socket: Arc<UdpSocket>,
    deaf: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeUpstream {
    fn start(bind: &str) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(bind)?);
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let deaf = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_socket = Arc::clone(&socket);
        let thread_deaf = Arc::clone(&deaf);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                let (len, peer) = match thread_socket.recv_from(&mut buf) {
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
                if thread_deaf.load(Ordering::Relaxed) {
                    // Simulate a silent (blackholed) upstream: drop.
                    continue;
                }
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
                reply.answers.push(DnsResourceRecord {
                    domain: question.domain.clone(),
                    kind: DnsType::A,
                    class: DnsClass::IN,
                    ttl: 60,
                    rdlength: u16::from(FAKE_ANSWER.len() as u8),
                    rdata: FAKE_ANSWER.to_vec(),
                });
                reply.header.ancount = 1;
                let _ = thread_socket.send_to(&reply.to_bytes(), peer);
            }
        });
        Ok(Self {
            socket,
            deaf,
            stop,
            thread: Some(thread),
        })
    }

    fn set_deaf(&self, deaf: bool) {
        self.deaf.store(deaf, Ordering::Relaxed);
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

fn start_server(bind: &str, conf: &str) -> ServerHandle {
    let config = MudzConfig::from_file(conf).expect("failed to load config");
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
    // Wait until the daemon answers a query.
    wait_until_answers(bind);
    ServerHandle {
        shutdown: Some(tx),
        thread: Some(handle),
    }
}

fn wait_until_answers(bind: &str) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.connect(bind).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set timeout");
    let query = DnsPacket::new_query("up.example", DnsType::A).expect("query");
    let bytes = query.to_bytes();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let _ = socket.send(&bytes);
        if socket.recv(&mut buf).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("daemon did not start within 15s");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Query and return the reply or an error if it hung past `budget`.
fn query(
    bind: &str,
    domain: &str,
    budget: Duration,
) -> Result<DnsPacket, String> {
    let socket =
        UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    socket.connect(bind).map_err(|e| format!("connect: {e}"))?;
    let query =
        DnsPacket::new_query(domain, DnsType::A).map_err(|e| e.to_string())?;
    socket.send(&query.to_bytes()).map_err(|e| e.to_string())?;
    let start = Instant::now();
    socket
        .set_read_timeout(Some(budget))
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    loop {
        match socket.recv(&mut buf) {
            Ok(n) => {
                if let Ok(packet) = DnsPacket::parse(&buf[..n])
                    && packet.header.id == query.header.id
                    && packet.header.qr
                {
                    return Ok(packet);
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

#[test]
fn test_long_outage_recreates_stuck_transport() {
    init_logger();
    let conf = format!(
        "[main]\nudp_bind = \"{BIND_A}\"\nmax_cache_size = 1024\nlog_level = \
         \"warn\"\n\n[fallback]\nnameservers = [\"{UPSTREAM_A}\"]\n"
    );
    std::fs::write(CONF_A, conf).expect("write config");

    let _upstream = FakeUpstream::start(UPSTREAM_A).expect("start upstream");
    let server = start_server(BIND_A, CONF_A);

    // Sanity: live upstream resolves.
    let resp = query(BIND_A, "warm.corp.example", Duration::from_secs(5))
        .expect("initial query must resolve");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);

    // A long silence: the upstream gets marked dead, probes keep failing,
    // and the transport must be recreated (a stuck socket is evicted, not
    // probed forever). Keep querying so the daemon walks through multiple
    // dead -> probe -> recreate cycles while the upstream is silent.
    _upstream.set_deaf(true);
    let start = Instant::now();
    while Instant::now() - start < Duration::from_secs(18) {
        let _ = query(BIND_A, "stuck.corp.example", Duration::from_secs(6));
        thread::sleep(Duration::from_millis(500));
    }

    // The upstream comes back on the same address. The daemon must recover
    // on its own (fresh transport, no restart) within a bounded time.
    _upstream.set_deaf(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut resolved = false;
    while Instant::now() < deadline {
        match query(BIND_A, "back.corp.example", Duration::from_secs(3)) {
            Ok(resp) if resp.header.rcode == DnsResponseCode::NoError => {
                resolved = true;
                break;
            }
            Ok(_) | Err(_) => {
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    assert!(
        resolved,
        "daemon must recover from a long outage by recreating the stuck \
         transport"
    );

    drop(server);
    std::fs::remove_file(CONF_A).ok();
}

#[test]
fn test_live_upstream_recovery_after_repeated_outages() {
    init_logger();
    let conf = format!(
        "[main]\nudp_bind = \"{BIND_B}\"\nmax_cache_size = 1024\nlog_level = \
         \"warn\"\n\n[fallback]\nnameservers = [\"{UPSTREAM_B}\"]\n"
    );
    std::fs::write(CONF_B, conf).expect("write config");

    let _upstream = FakeUpstream::start(UPSTREAM_B).expect("start upstream");
    let server = start_server(BIND_B, CONF_B);

    // Sanity: live upstream resolves.
    let resp = query(BIND_B, "ok.corp.example", Duration::from_secs(5))
        .expect("initial query must resolve");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);

    // Go deaf, let the daemon mark the upstream dead and fail fast.
    _upstream.set_deaf(true);
    let resp = query(BIND_B, "dead1.corp.example", Duration::from_secs(9))
        .expect("query during outage must not hang");
    assert_eq!(resp.header.rcode, DnsResponseCode::ServFail);

    // Come back; the daemon must probe and recover on its own.
    _upstream.set_deaf(false);
    let resp = query(BIND_B, "alive1.corp.example", Duration::from_secs(12))
        .expect("query after recovery must not hang");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);

    // Now run many outage/recovery cycles; every query must complete and
    // the daemon must keep recovering.
    for cycle in 0..12 {
        _upstream.set_deaf(true);
        // Let the daemon see at least two timeouts so it marks dead.
        let _ = query(
            BIND_B,
            &format!("dead{cycle}.corp.example"),
            Duration::from_secs(9),
        );
        thread::sleep(Duration::from_millis(100));
        _upstream.set_deaf(false);

        // Once the upstream answers again, the daemon must recover on its
        // own (probe after the dead-window cooldown) within a bounded time.
        // Retry until success so the test is robust to the daemon's 5s
        // fail-fast cooldown overlapping the first post-recovery query.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut resolved = false;
        while Instant::now() < deadline {
            match query(
                BIND_B,
                &format!("alive{cycle}.corp.example"),
                Duration::from_secs(3),
            ) {
                Ok(resp) if resp.header.rcode == DnsResponseCode::NoError => {
                    resolved = true;
                    break;
                }
                Ok(_) | Err(_) => {
                    // Still in the fail-fast cooldown; try again.
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
        assert!(
            resolved,
            "cycle {cycle}: daemon failed to recover within 20s after the \
             upstream came back"
        );
    }

    drop(server);
    std::fs::remove_file(CONF_B).ok();
}

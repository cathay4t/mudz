// SPDX-License-Identifier: Apache-2.0

//! The embedder owns the host network state, so it is the one which knows
//! when the default gateway changed (route apply, DHCP lease, resume). The
//! embedding contract tested here: a server holding a dead or broken
//! upstream group must retry it immediately after the embedder reports a
//! network change through [`MudzNotifier`], instead of failing fast until
//! the retry backoff elapsed.

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

use mudz::{
    DnsClass, DnsPacket, DnsResourceRecord, DnsResponseCode, DnsType,
    MudzConfig, MudzFallbackConfig, MudzMainConfig, MudzNotifier, MudzServer,
};

/// Listen address of the embedded server. Distinct from the ports used by
/// the other end-to-end tests (53530-53544 and 53560-53561).
const BIND: &str = "127.0.0.1:53562";
/// Upstream port: nothing listens there until the test starts the fake
/// upstream, mimicking the default gateway going away and coming back.
const UPSTREAM: &str = "127.0.0.1:53563";
const FAKE_ANSWER: [u8; 4] = [192, 0, 2, 200];
/// A client must never wait longer than one upstream timeout (5s) for a
/// reply; the server answers SERVFAIL instead of hanging.
const QUERY_BUDGET: Duration = Duration::from_secs(8);

static LOGGER: Once = Once::new();

fn init_logger() {
    LOGGER.call_once(|| {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("warn"),
        )
        .try_init();
    });
}

/// A fake upstream answering A queries, started only after the server saw
/// the upstream fail.
struct FakeUpstream {
    #[allow(dead_code)] // kept bound for the upstream's lifetime
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeUpstream {
    fn start(bind: &str) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(bind)?);
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_socket = Arc::clone(&socket);
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

/// A running embedded server plus the notifier the embedder would keep.
struct ServerHandle {
    notifier: MudzNotifier,
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

fn embedded_config() -> MudzConfig {
    MudzConfig {
        main: MudzMainConfig {
            udp_bind: BIND.to_string(),
            max_cache_size: 64,
            log_level: "warn".to_string(),
            ..Default::default()
        },
        fallback: MudzFallbackConfig {
            nameservers: vec![UPSTREAM.to_string()],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Start the server on its own runtime and hand the notifier back to the
/// test thread, the way an embedder owns the server task and the network
/// state separately.
fn start_server() -> ServerHandle {
    let config = embedded_config();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (notifier_tx, notifier_rx) = std::sync::mpsc::channel::<MudzNotifier>();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build test runtime");
        rt.block_on(async move {
            let server = MudzServer::new(config)
                .await
                .expect("failed to start DNS server");
            notifier_tx.send(server.notifier()).expect("send notifier");
            server
                .run_with_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("DNS server exited with error");
        });
    });
    wait_until_answers(BIND);
    let notifier = notifier_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server must hand out its notifier");
    ServerHandle {
        notifier,
        shutdown: Some(shutdown_tx),
        thread: Some(handle),
    }
}

/// Wait until the server replies to a query. The upstream port is still
/// refused, so the reply is a SERVFAIL.
fn wait_until_answers(bind: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if query(bind, "boot.network-change.example").is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("daemon did not start within 15s");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Query the embedded server and return the reply, or an error when no
/// reply arrived within [`QUERY_BUDGET`].
fn query(bind: &str, domain: &str) -> Result<DnsPacket, String> {
    let socket =
        UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    socket.connect(bind).map_err(|e| format!("connect: {e}"))?;
    let query =
        DnsPacket::new_query(domain, DnsType::A).map_err(|e| e.to_string())?;
    socket.send(&query.to_bytes()).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(QUERY_BUDGET))
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    match socket.recv(&mut buf) {
        Ok(n) => {
            let packet =
                DnsPacket::parse(&buf[..n]).map_err(|e| e.to_string())?;
            if packet.header.qr {
                Ok(packet)
            } else {
                Err("received a non-reply packet".to_string())
            }
        }
        Err(e) => Err(format!("no DNS reply for {domain}: {e}")),
    }
}

/// A network change reported by the embedder must make the server retry a
/// group whose transport was broken because the upstream was unreachable,
/// without waiting for the 5s transport recreation cooldown.
#[test]
fn test_network_change_retries_failed_group_immediately() {
    init_logger();
    let server = start_server();

    // Nothing listens on the upstream port: the kernel answers with ICMP
    // port-unreachable, which is fatal to the transport's receive loop.
    let resp = query(BIND, "one.network-change.example")
        .expect("refused upstream must answer SERVFAIL, not hang");
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::ServFail,
        "ICMP-refusing upstream must produce SERVFAIL"
    );

    // The next query fails fast too: the broken transport is only
    // recreated after the retry cooldown, exactly the state a default
    // gateway change leaves the cache in.
    let resp = query(BIND, "two.network-change.example")
        .expect("query during the retry cooldown must fail fast, not hang");
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::ServFail,
        "the unreachable upstream must produce SERVFAIL"
    );

    // The upstream comes back on the same address:port, and the embedder
    // learns about the new default route. Only the notification may make
    // the server retry now: the transport recreation cooldown has not
    // elapsed yet.
    let _upstream = FakeUpstream::start(UPSTREAM).expect("start fake upstream");
    server
        .notifier
        .notify_network_change()
        .expect("server must accept the notification");

    // The notification clears the cooldown and drops the dead transports:
    // the very next query must go through.
    let start = Instant::now();
    let resp = query(BIND, "three.network-change.example")
        .expect("query after the network change must resolve");
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "the failed group must be retried right after the network change"
    );
    assert_eq!(
        resp.answers.first().map(|a| a.rdata.clone()),
        Some(FAKE_ANSWER.to_vec())
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the retry must not wait for the transport recreation cooldown"
    );

    drop(server);
}

/// The notifier must fail once the server is gone, so the embedder can log
/// the dropped notification instead of assuming the failed groups were
/// reset.
#[test]
fn test_notify_without_running_server_fails() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime");
    let config = MudzConfig {
        main: MudzMainConfig {
            udp_bind: "127.0.0.1:53564".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    rt.block_on(async move {
        let server = MudzServer::new(config)
            .await
            .expect("failed to start DNS server");
        let notifier = server.notifier();
        server
            .run_with_shutdown(std::future::ready(()))
            .await
            .expect("failed to stop DNS server");

        let err = notifier
            .notify_network_change()
            .expect_err("a stopped server cannot receive notifications");
        assert!(
            err.to_string().contains("not running"),
            "unexpected error: {err}"
        );
    });
}

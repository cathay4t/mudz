// SPDX-License-Identifier: Apache-2.0

//! Embedding contract of the `mudz` crate.
//!
//! An embedder such as nipart builds a [`MudzConfig`] in code, hands it to
//! [`MudzServer::new`] and owns the server task itself:
//!
//! ```text
//! let srv = MudzServer::new(MudzConfig::default()).await?;
//! srv.run().await; // runs until the task is killed
//! ```
//!
//! These tests pin the parts of that contract which are easy to break:
//!
//! - `MudzServer` and the future returned by `run()` are `Send + 'static`, so
//!   an embedder can spawn them on its own Tokio runtime.
//! - Killing the running task releases the listening sockets, so a config
//!   change can drop the old server and build a new one on the same port.
//! - `run_with_shutdown` gives an embedder-owned shutdown path.

use std::{
    io,
    net::{Ipv4Addr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use mudz::{
    DnsClass, DnsPacket, DnsResourceRecord, DnsResponseCode, DnsType,
    MudzConfig, MudzFallbackConfig, MudzMainConfig, MudzServer,
};

/// Listen address of the embedded server. Distinct from the ports used by
/// the other integration tests (53530-53544).
const BIND: &str = "127.0.0.1:53560";
/// Loopback address of the fake upstream.
const UPSTREAM: &str = "127.0.0.1:53561";
const DOMAIN: &str = "embedded.example";
const ANSWER: [u8; 4] = [10, 20, 30, 40];
const ANSWER_STR: &str = "10.20.30.40";
const QUERY_BUDGET: Duration = Duration::from_secs(5);

/// Both tests bind the same ports, so they must not run concurrently.
static PORT_LOCK: Mutex<()> = Mutex::new(());

/// Build the runtime configuration the way an embedder does: plain Rust
/// structs, no TOML file and no `MudzConfig::from_file`.
fn embedded_config() -> MudzConfig {
    MudzConfig {
        main: MudzMainConfig {
            udp_bind: BIND.to_string(),
            max_cache_size: 64,
            log_level: "error".to_string(),
            ..Default::default()
        },
        fallback: MudzFallbackConfig {
            nameservers: vec![UPSTREAM.to_string()],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A runtime shaped like the one an embedder runs: multi-threaded with all
/// drivers enabled, which `run()` needs for its signal handlers.
fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

/// Compile-time proof that an embedder may keep the server around and share
/// it across tasks. The `tokio::spawn(server.run())` calls below prove the
/// same for the `run()` future.
fn assert_send_sync_static<T: Send + Sync + 'static>() {}

#[test]
fn test_embed_spawn_abort_and_recreate() {
    let _lock = PORT_LOCK.lock().expect("port lock poisoned");
    assert_send_sync_static::<MudzServer>();
    let _upstream = FakeUpstream::start(UPSTREAM).expect("start upstream");
    let rt = test_runtime();

    rt.block_on(async {
        // The nipart pattern: build the config in code, create the server,
        // then hand `run()` to `tokio::spawn`.
        let server = MudzServer::new(embedded_config())
            .await
            .expect("create server");
        let task = tokio::spawn(server.run());
        assert_eq!(query_a(DOMAIN).await.as_deref(), Some(ANSWER_STR));

        // A config change makes the embedder kill the task and build a new
        // server, so killing it must release the listening sockets.
        task.abort();
        assert!(task.await.is_err(), "aborted run() must not return Ok");
        wait_until_ports_free().await;

        let server = MudzServer::new(embedded_config())
            .await
            .expect("recreate server on the same port");
        let task = tokio::spawn(server.run());
        assert_eq!(query_a(DOMAIN).await.as_deref(), Some(ANSWER_STR));
        task.abort();
        let _ = task.await;
    });
}

#[test]
fn test_embed_run_with_embedder_owned_shutdown() {
    let _lock = PORT_LOCK.lock().expect("port lock poisoned");
    let _upstream = FakeUpstream::start(UPSTREAM).expect("start upstream");
    let rt = test_runtime();

    rt.block_on(async {
        let server = MudzServer::new(embedded_config())
            .await
            .expect("create server");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(server.run_with_shutdown(async move {
            let _ = rx.await;
        }));

        assert_eq!(query_a(DOMAIN).await.as_deref(), Some(ANSWER_STR));

        tx.send(()).expect("send shutdown signal");
        let result = task.await.expect("join server task");
        assert!(result.is_ok(), "run_with_shutdown failed: {result:?}");
        wait_until_ports_free().await;
    });
}

/// Send one A query for `domain` to the embedded server, retrying until it
/// answers or the budget expires. Returns the address of the first A record.
async fn query_a(domain: &str) -> Option<String> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind query socket");
    socket.connect(BIND).await.expect("connect query socket");
    let query = DnsPacket::new_query(domain, DnsType::A).expect("build query");
    let bytes = query.to_bytes();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + QUERY_BUDGET;
    loop {
        socket.send(&bytes).await.expect("send query");
        let reply = tokio::time::timeout(
            Duration::from_millis(200),
            socket.recv(&mut buf),
        )
        .await;
        if let Ok(Ok(len)) = reply
            && let Ok(packet) = DnsPacket::parse(&buf[..len])
            && packet.header.id == query.header.id
            && packet.header.qr
        {
            return packet
                .answers
                .iter()
                .find(|record| record.kind == DnsType::A)
                .and_then(|record| {
                    <[u8; 4]>::try_from(record.rdata.as_slice()).ok()
                })
                .map(|octets| Ipv4Addr::from(octets).to_string());
        }
        assert!(
            Instant::now() <= deadline,
            "no reply for {domain} from {BIND} within {QUERY_BUDGET:?}"
        );
    }
}

/// Wait until the server released its sockets: the UDP port can be bound
/// again and a TCP listener can listen on it again.
async fn wait_until_ports_free() {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let udp_free = UdpSocket::bind(BIND).is_ok();
        let tcp_free = std::net::TcpListener::bind(BIND).is_ok();
        if udp_free && tcp_free {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "server still holds {BIND} (udp_free={udp_free}, \
             tcp_free={tcp_free}) after it stopped"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A fake upstream answering every A query for [`DOMAIN`] with [`ANSWER`],
/// so the embedding tests need no real nameserver.
struct FakeUpstream {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeUpstream {
    fn start(bind: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                let (len, peer) = match socket.recv_from(&mut buf) {
                    Ok(received) => received,
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
                if question.domain.to_string() != DOMAIN {
                    continue;
                }
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
                    rdlength: ANSWER.len() as u16,
                    rdata: ANSWER.to_vec(),
                });
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

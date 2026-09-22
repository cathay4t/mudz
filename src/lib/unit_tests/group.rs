// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicUsize, Ordering},
};

use super::*;
use crate::{
    DnsPacket, DnsResponseCode, DnsType,
    config::{
        MudzConfig, MudzDohConfig, MudzFallbackConfig, MudzGroupConfig,
        MudzMainConfig,
    },
    host::HostsFile,
    retry::now_secs,
};

fn test_config(fallback_ns: &str) -> MudzConfig {
    MudzConfig {
        main: MudzMainConfig::default(),
        fallback: MudzFallbackConfig {
            nameservers: vec![fallback_ns.to_string()],
            disable_ipv6: false,
        },
        doh: None,
        groups: HashMap::new(),
    }
}

/// Spawn a fake plain-TCP DNS upstream (RFC 7766) on loopback. The listener
/// answers framed queries, and closes a TLS ClientHello immediately so a
/// bare-IP `Auto` probe fails fast and falls through to TCP. The returned
/// counter counts the TLS ClientHello connections so tests can assert how
/// often the opportunistic DoT probe ran.
async fn spawn_tcp_dns_upstream()
-> (SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls_probes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&tls_probes);
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handle_tcp_dns_connection(
                socket,
                Arc::clone(&counter),
            ));
        }
    });
    (addr, task, tls_probes)
}

async fn handle_tcp_dns_connection(
    mut socket: tokio::net::TcpStream,
    tls_probes: Arc<AtomicUsize>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut prefix = [0u8; 2];
    if !matches!(socket.peek(&mut prefix).await, Ok(2)) {
        return;
    }
    // 0x16 0x03 is the start of a TLS record; plain DNS over TCP starts
    // with a small message length whose first byte is usually 0x00.
    if prefix[0] == 0x16 {
        tls_probes.fetch_add(1, Ordering::SeqCst);
        return;
    }
    loop {
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
        let Some(question) = query.first_question() else {
            return;
        };
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
}

/// Nothing listens on the upstream port, so the kernel answers with
/// ICMP port-unreachable; the latched socket error must reach the recv
/// loop (tokio >= 1.51.1, see tokio#8001) and mark the transport
/// broken. Uses its own port so it never collides with the end-to-end
/// tests.
#[tokio::test]
async fn test_transport_broken_on_icmp_refused() {
    let addr: SocketAddr = "127.0.0.1:53537".parse().unwrap();
    let transport = DnsUdpTransport::new("127.0.0.1:53537", addr, "test")
        .await
        .expect("create transport to dead port");
    let query = DnsPacket::new_query("example.com", DnsType::A).expect("query");
    let key = (
        "example.com".to_string(),
        DnsType::A,
        DnsClass::IN,
        query.header.id,
    );
    // Let the receive loop park in recv before triggering the ICMP
    // error, exactly like the running daemon.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rx = transport
        .send_query(&query.to_bytes(), &key)
        .await
        .expect("send query");
    // The reply never comes; the rx oneshot only ends when it is
    // dropped after the timeout future gives up.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(rx);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        transport.state.is_broken(),
        "recv loop must consume the latched ICMP error and mark the transport \
         broken"
    );
    assert!(
        transport.is_broken(),
        "a broken transport must be detected via the transport itself so \
         ensure_transports can evict it"
    );
}

#[tokio::test]
async fn test_transport_is_broken_when_recv_loop_panics() {
    // A transport whose receive loop exits for any reason other than a
    // fatal socket error (here: a panic) must still be detected as
    // broken. `recv_loop` only exits on a fatal error or a panic, so a
    // finished task handle is a reliable liveness signal even when the
    // panic path never ran `mark_broken`.
    let addr: SocketAddr = "127.0.0.1:53538".parse().unwrap();
    let transport = DnsUdpTransport::new("127.0.0.1:53538", addr, "test")
        .await
        .expect("create transport");
    assert!(
        !transport.is_broken(),
        "a freshly created transport must be live"
    );

    // Abort the receive loop to simulate a silent exit (e.g. a panic
    // in `recv_loop` being caught by tokio). The transport must then
    // be detected as broken without any fatal socket error.
    transport.recv_task.abort();
    // Allow the abort to take effect.
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !transport.is_broken() && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    assert!(
        transport.is_broken(),
        "a transport whose receive loop exited silently must be detected as \
         broken so it is evicted and recreated"
    );
}

#[tokio::test]
async fn test_fallback_servfail_when_no_transports() {
    // An unparseable nameserver address always fails transport creation,
    // leaving the fallback group with no upstream connections.
    let config = test_config("not-an-address");
    let groups = DnsGroups::new(config, None);
    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");

    // Must be a SERVFAIL reply, not an error: the resolver turns the
    // former into a reply to the client.
    let resp = groups
        .request(query)
        .await
        .expect("request must return a reply");
    assert_eq!(resp.header.rcode, DnsResponseCode::ServFail);
    assert!(resp.header.qr);
    assert_eq!(resp.questions[0].domain.to_string(), "example.com");
}

#[tokio::test]
async fn test_group_transports_created_on_demand() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );

    {
        let state = group.state.read().await;
        assert!(
            state.udp_transports.is_empty(),
            "no upstream transport should be created until first request"
        );
    }

    assert!(group.ensure_transports().await);
    let state = group.state.read().await;
    assert_eq!(state.udp_transports.len(), 1);
}

/// A bare IP nameserver whose configured port refuses TLS and TCP must still
/// yield a UDP transport. The test picks a free loopback port and closes the
/// listener, so both stream probes connect to the *configured* port and are
/// refused by the kernel (ECONNREFUSED) — `create_upstream` then falls back
/// to a UDP transport for the same address.
#[tokio::test]
async fn test_ip_nameserver_falls_back_to_udp() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(
        group.ensure_transports().await,
        "create_state must succeed by falling back to UDP"
    );
    let state = group.state.read().await;
    assert_eq!(state.dot_transports.len(), 0);
    assert_eq!(state.tcp_transports.len(), 0);
    assert_eq!(
        state.udp_transports.len(),
        1,
        "the fallback UDP transport must exist for the IP nameserver"
    );
}

/// `udp://` forces plain UDP: the transport is created even though no TCP
/// or TLS endpoint exists.
#[tokio::test]
async fn test_forced_udp_scheme_creates_only_udp() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![format!("udp://{addr}")],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(group.transport_counts().await, (1, 0, 0, 0));
}

/// `tcp://` forces plain DNS over TCP and resolves through the shared
/// framed-stream transport.
#[tokio::test]
async fn test_forced_tcp_scheme_resolves_over_tcp() {
    let (addr, server, _tls_probes) = spawn_tcp_dns_upstream().await;
    let group = DnsGroup::new(
        "test".to_string(),
        vec![format!("tcp://{addr}")],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(
        group.transport_counts().await,
        (0, 1, 0, 0),
        "tcp:// must create exactly one plain-TCP transport"
    );

    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    let resp = group
        .request(query)
        .await
        .expect("TCP upstream must answer");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    server.abort();
}

/// A bare IP address prefers TCP over UDP once the TLS probe fails, matching
/// the documented TLS -> TCP -> UDP order.
#[tokio::test]
async fn test_bare_ip_prefers_tcp_over_udp() {
    let (addr, server, _tls_probes) = spawn_tcp_dns_upstream().await;
    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(
        group.transport_counts().await,
        (0, 1, 0, 0),
        "a bare IP must use TCP when the DoT probe fails"
    );

    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    let resp = group
        .request(query)
        .await
        .expect("TCP upstream must answer");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    server.abort();
}

/// The opportunistic DoT probe for a bare IP runs once per endpoint: a
/// transport recreated after the upstream closed its TCP stream must go
/// straight to the plaintext fallback instead of probing TLS again.
#[tokio::test]
async fn test_dot_probe_cached_across_transport_recreation() {
    let (addr, server, tls_probes) = spawn_tcp_dns_upstream().await;
    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(group.transport_counts().await, (0, 1, 0, 0));
    assert_eq!(
        tls_probes.load(Ordering::SeqCst),
        1,
        "the first transport must probe DoT once"
    );

    // The upstream closed the TCP stream (routine idle close): the next
    // query evicts and recreates the broken transport.
    {
        let state = group.state.read().await;
        state.tcp_transports[0].state.mark_broken();
    }
    group.recreate_gate.set_last_attempt(0);
    assert!(group.ensure_transports().await);
    assert_eq!(
        tls_probes.load(Ordering::SeqCst),
        1,
        "transport recreation must not probe DoT again"
    );
    assert_eq!(
        group.transport_counts().await,
        (0, 1, 0, 0),
        "the recreated transport must still use TCP"
    );

    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    let resp = group
        .request(query)
        .await
        .expect("TCP upstream must answer");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    server.abort();
}

/// A network change invalidates the cached DoT capability: the path to the
/// DoT port may now be usable, so the probe is allowed again.
#[tokio::test]
async fn test_network_change_clears_dot_probe_cache() {
    let (addr, server, tls_probes) = spawn_tcp_dns_upstream().await;
    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(tls_probes.load(Ordering::SeqCst), 1);

    group.handle_network_change().await;
    assert!(group.ensure_transports().await);
    assert_eq!(
        tls_probes.load(Ordering::SeqCst),
        2,
        "a network change must re-probe DoT"
    );
    assert_eq!(group.transport_counts().await, (0, 1, 0, 0));
    server.abort();
}

/// Forced `tls://` and `tcp://` have no fallback: when the endpoint is
/// unreachable the group stays empty instead of quietly switching to UDP.
#[tokio::test]
async fn test_forced_stream_schemes_have_no_fallback() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    for scheme in ["tls", "tcp"] {
        let group = DnsGroup::new(
            "test".to_string(),
            vec![format!("{scheme}://{addr}")],
            false,
            false,
            None,
            DohOptions::default(),
        );
        assert!(
            !group.ensure_transports().await,
            "{scheme}:// must not fall back to UDP"
        );
        assert_eq!(group.transport_counts().await, (0, 0, 0, 0));
    }
}

/// `tls://hostname` depends on the startup-pinned bootstrap cache. Config
/// validation rejects this combination without a [doh] section, but the
/// group must also fail gracefully rather than panicking or falling back.
#[tokio::test]
async fn test_dot_hostname_without_bootstrap_cache_fails() {
    let group = DnsGroup::new(
        "test".to_string(),
        vec!["tls://dns.example.com".to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(!group.ensure_transports().await);
    assert_eq!(group.transport_counts().await, (0, 0, 0, 0));
}

/// A broken transport in a group that still has a live upstream must be
/// recreated instead of being dropped silently. The recreation gate delays
/// the attempt; until then the broken member is kept (but skipped by
/// requests) so it is not forgotten.
#[tokio::test]
async fn test_broken_transport_recreated_with_live_peer() {
    let probe_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let probe_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addrs = [probe_a.local_addr().unwrap(), probe_b.local_addr().unwrap()];
    drop(probe_a);
    drop(probe_b);

    let group = DnsGroup::new(
        "test".to_string(),
        addrs.iter().map(|a| a.to_string()).collect(),
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    {
        let state = group.state.read().await;
        assert_eq!(state.udp_transports.len(), 2);
        // Simulate a receive loop that died: this transport can never
        // dispatch a response again.
        state.udp_transports[0].state.mark_broken();
    }

    // While the recreation gate is closed, the broken member must be kept
    // (and skipped by the request path) so a later request retries it.
    group.recreate_gate.set_last_attempt(now_secs());
    assert!(group.ensure_transports().await);
    {
        let state = group.state.read().await;
        assert_eq!(state.udp_transports.len(), 2);
        assert_eq!(
            state
                .udp_transports
                .iter()
                .filter(|t| t.is_broken())
                .count(),
            1,
            "the broken transport must be kept until the retry is allowed"
        );
    }

    // Once the cooldown has elapsed, only the broken member is recreated;
    // the healthy peer's transport is left untouched.
    group.recreate_gate.set_last_attempt(0);
    assert!(group.ensure_transports().await);
    let state = group.state.read().await;
    assert_eq!(state.udp_transports.len(), 2);
    assert!(
        state.udp_transports.iter().all(|t| !t.is_broken()),
        "the broken member must be replaced by a live transport"
    );
}

/// Cancelling `ensure_transports` (the request path bounds it with a
/// timeout) must not drop the broken transports before a replacement
/// exists: otherwise a group that still has a live peer would forget the
/// broken nameserver forever.
#[tokio::test]
async fn test_cancelled_recreation_keeps_broken_transport() {
    // A peer that accepts TCP connections but never answers the TLS
    // handshake, so recreating its transport takes the full 1.5 s
    // handshake timeout and can be cancelled mid-flight.
    let hang_listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hang_addr = hang_listener.local_addr().unwrap();
    let hang_task = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = hang_listener.accept().await {
            // Hold the connection open without ever replying.
            sockets.push(socket);
        }
    });

    let live = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let live_addr = live.local_addr().unwrap();
    drop(live);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![hang_addr.to_string(), format!("udp://{live_addr}")],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    assert_eq!(group.transport_counts().await, (1, 1, 0, 0));
    {
        let state = group.state.read().await;
        state.tcp_transports[0].state.mark_broken();
    }

    // The initial creation consumed the group's recreation gate; open it so
    // the next call actually attempts the (hanging) recreation.
    group.recreate_gate.set_last_attempt(0);
    // The initial creation cached the failed DoT probe; clear it so the
    // recreation still goes through the hanging TLS handshake this test
    // needs to cancel.
    group.dot_probe_cache.clear();

    // The recreation hangs in the TLS handshake and is cancelled by the
    // request-path timeout.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            group.ensure_transports()
        )
        .await
        .is_err(),
        "the recreation must still be running when the guard fires"
    );

    let state = group.state.read().await;
    assert_eq!(
        state.tcp_transports.len(),
        1,
        "the broken transport must survive a cancelled recreation"
    );
    assert!(state.tcp_transports[0].is_broken());
    assert_eq!(state.udp_transports.len(), 1);
    hang_task.abort();
}

#[tokio::test]
async fn test_named_group_resolves_when_fallback_unavailable() {
    let upstream =
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_addr = upstream.local_addr().unwrap();
    let server = upstream.clone();
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = tokio::time::timeout(
            Duration::from_secs(5),
            server.recv_from(&mut buf),
        )
        .await
        .expect("named group must query its upstream")
        .unwrap();
        let query = DnsPacket::parse(&buf[..len]).unwrap();
        let question = query.first_question().unwrap();
        let reply = DnsPacket::new_reply(
            query.header.id,
            DnsResponseCode::NoError,
            question.domain.clone(),
            question.kind,
            question.class,
            true,
        );
        server.send_to(&reply.to_bytes(), peer).await.unwrap();
    });

    let mut groups = HashMap::new();
    groups.insert(
        "corp".to_string(),
        MudzGroupConfig {
            nameservers: vec![upstream_addr.to_string()],
            domains: vec!["corp.example".to_string()],
            disable_ipv6: false,
        },
    );
    let config = MudzConfig {
        main: MudzMainConfig::default(),
        fallback: MudzFallbackConfig {
            nameservers: vec!["not-an-address".to_string()],
            disable_ipv6: false,
        },
        doh: None,
        groups,
    };
    let groups = DnsGroups::new(config, None);

    let resp = groups
        .request(
            DnsPacket::new_query("host.corp.example", DnsType::A)
                .expect("build query"),
        )
        .await
        .expect("named group request must succeed");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    server_task.await.unwrap();
}

fn test_doh_upstream(name: &str) -> Arc<DohUpstream> {
    let client = DohClient::new(
        "https://doh.test/dns-query",
        Arc::new(DohResolvCache::new(HashMap::new())),
        DohOptions::default(),
    )
    .expect("create test DoH client");
    Arc::new(DohUpstream::new(client, name, "test"))
}

fn test_doh_group() -> DnsGroup {
    DnsGroup::new(
        "test".to_string(),
        vec!["https://doh.test/dns-query".to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    )
}

#[tokio::test]
async fn test_handle_resume_resets_doh_health_and_pool() {
    let upstream = test_doh_upstream("doh.test");
    upstream.state.record_failure();
    upstream.state.record_failure();
    assert!(matches!(upstream.state.may_attempt(), Attempt::Dead));

    let group = test_doh_group();
    group
        .state
        .write()
        .await
        .doh_clients
        .push(Arc::clone(&upstream));
    let generation_before = upstream.client.pool_generation();

    group.handle_resume().await;

    assert!(
        matches!(upstream.state.may_attempt(), Attempt::Ready),
        "resume must clear the DoH upstream failure state"
    );
    assert_ne!(
        upstream.client.pool_generation(),
        generation_before,
        "resume must rebuild the DoH connection pool"
    );
}

#[tokio::test]
async fn test_handle_network_change_resets_doh_health_and_pool() {
    let upstream = test_doh_upstream("doh.test");
    upstream.state.record_failure();
    upstream.state.record_failure();
    assert!(matches!(upstream.state.may_attempt(), Attempt::Dead));

    let group = test_doh_group();
    group
        .state
        .write()
        .await
        .doh_clients
        .push(Arc::clone(&upstream));
    let generation_before = upstream.client.pool_generation();

    group.handle_network_change().await;

    assert!(
        matches!(upstream.state.may_attempt(), Attempt::Ready),
        "a network change must clear the DoH upstream failure state"
    );
    assert_ne!(
        upstream.client.pool_generation(),
        generation_before,
        "a network change must rebuild the DoH connection pool"
    );
}

/// A network change must drop the connected UDP transports (their source
/// address was picked when the old route was resolved) and clear the
/// transport recreation cooldown, so a group which was failing is retried
/// by the next query instead of after the retry backoff.
#[tokio::test]
async fn test_handle_network_change_recreates_udp_transport() {
    // Nothing listens on the port: the ICMP port-unreachable answer kills
    // the receive loop, mimicking an upstream behind a vanished gateway.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);
    let transport = {
        let state = group.state.read().await;
        Arc::clone(&state.udp_transports[0])
    };
    transport.state.record_failure();
    transport.state.record_failure();
    assert!(matches!(transport.state.may_attempt(), Attempt::Dead));

    group.recreate_gate.set_last_attempt(now_secs());
    assert!(
        !group.recreate_gate.try_acquire(),
        "the recreation gate must be in its cooldown window"
    );

    group.handle_network_change().await;

    assert!(
        transport.is_broken(),
        "the connected UDP transport must be dropped so it is recreated with \
         a fresh route and source address"
    );
    assert!(
        matches!(transport.state.may_attempt(), Attempt::Broken),
        "the dropped transport must not be probed again"
    );
    assert!(
        group.recreate_gate.try_acquire(),
        "a network change must clear the transport recreation cooldown"
    );
}

#[tokio::test]
async fn test_dead_doh_upstream_is_skipped() {
    let upstream = test_doh_upstream("doh.test");
    upstream.state.record_failure();
    upstream.state.record_failure();

    let group = test_doh_group();
    group
        .state
        .write()
        .await
        .doh_clients
        .push(Arc::clone(&upstream));

    let query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    let err = group
        .request(query)
        .await
        .expect_err("a dead DoH upstream must not be used");
    assert!(
        err.to_string().contains("dead, failing fast"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_ensure_transports_recovers_after_cooldown() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let group = DnsGroup::new(
        "test".to_string(),
        vec![addr.to_string()],
        false,
        false,
        None,
        DohOptions::default(),
    );
    assert!(group.ensure_transports().await);

    // Simulate a failed startup: no transports and a recent retry
    // attempt, so ensure_transports must respect the cooldown.
    *group.state.write().await = GroupState {
        udp_transports: Vec::new(),
        tcp_transports: Vec::new(),
        dot_transports: Vec::new(),
        doh_clients: Vec::new(),
    };
    group.recreate_gate.set_last_attempt(now_secs());
    assert!(
        !group.ensure_transports().await,
        "retry must be refused during the cooldown window"
    );

    // Once the cooldown has elapsed, the transports are recreated.
    group.recreate_gate.set_last_attempt(0);
    assert!(
        group.ensure_transports().await,
        "transports must be recreated after the cooldown"
    );
    let state = group.state.read().await;
    assert_eq!(state.udp_transports.len(), 1);
}

/// Concurrent queries for the same (domain, type, class) with the same
/// client transaction ID but different DNSSEC OK bits must each receive
/// their own response. Before per-query wire ID rewriting, the first
/// response was delivered to every waiter under the shared key, so one
/// caller received the other query's response.
#[tokio::test]
async fn test_concurrent_same_id_queries_not_cross_delivered() {
    // Fake upstream: reply to each query echoing the received ID and the
    // query's DO bit, so the two responses are distinguishable.
    let upstream =
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_addr = upstream.local_addr().unwrap();
    let server = upstream.clone();
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        for _ in 0..2 {
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = DnsPacket::parse(&buf[..n]).unwrap();
            let question = &query.questions[0];
            let mut reply = DnsPacket::new_reply(
                query.header.id,
                DnsResponseCode::NoError,
                question.domain.clone(),
                question.kind,
                question.class,
                true,
            );
            reply.add_opt_record(1232, query.dnssec_ok());
            server.send_to(&reply.to_bytes(), peer).await.unwrap();
        }
    });

    let name = upstream_addr.to_string();
    let transport = DnsUdpTransport::new(&name, upstream_addr, "test")
        .await
        .unwrap();

    // Two queries for the same name/type/class with the same client ID,
    // one with the DNSSEC OK bit set and one without.
    let mut query_do0 =
        DnsPacket::new_query("example.com", DnsType::A).unwrap();
    query_do0.add_opt_record(1232, false);
    let mut query_do1 =
        DnsPacket::new_query("example.com", DnsType::A).unwrap();
    query_do1.add_opt_record(1232, true);
    query_do1.header.id = query_do0.header.id;
    let client_id = query_do0.header.id;
    let question = query_do0.questions[0].clone();
    let key = (
        question.domain.to_string(),
        question.kind,
        question.class,
        client_id,
    );

    let bytes_do0 = query_do0.to_bytes();
    let bytes_do1 = query_do1.to_bytes();
    let (rx_do0, rx_do1) = tokio::join!(
        transport.send_query(&bytes_do0, &key),
        transport.send_query(&bytes_do1, &key),
    );
    let rx_do0 = rx_do0.expect("send DO=0 query");
    let rx_do1 = rx_do1.expect("send DO=1 query");

    let (resp_do0, resp_do1) = tokio::join!(rx_do0, rx_do1);
    let mut resp_do0 = resp_do0.expect("DO=0 response");
    let mut resp_do1 = resp_do1.expect("DO=1 response");
    // Restore the client ID, as `DnsGroup::request_inner` does.
    resp_do0.header.id = client_id;
    resp_do1.header.id = client_id;

    assert_eq!(resp_do0.header.id, client_id);
    assert_eq!(resp_do1.header.id, client_id);
    assert!(
        !resp_do0.dnssec_ok(),
        "DO=0 caller must not receive the DO=1 response"
    );
    assert!(
        resp_do1.dnssec_ok(),
        "DO=1 caller must not receive the DO=0 response"
    );

    server_task.await.unwrap();
}

/// Full group-level exercise against a real DoT-capable upstream that the
/// user cited as a reference (`dig @223.5.5.5 bing.com +tls`). Proves the
/// fan-out actually establishes a `DnsDotTransport` for the IP nameserver
/// (not UDP) and delivers a valid NoError response for the query.
/// `#[ignore]`d for hermetic CI; run on network-enabled machines:
///   cargo test --lib -- --ignored group::tests::test_group_routes_ip_via_dot
#[tokio::test]
#[ignore = "requires outbound connectivity to 223.5.5.5:853"]
async fn test_group_routes_ip_via_dot() {
    let config = test_config("223.5.5.5");
    let groups = DnsGroups::new(config, None);
    let query =
        DnsPacket::new_query("bing.com", DnsType::A).expect("build query");

    let resp = groups.request(query).await.expect("request succeeds");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    assert!(
        !resp.answers.is_empty(),
        "bing.com should have at least one A record"
    );

    // The group should have established a DoT transport (not a UDP one) for
    // this IP nameserver — the probe to 223.5.5.5:853 succeeded and the
    // fallback to UDP did not fire.
    let (udp, tcp, dot, _doh) = groups.fallback.transport_counts().await;
    assert_eq!(dot, 1, "a DoT transport must be established for 223.5.5.5");
    assert_eq!(udp, 0, "UDP fallback must not be active when DoT is up");
    assert_eq!(tcp, 0, "TCP fallback must not be active when DoT is up");

    // A failed probe on an established stream must tear the stream down:
    // a half-open stream never errors, so keeping it would probe the same
    // dead connection forever instead of reconnecting.
    let transport = {
        let state = groups.fallback.state.read().await;
        Arc::clone(&state.dot_transports[0])
    };
    record_upstream_failure(
        Some(Upstream::Dot(Arc::clone(&transport))),
        &MudzError::new(ErrorKind::Timeout, "DoT probe timed out"),
        true,
    )
    .await;
    assert!(
        transport.state.is_broken(),
        "a failed DoT probe must mark the stream broken for recreation"
    );
}

/// `tls://hostname` is resolved through the plain-IP `[doh]` bootstrap
/// nameservers at startup, then connects to the pinned address while the
/// certificate is verified against the hostname (SNI + DNS SANs).
///
/// `#[ignore]`d for hermetic CI; run on network-enabled machines:
///   cargo test --lib -- --ignored group::tests::test_group_routes_tls_hostname
#[tokio::test]
#[ignore = "requires outbound connectivity to 223.5.5.5 and dns.alidns.com"]
async fn test_group_routes_tls_hostname() {
    let config = MudzConfig {
        main: MudzMainConfig::default(),
        fallback: MudzFallbackConfig {
            nameservers: vec!["tls://dns.alidns.com".to_string()],
            disable_ipv6: false,
        },
        doh: Some(MudzDohConfig {
            nameservers: vec![IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))],
            disable_ipv6: true,
            ..Default::default()
        }),
        groups: HashMap::new(),
    };
    let cache = crate::doh::bootstrap_doh_cache(&config, &HostsFile::empty())
        .await
        .expect("the DoT hostname must resolve through the bootstrap servers");
    let groups = DnsGroups::new(config, cache);

    let query =
        DnsPacket::new_query("bing.com", DnsType::A).expect("build query");
    let resp = groups.request(query).await.expect("request succeeds");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    assert!(!resp.answers.is_empty());

    let (udp, tcp, dot, _doh) = groups.fallback.transport_counts().await;
    assert_eq!(dot, 1, "tls://hostname must establish a DoT transport");
    assert_eq!(udp, 0, "a forced tls:// endpoint has no UDP fallback");
    assert_eq!(tcp, 0, "a forced tls:// endpoint has no TCP fallback");
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use mudz::{DnsPacket, DnsResponseCode, DnsType};

use super::*;
use crate::{
    config::{
        DnsUpstreamGroup, MudzConfig, MudzFallbackConfig, MudzMainConfig,
    },
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

/// Nothing listens on the upstream port, so the kernel answers with
/// ICMP port-unreachable; the latched socket error must reach the recv
/// loop (tokio >= 1.51.1, see tokio#8001) and mark the transport
/// broken. Uses its own port so it never collides with the end-to-end
/// tests.
#[tokio::test]
async fn test_transport_broken_on_icmp_refused() {
    let transport = DnsUdpTransport::new("127.0.0.1:53537", "test")
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
    let transport = DnsUdpTransport::new("127.0.0.1:53538", "test")
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
        DnsUpstreamGroup {
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

    let transport = DnsUdpTransport::new(&upstream_addr.to_string(), "test")
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

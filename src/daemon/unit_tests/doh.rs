// SPDX-License-Identifier: Apache-2.0

use mudz::{DnsClass, DnsResourceRecord};

use super::*;
use crate::config::{
    DnsUpstreamGroup, MudzDohConfig, MudzFallbackConfig, MudzMainConfig,
};

fn a_reply(query: &DnsPacket, ips: &[Ipv4Addr]) -> DnsPacket {
    let question = query.first_question().unwrap();
    let mut reply = DnsPacket::new_reply(
        query.header.id,
        DnsResponseCode::NoError,
        question.domain.clone(),
        DnsType::A,
        DnsClass::IN,
        true,
    );
    for ip in ips {
        reply.answers.push(DnsResourceRecord {
            domain: question.domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 4,
            rdata: ip.octets().to_vec(),
        });
    }
    reply.header.ancount = reply.answers.len() as u16;
    reply
}

/// Fake bootstrap nameserver answering A queries with `ips` and the
/// given rcode.
async fn fake_nameserver(
    rcode: DnsResponseCode,
    ips: Vec<Ipv4Addr>,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = DnsPacket::parse(&buf[..len]) else {
                continue;
            };
            if query.questions.first().map(|q| q.kind) != Some(DnsType::A) {
                continue;
            }
            let mut reply = a_reply(
                &query,
                if rcode == DnsResponseCode::NoError {
                    &ips
                } else {
                    &[]
                },
            );
            reply.header.rcode = rcode;
            let _ = socket.send_to(&reply.to_bytes(), peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_resolve_hostname_uses_bootstrap_nameserver() {
    let expected = Ipv4Addr::new(10, 1, 2, 3);
    let addr = fake_nameserver(DnsResponseCode::NoError, vec![expected]).await;
    let ips = resolve_hostname(
        "doh-bootstrap.test",
        &[addr],
        true,
        &HostsFile::new(),
    )
    .await
    .expect("bootstrap resolution must succeed");
    assert_eq!(ips, vec![IpAddr::V4(expected)]);
}

#[tokio::test]
async fn test_resolve_hostname_fails_when_bootstrap_fails() {
    let addr = fake_nameserver(DnsResponseCode::ServFail, Vec::new()).await;
    let err = resolve_hostname(
        "doh-bootstrap.test",
        &[addr],
        true,
        &HostsFile::new(),
    )
    .await
    .expect_err("a failing bootstrap nameserver must abort resolution");
    assert!(
        err.to_string().contains("doh-bootstrap.test"),
        "error must identify the hostname: {err}"
    );
}

#[test]
fn test_doh_hostnames_are_unique_and_lowercased() {
    let mut groups = HashMap::new();
    groups.insert(
        "corp".to_string(),
        DnsUpstreamGroup {
            nameservers: vec![
                "https://DNS.Example.COM/dns-query".to_string(),
                "8.8.8.8".to_string(),
            ],
            domains: Vec::new(),
            disable_ipv6: false,
        },
    );
    let config = MudzConfig {
        main: MudzMainConfig::default(),
        fallback: MudzFallbackConfig {
            nameservers: vec![
                "https://doh.example.org/dns-query".to_string(),
                "https://dns.example.com/dns-query".to_string(),
            ],
            disable_ipv6: false,
        },
        doh: Some(MudzDohConfig {
            nameservers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            disable_ipv6: false,
            ..Default::default()
        }),
        groups,
    };

    let hostnames: Vec<String> =
        doh_hostnames(&config).unwrap().into_iter().collect();
    assert_eq!(
        hostnames,
        vec!["dns.example.com".to_string(), "doh.example.org".to_string()]
    );
}

#[tokio::test]
async fn test_bootstrap_without_doh_is_none() {
    let config = MudzConfig::default();
    let cache = bootstrap_doh_cache(&config, &HostsFile::new())
        .await
        .expect("no DoH configured must not fail");
    assert!(cache.is_none());
}

#[tokio::test]
async fn test_bootstrap_without_doh_section_fails() {
    let config = MudzConfig {
        fallback: MudzFallbackConfig {
            nameservers: vec!["https://dns.example.com/dns-query".to_string()],
            disable_ipv6: false,
        },
        ..Default::default()
    };
    let err = bootstrap_doh_cache(&config, &HostsFile::new())
        .await
        .err()
        .expect("DoH without a [doh] section must fail startup");
    assert!(
        err.to_string().contains("[doh]"),
        "error must mention the missing [doh] section: {err}"
    );
}

#[tokio::test]
async fn test_pinned_connector_rejects_unknown_hostname() {
    let mut connector =
        PinnedTcpConnector::new(Arc::new(DohResolvCache::new(HashMap::new())));
    let uri = Uri::from_static("https://unknown.test/dns-query");

    let err = connector
        .call(uri)
        .await
        .expect_err("hostname outside the pinned registry must not connect");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn test_pinned_connector_uses_pinned_ip_and_uri_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut store = HashMap::new();
    store.insert(
        "doh.test".to_string(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    let mut connector =
        PinnedTcpConnector::new(Arc::new(DohResolvCache::new(store)));
    // Mixed-case hostname and non-default port: the connector must match the
    // pinned entry case-insensitively and connect to the port from the URI.
    let uri = format!("https://DoH.test:{port}/dns-query")
        .parse::<Uri>()
        .unwrap();

    let (accepted, connected) =
        tokio::join!(listener.accept(), connector.call(uri));
    let (_stream, peer) = accepted.expect("pinned connector must connect");
    connected.expect("pinned connector must return the TCP stream");
    assert!(peer.ip().is_loopback());
}

const DOH_PROXY_HOST: &str = "dns.alidns.com";

struct BlackholeProxy {
    port: u16,
    blackhole: tokio::sync::watch::Sender<bool>,
}

impl BlackholeProxy {
    fn url(&self, hostname: &str) -> String {
        format!("https://{hostname}:{}/dns-query", self.port)
    }
}

/// Resolve the real DoH endpoint and start a TCP passthrough proxy on
/// loopback.
///
/// Connections opened before [`BlackholeProxy::blackhole`] is signalled stop
/// forwarding data but stay open, emulating a pooled connection that became
/// half-open after suspend or a network change. Connections opened afterwards
/// are relayed normally.
async fn spawn_blackhole_proxy(hostname: &str) -> BlackholeProxy {
    let targets: Vec<SocketAddr> =
        tokio::net::lookup_host((hostname, DOH_HTTPS_PORT))
            .await
            .expect("resolve DoH endpoint for the test proxy")
            .collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let port = listener.local_addr().unwrap().port();
    let (blackhole, blackhole_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let Some(upstream) = connect_any(&targets).await else {
                continue;
            };
            if *blackhole_rx.borrow() {
                tokio::spawn(relay(client, upstream));
            } else {
                tokio::spawn(relay_until_blackholed(
                    client,
                    upstream,
                    blackhole_rx.clone(),
                ));
            }
        }
    });
    BlackholeProxy { port, blackhole }
}

async fn connect_any(targets: &[SocketAddr]) -> Option<TcpStream> {
    for target in targets {
        if let Ok(stream) = TcpStream::connect(target).await {
            return Some(stream);
        }
    }
    None
}

async fn relay(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn relay_until_blackholed(
    mut client: TcpStream,
    mut upstream: TcpStream,
    mut blackhole: tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
        _ = blackhole.changed() => {
            // Keep the sockets owned and open without reading or writing:
            // the client sees an ESTABLISHED connection that silently
            // swallows requests, like a stale pooled connection whose NAT
            // mapping disappeared during suspend.
            let _held = (client, upstream);
            std::future::pending::<()>().await;
        }
    }
}

/// Regression test for the DoH client wedging after suspend: a request that
/// lands on a blackholed pooled connection must be retried on a fresh
/// connection instead of failing until the daemon is restarted.
#[tokio::test]
async fn test_doh_client_recovers_from_blackholed_connection() {
    // The proxy relays TLS transparently, so the certificate is still the
    // real endpoint's and webpki validation stays enabled.
    let proxy = spawn_blackhole_proxy(DOH_PROXY_HOST).await;
    let mut store = HashMap::new();
    store.insert(
        DOH_PROXY_HOST.to_string(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    );
    let client = DohClient::new(
        &proxy.url(DOH_PROXY_HOST),
        Arc::new(DohResolvCache::new(store)),
        DohOptions::default(),
    )
    .expect("create DoH client");

    let query = DnsPacket::new_query("i.root-servers.net", DnsType::A)
        .expect("build query");
    let first = client
        .request(&query)
        .await
        .expect("first DoH request must succeed through the proxy");
    assert!(
        !first.answers.is_empty(),
        "first reply must carry an answer"
    );

    proxy
        .blackhole
        .send(true)
        .expect("signal the proxy to blackhole the pooled connection");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = std::time::Instant::now();
    let second = client.request(&query).await.expect(
        "a request over the blackholed pooled connection must recover on a \
         fresh connection",
    );
    assert!(
        !second.answers.is_empty(),
        "recovered reply must carry an answer"
    );
    assert!(
        started.elapsed() < DEFAULT_TIMEOUT_SEC,
        "recovery must stay within the DoH timeout budget, took {:?}",
        started.elapsed()
    );
}

#[test]
fn test_doh_transport_error_classification() {
    for kind in [ErrorKind::Timeout, ErrorKind::Bug] {
        assert!(
            is_transport_error(&MudzError::new(
                kind.clone(),
                "transport failure"
            )),
            "{kind} must count as a transport failure"
        );
    }
    for kind in [
        ErrorKind::InvalidPacket,
        ErrorKind::InvalidConfig,
        ErrorKind::InvalidArgument,
    ] {
        assert!(
            !is_transport_error(&MudzError::new(
                kind.clone(),
                "protocol failure"
            )),
            "{kind} must not count as a transport failure"
        );
    }
}

#[test]
fn test_doh_http_status_classification() {
    let retryable = |status: hyper::StatusCode| {
        DohAttemptError::http(status, None).retryable
    };
    assert!(retryable(hyper::StatusCode::TOO_MANY_REQUESTS));
    assert!(retryable(hyper::StatusCode::INTERNAL_SERVER_ERROR));
    assert!(retryable(hyper::StatusCode::SERVICE_UNAVAILABLE));
    assert!(!retryable(hyper::StatusCode::NOT_ACCEPTABLE));
    assert!(!retryable(hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE));
    assert!(!retryable(hyper::StatusCode::BAD_REQUEST));
    assert!(!retryable(hyper::StatusCode::UNAUTHORIZED));
}

#[test]
fn test_doh_retry_after_parsing() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(header::RETRY_AFTER, "7".parse().unwrap());
    assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(7)));

    headers.insert(header::RETRY_AFTER, "not-a-number".parse().unwrap());
    assert_eq!(parse_retry_after(&headers), None);
}

#[test]
fn test_doh_address_rotation_wraps() {
    assert_eq!(rotated_address_index(0, 0, 3), 0);
    assert_eq!(rotated_address_index(2, 1, 3), 0);
    assert_eq!(rotated_address_index(usize::MAX, 1, 3), 0);
}

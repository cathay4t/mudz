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

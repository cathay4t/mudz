// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use super::*;

#[test]
fn test_bare_ipv4_is_auto() {
    let parsed = NameserverEndpoint::parse("192.0.2.1").expect("bare IPv4");
    assert_eq!(parsed.scheme, NameserverScheme::Auto);
    assert_eq!(
        parsed.address,
        NameserverAddress::Ip("192.0.2.1".parse().unwrap())
    );
    assert_eq!(parsed.port_or(853), 853);
    assert_eq!(parsed.port_or(53), 53);
}

#[test]
fn test_bare_ipv6_is_auto() {
    let expected = "2001:db8::1".parse::<IpAddr>().expect("test literal");
    for text in ["2001:db8::1", "[2001:db8::1]"] {
        let parsed = NameserverEndpoint::parse(text).expect("bare IPv6");
        assert_eq!(parsed.scheme, NameserverScheme::Auto);
        assert_eq!(parsed.address, NameserverAddress::Ip(expected));
        assert_eq!(parsed.port, None);
    }
}

/// A port pinned in the configuration must be honored by every transport
/// instead of being replaced by the protocol default.
#[test]
fn test_explicit_port_is_honored() {
    for text in ["192.0.2.1:8530", "[2001:db8::1]:8530"] {
        let parsed = NameserverEndpoint::parse(text).expect("ip:port");
        assert_eq!(parsed.scheme, NameserverScheme::Auto);
        assert_eq!(parsed.port_or(853), 8530);
        assert_eq!(parsed.port_or(53), 8530);
    }
}

#[test]
fn test_transport_schemes_for_ip_literals() {
    let cases = [
        ("tls://192.0.2.1", NameserverScheme::Tls),
        ("tcp://192.0.2.1", NameserverScheme::Tcp),
        ("udp://192.0.2.1", NameserverScheme::Udp),
        ("tls://192.0.2.1:8530", NameserverScheme::Tls),
        ("tcp://192.0.2.1:5353", NameserverScheme::Tcp),
        ("udp://192.0.2.1:5353", NameserverScheme::Udp),
        ("tls://[2001:db8::1]", NameserverScheme::Tls),
        ("tcp://[2001:db8::1]:5353", NameserverScheme::Tcp),
    ];
    for (text, scheme) in cases {
        let parsed = NameserverEndpoint::parse(text).expect("scheme address");
        assert_eq!(parsed.scheme, scheme, "for '{text}'");
        assert!(parsed.address.ip().is_some(), "for '{text}'");
    }
    assert_eq!(
        NameserverEndpoint::parse("tls://192.0.2.1:8530")
            .expect("tls with port")
            .port_or(853),
        8530
    );
}

/// `tls://hostname[:port]` keeps the hostname for SNI and certificate
/// verification; the address is resolved during bootstrap.
#[test]
fn test_tls_hostname() {
    let parsed =
        NameserverEndpoint::parse("tls://dns.alidns.com").expect("hostname");
    assert_eq!(parsed.scheme, NameserverScheme::Tls);
    assert_eq!(
        parsed.address,
        NameserverAddress::Hostname("dns.alidns.com".to_string())
    );
    assert_eq!(parsed.port_or(853), 853);

    let parsed = NameserverEndpoint::parse("tls://DNS.Example.COM:8530")
        .expect("hostname with port");
    assert_eq!(
        parsed.address,
        NameserverAddress::Hostname("dns.example.com".to_string())
    );
    assert_eq!(parsed.port_or(853), 8530);
}

#[test]
fn test_whitespace_is_trimmed() {
    let parsed = NameserverEndpoint::parse("  192.0.2.1  ").expect("padded IP");
    assert_eq!(
        parsed.address,
        NameserverAddress::Ip("192.0.2.1".parse().unwrap())
    );
}

#[test]
fn test_hostname_rejected_for_plain_transports() {
    for text in [
        "dns.example",
        "dns.example:53",
        "tcp://dns.example",
        "udp://dns.example:5353",
    ] {
        let err = NameserverEndpoint::parse(text).expect_err(text);
        assert_eq!(err.kind, ErrorKind::InvalidConfig, "for '{text}'");
    }
}

#[test]
fn test_invalid_addresses_are_rejected() {
    for text in [
        "tls://",
        "tls://dns.example:not-a-port",
        "tls://-bad-.example",
        "foo://192.0.2.1",
        "https://dns.example/dns-query",
        "",
        "not-an-address",
    ] {
        let err = NameserverEndpoint::parse(text).expect_err(text);
        assert_eq!(err.kind, ErrorKind::InvalidConfig, "for '{text}'");
    }
}

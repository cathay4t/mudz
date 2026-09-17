// SPDX-License-Identifier: Apache-2.0

//! Unit tests of the configuration helpers that are not part of the public
//! API.

use std::net::{IpAddr, Ipv4Addr};

use super::{
    MudzConfig, MudzDohConfig, MudzFallbackConfig, extract_doh_hostname,
};

#[test]
fn test_extract_doh_hostname() {
    assert_eq!(
        extract_doh_hostname("https://dns.alidns.com/dns-query"),
        Some("dns.alidns.com".to_string())
    );
    assert_eq!(
        extract_doh_hostname("https://doh.pub/dns-query"),
        Some("doh.pub".to_string())
    );
    assert_eq!(
        extract_doh_hostname("https://dns.google/dns-query"),
        Some("dns.google".to_string())
    );
    assert_eq!(
        extract_doh_hostname("https://dns.google:443/dns-query"),
        Some("dns.google".to_string())
    );
    assert_eq!(extract_doh_hostname("invalid"), None);
    assert_eq!(extract_doh_hostname("https://"), None);
    assert_eq!(extract_doh_hostname("https:///path"), None);
}

#[test]
fn test_tls_hostname_requires_doh_bootstrap() {
    let mut config = MudzConfig {
        fallback: MudzFallbackConfig {
            nameservers: vec!["tls://dns.example.com".to_string()],
            disable_ipv6: false,
        },
        ..Default::default()
    };
    let err = config
        .validate()
        .expect_err("tls://hostname requires the [doh] bootstrap");
    assert!(
        err.to_string().contains("[doh]"),
        "error must mention the missing [doh] section: {err}"
    );

    config.doh = Some(MudzDohConfig {
        nameservers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        ..Default::default()
    });
    config
        .validate()
        .expect("tls://hostname with a [doh] bootstrap must be valid");
}

#[test]
fn test_tls_ip_literal_does_not_require_doh_bootstrap() {
    let config = MudzConfig {
        fallback: MudzFallbackConfig {
            nameservers: vec!["tls://1.1.1.1".to_string()],
            disable_ipv6: false,
        },
        ..Default::default()
    };
    config
        .validate()
        .expect("an IP-literal DoT endpoint needs no resolution");
}

/// A malformed nameserver must fail validation instead of reaching the
/// transport layer, where it would only be logged and leave the group
/// answering SERVFAIL for every query.
#[test]
fn test_invalid_nameservers_are_rejected() {
    for nameserver in [
        "tcp://dns.example.com",
        "udp://dns.example.com:53",
        "foo://1.2.3.4",
        "dns.example.com",
        "8.8.8.8:99999",
        "tls://",
        "https:///dns-query",
    ] {
        let config = MudzConfig {
            fallback: MudzFallbackConfig {
                nameservers: vec![nameserver.to_string()],
                disable_ipv6: false,
            },
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("an invalid nameserver must be rejected");
        assert!(
            err.to_string().contains(nameserver),
            "error '{err}' must name the invalid nameserver '{nameserver}'"
        );
    }
}

/// Every supported nameserver form must still pass validation.
#[test]
fn test_valid_nameservers_are_accepted() {
    let config = MudzConfig {
        fallback: MudzFallbackConfig {
            nameservers: vec![
                "https://dns.example.com/dns-query".to_string(),
                "1.1.1.1".to_string(),
                "2001:db8::1".to_string(),
                "[2001:db8::1]:853".to_string(),
                "1.1.1.1:53".to_string(),
                "tls://1.1.1.1".to_string(),
                "tls://dns.example.com".to_string(),
                "tcp://1.1.1.1:53".to_string(),
                "udp://1.1.1.1".to_string(),
            ],
            disable_ipv6: false,
        },
        doh: Some(MudzDohConfig {
            nameservers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            ..Default::default()
        }),
        ..Default::default()
    };
    config
        .validate()
        .expect("all supported nameserver forms must be valid");
}

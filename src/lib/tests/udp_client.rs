// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr};

use mudz::DnsUdpClient;
use tokio::runtime::Runtime;

#[test]
fn test_query_a_record() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsUdpClient::new().unwrap();
        client.query_a_record("a.root-servers.net").await
    });

    // The query should succeed and return at least one IP address
    assert!(result.is_ok());
    let ips = result.unwrap();
    assert!(!ips.is_empty());

    // Should contain the known fixed IP for a.root-servers.net
    assert!(ips.iter().any(|ip| *ip == Ipv4Addr::new(198, 41, 0, 4)));
}

#[test]
fn test_query_a_record_with_custom_server() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsUdpClient::with_server("8.8.4.4").unwrap();
        client.query_a_record("a.root-servers.net").await
    });

    // The query should succeed
    assert!(result.is_ok());
    let ips = result.unwrap();
    assert!(!ips.is_empty());

    // Should contain the known fixed IP for a.root-servers.net
    assert!(ips.iter().any(|ip| *ip == Ipv4Addr::new(198, 41, 0, 4)));
}

#[test]
fn test_query_a_record_with_cname() {
    // Test a domain that is known to use CNAME redirection
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsUdpClient::new().unwrap();
        // Many domains like this use CNAME chains
        client.query_a_record("www.google.com").await
    });

    // The query should succeed even with CNAME redirection
    assert!(result.is_ok());
    let ips = result.unwrap();
    assert!(!ips.is_empty());
}

#[test]
fn test_query_invalid_domain() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsUdpClient::new().unwrap();
        // This domain shouldn't exist
        client
            .query_a_record("this-domain-definitely-does-not-exist-12345.com")
            .await
    });

    // Should get an error (NXDomain)
    assert!(result.is_err());
}

#[test]
fn test_query_aaaa_record() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsUdpClient::new().unwrap();
        client.query_aaaa_record("a.root-servers.net").await
    });

    // The query should succeed and return at least one IP address
    assert!(result.is_ok());
    let ips = result.unwrap();
    assert!(!ips.is_empty());

    // Should contain the known fixed IPv6 for a.root-servers.net
    let expected_ipv6 = Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30);
    assert!(ips.contains(&expected_ipv6));
}

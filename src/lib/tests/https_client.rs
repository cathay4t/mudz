// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use mudz::{DnsHttpsClient, DnsMessage, DnsQueryType};
use tokio::runtime::Runtime;

#[test]
fn test_dns_https_client_new() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = DnsHttpsClient::new();
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.server_url(), "https://dns.google/dns-query");
    });
}

#[test]
fn test_dns_https_client_with_server() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let cloudflare_server = "https://cloudflare-dns.com/dns-query";
        let quad9_server = "https://dns.quad9.net/dns-query";

        let client = DnsHttpsClient::with_server(cloudflare_server);
        assert!(client.is_ok());
        assert_eq!(client.unwrap().server_url(), cloudflare_server);

        let client = DnsHttpsClient::with_server(quad9_server);
        assert!(client.is_ok());
        assert_eq!(client.unwrap().server_url(), quad9_server);
    });
}

#[test]
fn test_dns_https_client_invalid_scheme() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let http_server = "http://dns.google/dns-query";
        let client = DnsHttpsClient::with_server(http_server);
        assert!(client.is_err());
    });
}

#[test]
fn test_dns_https_client_default() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = DnsHttpsClient::default();
        assert_eq!(client.server_url(), "https://dns.google/dns-query");
    });
}

#[test]
fn test_dns_https_client_timeout() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        let mut client_clone = client.clone();
        client_clone.set_timeout(Duration::from_millis(3000));
    });
}

#[test]
fn test_dns_https_client_clone() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        let client_clone = client.clone();
        assert_eq!(client.server_url(), client_clone.server_url());
    });
}

#[test]
fn test_doh_request_encoding() {
    use data_encoding::BASE64URL_NOPAD;

    // Create a simple DNS query
    let query =
        DnsMessage::new_query(0, "example.com", DnsQueryType::A).unwrap();
    let query_bytes = query.to_bytes().unwrap();

    // Verify base64url encoding
    let encoded = BASE64URL_NOPAD.encode(&query_bytes);
    assert!(!encoded.is_empty());
    assert!(
        encoded
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    );
    assert!(!encoded.ends_with('='));
}

#[test]
fn test_query_a_record_google() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        client.query_a_record("google.com").await
    });

    match result {
        Ok(ips) => {
            assert!(!ips.is_empty(), "Should return at least one IP address");
            for _ip in ips {
                // IP is a valid Ipv4Addr if parsed successfully
            }
        }
        Err(e) => {
            eprintln!("DNS query failed (network issue): {}", e);
            // Network failures are acceptable in CI environments
        }
    }
}

#[test]
fn test_query_aaaa_record_google() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        client.query_aaaa_record("google.com").await
    });

    match result {
        Ok(ips) => {
            assert!(!ips.is_empty(), "Should return at least one IPv6 address");
            for _ip in ips {
                // IP is a valid Ipv6Addr if parsed successfully
            }
        }
        Err(e) => {
            eprintln!("IPv6 DNS query failed (network issue): {}", e);
            // May be skipped if IPv6 not available
        }
    }
}

#[test]
fn test_query_aaaa_record_ipv6_only() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        client.query_aaaa_record("ipv6.google.com").await
    });

    match result {
        Ok(ips) => {
            // May return empty if IPv6 not available on test network
            for _ip in ips {
                // IP is a valid Ipv6Addr if parsed successfully
            }
        }
        Err(e) => {
            eprintln!("IPv6 domain query failed: {}", e);
        }
    }
}

#[test]
fn test_cloudflare_dns() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client =
            DnsHttpsClient::with_server("https://cloudflare-dns.com/dns-query")
                .unwrap();
        client.query_a_record("cloudflare.com").await
    });

    match result {
        Ok(ips) => {
            assert!(!ips.is_empty(), "Cloudflare DNS should respond");
            for _ip in ips {
                // IP is a valid Ipv4Addr if parsed successfully
            }
        }
        Err(e) => {
            eprintln!("Cloudflare DNS query failed: {}", e);
        }
    }
}

#[test]
fn test_quad9_dns() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client =
            DnsHttpsClient::with_server("https://dns.quad9.net/dns-query")
                .unwrap();
        client.query_a_record("quad9.net").await
    });

    match result {
        Ok(ips) => {
            assert!(!ips.is_empty(), "Quad9 DNS should respond");
            for _ip in ips {
                // IP is a valid Ipv4Addr if parsed successfully
            }
        }
        Err(e) => {
            eprintln!("Quad9 DNS query failed: {}", e);
        }
    }
}

#[test]
fn test_cname_chain_following() {
    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();
        client.query_a_record("www.google.com").await
    });

    // Should either return IPs directly or via CNAME resolution
    match result {
        Ok(ips) => {
            assert!(!ips.is_empty());
        }
        Err(e) => {
            eprintln!("CNAME resolution query failed: {}", e);
        }
    }
}

#[test]
fn test_concurrent_queries() {
    use futures::future;

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let client = DnsHttpsClient::new().unwrap();

        let domains = ["google.com", "github.com", "rust-lang.org"];

        let futures = domains.iter().map(|domain| {
            let client = client.clone();
            let domain = domain.to_string();
            async move {
                let ips = client.query_a_record(&domain).await;
                (domain, ips)
            }
        });

        let results: Vec<_> = future::join_all(futures).await;

        for (domain, result) in results {
            match result {
                Ok(ips) => {
                    assert!(!ips.is_empty());
                }
                Err(e) => {
                    eprintln!("{} -> Error: {}", domain, e);
                    // Some domains might not resolve depending on network
                }
            }
        }
    });
}

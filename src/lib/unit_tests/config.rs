// SPDX-License-Identifier: Apache-2.0

//! Unit tests of the configuration helpers that are not part of the public
//! API.

use super::extract_doh_hostname;

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

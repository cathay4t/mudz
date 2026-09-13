// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use super::{CacheKey, DnsCacheStore};
use crate::{
    DnsClass, DnsDomainName, DnsHeader, DnsPacket, DnsQuestion,
    DnsResourceRecord, DnsResponseCode, DnsType,
};

fn response_for(domain: &str, ip_last_octet: u8) -> DnsPacket {
    let domain_obj = DnsDomainName::from_str(domain).unwrap();
    DnsPacket {
        header: DnsHeader {
            id: 0x1234,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
            ..Default::default()
        },
        questions: vec![DnsQuestion {
            domain: domain_obj.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
        }],
        answers: vec![DnsResourceRecord {
            domain: domain_obj,
            kind: DnsType::A,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 4,
            rdata: vec![10, 0, 0, ip_last_octet],
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn key_for(domain: &str) -> CacheKey {
    (domain.to_string(), DnsType::A, DnsClass::IN, false)
}

#[test]
fn test_lru_evicts_least_recently_accessed() {
    let mut cache = DnsCacheStore::new(2);

    cache.add(key_for("a.com"), response_for("a.com", 1));
    cache.add(key_for("b.com"), response_for("b.com", 2));

    // Access "a.com" so "b.com" becomes the LRU entry.
    assert!(cache.get(&key_for("a.com")).is_some());

    // Inserting a third entry must evict "b.com" (least recently
    // accessed), not "a.com".
    cache.add(key_for("c.com"), response_for("c.com", 3));

    assert!(
        cache.get(&key_for("a.com")).is_some(),
        "recently accessed entry must survive eviction"
    );
    assert!(
        cache.get(&key_for("b.com")).is_none(),
        "LRU entry must be evicted"
    );
    assert!(cache.get(&key_for("c.com")).is_some());
}

#[test]
fn test_zero_max_size_disables_caching() {
    let mut cache = DnsCacheStore::new(0);
    assert!(!cache.is_enabled());

    cache.add(key_for("a.com"), response_for("a.com", 1));

    assert!(
        cache.get(&key_for("a.com")).is_none(),
        "a disabled cache must not store responses"
    );
}

#[test]
fn test_cache_hit_returns_adjusted_ttl() {
    let mut cache = DnsCacheStore::new(16);
    cache.add(key_for("example.com"), response_for("example.com", 42));

    let cached = cache.get(&key_for("example.com")).expect("cache hit");
    // TTL should be close to 300 (may have decremented by 0-1s).
    assert!(cached.answers[0].ttl <= 300);
    assert!(cached.answers[0].ttl >= 299);
    assert_eq!(cached.answers[0].rdata, vec![10, 0, 0, 42]);
}

#[test]
fn test_add_replaces_existing_entry() {
    let mut cache = DnsCacheStore::new(16);
    cache.add(key_for("example.com"), response_for("example.com", 1));
    cache.add(key_for("example.com"), response_for("example.com", 2));

    let cached = cache.get(&key_for("example.com")).expect("cache hit");
    assert_eq!(
        cached.answers[0].rdata,
        vec![10, 0, 0, 2],
        "re-inserted entry must carry the new data"
    );
    assert_eq!(cache.entries.len(), 1, "no duplicate keys");
}

#[test]
fn test_add_strips_opt_records() {
    let mut cache = DnsCacheStore::new(16);
    let mut response = response_for("example.com", 7);
    let domain = response.questions[0].domain.clone();
    response.additionals.push(DnsResourceRecord {
        domain,
        kind: DnsType::Other(41),
        class: DnsClass::IN,
        ttl: 0,
        rdlength: 0,
        rdata: Vec::new(),
    });
    response.header.arcount = 1;

    cache.add(key_for("example.com"), response);

    let cached = cache.get(&key_for("example.com")).expect("cache hit");
    assert_eq!(cached.header.arcount, 0);
    assert!(
        cached.additionals.iter().all(|r| u16::from(r.kind) != 41),
        "OPT pseudo-records must not be cached"
    );
}

#[test]
fn test_gc_keeps_fresh_entries() {
    let mut cache = DnsCacheStore::new(16);
    cache.add(key_for("example.com"), response_for("example.com", 9));

    cache.gc();

    assert!(
        cache.get(&key_for("example.com")).is_some(),
        "fresh entries must survive GC"
    );
}

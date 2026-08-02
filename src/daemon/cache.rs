// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use mudz::{DnsClass, DnsPacket, DnsType};

const MIN_CACHE_TTL_SEC: u32 = 5;
const MAX_CACHE_TTL_SEC: u32 = 86400;

/// Cache key: (domain, query-type, query-class, DNSSEC-OK bit). The DO bit
/// is part of the key because a DO=1 response may carry RRSIGs that a DO=0
/// client never asked for (and a DO=0 response lacks them for a validator),
/// so the two flavours must not share an entry.
pub(crate) type CacheKey = (String, DnsType, DnsClass, bool);

struct CacheEntry {
    raw_bytes: Vec<u8>,
    insertion_time: Instant,
    last_access: Instant,
    expires_at: Instant,
    ttl_positions: Vec<(usize, u32)>,
}

pub(crate) struct DnsCacheStore {
    entries: HashMap<CacheKey, CacheEntry>,
    max_size: usize,
}

impl DnsCacheStore {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            max_size,
        }
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Evict the least-recently-used entry. O(n) scan, but only called
    /// when the cache is full — far less frequent than cache hits.
    fn evict_lru(&mut self) {
        while self.entries.len() >= self.max_size {
            let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&oldest_key);
        }
    }

    fn dump_cache(&self) {
        if !log::log_enabled!(log::Level::Debug) {
            return;
        }
        log::debug!("Cache dump:");
        for ((domain, kind, class, _dnssec_ok), entry) in &self.entries {
            log::debug!(
                "  {} {}, {:?} (expires in {}s)",
                domain,
                kind,
                class,
                entry
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            );
        }
    }

    pub(crate) fn get(&mut self, request: &DnsPacket) -> Option<Vec<u8>> {
        let question = request.questions.first()?;
        let key = (
            question.domain.to_string(),
            question.kind,
            question.class,
            request.dnssec_ok(),
        );
        let now = Instant::now();

        let entry = self.entries.get_mut(&key)?;
        if entry.expires_at <= now {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!("Cache expired for {}", request.display_brief());
            }
            self.entries.remove(&key);
            return None;
        }

        entry.last_access = now;
        let elapsed = now.saturating_duration_since(entry.insertion_time);

        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Cache hit for {}", request.display_brief());
        }

        let mut bytes = entry.raw_bytes.clone();
        let ttl_sub = elapsed.as_secs() as u32;
        for &(offset, orig_ttl) in &entry.ttl_positions {
            let new_ttl = orig_ttl.saturating_sub(ttl_sub);
            bytes[offset..offset + 4].copy_from_slice(&new_ttl.to_be_bytes());
        }

        Some(bytes)
    }

    pub(crate) fn insert(
        &mut self,
        response: &DnsPacket,
        dnssec_ok: bool,
    ) -> Option<Vec<u8>> {
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            self.evict_lru();
        }
        let question = response.first_question()?;
        let ttl_sec = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
            .filter(|r| u16::from(r.kind) != 41)
            .map(|r| r.ttl)
            .min()
            .unwrap_or(MIN_CACHE_TTL_SEC);
        let ttl_sec = ttl_sec.clamp(MIN_CACHE_TTL_SEC, MAX_CACHE_TTL_SEC);

        let now = Instant::now();
        let mut ttl_positions = Vec::new();
        // Store the response without any OPT record (RFC 6891 §6.2.1); the
        // resolver synthesizes a per-client OPT ack on the way out.
        let raw_bytes = response.to_bytes_without_opt(Some(&mut ttl_positions));

        let key = (
            question.domain.to_string(),
            question.kind,
            question.class,
            dnssec_ok,
        );
        self.entries.insert(
            key,
            CacheEntry {
                raw_bytes: raw_bytes.clone(),
                insertion_time: now,
                last_access: now,
                ttl_positions,
                expires_at: now + Duration::from_secs(ttl_sec as u64),
            },
        );

        Some(raw_bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn debug_dump(&self) {
        self.dump_cache();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use mudz::{
        DnsClass, DnsDomainName, DnsHeader, DnsPacket, DnsQuestion,
        DnsResourceRecord, DnsResponseCode, DnsType,
    };

    use super::DnsCacheStore;

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

    fn query_for(domain: &str) -> DnsPacket {
        DnsPacket::new_query(domain, DnsType::A).unwrap()
    }

    #[test]
    fn test_lru_evicts_least_recently_accessed() {
        let mut cache = DnsCacheStore::new(2);

        cache.insert(&response_for("a.com", 1), false);
        cache.insert(&response_for("b.com", 2), false);

        // Access "a.com" so "b.com" becomes the LRU entry.
        assert!(cache.get(&query_for("a.com")).is_some());

        // Inserting a third entry must evict "b.com" (least recently
        // accessed), not "a.com".
        cache.insert(&response_for("c.com", 3), false);

        assert!(
            cache.get(&query_for("a.com")).is_some(),
            "recently accessed entry must survive eviction"
        );
        assert!(
            cache.get(&query_for("b.com")).is_none(),
            "LRU entry must be evicted"
        );
        assert!(cache.get(&query_for("c.com")).is_some());
    }

    #[test]
    fn test_cache_hit_returns_adjusted_ttl() {
        let mut cache = DnsCacheStore::new(16);
        cache.insert(&response_for("example.com", 42), false);

        let cached = cache.get(&query_for("example.com")).expect("cache hit");
        let parsed = DnsPacket::parse(&cached).unwrap();
        // TTL should be close to 300 (may have decremented by 0-1s).
        assert!(parsed.answers[0].ttl <= 300);
        assert!(parsed.answers[0].ttl >= 299);
        assert_eq!(parsed.answers[0].rdata, vec![10, 0, 0, 42]);
    }

    #[test]
    fn test_insert_replaces_existing_entry() {
        let mut cache = DnsCacheStore::new(16);
        cache.insert(&response_for("example.com", 1), false);
        cache.insert(&response_for("example.com", 2), false);

        let cached = cache.get(&query_for("example.com")).expect("cache hit");
        let parsed = DnsPacket::parse(&cached).unwrap();
        assert_eq!(
            parsed.answers[0].rdata,
            vec![10, 0, 0, 2],
            "re-inserted entry must carry the new data"
        );
        assert_eq!(cache.entries.len(), 1, "no duplicate keys");
    }
}

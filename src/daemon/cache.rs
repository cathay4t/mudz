// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use mudz::{DnsPacket, DnsType};

/// Minimum TTL to cache (seconds)
const MIN_CACHE_TTL_SEC: u32 = 60;
/// Maximum TTL to cache (seconds, 1 day)
const MAX_CACHE_TTL_SEC: u32 = 86400;

/// Cache entry for a DNS query result
struct CacheEntry {
    packet: DnsPacket,
    /// Time this entry was inserted into the cache
    insertion_time: Instant,
    /// Expiry time based on record TTL and clamped to MIN_CACHE_TTL_SEC and
    /// MAX_CACHE_TTL_SEC
    expires_at: Instant,
}

pub(crate) struct DnsCacheStore {
    /// Map of (domain, query_type) -> cache entry
    entries: HashMap<(String, DnsType), CacheEntry>,
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

    fn dump_cache(&self) {
        log::debug!("Cache dump:");
        for ((domain, kind), entry) in &self.entries {
            log::debug!(
                "  {} {} (expires in {}s)",
                domain,
                kind,
                entry
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            );
        }
    }

    pub(crate) fn get(&self, request: &DnsPacket) -> Option<DnsPacket> {
        let domain = request.questions.first().map(|q| q.domain.to_string())?;
        let kind = request.questions.first().map(|q| q.kind)?;

        let now = Instant::now();
        if let Some(entry) = self.entries.get(&(domain, kind))
            && entry.expires_at > now
        {
            log::debug!("Cache hit for {}", request.display_brief());
            let mut ret = entry.packet.clone();
            ret.header.id = request.header.id;
            let elapsed = now.saturating_duration_since(entry.insertion_time);
            let ttl_sub = elapsed.as_secs() as u32;
            for record in ret
                .answers
                .iter_mut()
                .chain(ret.authorities.iter_mut())
                .chain(ret.additionals.iter_mut())
            {
                record.ttl = record.ttl.saturating_sub(ttl_sub);
            }
            Some(ret)
        } else {
            log::debug!("Cache not hit for {}", request.display_brief());
            None
        }
    }

    pub(crate) fn insert(&mut self, response: DnsPacket) {
        // Evict old entries if cache is full
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            if self.entries.len() >= self.max_size {
                for _ in 0..(self.entries.len() - self.max_size + 1) {
                    // TODO: Use LRU eviction instead of removing first entry
                    if let Some(first_key) = self.entries.keys().next().cloned()
                    {
                        self.entries.remove(&first_key);
                    }
                }
            }
        }
        let Some(domain) =
            response.first_question().map(|q| q.domain.to_string())
        else {
            return;
        };
        let Some(kind) = response.first_question().map(|q| q.kind) else {
            return;
        };
        let ttl_sec = response
            .first_record()
            .map(|q| q.ttl)
            .unwrap_or(MIN_CACHE_TTL_SEC);
        let ttl_sec = ttl_sec.clamp(MIN_CACHE_TTL_SEC, MAX_CACHE_TTL_SEC);

        let now = Instant::now();
        self.entries.insert(
            (domain, kind),
            CacheEntry {
                insertion_time: now,
                packet: response,
                expires_at: now + Duration::from_secs(ttl_sec as u64),
            },
        );
        self.dump_cache();
    }
}

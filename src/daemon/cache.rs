// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use mudz::{DnsClass, DnsPacket, DnsType};

const MIN_CACHE_TTL_SEC: u32 = 5;
const MAX_CACHE_TTL_SEC: u32 = 86400;

/// How often expired entries are dropped by [`DnsCacheStore::gc`].
pub(crate) const CACHE_GC_INTERVAL: Duration = Duration::from_secs(60);

/// Cache key: (domain, query-type, query-class, DNSSEC-OK bit). The DO bit
/// is part of the key because a DO=1 response may carry RRSIGs that a DO=0
/// client never asked for (and a DO=0 response lacks them for a validator),
/// so the two flavours must not share an entry.
pub(crate) type CacheKey = (String, DnsType, DnsClass, bool);

struct CacheEntry {
    /// Cached response with its TTLs as received. OPT pseudo-records are
    /// stripped before storing.
    packet: DnsPacket,
    insertion_time: Instant,
    last_access: Instant,
    expires_at: Instant,
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

    /// Drop expired entries.
    pub(crate) fn gc(&mut self) {
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

    /// O(1) hashmap lookup. Returns the cached packet with decremented TTLs,
    /// or `None` on a miss.
    pub(crate) fn get(&mut self, key: &CacheKey) -> Option<DnsPacket> {
        let now = Instant::now();

        let entry = self.entries.get_mut(key)?;
        if entry.expires_at <= now {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!(
                    "Cache expired for {} {:?} {:?} (dnssec_ok={})",
                    key.0,
                    key.1,
                    key.2,
                    key.3
                );
            }
            self.entries.remove(key);
            return None;
        }

        entry.last_access = now;
        let elapsed = now.saturating_duration_since(entry.insertion_time);

        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "Cache hit for {} {:?} {:?} (dnssec_ok={})",
                key.0,
                key.1,
                key.2,
                key.3
            );
        }

        let elapsed = elapsed.as_secs() as u32;
        let mut packet = entry.packet.clone();
        for record in packet
            .answers
            .iter_mut()
            .chain(packet.authorities.iter_mut())
            .chain(packet.additionals.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }

        Some(packet)
    }

    /// Store or refresh the parsed response for `key`.
    pub(crate) fn add(&mut self, key: CacheKey, mut response: DnsPacket) {
        if self.entries.len() >= self.max_size {
            self.gc();
            self.evict_lru();
        }

        // OPT pseudo-records carry EDNS flags instead of a TTL and MUST NOT
        // be cached (RFC 6891 §6.2.1). The resolver synthesizes a per-client
        // OPT ack on the way out.
        let opt_count = response
            .additionals
            .iter()
            .filter(|r| u16::from(r.kind) == 41)
            .count() as u16;
        if opt_count > 0 {
            response.additionals.retain(|r| u16::from(r.kind) != 41);
            response.header.arcount =
                response.header.arcount.saturating_sub(opt_count);
        }

        let ttl_sec = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
            .map(|r| r.ttl)
            .min()
            .unwrap_or(MIN_CACHE_TTL_SEC);
        let ttl_sec = ttl_sec.clamp(MIN_CACHE_TTL_SEC, MAX_CACHE_TTL_SEC);

        let now = Instant::now();
        self.entries.insert(
            key,
            CacheEntry {
                packet: response,
                insertion_time: now,
                last_access: now,
                expires_at: now + Duration::from_secs(ttl_sec as u64),
            },
        );
    }

    #[allow(dead_code)]
    pub(crate) fn debug_dump(&self) {
        self.dump_cache();
    }
}

#[cfg(test)]
#[path = "unit_tests/cache.rs"]
mod tests;

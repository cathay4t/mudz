// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
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
    expires_at: Instant,
    ttl_positions: Vec<(usize, u32)>,
}

pub(crate) struct DnsCacheStore {
    entries: HashMap<CacheKey, CacheEntry>,
    lru_order: VecDeque<CacheKey>,
    max_size: usize,
}

impl DnsCacheStore {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            lru_order: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.lru_order.retain(|key| {
            self.entries.get(key).is_some_and(|e| e.expires_at > now)
        });
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    fn evict_lru(&mut self) {
        while self.entries.len() >= self.max_size {
            if let Some(key) = self.lru_order.pop_back() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    fn touch_lru(&mut self, key: &CacheKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
        }
        self.lru_order.push_front(key.clone());
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

        let expires_at = self.entries.get(&key)?.expires_at;
        if expires_at <= now {
            if log::log_enabled!(log::Level::Debug) {
                log::debug!("Cache expired for {}", request.display_brief());
            }
            self.entries.remove(&key);
            self.lru_order.retain(|k| k != &key);
            return None;
        }

        let entry = self.entries.get(&key)?;
        let (mut bytes, ttl_positions, elapsed) = (
            entry.raw_bytes.clone(),
            entry.ttl_positions.clone(),
            now.saturating_duration_since(entry.insertion_time),
        );

        self.touch_lru(&key);
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Cache hit for {}", request.display_brief());
        }

        let ttl_sub = elapsed.as_secs() as u32;
        for &(offset, orig_ttl) in &ttl_positions {
            let new_ttl = orig_ttl.saturating_sub(ttl_sub);
            bytes[offset..offset + 4].copy_from_slice(&new_ttl.to_be_bytes());
        }

        bytes[0..2].copy_from_slice(&request.header.id.to_be_bytes());

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
        self.lru_order.push_front(key.clone());
        self.entries.insert(
            key,
            CacheEntry {
                raw_bytes: raw_bytes.clone(),
                insertion_time: now,
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

// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use mudz::{DnsPacket, DnsType};

const MIN_CACHE_TTL_SEC: u32 = 60;
const MAX_CACHE_TTL_SEC: u32 = 86400;

pub(crate) type CacheKey = (String, DnsType);

struct CacheEntry {
    packet: DnsPacket,
    insertion_time: Instant,
    expires_at: Instant,
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

    pub(crate) fn get(&mut self, request: &DnsPacket) -> Option<DnsPacket> {
        let domain = request.questions.first().map(|q| q.domain.to_string())?;
        let kind = request.questions.first().map(|q| q.kind)?;

        let now = Instant::now();
        let (cached_packet, elapsed) = {
            let entry = self.entries.get(&(domain.clone(), kind))?;
            if entry.expires_at <= now {
                if log::log_enabled!(log::Level::Debug) {
                    log::debug!(
                        "Cache not hit for {}",
                        request.display_brief()
                    );
                }
                return None;
            }
            (
                entry.packet.clone(),
                now.saturating_duration_since(entry.insertion_time),
            )
        };

        self.touch_lru(&(domain, kind));
        log::debug!("Cache hit for {}", request.display_brief());
        let mut ret = cached_packet;
        ret.header.id = request.header.id;
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
    }

    pub(crate) fn insert(&mut self, response: DnsPacket) {
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            self.evict_lru();
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
        let key = (domain, kind);
        self.lru_order.push_front(key.clone());
        self.entries.insert(
            key,
            CacheEntry {
                insertion_time: now,
                packet: response,
                expires_at: now + Duration::from_secs(ttl_sec as u64),
            },
        );
    }

    #[allow(dead_code)]
    pub(crate) fn debug_dump(&self) {
        self.dump_cache();
    }
}

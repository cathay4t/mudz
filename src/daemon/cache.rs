// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use mudz::DnsQueryType;

/// Minimum TTL to cache (seconds)
pub const MIN_CACHE_TTL: u32 = 60;
/// Maximum TTL to cache (seconds, 1 day)
pub const MAX_CACHE_TTL: u32 = 86400;

/// Cache entry for a DNS query result
pub struct CacheEntry {
    /// Cached DNS message bytes (response format)
    pub response_bytes: Vec<u8>,
    /// Expiry time based on record TTL
    pub expires_at: Instant,
}

/// DNS cache storage
pub struct DnsCache {
    /// Map of (domain, query_type) -> cache entry
    entries: HashMap<(String, DnsQueryType), CacheEntry>,
    /// Maximum number of cache entries
    max_size: usize,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    /// Get a cached response if it exists and hasn't expired
    pub fn get(
        &self,
        domain: &str,
        query_type: DnsQueryType,
    ) -> Option<&CacheEntry> {
        self.entries
            .get(&(domain.to_string(), query_type))
            .filter(|entry| entry.expires_at > Instant::now())
    }

    /// Insert or update a cache entry
    pub fn insert(
        &mut self,
        domain: String,
        query_type: DnsQueryType,
        response: Vec<u8>,
        ttl: u32,
    ) {
        // Clamp TTL to reasonable bounds
        let effective_ttl = ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL);

        // Evict old entries if cache is full
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            // If still full, remove first entry
            if let Some(oldest_key) = self.entries.keys().next().cloned()
                && self.entries.len() >= self.max_size
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            (domain, query_type),
            CacheEntry {
                response_bytes: response,
                expires_at: Instant::now()
                    + Duration::from_secs(effective_ttl as u64),
            },
        );
    }

    /// Remove all expired entries
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Get current cache size
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

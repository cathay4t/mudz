// SPDX-License-Identifier: Apache-2.0

//! Unified fail-cooldown-retry policy for upstream name servers.
//!
//! Every dead-upstream path funnels through this module so failures are
//! handled consistently:
//!
//! * Per upstream ([`UpstreamState`]): consecutive failures (timeouts, send
//!   errors) mark the upstream dead for [`DNS_RETRY_COOLDOWN`] so clients fail
//!   fast with SERVFAIL instead of burning the per-request timeout on every
//!   lookup. After the cooldown one probe query is let through; a successful
//!   reply revives the upstream. A transport whose receive loop died on a fatal
//!   socket error is broken permanently — it is evicted and recreated, never
//!   probed.
//! * Per group ([`CooldownGate`]): transport-recreation attempts are throttled
//!   to at most one per [`DNS_RETRY_COOLDOWN`].

use std::{
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) const DNS_RETRY_COOLDOWN: Duration = Duration::from_secs(5);
/// Upper bound for the exponential probe backoff applied when a probing
/// query fails while the upstream is still dead.
pub(crate) const DNS_RETRY_COOLDOWN_MAX: Duration = Duration::from_secs(60);
/// Consecutive failures (timeout or send error) after which an upstream is
/// declared dead: queries then fail fast with SERVFAIL instead of waiting
/// out the per-request timeout on every lookup. After
/// [`DNS_RETRY_COOLDOWN`] one query is let through as a probe; a
/// successful reply revives the upstream.
pub(crate) const UPSTREAM_FAIL_THRESHOLD: u32 = 2;

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether an upstream may receive the next query.
pub(crate) enum Attempt {
    /// The upstream is alive.
    Ready,
    /// The upstream was dead but its cooldown has elapsed; the caller is
    /// the single probe allowed per cooldown window.
    Probing,
    /// Dead with an active cooldown: skip and fail fast.
    Dead,
    /// The receive loop died on a fatal socket error: this transport can
    /// never dispatch responses again and must be recreated, not probed.
    Broken,
}

#[derive(Default)]
struct HealthState {
    consecutive_failures: u32,
    /// Unix seconds until which the upstream is considered dead; 0 means
    /// alive.
    dead_until: u64,
    /// Current dead window in seconds. Starts at [`DNS_RETRY_COOLDOWN`] and
    /// doubles (up to [`DNS_RETRY_COOLDOWN_MAX`]) every time a probe fails,
    /// so an unreachable upstream is not probed once per cooldown forever.
    cooldown_secs: u64,
    /// The receive loop died on a fatal socket error. Never clears — a
    /// broken transport must be evicted and recreated.
    broken: bool,
}

/// Per-upstream failure, cooldown, and probe state.
///
/// Shared between the request path (which records failures/successes and
/// decides whether to send) and the transport's receive loop (which marks
/// the transport broken on a fatal socket error); hence it is always held
/// in an `Arc`. The name is kept only for log messages.
pub(crate) struct UpstreamState {
    name: String,
    group: String,
    health: Mutex<HealthState>,
}

impl UpstreamState {
    pub(crate) fn new(name: &str, group: &str) -> Self {
        Self {
            name: name.to_string(),
            group: group.to_string(),
            health: Mutex::new(HealthState::default()),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn group(&self) -> &str {
        &self.group
    }

    /// Whether the next query may be sent to this upstream. A dead
    /// upstream is skipped except when its cooldown has elapsed; the
    /// probing query extends the deadline immediately so concurrent
    /// queries never probe in parallel.
    pub(crate) fn may_attempt(&self) -> Attempt {
        let mut health = self.health.lock().expect("health lock poisoned");
        if health.broken {
            return Attempt::Broken;
        }
        let now = now_secs();
        if health.dead_until == 0 {
            return Attempt::Ready;
        }
        if now < health.dead_until {
            return Attempt::Dead;
        }
        let cooldown = if health.cooldown_secs == 0 {
            DNS_RETRY_COOLDOWN.as_secs()
        } else {
            health.cooldown_secs
        };
        health.dead_until = now + cooldown;
        log::debug!(
            "Probing dead upstream '{}' in group '{}'",
            self.name,
            self.group
        );
        Attempt::Probing
    }

    /// Record a failed attempt. Once failures reach
    /// [`UPSTREAM_FAIL_THRESHOLD`], the upstream is declared dead for
    /// [`DNS_RETRY_COOLDOWN`].
    pub(crate) fn record_failure(&self) {
        let mut health = self.health.lock().expect("health lock poisoned");
        health.consecutive_failures += 1;
        if health.consecutive_failures >= UPSTREAM_FAIL_THRESHOLD {
            let was_alive = health.dead_until == 0;
            if health.cooldown_secs == 0 {
                health.cooldown_secs = DNS_RETRY_COOLDOWN.as_secs();
            } else if !was_alive {
                // The upstream stayed dead through a probe: back off.
                health.cooldown_secs = (health.cooldown_secs * 2)
                    .min(DNS_RETRY_COOLDOWN_MAX.as_secs());
            }
            health.dead_until = now_secs() + health.cooldown_secs;
            if was_alive {
                log::warn!(
                    "Upstream '{}' in group '{}' marked dead for {}s after {} \
                     consecutive failures",
                    self.name,
                    self.group,
                    health.cooldown_secs,
                    health.consecutive_failures
                );
            } else {
                log::debug!(
                    "Probe to upstream '{}' in group '{}' failed; next probe \
                     in {}s",
                    self.name,
                    self.group,
                    health.cooldown_secs
                );
            }
        }
    }

    /// Record a successful attempt. A recovery message is only emitted when
    /// the upstream was inside a dead window (that is, it had actually been
    /// marked dead or was being probed); a single failure that never crossed
    /// the dead threshold is not reported as a recovery.
    pub(crate) fn record_success(&self) {
        let mut health = self.health.lock().expect("health lock poisoned");
        if health.dead_until != 0 && !health.broken {
            log::info!(
                "Upstream '{}' in group '{}' recovered",
                self.name,
                self.group
            );
        }
        health.consecutive_failures = 0;
        health.dead_until = 0;
        health.cooldown_secs = 0;
    }

    /// Clear the failure and backoff state without touching the broken flag.
    /// Used when the environment changed in a way that invalidates past
    /// failures, such as resuming from system suspend.
    pub(crate) fn reset(&self) {
        let mut health = self.health.lock().expect("health lock poisoned");
        health.consecutive_failures = 0;
        health.dead_until = 0;
        health.cooldown_secs = 0;
    }

    /// Mark the transport permanently unusable: its receive loop exited on
    /// a fatal socket error, so it can never dispatch responses again.
    /// This never clears — only eviction and recreation does.
    pub(crate) fn mark_broken(&self) {
        self.health.lock().expect("health lock poisoned").broken = true;
    }

    pub(crate) fn is_broken(&self) -> bool {
        self.health.lock().expect("health lock poisoned").broken
    }
}

/// Throttles retry attempts to at most one per cooldown window.
pub(crate) struct CooldownGate {
    last_attempt: AtomicU64,
    cooldown_secs: u64,
}

impl CooldownGate {
    pub(crate) fn new(cooldown: Duration) -> Self {
        Self {
            last_attempt: AtomicU64::new(0),
            cooldown_secs: cooldown.as_secs(),
        }
    }

    /// Record an attempt now and return whether the cooldown had elapsed.
    /// Callers serialize concurrent attempts themselves (the group state
    /// write lock); the atomic only keeps the timestamp consistent.
    pub(crate) fn try_acquire(&self) -> bool {
        let now = now_secs();
        let prev = self.last_attempt.load(Ordering::Acquire);
        if now.wrapping_sub(prev) < self.cooldown_secs {
            return false;
        }
        self.last_attempt.store(now, Ordering::Release);
        true
    }

    /// Seconds remaining in the current cooldown window (0 if ready).
    pub(crate) fn remaining_secs(&self) -> u64 {
        let prev = self.last_attempt.load(Ordering::Acquire);
        self.cooldown_secs
            .saturating_sub(now_secs().wrapping_sub(prev))
    }

    #[cfg(test)]
    pub(crate) fn set_last_attempt(&self, secs: u64) {
        self.last_attempt.store(secs, Ordering::Release);
    }
}

#[cfg(test)]
#[path = "unit_tests/retry.rs"]
mod tests;

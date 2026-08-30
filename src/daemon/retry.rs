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
        health.dead_until = now + DNS_RETRY_COOLDOWN.as_secs();
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
            health.dead_until = now_secs() + DNS_RETRY_COOLDOWN.as_secs();
            if was_alive {
                log::warn!(
                    "Upstream '{}' in group '{}' marked dead for {}s after {} \
                     consecutive failures",
                    self.name,
                    self.group,
                    DNS_RETRY_COOLDOWN.as_secs(),
                    health.consecutive_failures
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
mod tests {
    use super::*;

    fn upstream_state() -> UpstreamState {
        UpstreamState::new("192.0.2.1", "test")
    }

    /// Force the dead window to have elapsed without sleeping.
    fn expire_dead_window(state: &UpstreamState) {
        state
            .health
            .lock()
            .expect("health lock poisoned")
            .dead_until = 1;
    }

    #[test]
    fn test_failure_threshold_marks_dead() {
        let state = upstream_state();
        assert!(matches!(state.may_attempt(), Attempt::Ready));

        state.record_failure();
        assert!(
            matches!(state.may_attempt(), Attempt::Ready),
            "a single failure must not mark the upstream dead"
        );

        state.record_failure();
        assert!(
            matches!(state.may_attempt(), Attempt::Dead),
            "reaching the failure threshold must mark the upstream dead"
        );
    }

    #[test]
    fn test_dead_upstream_probes_once_per_cooldown() {
        let state = upstream_state();
        state.record_failure();
        state.record_failure();
        expire_dead_window(&state);

        assert!(
            matches!(state.may_attempt(), Attempt::Probing),
            "the first query after the cooldown must be the probe"
        );
        assert!(
            matches!(state.may_attempt(), Attempt::Dead),
            "the probe must extend the window: no second probe right away"
        );
    }

    #[test]
    fn test_success_revives_dead_upstream() {
        let state = upstream_state();
        state.record_failure();
        state.record_failure();
        expire_dead_window(&state);
        assert!(matches!(state.may_attempt(), Attempt::Probing));

        state.record_success();
        assert!(
            matches!(state.may_attempt(), Attempt::Ready),
            "a successful probe must revive the upstream"
        );
    }

    #[test]
    fn test_broken_never_recovers() {
        let state = upstream_state();
        state.mark_broken();
        assert!(state.is_broken());
        assert!(matches!(state.may_attempt(), Attempt::Broken));

        state.record_success();
        assert!(
            state.is_broken(),
            "broken means the receive loop is gone: no success can clear it"
        );
        assert!(matches!(state.may_attempt(), Attempt::Broken));
    }

    #[test]
    fn test_cooldown_gate() {
        let gate = CooldownGate::new(DNS_RETRY_COOLDOWN);
        assert!(gate.try_acquire(), "first attempt must pass");
        assert_eq!(gate.remaining_secs(), DNS_RETRY_COOLDOWN.as_secs());
        assert!(!gate.try_acquire(), "cooldown must block the next attempt");

        gate.set_last_attempt(0);
        assert!(
            gate.try_acquire(),
            "attempt must pass once the cooldown has elapsed"
        );
    }
}

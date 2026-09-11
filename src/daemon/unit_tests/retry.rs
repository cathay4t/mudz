// SPDX-License-Identifier: Apache-2.0

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

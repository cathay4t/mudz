// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_normal_clock_progress_is_not_a_resume() {
    let base = Instant::now();
    let mut detector = ResumeDetector {
        last_boottime: Some(Duration::from_secs(100)),
        last_monotonic: base,
    };

    assert_eq!(
        detector
            .observe(Duration::from_secs(110), base + Duration::from_secs(10)),
        None
    );
}

#[test]
fn test_suspend_gap_is_detected_once() {
    let base = Instant::now();
    let mut detector = ResumeDetector {
        last_boottime: Some(Duration::from_secs(100)),
        last_monotonic: base,
    };

    assert_eq!(
        detector
            .observe(Duration::from_secs(170), base + Duration::from_secs(10)),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        detector
            .observe(Duration::from_secs(171), base + Duration::from_secs(11)),
        None,
        "a resume must only be reported once"
    );
}

#[test]
fn test_small_skew_is_ignored() {
    let base = Instant::now();
    let mut detector = ResumeDetector {
        last_boottime: Some(Duration::from_secs(100)),
        last_monotonic: base,
    };

    assert_eq!(detector.observe(Duration::from_secs(101), base), None);
}

#[test]
fn test_monotonic_clock_going_backwards_is_ignored() {
    let base = Instant::now();
    let mut detector = ResumeDetector {
        last_boottime: Some(Duration::from_secs(100)),
        last_monotonic: base + Duration::from_secs(10),
    };

    assert_eq!(detector.observe(Duration::from_secs(101), base), None);
}

#[test]
fn test_missing_baseline_is_initialized_silently() {
    let base = Instant::now();
    let mut detector = ResumeDetector {
        last_boottime: None,
        last_monotonic: base,
    };

    assert_eq!(detector.observe(Duration::from_secs(500), base), None);
    assert_eq!(
        detector
            .observe(Duration::from_secs(510), base + Duration::from_secs(10)),
        None
    );
}

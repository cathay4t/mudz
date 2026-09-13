// SPDX-License-Identifier: Apache-2.0

//! Detects resume from system suspend without requiring a D-Bus connection.
//!
//! `CLOCK_BOOTTIME` keeps counting while the system is suspended, while
//! `CLOCK_MONOTONIC` (which backs [`std::time::Instant`]) stops. Comparing
//! the two clocks therefore reveals a suspend/resume cycle.

use std::time::{Duration, Instant};

/// Smaller gaps can be explained by normal clock read skew and are ignored.
const MIN_SUSPEND_GAP: Duration = Duration::from_secs(2);

pub(crate) struct ResumeDetector {
    last_boottime: Option<Duration>,
    last_monotonic: Instant,
}

impl ResumeDetector {
    pub(crate) fn new() -> Self {
        Self {
            last_boottime: boottime(),
            last_monotonic: Instant::now(),
        }
    }

    /// Returns how long the system was suspended if a resume happened since
    /// the previous call.
    pub(crate) fn poll(&mut self) -> Option<Duration> {
        let boottime = boottime()?;
        self.observe(boottime, Instant::now())
    }

    fn observe(
        &mut self,
        boottime: Duration,
        monotonic: Instant,
    ) -> Option<Duration> {
        let Some(last_boottime) = self.last_boottime else {
            self.last_boottime = Some(boottime);
            self.last_monotonic = monotonic;
            return None;
        };

        let boot_delta =
            boottime.checked_sub(last_boottime).unwrap_or_default();
        let monotonic_delta = monotonic
            .checked_duration_since(self.last_monotonic)
            .unwrap_or_default();

        self.last_boottime = Some(boottime);
        self.last_monotonic = monotonic;

        let suspended =
            boot_delta.checked_sub(monotonic_delta).unwrap_or_default();
        (suspended >= MIN_SUSPEND_GAP).then_some(suspended)
    }
}

fn boottime() -> Option<Duration> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes to the provided timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        log::debug!(
            "Failed to read CLOCK_BOOTTIME for suspend detection: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    let secs = u64::try_from(now.tv_sec).ok()?;
    let nsecs = u32::try_from(now.tv_nsec).ok()?;
    Some(Duration::new(secs, nsecs))
}

#[cfg(test)]
#[path = "unit_tests/suspend.rs"]
mod tests;

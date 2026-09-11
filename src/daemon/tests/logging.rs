// SPDX-License-Identifier: Apache-2.0

//! Log filter tests.
//!
//! The daemon's configured `log_level` must apply to mudz's own crates only;
//! third-party crates (hyper, h2, rustls, ...) must not leak their
//! TRACE/DEBUG chatter into the daemon log when `debug`/`trace` is
//! configured. `RUST_LOG` keeps its full override.

use env_logger::Logger;
use log::{Level, Log, Record};

fn enabled(logger: &Logger, target: &str, level: Level) -> bool {
    let record = Record::builder()
        .args(format_args!("test"))
        .level(level)
        .target(target)
        .module_path(Some("mudzd::doh"))
        .file(Some("main.rs"))
        .line(Some(1))
        .build();
    logger.enabled(record.metadata())
}

fn logger_for(log_level: &str) -> Logger {
    crate::build_logger(log_level, None).build()
}

#[test]
fn trace_level_applies_to_mudz_crates_only() {
    let logger = logger_for("trace");

    // mudz's own modules get the configured trace level.
    assert!(enabled(&logger, "mudzd", Level::Trace));
    assert!(enabled(&logger, "mudzd::doh", Level::Trace));
    assert!(enabled(&logger, "mudzd::group", Level::Trace));
    assert!(enabled(&logger, "mudz", Level::Trace));

    // Third-party crates are capped at info: no h2 TRACE spam.
    assert!(!enabled(&logger, "h2::codec", Level::Trace));
    assert!(!enabled(&logger, "h2::codec", Level::Debug));
    assert!(enabled(&logger, "h2::codec", Level::Info));
    assert!(!enabled(&logger, "hyper::client", Level::Trace));
    assert!(!enabled(&logger, "rustls", Level::Debug));
}

#[test]
fn info_level_keeps_previous_behavior() {
    let logger = logger_for("info");

    assert!(enabled(&logger, "mudzd", Level::Info));
    assert!(!enabled(&logger, "mudzd", Level::Debug));
    // Third parties stay at info, same as before this change.
    assert!(enabled(&logger, "h2::codec", Level::Info));
    assert!(enabled(&logger, "h2::codec", Level::Warn));
    assert!(!enabled(&logger, "h2::codec", Level::Debug));
}

#[test]
fn error_level_keeps_previous_behavior() {
    let logger = logger_for("error");

    assert!(enabled(&logger, "mudzd", Level::Error));
    assert!(!enabled(&logger, "mudzd", Level::Info));
    // Dependency errors must stay visible at any configured level.
    assert!(enabled(&logger, "h2::codec", Level::Error));
    assert!(!enabled(&logger, "h2::codec", Level::Warn));
}

#[test]
fn rust_log_overrides_module_defaults() {
    let logger =
        crate::build_logger("info", Some("h2=trace,mudzd=error")).build();

    // RUST_LOG wins over both the module defaults and the dependency cap.
    assert!(enabled(&logger, "h2::codec", Level::Trace));
    assert!(!enabled(&logger, "mudzd", Level::Info));
    assert!(enabled(&logger, "mudzd", Level::Error));
}

#[test]
fn invalid_log_level_falls_back_to_error() {
    let logger = logger_for("bogus");

    assert!(enabled(&logger, "mudzd", Level::Error));
    assert!(!enabled(&logger, "mudzd", Level::Info));
    assert!(enabled(&logger, "h2::codec", Level::Error));
}

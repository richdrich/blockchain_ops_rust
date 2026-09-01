//! Unit tests for the outbound token-bucket rate limiter (`RateLimiter`) and the
//! `with_rate_limit` builder. The limiter's `poll` takes an injected `Instant`, so these run
//! deterministically without sleeping or touching the network. `RateLimiter` is exposed only
//! under the `test-support` feature (enabled for this crate's own test build).

use algo_ops::{AlgoChainConfig, AlgoOps, RateLimitConfig, RateLimiter};
use std::time::{Duration, Instant};

fn cfg(max_requests: u32, per_millis: u64) -> RateLimitConfig {
    RateLimitConfig {
        max_requests,
        per_millis,
    }
}

#[test]
fn full_bucket_lets_the_burst_through_without_waiting() {
    let start = Instant::now();
    // Capacity 3 over 3 s → one token/s, but the bucket starts full.
    let mut rl = RateLimiter::new(&cfg(3, 3_000), start);

    // The first `max_requests` calls at t0 all proceed immediately (burst capacity).
    assert_eq!(rl.poll(start), Duration::ZERO);
    assert_eq!(rl.poll(start), Duration::ZERO);
    assert_eq!(rl.poll(start), Duration::ZERO);
}

#[test]
fn empty_bucket_returns_the_wait_until_the_next_token() {
    let start = Instant::now();
    // Capacity 1 over 1 s → one token/s.
    let mut rl = RateLimiter::new(&cfg(1, 1_000), start);

    // Drains the single starting token.
    assert_eq!(rl.poll(start), Duration::ZERO);

    // Still at t0: no token yet, must wait ~1 s for the next.
    let wait = rl.poll(start);
    assert!(
        wait > Duration::from_millis(900) && wait <= Duration::from_millis(1_000),
        "expected ~1s wait, got {wait:?}"
    );
}

#[test]
fn tokens_refill_over_elapsed_time() {
    let start = Instant::now();
    // Two tokens per second (capacity 2 over 1 s).
    let mut rl = RateLimiter::new(&cfg(2, 1_000), start);

    // Drain the full bucket.
    assert_eq!(rl.poll(start), Duration::ZERO);
    assert_eq!(rl.poll(start), Duration::ZERO);
    assert!(rl.poll(start) > Duration::ZERO, "bucket should be empty");

    // Half a second later one token has refilled (2/s * 0.5s = 1).
    let later = start + Duration::from_millis(500);
    assert_eq!(rl.poll(later), Duration::ZERO);
    assert!(rl.poll(later) > Duration::ZERO, "only one token refilled");
}

#[test]
fn refill_is_capped_at_capacity() {
    let start = Instant::now();
    let mut rl = RateLimiter::new(&cfg(2, 1_000), start);

    // Idle for a long time; the bucket cannot exceed its capacity of 2.
    let much_later = start + Duration::from_secs(3_600);
    assert_eq!(rl.poll(much_later), Duration::ZERO);
    assert_eq!(rl.poll(much_later), Duration::ZERO);
    assert!(
        rl.poll(much_later) > Duration::ZERO,
        "capacity must cap the accumulated tokens at 2"
    );
}

#[test]
fn zero_config_is_clamped_and_does_not_divide_by_zero() {
    let start = Instant::now();
    // Degenerate config: clamped to at least 1 request / 1 ms rather than panicking.
    let mut rl = RateLimiter::new(&cfg(0, 0), start);
    assert_eq!(rl.poll(start), Duration::ZERO);
    // Next token comes within the clamped 1 ms window.
    let wait = rl.poll(start);
    assert!(wait <= Duration::from_millis(1), "got {wait:?}");
}

#[test]
fn with_rate_limit_records_config_for_round_tripping() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
        .with_rate_limit(100, Duration::from_secs(60));

    let rl = ops
        .config
        .rate_limit
        .as_ref()
        .expect("with_rate_limit should record the limit on the config");
    assert_eq!(rl.max_requests, 100);
    assert_eq!(rl.per_millis, 60_000);
}

#[test]
fn rate_limit_is_none_by_default() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()));
    assert!(
        ops.config.rate_limit.is_none(),
        "the limiter must be off by default so existing behaviour is unchanged"
    );
}

#[test]
fn config_rate_limit_survives_json_round_trip() {
    let mut config = AlgoChainConfig::default();
    config.rate_limit = Some(cfg(50, 10_000));
    let json = serde_json::to_string(&config).expect("serialize");
    let back: AlgoChainConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.rate_limit, Some(cfg(50, 10_000)));
}

#[test]
#[cfg(not(target_os = "ios"))]
fn throttle_is_applied_on_the_real_call_path() {
    // End-to-end: a tight limit (one request per 200 ms, bucket capacity 1) pointed at an
    // unreachable local port, so each `round()` fails fast at connect time and the wall-clock is
    // dominated by the throttle, not the network. The starting token lets the first call through;
    // the next two each wait ~200 ms, so three calls take at least ~400 ms.
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19997; // nothing listening → fast connection-refused
    let ops = AlgoOps::new_for_algorand(None, None, Some(config))
        .with_rate_limit(1, Duration::from_millis(200));

    let start = Instant::now();
    for _ in 0..3 {
        // Each call fails (host unreachable); we only care that it was throttled.
        let _ = ops.round();
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "three throttled calls should take >= ~300 ms, took {elapsed:?}"
    );
}

#[test]
fn config_without_rate_limit_field_deserializes_to_none() {
    // A pre-existing serialized config (no `rate_limit` key) still deserializes, defaulting the
    // new field to `None` — so adding the field is backward compatible.
    let json = r#"{
        "client_api_url": "http://localhost",
        "client_api_port": 4001,
        "indexer_api_url": "http://localhost",
        "indexer_api_port": 8980,
        "token": null,
        "token_key": null,
        "app_id": null,
        "asset_id": null
    }"#;
    let cfg: AlgoChainConfig = serde_json::from_str(json).expect("deserialize legacy config");
    assert!(cfg.rate_limit.is_none());
}

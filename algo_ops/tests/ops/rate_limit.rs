//! Unit tests for the outbound token-bucket rate limiter (`RateLimiter`) and the
//! `with_rate_limit` builder. The limiter's `poll` takes an injected `Instant`, so these run
//! deterministically without sleeping or touching the network. `RateLimiter` is exposed only
//! under the `test-support` feature (enabled for this crate's own test build).

use algo_ops::{AlgoChainConfig, AlgoError, AlgoOps, RateLimitConfig, RateLimitMode, RateLimiter};
use std::time::{Duration, Instant};

// An `AlgoOps` whose endpoint points at a dead local port, so a call fails fast at connect and the
// only thing worth observing is what the rate limiter did *before* the network. `Reject` mode at the
// given bucket size.
fn reject_ops_on_dead_port(max: u32, per: Duration) -> AlgoOps {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19996; // nothing listening → immediate connection-refused
    AlgoOps::new_for_algorand(None, None, Some(config)).with_rate_limit_mode(
        max,
        per,
        RateLimitMode::Reject,
    )
}

fn cfg(max_requests: u32, per_millis: u64) -> RateLimitConfig {
    RateLimitConfig {
        max_requests,
        per_millis,
        mode: RateLimitMode::Block,
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
#[cfg(not(target_os = "ios"))]
fn reject_mode_on_empty_bucket_errors_without_sleeping() {
    // Capacity 1 over a long 2 s window: the first call spends the only token (then fails at
    // connect), leaving the bucket empty. In Reject mode the second call must fail *fast* with a
    // RateLimited error carrying the wait — a Block-mode limiter would instead sleep ~2 s here.
    let ops = reject_ops_on_dead_port(1, Duration::from_secs(2));

    // Drain the single starting token (the network attempt fails, which is fine — the token is spent).
    let _ = ops.round();

    let start = Instant::now();
    let err = ops
        .round()
        .expect_err("an empty bucket in Reject mode must return an error, not block");
    let elapsed = start.elapsed();

    // Fast: no sleeping-until-available (Block would have taken ~2 s).
    assert!(
        elapsed < Duration::from_millis(200),
        "Reject must not sleep; the call took {elapsed:?}"
    );

    let ae = err
        .downcast_ref::<AlgoError>()
        .expect("the rejection should be a typed AlgoError");
    assert!(
        ae.is_rate_limited(),
        "the error must classify as the client's own rate-limit rejection"
    );
    // Distinct from a server-side quota/forbidden stop.
    assert!(!ae.is_quota() && !ae.is_forbidden());

    let retry_after = ae
        .retry_after()
        .expect("a RateLimited error must carry the wait until the next token");
    assert!(retry_after > Duration::ZERO, "retry_after must be positive");
    assert!(
        retry_after <= Duration::from_secs(2),
        "retry_after must be within the bucket refill interval, got {retry_after:?}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
fn reject_mode_does_not_consume_a_token_on_rejection() {
    // A rejected call must not consume a token, so once the bucket refills the next call is let
    // through the limiter (it then fails at the network, but crucially it is *not* rate-limited).
    let ops = reject_ops_on_dead_port(1, Duration::from_millis(200));

    // Spend the starting token, then reject on the empty bucket.
    let _ = ops.round();
    let rejected = ops.round().expect_err("empty bucket should reject");
    assert!(
        rejected
            .downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_rate_limited),
        "the second call should be rate-limited while the bucket is empty"
    );

    // Wait past the refill interval so a token is available again.
    std::thread::sleep(Duration::from_millis(250));

    let after_refill = ops
        .round()
        .expect_err("no node is listening, so the call still fails at the network");
    // The limiter granted a token (refilled) — the failure is the dead endpoint, not a rejection.
    assert!(
        !after_refill
            .downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_rate_limited),
        "after the bucket refills the limiter must let the call through, not reject it"
    );
}

#[test]
fn with_rate_limit_defaults_to_block_mode() {
    // The back-compatible builder keeps today's blocking behaviour.
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
        .with_rate_limit(10, Duration::from_secs(1));
    let mode = ops
        .config
        .rate_limit
        .as_ref()
        .expect("with_rate_limit should record the limit")
        .mode;
    assert_eq!(mode, RateLimitMode::Block);
}

#[test]
fn rate_limit_mode_survives_json_round_trip() {
    let mut config = AlgoChainConfig::default();
    config.rate_limit = Some(RateLimitConfig {
        max_requests: 5,
        per_millis: 1_000,
        mode: RateLimitMode::Reject,
    });
    let json = serde_json::to_string(&config).expect("serialize");
    let back: AlgoChainConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back.rate_limit.expect("rate_limit present").mode,
        RateLimitMode::Reject
    );
}

#[test]
fn rate_limit_config_without_mode_field_defaults_to_block() {
    // A config serialized before `mode` existed still deserializes, defaulting to Block — so adding
    // the field is backward compatible and existing consumers keep blocking.
    let json = r#"{
        "client_api_url": "http://localhost",
        "client_api_port": 4001,
        "indexer_api_url": "http://localhost",
        "indexer_api_port": 8980,
        "token": null,
        "token_key": null,
        "app_id": null,
        "asset_id": null,
        "rate_limit": { "max_requests": 50, "per_millis": 10000 }
    }"#;
    let cfg: AlgoChainConfig = serde_json::from_str(json).expect("deserialize legacy rate_limit");
    assert_eq!(
        cfg.rate_limit.expect("rate_limit present").mode,
        RateLimitMode::Block
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

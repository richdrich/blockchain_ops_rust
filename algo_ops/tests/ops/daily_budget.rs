//! Unit tests for the wall-clock daily-budget backstop (`DailyBudget`), the always-on cumulative
//! request counter (`requests_made`), and their builders on `AlgoOps`. The limiter's `check`/`record`
//! take an injected `now` (unix seconds), so the pure window logic runs deterministically without
//! the wall clock; the counter/enforcement tests point at a dead local port so each call fails fast
//! at connect and the only thing observed is what the limiters did *before* the network. `DailyBudget`
//! is exposed only under the `test-support` feature (enabled for this crate's own test build).

use algo_ops::{
    AlgoChainConfig, AlgoError, AlgoOps, DailyBudget, DailyBudgetConfig, RateLimitMode,
};
use std::time::Duration;

const DAY: u64 = 86_400;

fn cfg(max: u32, offset: u32) -> DailyBudgetConfig {
    DailyBudgetConfig {
        max_requests_per_day: max,
        day_start_offset_secs: offset,
    }
}

// An `AlgoOps` whose endpoint points at a dead local port, so a call fails fast at connect and the
// only thing worth observing is what the limiters/counter did *before* the network.
fn dead_port_ops() -> AlgoOps {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19990; // nothing listening → immediate connection-refused
    AlgoOps::new_for_algorand(None, None, Some(config))
}

// ── Pure `DailyBudget` window logic (injected `now`) ─────────────────────────

#[test]
fn admits_while_under_budget_and_rejects_at_it() {
    let now = 1_700_000_000;
    let mut b = DailyBudget::new(&cfg(3, 0), now, 0);
    for _ in 0..3 {
        assert!(b.check(now).is_ok(), "a request under budget is admitted");
        b.record(now);
    }
    assert!(
        b.check(now).is_err(),
        "the fourth request is over the budget of 3"
    );
}

#[test]
fn rejects_at_budget_with_wait_to_the_next_boundary() {
    // 100 s into a midnight-aligned window, budget of 1.
    let window_start = (1_700_000_000u64 / DAY) * DAY;
    let now = window_start + 100;
    let mut b = DailyBudget::new(&cfg(1, 0), now, 0);
    b.record(now); // spend the only request
    let wait = b.check(now).expect_err("a spent budget rejects");
    // The wait is to the end of the window: DAY - 100.
    assert_eq!(wait, Duration::from_secs(DAY - 100));
}

#[test]
fn check_does_not_consume_only_record_does() {
    let now = 1_700_000_000;
    let mut b = DailyBudget::new(&cfg(1, 0), now, 0);
    // Peeking never spends the budget, however many times.
    for _ in 0..10 {
        assert!(b.check(now).is_ok());
    }
    // The single record spends it.
    b.record(now);
    assert!(b.check(now).is_err(), "record consumed the one request");
}

#[test]
fn window_roll_at_midnight_zeroes_spent() {
    let window_start = (1_700_000_000u64 / DAY) * DAY;
    let mut b = DailyBudget::new(&cfg(2, 0), window_start + 10, 0);
    b.record(window_start + 10);
    b.record(window_start + 20);
    assert!(
        b.check(window_start + 30).is_err(),
        "budget spent within the window"
    );
    // Cross into the next window: spent resets, requests are admitted again.
    let next = window_start + DAY;
    assert!(b.check(next).is_ok(), "the new window admits");
    b.record(next);
    assert!(
        b.check(next + 5).is_ok(),
        "one of two spent in the new window"
    );
}

#[test]
fn window_roll_at_non_midnight_offset_zeroes_spent() {
    // Start-of-day at 08:00 UTC.
    let offset = 8 * 3600;
    let window_start = 19_675u64 * DAY + offset as u64;
    let mut b = DailyBudget::new(&cfg(1, offset), window_start + 60, 0);
    b.record(window_start + 60);
    assert!(
        b.check(window_start + 120).is_err(),
        "spent within the offset window"
    );
    assert!(
        b.check(window_start + DAY - 1).is_err(),
        "still the same window one second before the next 08:00 boundary"
    );
    assert!(
        b.check(window_start + DAY).is_ok(),
        "the next 08:00 boundary rolls the window and admits"
    );
}

#[test]
fn primed_spent_resumes_mid_window() {
    let window_start = (1_700_000_000u64 / DAY) * DAY;
    let now = window_start + 500;
    // Restored with 4 of 5 already spent in this window.
    let mut b = DailyBudget::new(&cfg(5, 0), now, 4);
    assert!(b.check(now).is_ok(), "one request remains");
    b.record(now); // the fifth
    assert!(
        b.check(now).is_err(),
        "the primed count is honored — the budget is now spent"
    );
}

#[test]
fn backward_clock_jump_recomputes_the_window() {
    let window_start = (1_700_000_000u64 / DAY) * DAY;
    let now = window_start + 1_000;
    let mut b = DailyBudget::new(&cfg(1, 0), now, 0);
    b.record(now);
    assert!(b.check(now).is_err(), "spent in the current window");
    // The clock jumps back a full day: the window recomputes rather than trapping `spent`.
    assert!(
        b.check(now - DAY).is_ok(),
        "a backward clock jump recomputes the window and admits"
    );
}

// ── Cumulative request counter ───────────────────────────────────────────────

#[test]
fn requests_made_counts_every_request_even_failures() {
    let ops = dead_port_ops();
    assert_eq!(ops.requests_made(), 0, "starts at zero");
    for _ in 0..3 {
        // Each call fails at connect; we only care that the request was counted.
        let _ = ops.round();
    }
    assert_eq!(
        ops.requests_made(),
        3,
        "every outbound request counts, including failed ones"
    );
}

#[test]
fn with_initial_request_count_is_honored() {
    let ops = dead_port_ops().with_initial_request_count(1_000);
    assert_eq!(ops.requests_made(), 1_000, "resumes from the primed value");
    let _ = ops.round();
    let _ = ops.round();
    assert_eq!(
        ops.requests_made(),
        1_002,
        "counting continues from the primed value"
    );
}

#[test]
fn the_counter_is_shared_across_clones() {
    let ops = dead_port_ops();
    let clone = ops.clone();
    let _ = ops.round();
    let _ = clone.round();
    assert_eq!(ops.requests_made(), 2, "clones share one counter");
    assert_eq!(clone.requests_made(), 2);
}

#[test]
fn a_token_bucket_rejection_is_not_counted() {
    // Reject bucket, capacity 1 over a long window: the first call spends the only token (then fails
    // at connect); the second is rejected by the bucket without a request going out.
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19991;
    let ops = AlgoOps::new_for_algorand(None, None, Some(config)).with_rate_limit_mode(
        1,
        Duration::from_secs(5),
        RateLimitMode::Reject,
    );
    let _ = ops.round(); // spends the token; the request goes out (and fails)
    let rejected = ops
        .round()
        .expect_err("an empty bucket in Reject mode rejects");
    assert!(
        rejected
            .downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_rate_limited),
        "the second call is the client's own rate-limit rejection"
    );
    assert_eq!(
        ops.requests_made(),
        1,
        "a rate-limit rejection made no request, so it is not counted"
    );
}

// ── Daily budget on the real call path + composition with the token bucket ────

#[test]
fn daily_budget_rejects_after_max_on_the_real_path() {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19992;
    let ops = AlgoOps::new_for_algorand(None, None, Some(config)).with_daily_budget(2, 0);

    let _ = ops.round();
    let _ = ops.round();
    assert_eq!(ops.requests_made(), 2, "two requests went out");

    let err = ops.round().expect_err("the daily budget of 2 is spent");
    let ae = err.downcast_ref::<AlgoError>().expect("a typed AlgoError");
    assert!(
        ae.is_daily_budget_exceeded(),
        "the rejection classifies as a daily-budget event"
    );
    assert!(!ae.is_rate_limited(), "distinct from the burst clip");
    assert!(
        ae.retry_after().is_some_and(|d| d > Duration::ZERO),
        "carries the wait to the next day-start reset"
    );
    assert_eq!(
        ops.requests_made(),
        2,
        "the rejected request never went out, so it is not counted"
    );

    let state = ops.daily_budget_state().expect("a budget is configured");
    assert_eq!(state.spent, 2);
    assert_eq!(state.max, 2);
}

#[test]
fn a_token_bucket_rejection_does_not_charge_the_daily_budget() {
    // Both limiters set: a tiny Reject bucket + a large daily budget. When the bucket rejects, the
    // request never goes out, so the daily budget must not be charged.
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19993;
    let ops = AlgoOps::new_for_algorand(None, None, Some(config))
        .with_rate_limit_mode(1, Duration::from_secs(5), RateLimitMode::Reject)
        .with_daily_budget(100, 0);

    let _ = ops.round(); // both admit; daily spent → 1
    let rejected = ops.round().expect_err("the empty bucket rejects");
    assert!(
        rejected
            .downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_rate_limited)
    );
    assert_eq!(
        ops.daily_budget_state().expect("configured").spent,
        1,
        "the token-bucket rejection must not charge the daily budget"
    );
}

#[test]
fn the_daily_budget_is_checked_before_the_token_bucket() {
    // daily max 1, plus a roomy Reject bucket. After one request the daily budget is spent; the next
    // call must fail as daily-budget-exceeded (checked first), not rate-limited.
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19994;
    let ops = AlgoOps::new_for_algorand(None, None, Some(config))
        .with_rate_limit_mode(5, Duration::from_secs(5), RateLimitMode::Reject)
        .with_daily_budget(1, 0);

    let _ = ops.round();
    let err = ops.round().expect_err("the daily budget of 1 is spent");
    let ae = err.downcast_ref::<AlgoError>().expect("a typed AlgoError");
    assert!(ae.is_daily_budget_exceeded());
    assert!(
        !ae.is_rate_limited(),
        "the daily budget is checked before the token bucket"
    );
}

#[test]
fn with_daily_spent_resumes_mid_window_on_the_real_path() {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19995;
    let ops = AlgoOps::new_for_algorand(None, None, Some(config))
        .with_daily_budget(3, 0)
        .with_daily_spent(2);

    // Two already spent this window: one request remains, then the budget is exhausted.
    let _ = ops.round();
    let err = ops
        .round()
        .expect_err("the primed spent count plus one request exhausts the budget");
    assert!(
        err.downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_daily_budget_exceeded)
    );
}

#[test]
fn with_daily_spent_is_a_noop_without_a_budget() {
    let ops = dead_port_ops().with_daily_spent(50);
    assert!(
        ops.daily_budget_state().is_none(),
        "no budget configured → nothing to seed"
    );
}

#[test]
fn a_declared_daily_budget_builds_a_live_limiter() {
    // A daily budget set declaratively (deserialized config) is honored, like `with_daily_budget`.
    let mut config = AlgoChainConfig::default();
    config.client_api_url = "http://127.0.0.1".to_string();
    config.client_api_port = 19996;
    config.daily_budget = Some(cfg(1, 0));
    let ops = AlgoOps::new_for_algorand(None, None, Some(config));

    let _ = ops.round();
    let err = ops
        .round()
        .expect_err("the declared budget of 1 rejects the second request");
    assert!(
        err.downcast_ref::<AlgoError>()
            .is_some_and(AlgoError::is_daily_budget_exceeded)
    );
}

#[test]
fn out_of_range_offset_is_reduced_modulo_a_day() {
    let mk = |offset: u32| {
        let mut config = AlgoChainConfig::default();
        config.client_api_url = "http://127.0.0.1".to_string();
        config.client_api_port = 19997;
        AlgoOps::new_for_algorand(None, None, Some(config))
            .with_daily_budget(10, offset)
            .daily_budget_state()
            .expect("configured")
            .window_start_unix
    };
    assert_eq!(
        mk(DAY as u32 + 3_600),
        mk(3_600),
        "an offset beyond a day reduces modulo 86_400"
    );
}

// ── Config surface ───────────────────────────────────────────────────────────

#[test]
fn with_daily_budget_records_config_for_round_tripping() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
        .with_daily_budget(5_000, 8 * 3600);
    let db = ops
        .config
        .daily_budget
        .as_ref()
        .expect("with_daily_budget should record the budget on the config");
    assert_eq!(db.max_requests_per_day, 5_000);
    assert_eq!(db.day_start_offset_secs, 8 * 3600);
}

#[test]
fn daily_budget_is_none_by_default() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()));
    assert!(
        ops.config.daily_budget.is_none(),
        "the daily backstop must be off by default so existing behaviour is unchanged"
    );
    assert!(ops.daily_budget_state().is_none());
}

#[test]
fn config_daily_budget_survives_json_round_trip() {
    let mut config = AlgoChainConfig::default();
    config.daily_budget = Some(cfg(1_234, 3_600));
    let json = serde_json::to_string(&config).expect("serialize");
    let back: AlgoChainConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.daily_budget, Some(cfg(1_234, 3_600)));
}

#[test]
fn config_without_daily_budget_field_deserializes_to_none() {
    // A pre-existing serialized config (no `daily_budget` key) still deserializes, defaulting the
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
    assert!(cfg.daily_budget.is_none());
}

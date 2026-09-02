# algo_ops

In producing distributed blockchain applications, we found a need for a shared high level interface to
a blockchain (initially Algorand).

This crate is part of that interface - it provides the Algorand implementation of the [`blockchain_ops`] traits, over [`algonaut`].
`AlgoOps` covers accounts, payments, Algorand Standard Assets, and the
Transaction Execution Approval Language (TEAL) application lifecycle, and
implements `BlockChainOps` and `AssetOps`. Construct it with
`AlgoOps::new_for_algorand`.

The consumer is expected to be blockchain-aware: the traits cover what reads
naturally on any chain, while Algorand-specific power is reached directly on
`AlgoOps` or via its native escape hatch (the `algonaut` client accessors).

## Example: print an account balance

`AlgoChainConfig::default()` targets [algokit] localnet (algod on
`localhost:4001`). Start it with `algokit localnet start`, then:

```rust
use algo_ops::{AlgoChainConfig, AlgoOps};

fn main() -> anyhow::Result<()> {
    let address = "P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA".to_string();

    // `AlgoChainConfig::default()` targets algokit localnet (algod on localhost:4001).
    let ops = AlgoOps::new_for_algorand(
        None,
        Some(address.clone()),
        Some(AlgoChainConfig::default()),
    );

    // `account_balance` returns whole ALGO, or `None` if the account does not exist yet.
    match ops.account_balance()? {
        Some(algos) => println!("{address}: {algos} ALGO"),
        None => println!("{address}: account not found"),
    }
    Ok(())
}
```

The same program is a runnable example — `cargo run -p algo_ops --example print_balance -- <ADDRESS>`.

## Outbound rate limiting

Every algod and indexer request funnels through one call path, so a single, optional
outbound rate limit protects a metered endpoint from a busy caller (for example a
consumer polling the current round on every tick). It is off by default, so unset it
behaves exactly as before.

Set it at construction with `with_rate_limit(max, per)` — a token bucket, so up to `max`
requests may burst before the rate settles to `max`/`per`:

```rust
use std::time::Duration;
use algo_ops::{AlgoChainConfig, AlgoOps};

// At most 100 requests per minute to the node/indexer.
let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
    .with_rate_limit(100, Duration::from_secs(60));
```

Or set it declaratively on the config (it round-trips through serialization) via
`AlgoChainConfig::rate_limit = Some(RateLimitConfig { max_requests, per_millis, mode })`. The
limiter is shared across clones of a client, so cloning does not multiply the allowance.

### Block vs Reject mode

When the bucket is empty the limiter's `mode` decides what happens:

- `RateLimitMode::Block` (the default) sleeps the calling thread until a token frees, then
  proceeds. `with_rate_limit(max, per)` uses this — behaviour is unchanged from before.
- `RateLimitMode::Reject` never sleeps: it fails fast with
  `AlgoError::rate_limited { retry_after }`, carrying the wait until the next token, and
  consumes no token. A latency-sensitive caller (e.g. a consensus loop that must not freeze)
  selects it and backs off — or serves cached state — on its own terms.

```rust
use std::time::Duration;
use algo_ops::{AlgoChainConfig, AlgoError, AlgoOps, RateLimitMode};

let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
    .with_rate_limit_mode(100, Duration::from_secs(60), RateLimitMode::Reject);

match ops.round() {
    Ok(round) => { /* use it */ }
    Err(e) => match e.downcast_ref::<AlgoError>() {
        Some(ae) if ae.is_rate_limited() => {
            // Back off for exactly as long as the bucket says, without blocking now.
            let wait = ae.retry_after().unwrap_or(Duration::from_millis(0));
            // schedule a retry after `wait`, or serve cached state
        }
        _ => { /* other error */ }
    },
}
```

A `Reject` rejection is distinct from a server-side 429 (a retryable transient failure) and
from a 403/quota stop: `is_rate_limited()` is true while `is_quota()`/`is_forbidden()` are
false. A rejected call makes no network request and does not consume an internal retry.

## Daily request backstop

The rate limit above is a burst clip: it bounds the short-term rate, not the total over a
day. To stay under a metered provider's per-IP daily request quota (which halts a node until
the provider's start-of-day reset), enable the wall-clock daily budget — independent of the
token bucket, so both may be set: the bucket clips bursts, the budget caps the daily total.
It counts at the same shared per-request hook, so each page of a paged fetch and each retry
counts as one request.

```rust
use std::time::Duration;
use algo_ops::{AlgoChainConfig, AlgoError, AlgoOps, RateLimitMode};

let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()))
    .with_rate_limit_mode(240, Duration::from_secs(60), RateLimitMode::Reject) // burst clip
    .with_daily_budget(50_000, 0);                                             // 50k/day at 00:00 UTC

match ops.round() {
    Ok(round) => { /* use it */ }
    Err(e) => match e.downcast_ref::<AlgoError>() {
        Some(ae) if ae.is_daily_budget_exceeded() => {
            // The self-imposed daily budget is spent — a quota-class event. Log/alarm once and
            // self-heal at the boundary; `retry_after()` is the time to the next day-start reset.
            let _until_reset = ae.retry_after();
        }
        Some(ae) if ae.is_rate_limited() => { /* transient burst clip — back off briefly */ }
        _ => { /* other error */ }
    },
}
```

The start-of-day is a UTC seconds-of-day offset in `[0, 86_400)` (`0` = 00:00 UTC); a consumer
parsing an `HH:MM±TZ` day-start resolves it to that offset first. Set it declaratively on the
config via `AlgoChainConfig::daily_budget = Some(DailyBudgetConfig { max_requests_per_day,
day_start_offset_secs })` (it round-trips through serialization). The daily count is checked
*before* the token bucket, so neither limiter is charged for a request the other blocks.

`is_daily_budget_exceeded()` is distinct from `is_rate_limited()` (a transient burst clip) and
from `is_quota()`/`is_forbidden()` (a server-side 403): all three are false here.

### Persisting the count across restarts

A restart does not refill the provider's quota, so the running total must survive one — a
counter internal to a client instance otherwise resets on both a config rebuild and a process
restart, letting a crash-loop re-spend the budget. Both the cumulative request counter and the
daily-window count are primeable at construction and readable for persistence:

```rust
// Boot: restore the persisted totals into a freshly built client.
let ops = AlgoOps::new_for_algorand(None, None, Some(config))
    .with_daily_budget(50_000, day_start_offset_secs)
    .with_daily_spent(persisted_spent_for_this_window) // resume mid-day rather than from zero
    .with_initial_request_count(persisted_total);      // resume the lifetime counter

// Periodically snapshot to disk.
let total = ops.requests_made();                        // monotonic lifetime total
let state = ops.daily_budget_state();                   // Some({ window_start_unix, spent, max })
```

`requests_made()` counts every outbound request (each page, each retry) and is always on,
independent of any rate limit. Both the counter and the daily budget are shared across clones,
so cloning a client neither multiplies the allowance nor splits the count.

## Distinguishing a quota rejection from a transient failure

A failed call surfaces the underlying HTTP status as a typed `AlgoError`, so a caller can
tell a hard quota/forbidden rejection (do not retry) from a transient failure (retry)
without string-matching the message. Downcast the returned `anyhow::Error`:

```rust
use algo_ops::AlgoError;

// `ops.round()` returns `anyhow::Result<u64>`; downcast a failure to classify it.
match ops.round() {
    Ok(round) => { /* use the current round */ }
    Err(e) => match e.downcast_ref::<AlgoError>() {
        // HTTP 403 daily-quota stop (or a "quota" message): back off, do not retry.
        Some(ae) if ae.is_quota() => { /* stop polling until the quota resets */ }
        // Some other typed failure carrying a status (or `None` when transport-level).
        Some(ae) => { let _status = ae.status(); }
        None => { /* an untyped error */ }
    },
}
```

A per-second server rate limit (HTTP 429) is retried with backoff internally and, if it
still fails, surfaces as `AlgoErrorKind::TransientFailure`; a daily-quota 403 surfaces as
`AlgoErrorKind::HttpError` with `is_quota()` / `is_forbidden()` true.

Part of the [`blockchain_ops_rust`] workspace — see the root README for the full
picture.

[`blockchain_ops`]: https://crates.io/crates/blockchain_ops
[`algonaut`]: https://crates.io/crates/algonaut
[algokit]: https://github.com/algorandfoundation/algokit-cli
[`blockchain_ops_rust`]: https://github.com/richdrich/blockchain_ops_rust

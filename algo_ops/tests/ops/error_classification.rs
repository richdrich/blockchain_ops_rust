//! Unit tests for the typed HTTP-status surface on `AlgoError`: `status()`, `is_forbidden()`,
//! `is_quota()`, and `contextualize()`. These let a caller distinguish a hard 403/quota stop
//! from a transient failure without string-matching the message.

use algo_ops::error::{AlgoError, AlgoErrorKind};

#[test]
fn http_error_carries_its_status_code() {
    let e = AlgoError::http(
        "node_status",
        403,
        "you exceeded daily byte or request quota",
    );
    assert_eq!(e.status(), Some(403));
    assert_eq!(e.kind, AlgoErrorKind::HttpError);
}

#[test]
fn is_forbidden_is_true_only_for_403() {
    assert!(AlgoError::http("op", 403, "forbidden").is_forbidden());
    assert!(!AlgoError::http("op", 400, "bad request").is_forbidden());
    assert!(!AlgoError::http("op", 429, "too many requests").is_forbidden());
    assert!(!AlgoError::transient("op", "retryable").is_forbidden());
    assert!(!AlgoError::unreachable("op", "down").is_forbidden());
}

#[test]
fn is_quota_matches_403_and_quota_messages() {
    // A 403 is the documented daily-quota stop.
    assert!(AlgoError::http("op", 403, "anything").is_quota());
    // Message-based fallback for providers that phrase it differently (case-insensitive).
    assert!(AlgoError::http("op", 400, "Daily QUOTA exceeded").is_quota());
    // A plain 400 with no quota wording is not a quota rejection.
    assert!(!AlgoError::http("op", 400, "bad request").is_quota());
    // A per-second rate limit is transient (429), not a quota stop.
    assert!(!AlgoError::http("op", 429, "too many requests").is_quota());
}

#[test]
fn status_is_none_for_transport_level_errors() {
    assert_eq!(
        AlgoError::unreachable("op", "connection refused").status(),
        None
    );
    assert_eq!(AlgoError::transient("op", "503").status(), None);
}

#[test]
fn contextualize_preserves_a_typed_algo_error_for_downcasting() {
    let typed: anyhow::Error = AlgoError::http("algod call", 403, "quota").into();
    let wrapped = AlgoError::contextualize("failed to get node status", typed);

    let ae = wrapped
        .downcast_ref::<AlgoError>()
        .expect("typed AlgoError must survive contextualize so callers can classify it");
    assert!(ae.is_quota());
    assert!(ae.is_forbidden());
}

#[test]
fn contextualize_prefixes_a_plain_error() {
    let plain = anyhow::anyhow!("some transport glitch");
    let wrapped = AlgoError::contextualize("failed to get node status", plain);
    assert!(wrapped.downcast_ref::<AlgoError>().is_none());
    assert!(
        wrapped.to_string().contains("failed to get node status"),
        "plain errors should still get the operation context: {wrapped}"
    );
}

#[test]
fn display_includes_the_status_when_present() {
    let e = AlgoError::http("node_status", 403, "quota");
    let shown = e.to_string();
    assert!(
        shown.contains("403"),
        "status should appear in Display: {shown}"
    );
}

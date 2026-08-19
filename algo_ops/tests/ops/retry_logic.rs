use algo_ops::AlgoOps;
use algonaut::error::{RequestError, RequestErrorDetails};

fn make_http_error(status: u16) -> algonaut::Error {
    algonaut::Error::Request(RequestError::new(
        None,
        RequestErrorDetails::Http {
            status,
            message: format!("test error {status}"),
        },
    ))
}

fn make_timeout_error() -> algonaut::Error {
    algonaut::Error::Request(RequestError::new(None, RequestErrorDetails::Timeout))
}

fn make_client_error() -> algonaut::Error {
    algonaut::Error::Request(RequestError::new(
        None,
        RequestErrorDetails::Client {
            description: "test client error".to_string(),
        },
    ))
}

#[test]
fn test_retryable_status_codes_constant_contains_expected_codes() {
    let codes = AlgoOps::RETRYABLE_STATUS_CODES;
    assert!(
        codes.contains(&408),
        "408 (request timeout) should be retryable"
    );
    assert!(codes.contains(&425), "425 (too early) should be retryable");
    assert!(
        codes.contains(&429),
        "429 (too many requests) should be retryable"
    );
    assert!(
        codes.contains(&502),
        "502 (bad gateway) should be retryable"
    );
    assert!(
        codes.contains(&503),
        "503 (service unavailable) should be retryable"
    );
    assert!(
        codes.contains(&504),
        "504 (gateway timeout) should be retryable"
    );
}

#[test]
fn test_retryable_status_codes_constant_does_not_contain_non_retryable_codes() {
    let codes = AlgoOps::RETRYABLE_STATUS_CODES;
    assert!(
        !codes.contains(&400),
        "400 (bad request) should not be retryable"
    );
    assert!(
        !codes.contains(&401),
        "401 (unauthorized) should not be retryable"
    );
    assert!(
        !codes.contains(&404),
        "404 (not found) should not be retryable"
    );
    assert!(
        !codes.contains(&500),
        "500 (internal server error) should not be retryable"
    );
}

#[test]
fn test_is_retryable_returns_true_for_408() {
    assert!(AlgoOps::is_retryable(&make_http_error(408)));
}

#[test]
fn test_is_retryable_returns_true_for_425() {
    assert!(AlgoOps::is_retryable(&make_http_error(425)));
}

#[test]
fn test_is_retryable_returns_true_for_429() {
    assert!(AlgoOps::is_retryable(&make_http_error(429)));
}

#[test]
fn test_is_retryable_returns_true_for_502() {
    assert!(AlgoOps::is_retryable(&make_http_error(502)));
}

#[test]
fn test_is_retryable_returns_true_for_503() {
    assert!(AlgoOps::is_retryable(&make_http_error(503)));
}

#[test]
fn test_is_retryable_returns_true_for_504() {
    assert!(AlgoOps::is_retryable(&make_http_error(504)));
}

#[test]
fn test_is_retryable_returns_false_for_400() {
    assert!(!AlgoOps::is_retryable(&make_http_error(400)));
}

#[test]
fn test_is_retryable_returns_false_for_401() {
    assert!(!AlgoOps::is_retryable(&make_http_error(401)));
}

#[test]
fn test_is_retryable_returns_false_for_404() {
    assert!(!AlgoOps::is_retryable(&make_http_error(404)));
}

#[test]
fn test_is_retryable_returns_false_for_500() {
    assert!(!AlgoOps::is_retryable(&make_http_error(500)));
}

#[test]
fn test_is_retryable_returns_false_for_timeout_error() {
    assert!(!AlgoOps::is_retryable(&make_timeout_error()));
}

#[test]
fn test_is_retryable_returns_false_for_client_error() {
    assert!(!AlgoOps::is_retryable(&make_client_error()));
}

#[test]
fn test_is_retryable_returns_false_for_non_request_error() {
    let e = algonaut::Error::Msg("some message".to_string());
    assert!(!AlgoOps::is_retryable(&e));
}

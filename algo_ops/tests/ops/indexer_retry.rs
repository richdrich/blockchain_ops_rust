//! Unit tests for retrying an HTTP 500 on indexer reads (#121). Each test drives a real algonaut
//! request through `indexer_call` or `algod_call` against a local stub server that answers with a
//! scripted sequence of HTTP statuses, then checks how many requests it served and the error.

use algo_ops::error::{AlgoError, AlgoErrorKind};
use algo_ops::{AlgoChainConfig, AlgoOps};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A valid indexer `/health` body, so a 200 decodes.
const HEALTH_BODY: &str =
    r#"{"db-available":true,"is-migrating":false,"message":"ok","round":1,"version":"3.0.0"}"#;

/// The body the Nodely indexer sent with its transient 500 (shortened).
const ERROR_BODY: &str = r#"{"message":"failed while searching for account: current transaction is aborted, commands ignored until end of transaction block (SQLSTATE 25P02)"}"#;

/// Bind a stub HTTP server that answers the n-th request with `statuses[n]` (the last status
/// repeats once the script runs out) and closes each connection. A 200 carries `HEALTH_BODY`;
/// any other status carries `ERROR_BODY`. Returns the address and a count of requests served.
fn scripted_endpoint(statuses: Vec<u16>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            // read the request head; the requests under test carry no body
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let status = *statuses
                .get(n)
                .or(statuses.last())
                .expect("a non-empty status script");
            let (reason, body) = if status == 200 {
                ("OK", HEALTH_BODY)
            } else {
                ("Error", ERROR_BODY)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, served)
}

/// An `AlgoOps` whose algod and indexer both point at `addr`.
fn ops_at(addr: SocketAddr) -> AlgoOps {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = format!("http://{}", addr.ip());
    config.client_api_port = addr.port();
    config.indexer_api_url = format!("http://{}", addr.ip());
    config.indexer_api_port = addr.port();
    AlgoOps::new_for_algorand(None, None, Some(config))
}

/// A `MakeWriter` that appends formatted log output to a shared buffer.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
    }
}

impl Write for CapturedLogs {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `f` with this thread's `warn` (and above) logs captured, returning its result and the logs.
fn with_captured_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    (result, logs.text())
}

fn algo_error(e: &anyhow::Error) -> &AlgoError {
    e.downcast_ref::<AlgoError>()
        .unwrap_or_else(|| panic!("expected an AlgoError, got: {e}"))
}

#[test]
#[cfg(not(target_os = "ios"))]
fn indexer_read_retries_a_500_then_succeeds() {
    let (addr, served) = scripted_endpoint(vec![500, 200]);
    let ops = ops_at(addr);
    let client = ops.indexer_client().expect("indexer client");

    let (result, logs) = with_captured_logs(|| ops.indexer_call(|| client.health()));

    let health = result.expect("the read succeeds after one retry");
    assert!(health.db_available, "the 200 body decodes");
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "one failed attempt, one retry"
    );
    assert!(
        logs.contains("indexer search transient error (attempt 1/3)"),
        "a warn names the retry: {logs}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
fn indexer_read_that_keeps_returning_500_fails_as_transient() {
    let (addr, served) = scripted_endpoint(vec![500]);
    let ops = ops_at(addr);
    let client = ops.indexer_client().expect("indexer client");

    let err = ops
        .indexer_call(|| client.health())
        .expect_err("every attempt fails");

    let e = algo_error(&err);
    assert_eq!(
        e.kind,
        AlgoErrorKind::TransientFailure,
        "fails as transient: {e}"
    );
    assert_eq!(e.operation, "indexer search", "names the indexer: {e}");
    assert_eq!(
        served.load(Ordering::SeqCst),
        4,
        "the first attempt plus 3 retries"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
fn algod_submission_that_returns_500_is_not_retried() {
    let (addr, served) = scripted_endpoint(vec![500, 200]);
    let ops = ops_at(addr);
    let client = ops.algod_client().expect("algod client");

    let err = ops
        .algod_call(|| client.send_raw(&[0u8; 4]))
        .expect_err("the 500 goes back to the caller");

    let e = algo_error(&err);
    assert_eq!(e.kind, AlgoErrorKind::HttpError, "a plain HTTP error: {e}");
    assert_eq!(e.status, Some(500));
    assert_eq!(e.operation, "algod call");
    assert_eq!(served.load(Ordering::SeqCst), 1, "no retry");
}

#[test]
#[cfg(not(target_os = "ios"))]
fn indexer_error_names_the_indexer() {
    let (addr, served) = scripted_endpoint(vec![404]);
    let ops = ops_at(addr);
    let client = ops.indexer_client().expect("indexer client");

    let err = ops
        .indexer_call(|| client.health())
        .expect_err("a 404 is returned");

    let e = algo_error(&err);
    assert_eq!(e.kind, AlgoErrorKind::HttpError);
    assert_eq!(e.status, Some(404));
    assert_eq!(e.operation, "indexer search", "names the indexer: {e}");
    assert!(
        err.to_string().contains("indexer search"),
        "the message names the indexer, not algod: {err}"
    );
    assert_eq!(served.load(Ordering::SeqCst), 1, "a 404 is not retried");
}

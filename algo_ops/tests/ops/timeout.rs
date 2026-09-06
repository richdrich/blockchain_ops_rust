//! Unit tests for the `with_timeout` builder: an algod/indexer call is bounded and cancelled rather
//! than hanging the caller on a stalled endpoint. Drives a real call against a local TCP listener that
//! accepts a connection and never replies, so the HTTP response read blocks until the timeout fires.

use algo_ops::{AlgoChainConfig, AlgoOps};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

/// bind a listener that accepts connections and holds them open without ever reading the request or
/// writing a response — a client's HTTP call blocks on the response read until it is cancelled. Returns
/// the bound address; the listener thread runs for the test's lifetime.
fn stalled_endpoint() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        // Hold every accepted socket open and NEVER read the request or write a response — the client's
        // response read blocks indefinitely, a true hang, so it is the timeout (not a connection close)
        // that ends the call. Keeping the sockets in scope stops them being dropped/closed.
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    addr
}

fn ops_at(addr: SocketAddr, timeout: Option<Duration>) -> AlgoOps {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = format!("http://{}", addr.ip());
    config.client_api_port = addr.port();
    let ops = AlgoOps::new_for_algorand(None, None, Some(config));
    match timeout {
        Some(t) => ops.with_timeout(t),
        None => ops,
    }
}

#[test]
fn with_timeout_bounds_a_stalled_call() {
    let addr = stalled_endpoint();
    let ops = ops_at(addr, Some(Duration::from_millis(300)));

    let start = Instant::now();
    let result = ops.round();
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "a stalled call surfaces an error rather than a value"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the call is bounded near the timeout ({elapsed:?}), not the 30s stall"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("timeout"),
        "the error names the timeout: {message}"
    );
}

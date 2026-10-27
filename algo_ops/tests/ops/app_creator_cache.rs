//! Unit tests for the per-client app-creator cache (#132). Each test points an `AlgoOps` at a local
//! stub algod that answers application-information requests from a scripted sequence of statuses,
//! then checks how many requests reached it: an app's creator is read once per `app_id` and reused by
//! later lookups (and by `Clone`d handles), while a failed lookup is not cached.

use algo_ops::{AlgoChainConfig, AlgoOps};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bind a stub algod that answers the n-th request with `statuses[n]` (the last status repeats once
/// the script runs out) and closes each connection. A 200 carries an application-information body
/// whose creator is `creator`; any other status carries an error body. Returns the address and a
/// count of requests served.
fn scripted_algod(statuses: Vec<u16>, creator: String) -> (SocketAddr, Arc<AtomicUsize>) {
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
                (
                    "OK",
                    format!(
                        r#"{{"id":7,"params":{{"approval-program":"","clear-state-program":"","creator":"{creator}"}}}}"#
                    ),
                )
            } else {
                (
                    "Not Found",
                    r#"{"message":"application does not exist"}"#.to_string(),
                )
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

/// An `AlgoOps` whose algod points at `addr`.
fn ops_at(addr: SocketAddr) -> AlgoOps {
    let mut config = AlgoChainConfig::default();
    config.client_api_url = format!("http://{}", addr.ip());
    config.client_api_port = addr.port();
    AlgoOps::new_for_algorand(None, None, Some(config))
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn app_creator_reads_algod_once_per_app() {
    let (creator, _) = AlgoOps::generate_keypair();
    let (addr, served) = scripted_algod(vec![200], creator.clone());
    let ops = ops_at(addr);

    assert_eq!(ops.app_creator(7).expect("first lookup"), creator);
    assert_eq!(ops.app_creator(7).expect("cached lookup"), creator);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the second lookup of the same app is served from the cache"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn app_creator_cache_is_shared_by_clones() {
    let (creator, _) = AlgoOps::generate_keypair();
    let (addr, served) = scripted_algod(vec![200], creator.clone());
    let ops = ops_at(addr);
    let cloned = ops.clone();

    assert_eq!(ops.app_creator(7).expect("lookup via original"), creator);
    assert_eq!(cloned.app_creator(7).expect("lookup via clone"), creator);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "a clone reuses the original's cached creator"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn app_creator_caches_each_app_separately() {
    let (creator, _) = AlgoOps::generate_keypair();
    let (addr, served) = scripted_algod(vec![200], creator.clone());
    let ops = ops_at(addr);

    ops.app_creator(7).expect("app 7");
    ops.app_creator(8).expect("app 8");
    ops.app_creator(7).expect("app 7 again");
    ops.app_creator(8).expect("app 8 again");
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "one read per distinct app id"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn a_failed_app_creator_lookup_is_not_cached() {
    let (creator, _) = AlgoOps::generate_keypair();
    let (addr, served) = scripted_algod(vec![404, 200], creator.clone());
    let ops = ops_at(addr);

    assert!(
        ops.app_creator(7).is_err(),
        "a 404 from algod is an error, not a creator"
    );
    assert_eq!(
        ops.app_creator(7).expect("retry after the failure"),
        creator
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "the failed lookup was not cached, so the next one re-read algod"
    );
}

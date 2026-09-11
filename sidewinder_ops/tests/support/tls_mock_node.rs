//! A tiny in-process **mutual-TLS** Sidewinder node for the offline discovery/mTLS tests (#375).
//!
//! Presents an identity-bound certificate for a given node key and requires an authenticated client
//! certificate (an authorized identity), then answers `GET /health` with `200`. It uses a blocking
//! `rustls::ServerConnection` on a std thread — the same shape as [`super::mock_node::MockNode`] but over
//! TLS — so no async runtime is needed. Enough to prove a client pins the node identity and presents its
//! own.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sw_identity_tls::server::{IdentityClientVerifier, server_config};
use sw_identity_tls::{StaticMembership, default_provider, generate};

/// A loopback TLS node bound to an ephemeral port; shuts down on drop.
pub struct TlsMockNode {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TlsMockNode {
    /// Start a node whose certificate is bound to `node_key`, accepting client certificates from the
    /// `authorized_clients` identities (as API clients). Returns once the socket is bound.
    pub fn start(node_key: &SigningKey, authorized_clients: Vec<String>) -> TlsMockNode {
        let cert = generate(node_key).expect("mint node identity certificate");
        let authority = Arc::new(StaticMembership::from_sets(Vec::new(), authorized_clients));
        let verifier = Arc::new(IdentityClientVerifier::new(authority, default_provider()));
        let config: Arc<ServerConfig> =
            Arc::new(server_config(cert, verifier).expect("build node server config"));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls mock node");
        listener
            .set_nonblocking(true)
            .expect("set tls mock node nonblocking");
        let addr = listener.local_addr().expect("tls mock node local addr");
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve_connection(stream, config.clone()),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        TlsMockNode {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }

    /// The `https` base URL of this node, for example `https://127.0.0.1:54321`.
    pub fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// The bound socket address (to build an [`sw_identity_tls::EndpointRecord`] pointing at it).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TlsMockNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Complete one mutual-TLS handshake and answer `GET /health` with `200`. Any handshake failure (an
/// unauthorized or absent client certificate) or read error just drops the connection.
fn serve_connection(tcp: TcpStream, config: Arc<ServerConfig>) {
    tcp.set_nonblocking(false).ok();
    let conn = match ServerConnection::new(config) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let mut tls = StreamOwned::new(conn, tcp);

    // read the request line + headers (the handshake is driven by the first read); we only need to
    // consume up to the blank line before responding.
    let mut reader = BufReader::new(&mut tls);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return; // handshake failed or peer hung up.
    }
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header.trim_end_matches(['\r', '\n']).is_empty() => break,
            Ok(_) => continue,
            Err(_) => return,
        }
    }

    let body = b"";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.write_all(body);
    let _ = tls.flush();
}

/// The Algorand address bound to `key` — the identity a client pins, or the node authorizes.
pub fn identity_address(key: &SigningKey) -> String {
    generate(key).expect("mint identity certificate").address
}

//! A tiny in-process HTTP node for the `sidewinder_ops` unit tests.
//!
//! Binds an ephemeral loopback port, serves a fixed routing table (method + path, ignoring the query
//! string), records every request for assertions, and shuts down on drop. No external services and no
//! extra crates — enough to drive [`sidewinder_ops::SidewinderClient`] against canned REST responses.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// One canned response, matched on HTTP method and the path (without its query string).
#[derive(Clone)]
pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Route {
    /// A `200 OK` JSON route.
    pub fn ok_json(method: &'static str, path: &'static str, body: &str) -> Self {
        Self::json(method, path, 200, body)
    }

    /// A JSON route with an explicit status.
    pub fn json(method: &'static str, path: &'static str, status: u16, body: &str) -> Self {
        Self {
            method,
            path,
            status,
            content_type: "application/json",
            body: body.as_bytes().to_vec(),
        }
    }

    /// A route with an empty body and an explicit status (for `/health`).
    pub fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
        Self {
            method,
            path,
            status,
            content_type: "text/plain",
            body: Vec::new(),
        }
    }
}

/// A request the mock received, captured for assertions.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    /// Full request target including the query string.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// The `Authorization` header value, if present (case-insensitive lookup).
    pub fn authorization(&self) -> Option<&str> {
        self.header("authorization")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct MockNode {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockNode {
    /// Start a mock node serving `routes`. Returns once the socket is bound.
    pub fn start(routes: Vec<Route>) -> MockNode {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock node");
        listener
            .set_nonblocking(true)
            .expect("set mock node nonblocking");
        let addr = listener.local_addr().expect("mock node local addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let thread_shutdown = Arc::clone(&shutdown);
        let thread_requests = Arc::clone(&requests);
        let handle = std::thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_connection(stream, &routes, &thread_requests);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        MockNode {
            addr,
            shutdown,
            handle: Some(handle),
            requests,
        }
    }

    /// The base URL to hand to `SidewinderConfig`, for example `http://127.0.0.1:54321`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// A snapshot of every request received so far.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests lock").clone()
    }

    /// The most recent request received, if any.
    pub fn last_request(&self) -> Option<RecordedRequest> {
        self.requests.lock().expect("requests lock").last().cloned()
    }
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    routes: &[Route],
    requests: &Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let mut write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    // Request line: e.g. "POST /v2/transactions HTTP/1.1".
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    // Headers until the blank line.
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    // Body, if the request declared one.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body);
    }

    let path_only = path.split('?').next().unwrap_or(&path);
    requests
        .lock()
        .expect("requests lock")
        .push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            headers,
            body,
        });

    let route = routes
        .iter()
        .find(|r| r.method.eq_ignore_ascii_case(&method) && r.path == path_only);

    let (status, content_type, payload): (u16, &str, Vec<u8>) = match route {
        Some(r) => (r.status, r.content_type, r.body.clone()),
        None => (
            404,
            "application/json",
            br#"{"message":"no route in mock node"}"#.to_vec(),
        ),
    };

    let reason = reason_phrase(status);
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = write_stream.write_all(header.as_bytes());
    let _ = write_stream.write_all(&payload);
    let _ = write_stream.flush();
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

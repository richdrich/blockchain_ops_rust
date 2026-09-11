// single default test target for the crate (see CLAUDE.md test conventions): each file is pulled in as
// a module via `#[path]`, so the crate exposes one `unit` target rather than a binary per file.

#[path = "support.rs"]
#[allow(dead_code, unreachable_pub)]
mod support;

#[path = "membership.rs"]
mod membership;

#[path = "verify.rs"]
mod verify;

#[path = "handshake.rs"]
mod handshake;

#[path = "decoder.rs"]
mod decoder;

#[path = "endpoint.rs"]
mod endpoint;

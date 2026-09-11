# sw_identity_tls

Identity-bound TLS for Sidewinder access, plus the endpoint-discovery codec — the single, publishable
source of this logic, shared by the Sidewinder node/server side (the `sw-tls` / `sw-membership` crates in
the sidewinder repository re-export from here) and the client side (`sidewinder_ops`).

## What it provides

- **Identity certificates.** `generate` mints a self-signed leaf certificate whose ephemeral key is
  signed by a long-lived Algorand Ed25519 identity (a custom X.509 extension) — the libp2p TLS pattern
  rooted in an on-chain identity rather than a Certificate Authority.
- **Offline verification.** `verify_identity_cert` / `verify_identity_cert_for_role` check a presented
  certificate against a `MembershipAuthority` (the fail-closed, I/O-free authorization seam) and return
  the bound Algorand address. No node or indexer call is made.
- **rustls wiring.** `client_config` + `IdentityServerVerifier` authenticate a server by identity;
  `server_config` + `IdentityClientVerifier` (behind the `server` feature) authenticate a client. A pure
  API client builds with `default-features = false` to omit the server side.
- **Discovery.** `EndpointRecord` is the compact, base64-wrapped on-chain endpoint codec, and
  `EndpointResolver` resolves the live `(identity, endpoint)` set of an application's permitted nodes off
  `algo_ops`'s incremental opted-in-accounts scan. `bit_decoder` / `key_set_decoder` are the generic
  local-state decoders both discovery and the on-chain membership sources build on.

## Features

- `server` (default) — the server-side verifier and `ServerConfig` builder. Omit for a client-only build.

See `design_docs/sidewinder_authenticated_access.md` in the sidewinder repository for the epic (#240)
this supports.

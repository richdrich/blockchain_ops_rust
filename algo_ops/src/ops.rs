use crate::error::AlgoError;
use algonaut::core::ToMsgPack;
use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Ensure the algonaut crate is referenced so this module is explicitly implemented with it.
// We keep most calls abstracted for now and will progressively replace stubs with concrete calls.
#[allow(unused_imports)]
use algonaut as _algonaut;

/// Configuration for Algod and Indexer endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgoChainConfig {
    pub client_api_url: String,
    pub client_api_port: u16,
    pub indexer_api_url: String,
    pub indexer_api_port: u16,
    pub token: Option<String>,
    pub token_key: Option<String>,
    pub app_id: Option<u64>,
    pub asset_id: Option<u64>,
}

impl Default for AlgoChainConfig {
    fn default() -> Self {
        // Defaults to localnet configuration matching the Kotlin implementation
        Self {
            client_api_url: "http://localhost".to_string(),
            client_api_port: 4001,
            indexer_api_url: "http://localhost".to_string(),
            indexer_api_port: 8980,
            token: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            token_key: Some("X-Algo-API-Token".to_string()),
            app_id: None,
            asset_id: None,
        }
    }
}

/// Neutral snapshot of the algod suggested transaction parameters, returned by
/// [`AlgoOps::suggested_params`].
///
/// Carries only plain types (no `algonaut` types on the boundary) so a consumer built against
/// a different `algonaut` version can size a payment without a version bump. These are the
/// fields a payment builder needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgoSuggestedParams {
    /// The last committed round the node had seen when it suggested these params.
    pub last_round: u64,
    /// The network minimum transaction fee (not per byte), in microALGOs.
    pub min_fee: u64,
    /// The 32-byte genesis hash of the network.
    pub genesis_hash: [u8; 32],
    /// The genesis id string of the network (e.g. `"testnet-v1.0"`).
    pub genesis_id: String,
}

// Neutral view of a pending or confirmed transaction. Defined in `blockchain_ops` alongside the
// `TransactionQueryOps` trait it is returned by; re-exported here so `algo_ops::ConfirmedTxn` and
// `crate::ops::ConfirmedTxn` keep resolving.
pub use blockchain_ops::ConfirmedTxn;

/// Minimal key provider trait analogous to the Kotlin IKeyProvider interface.
pub trait KeyProvider: Send + Sync {
    fn get_id(&self) -> Option<String> {
        None
    }
    fn get_private_key(&self) -> Option<String> {
        None
    }
    fn save_private_key_object(&self, _address: &str, _passphrase: &str) {}
}

/// Main operations struct analogous to Kotlin's AlgoOps.
#[derive(Debug, Clone)]
pub struct AlgoOps {
    pub passphrase: Option<String>,
    pub address: Option<String>,
    pub config: AlgoChainConfig,
}

impl AlgoOps {
    /// Generate a new Algorand keypair (secure random) and return `(id, passphrase)`.
    ///
    /// - `id` is the Algorand base32 address derived from the public key.
    /// - `passphrase` is the 25-word Algorand mnemonic.
    pub fn generate_keypair() -> (String, String) {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, RngCore};

        // Generate a secure random 32-byte seed
        let mut rng = OsRng;
        let mut sk: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut sk);

        // Derive public key and Algorand address
        let signing_key = SigningKey::from_bytes(&sk);
        let verifying_key = signing_key.verifying_key();
        let pk: [u8; 32] = verifying_key.to_bytes();
        let id =
            byte_key_to_address(&pk).expect("failed to derive Algorand address from public key");

        // Encode secret seed as 25-word mnemonic passphrase
        let passphrase =
            algonaut::crypto::mnemonic::from_key(&sk).expect("failed to generate mnemonic");
        (id, passphrase)
    }

    /// Derive the 32-byte ed25519 secret seed for a `passphrase`, accepting either a 25-word
    /// Algorand mnemonic or a legacy base64-encoded secret with a "b64:" prefix (used by tests).
    /// This is the single source of truth for passphrase → seed used by `new`,
    /// `address_from_passphrase`, and `private_key_bytes`.
    pub fn seed_from_passphrase(passphrase: &str) -> Result<[u8; 32]> {
        // Algorand 25-word mnemonic.
        if !passphrase.is_empty()
            && let Ok(key) = algonaut::crypto::mnemonic::to_key(passphrase)
        {
            return key
                .to_vec()
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("invalid passphrase: derived seed is not 32 bytes"));
        }

        // Legacy base64-encoded secret with a "b64:" prefix.
        if let Some(rest) = passphrase.strip_prefix("b64:") {
            let bytes = general_purpose::STANDARD
                .decode(rest)
                .map_err(|e| anyhow!("invalid passphrase: bad base64 secret ({e})"))?;
            return bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("invalid passphrase: secret is not 32 bytes"));
        }

        bail!("invalid passphrase: expected a 25-word Algorand mnemonic")
    }

    /// Derive the Algorand address for an existing `passphrase`, without generating a new key.
    /// This is the inverse of `generate_keypair`. Returns an error if `passphrase` is not a valid
    /// Algorand mnemonic (or b64: secret).
    pub fn address_from_passphrase(passphrase: &str) -> Result<String> {
        use ed25519_dalek::SigningKey;

        let sk = Self::seed_from_passphrase(passphrase)?;
        let signing_key = SigningKey::from_bytes(&sk);
        let pk: [u8; 32] = signing_key.verifying_key().to_bytes();
        byte_key_to_address(&pk)
    }

    // Construction is sealed to the crate: consumers go through the
    // `AlgoOps::new_for_algorand` factory (see lib.rs). For indexer-only use,
    // construct with `new_for_algorand(None, None, config)`.
    pub(crate) fn new(
        passphrase: Option<String>,
        address: Option<String>,
        config: Option<AlgoChainConfig>,
    ) -> Self {
        // Use explicit config if provided; else Default (localnet)
        let config = config.unwrap_or_default();
        let mut ops = Self {
            passphrase,
            address,
            config,
        };

        // If no address was provided but we have a passphrase, derive the address immediately.
        // A malformed passphrase simply leaves the address unset (callers surface the error later).
        if ops.address.is_none()
            && let Some(ref pass) = ops.passphrase
            && let Ok(addr) = Self::address_from_passphrase(pass)
        {
            ops.address = Some(addr);
        }

        ops
    }

    /// Helper to generate a unique note (e.g. for avoiding "transaction already in ledger" errors)
    pub fn unique_note() -> Vec<u8> {
        let mut n = Vec::new();
        n.extend_from_slice(Uuid::new_v4().as_bytes());
        n
    }

    pub fn algod_client(&self) -> Result<algonaut::Algod> {
        // Build base URL including port, e.g., http://localhost:4001
        let url = format!(
            "{}:{}",
            self.config.client_api_url, self.config.client_api_port
        );
        // Per requirement: default the token to empty string for Algod::new calls
        let token = self.config.token.clone().unwrap_or_default();
        algonaut::Algod::new(&url, &token)
            .map_err(|e| anyhow!("failed to construct Algod client: {e}"))
    }

    pub fn indexer_client(&self) -> Result<algonaut::Indexer> {
        let url = format!(
            "{}:{}",
            self.config.indexer_api_url, self.config.indexer_api_port
        );
        let token = self.config.token.clone().unwrap_or_default();
        algonaut::Indexer::new(&url, &token)
            .map_err(|e| anyhow!("failed to construct Indexer client: {e}"))
    }

    // HTTP status codes that warrant a retry (transient/overload errors).
    // `pub(crate)` in production; re-exported publicly only under `test-support`.
    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    pub(crate) const RETRYABLE_STATUS_CODES: &'static [u16] = &[408, 425, 429, 502, 503, 504];

    // Returns true if the algonaut error is a retryable transient HTTP error.
    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    pub(crate) fn is_retryable(e: &algonaut::Error) -> bool {
        if let algonaut::Error::Request(req) = e
            && let algonaut::error::RequestErrorDetails::Http { status, .. } = &req.details
        {
            return Self::RETRYABLE_STATUS_CODES.contains(status);
        }
        false
    }

    // Helper: run an algonaut async call and flatten the double-Result, with
    // up to 3 retries (with exponential backoff: 1 s, 2 s, 4 s) on transient
    // HTTP errors (408, 425, 429, 502, 503, 504).
    //
    // Accepts a closure rather than a bare future so the future can be
    // reconstructed on each retry attempt (futures are consumed on first poll).
    pub fn algod_call<T, F, Fut>(&self, make_fut: F) -> Result<T>
    where
        T: Send,
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, algonaut::Error>> + Send,
    {
        const MAX_RETRIES: u32 = 3;
        const RETRY_BASE_MS: u64 = 1_000;

        let mut attempt = 0u32;
        loop {
            let result = self
                .rt_block_on(make_fut())
                .map_err(|e| anyhow!("runtime error: {e}"))?;

            match result {
                Ok(val) => return Ok(val),
                Err(ref e) if attempt < MAX_RETRIES && Self::is_retryable(e) => {
                    let delay = std::time::Duration::from_millis(RETRY_BASE_MS * (1u64 << attempt));
                    tracing::warn!(
                        "algod transient error (attempt {}/{}), retrying in {:?}: {}",
                        attempt + 1,
                        MAX_RETRIES,
                        delay,
                        e
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                }
                Err(e) => {
                    if attempt >= MAX_RETRIES && Self::is_retryable(&e) {
                        return Err(AlgoError::transient("algod call", &e.to_string()).into());
                    }
                    return Err(anyhow!("{e}"));
                }
            }
        }
    }

    // Helper: run an async future on a fresh current-thread Tokio runtime.
    fn rt_block_on<T: Send>(&self, fut: impl Future<Output = T> + Send) -> Result<T> {
        // If we are already in a tokio runtime, we must avoid nested block_on and
        // the "cannot drop runtime" panic during unwinding/drop.
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::scope(|s| {
                let handle = s.spawn(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build temporary tokio runtime");
                    rt.block_on(fut)
                });
                handle
                    .join()
                    .map_err(|_| anyhow!("rt_block_on thread panicked"))
            });
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
        Ok(rt.block_on(fut))
    }

    // Helper: parse address string into algonaut Address.
    fn parse_address(addr: &str) -> Result<algonaut::core::Address> {
        use std::str::FromStr;
        algonaut::core::Address::from_str(addr).map_err(|e| anyhow!("invalid address: {e}"))
    }

    // Helper: require self.address and parse it.
    fn require_address(&self) -> Result<algonaut::core::Address> {
        let addr_str = self
            .address
            .as_ref()
            .ok_or_else(|| anyhow!("This operation needs an address"))?;
        Self::parse_address(addr_str)
    }

    pub fn address_str(&self) -> Result<String> {
        self.address
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("This operation needs an address"))
    }

    // Helper: JSON field accessor that supports snake_case and kebab-case alternatives.
    fn json_get<'a>(o: &'a serde_json::Value, k1: &str, k2: &str) -> Option<&'a serde_json::Value> {
        o.get(k1).or_else(|| o.get(k2))
    }

    // Helper: decode TEAL key/value state entries from JSON into vector of (key, value) strings.
    // - Keys are base64-encoded in algod JSON and represent UTF-8 strings: decode to UTF-8.
    // - Byte values (type == 1) may be represented as an array of numbers (bytes) or as a base64 string,
    //   depending on the source struct and serializer. Handle both. Attempt to decode to UTF-8; if not valid,
    //   fall back to a 0x-prefixed hex string for readability.
    fn decode_state_entries(entries: &[serde_json::Value]) -> Vec<(String, String)> {
        let mut kvs: Vec<(String, String)> = Vec::new();
        for entry in entries {
            let key_b64 = match entry.get("key").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let key = match general_purpose::STANDARD.decode(key_b64) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| key_b64.to_string()),
                Err(_) => key_b64.to_string(),
            };
            let val_obj = match entry.get("value").and_then(|x| x.as_object()) {
                Some(o) => o,
                None => continue,
            };
            let vtype = val_obj.get("type").and_then(|x| x.as_u64()).unwrap_or(0);
            let val = if vtype == 1 {
                // bytes can be an array of numbers or a base64 string
                let bytes_opt = if let Some(arr) = val_obj.get("bytes").and_then(|x| x.as_array()) {
                    // Collect numeric array into bytes
                    let mut buf: Vec<u8> = Vec::with_capacity(arr.len());
                    for n in arr {
                        if let Some(u) = n.as_u64() {
                            buf.push((u & 0xFF) as u8);
                        } else if let Some(i) = n.as_i64()
                            && i >= 0
                        {
                            buf.push(((i as u64) & 0xFF) as u8);
                        }
                    }
                    Some(buf)
                } else if let Some(b64) = val_obj.get("bytes").and_then(|x| x.as_str()) {
                    general_purpose::STANDARD.decode(b64).ok()
                } else {
                    None
                };

                if let Some(bytes) = bytes_opt {
                    match String::from_utf8(bytes.clone()) {
                        Ok(s) => s,
                        Err(_) => {
                            // Fallback: hex string for non-UTF8 bytes
                            let mut hex = String::from("0x");
                            for byte in bytes {
                                hex.push_str(&format!("{:02x}", byte));
                            }
                            hex
                        }
                    }
                } else {
                    String::new()
                }
            } else {
                val_obj
                    .get("uint")
                    .and_then(|x| x.as_u64())
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "0".to_string())
            };
            kvs.push((key, val));
        }
        kvs
    }

    /// Create a new address, generating an ed25519 keypair. For compatibility with
    /// existing tests, we store the secret key in `passphrase` as a base64-encoded
    /// string with a "b64:" prefix. Note: production code expects an ASCII mnemonic
    /// passphrase to be provided by callers; this storage is only used by tests.
    pub fn create_address(&mut self) -> Result<String> {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, RngCore};

        let mut rng = OsRng;
        let mut sk: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let signing_key = SigningKey::from_bytes(&sk);
        let verifying_key = signing_key.verifying_key();
        let pk: [u8; 32] = verifying_key.to_bytes();

        let addr = byte_key_to_address(&pk)?;
        self.address = Some(addr.clone());
        // Store secret key as base64 so we can recover it for signing
        let sk_b64 = general_purpose::STANDARD.encode(sk);
        self.passphrase = Some(format!("b64:{}", sk_b64));
        Ok(addr)
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        let addr = self
            .address
            .as_ref()
            .ok_or_else(|| anyhow!("This operation needs an address"))?;
        address_to_byte_key(addr)
    }

    pub fn private_key_bytes(&self) -> Result<Vec<u8>> {
        let pass = self
            .passphrase
            .as_ref()
            .ok_or_else(|| anyhow!("This operation needs account access"))?;

        // Accepts an ASCII Algorand mnemonic or a legacy "b64:" secret (see seed_from_passphrase).
        Ok(Self::seed_from_passphrase(pass)?.to_vec())
    }

    /// Compute the application (contract) address from app id.
    /// Spec: pubkey = SHA512/256("appID" || app_id_be_u64), then Algorand address from pubkey.
    pub fn contract_address(&self, app_id: u64) -> Result<String> {
        use sha2::{Digest, Sha512_256};
        let mut hasher = Sha512_256::new();
        hasher.update(b"appID");
        hasher.update(app_id.to_be_bytes());
        let pk_bytes: [u8; 32] = hasher.finalize().into();
        byte_key_to_address(&pk_bytes)
    }

    pub fn sign(&self, text: &str) -> Result<String> {
        use ed25519_dalek::{Signer, SigningKey};
        let sk_bytes = self.private_key_bytes()?;
        let sk_arr: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&sk_arr);
        let signature = signing_key.sign(text.as_bytes());
        Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Sign arbitrary bytes with this account's Ed25519 key, returning the raw 64-byte signature.
    ///
    /// This is a plain `Ed25519(sk, message)` over the exact bytes given, with no domain-separation
    /// tag. It differs from [`AlgoOps::sign`] (which base64-encodes the signature for text callers)
    /// and from [`AlgoOps::sign_notify_envelope`] (which prepends Algorand's `"MX"` byte-signing
    /// tag). It is the form a Sidewinder canonical transaction body is signed with: the verifier
    /// re-encodes the same canonical body and checks the signature over those bytes directly, so any
    /// prefix here would make the signature fail to verify.
    pub fn sign_bytes(&self, message: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::{Signer, SigningKey};
        let sk_bytes = self.private_key_bytes()?;
        let sk_arr: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&sk_arr);
        Ok(signing_key.sign(message).to_bytes())
    }

    /// Sign the canonical bingle-notify envelope with this account's key.
    ///
    /// Builds the fixed, newline-delimited UTF-8 message (NOT JSON)
    /// `"bingle-notify:v1"\nroute\niss\naudience\nbodyHash\nnonce\nexp`, then signs it with the
    /// Algorand byte-signing scheme — `Ed25519(sk, "MX" || msg)` — which is exactly what
    /// `algosdk.signBytes` produces and `algosdk.verifyBytes` checks. Returns the base64 of the
    /// 64-byte signature.
    ///
    /// `bodyHash` is the lowercase hex SHA-256 of the route-specific body:
    /// - `"register"`: `sha256(utf8(token + "\n" + env))`, with `env` in {"sandbox","production"};
    /// - `"alert"`: `sha256("")` (empty; `token`/`env` are ignored, `audience` is the recipient).
    ///
    /// Source of truth for the contract: bingle_notify/src/lib/verify.ts.
    pub fn sign_notify_envelope(
        &self,
        route: &str,
        iss: &str,
        audience: &str,
        token: &str,
        env: &str,
        nonce: &str,
        exp: i64,
    ) -> Result<String> {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        // bodyHash: lowercase hex sha256 of the route-specific body.
        let body = match route {
            "register" => format!("{token}\n{env}"),
            "alert" => String::new(),
            other => bail!("unknown notify route: {other}"),
        };
        let body_hash = HEXLOWER.encode(&Sha256::digest(body.as_bytes()));

        // Canonical, newline-delimited message.
        let msg =
            format!("bingle-notify:v1\n{route}\n{iss}\n{audience}\n{body_hash}\n{nonce}\n{exp}");

        // Algorand byte-signing: Ed25519(sk, "MX" || msg).
        let sk_bytes = self.private_key_bytes()?;
        let sk_arr: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&sk_arr);
        let mut signed = Vec::with_capacity(2 + msg.len());
        signed.extend_from_slice(b"MX");
        signed.extend_from_slice(msg.as_bytes());
        let signature = signing_key.sign(&signed);
        Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    pub fn verify(&self, text: &str, sig_b64: &str) -> Result<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let sig_bytes = match general_purpose::STANDARD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        if sig_bytes.len() != 64 {
            return Ok(false);
        }
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(false),
        };
        let signature = Signature::from_bytes(&sig_arr);
        let pk = self.public_key_bytes()?;
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|e| anyhow!("invalid verifying key from address: {e}"))?;
        Ok(vk.verify(text.as_bytes(), &signature).is_ok())
    }

    pub fn account_balance(&self) -> Result<Option<f64>> {
        let client = match self.algod_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[account_balance] Failed to access algod client: {}", e);
                return Err(e);
            }
        };
        let address = match self.require_address() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("[account_balance] Failed to resolve address: {}", e);
                return Err(e);
            }
        };
        let info = match self.algod_call(|| client.account(&address)) {
            Ok(r) => r,
            Err(e) => {
                if AlgoError::is_host_unreachable(&e) {
                    // Expected during a transient node outage; callers fall back to cached state,
                    // so log at debug to avoid flooding the log while the node is unreachable.
                    tracing::debug!(
                        "[account_balance] account information unreachable for {}: {}",
                        address,
                        e
                    );
                    return Err(
                        AlgoError::unreachable("account_information", &e.to_string()).into(),
                    );
                }
                tracing::error!(
                    "[account_balance] Failed to fetch account information for {}: {}",
                    address,
                    e
                );
                return Err(e);
            }
        };
        // Next log is huge!
        // algo_log!("[account_balance] Retrieved account info for address: {} => {:?}", address, info);
        // amount is in microalgos
        let micro: u64 = info.amount;
        algo_log!(
            "[account_balance] Balance for address {} is {} microalgos",
            address,
            micro
        );
        Ok(Some(micro as f64 / 1_000_000.0))
    }

    pub fn global_state(
        &self,
        maybe_app_id: Option<u64>,
    ) -> Result<Option<Vec<(u64, Vec<(String, String)>)>>> {
        let client = self.algod_client()?;
        let address = self.require_address()?;
        let info = match self.algod_call(|| client.account(&address)) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&anyhow!(e.to_string())) => {
                return Err(AlgoError::unreachable("account_information", &e.to_string()).into());
            }
            Err(_) => return Ok(None),
        };

        // Convert to json Value for resilient traversal
        let v = serde_json::to_value(&info)
            .map_err(|e| anyhow!("failed to serialize account info: {e}"))?;

        let created =
            match Self::json_get(&v, "created_apps", "created-apps").and_then(|x| x.as_array()) {
                Some(a) => a,
                None => return Ok(Some(vec![])),
            };

        let mut out: Vec<(u64, Vec<(String, String)>)> = Vec::new();
        for app in created {
            let id = match app.get("id").and_then(|x| x.as_u64()) {
                Some(i) => i,
                None => continue,
            };
            if let Some(filter) = maybe_app_id
                && filter != id
            {
                continue;
            }
            let params = match app.get("params").and_then(|x| x.as_object()) {
                Some(p) => p,
                None => continue,
            };
            let params_value = serde_json::Value::Object(params.clone());
            let gs_vec: Vec<serde_json::Value> =
                Self::json_get(&params_value, "global_state", "global-state")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
            let kvs = Self::decode_state_entries(&gs_vec);
            out.push((id, kvs));
        }
        Ok(Some(out))
    }

    /// Read a single byte-valued global state entry from an arbitrary application (any app id,
    /// not limited to apps created by the sender) and return the raw bytes. Returns None if the
    /// application or the key is absent. Unlike `global_state`, this does not lossily decode the
    /// value to UTF-8, so it is safe for packed binary values.
    pub fn app_global_bytes(&self, app_id: u64, key: &str) -> Result<Option<Vec<u8>>> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let client = self.algod_client()?;
        let app_info = match self.algod_call(|| client.app(algonaut::core::AppId(app_id))) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&anyhow!(e.to_string())) => {
                return Err(AlgoError::unreachable("app_information", &e.to_string()).into());
            }
            Err(_) => return Ok(None),
        };
        let v = serde_json::to_value(&app_info)
            .map_err(|e| anyhow!("failed to serialize app info: {e}"))?;
        let params = match Self::json_get(&v, "params", "params").and_then(|x| x.as_object()) {
            Some(p) => serde_json::Value::Object(p.clone()),
            None => return Ok(None),
        };
        let gs: Vec<serde_json::Value> = Self::json_get(&params, "global_state", "global-state")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for entry in &gs {
            let key_b64 = match entry.get("key").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let entry_key = match general_purpose::STANDARD.decode(key_b64) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            if entry_key != key {
                continue;
            }
            let val_obj = match entry.get("value").and_then(|x| x.as_object()) {
                Some(o) => o,
                None => continue,
            };
            // Byte values (type == 1) may be a numeric array or a base64 string.
            let bytes = if let Some(arr) = val_obj.get("bytes").and_then(|x| x.as_array()) {
                let mut buf: Vec<u8> = Vec::with_capacity(arr.len());
                for n in arr {
                    if let Some(u) = n.as_u64() {
                        buf.push((u & 0xFF) as u8);
                    } else if let Some(i) = n.as_i64()
                        && i >= 0
                    {
                        buf.push(((i as u64) & 0xFF) as u8);
                    }
                }
                Some(buf)
            } else if let Some(b64) = val_obj.get("bytes").and_then(|x| x.as_str()) {
                general_purpose::STANDARD.decode(b64).ok()
            } else {
                None
            };
            return Ok(bytes);
        }
        Ok(None)
    }

    /// Read an app's local-state schema `(num_uints, num_byte_slices)` from application info.
    ///
    /// Generic to any app: these counts drive the minimum-balance increase an account incurs
    /// when it opts in to the app, so callers can size the exact funding an opt-in requires.
    pub fn get_app_local_schema(&self, app_id: u64) -> Result<(u64, u64)> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let client = self.algod_client()?;
        let app_info = self
            .algod_call(|| client.app(algonaut::core::AppId(app_id)))
            .map_err(|e| anyhow!("application_information failed: {e}"))?;
        let v = serde_json::to_value(&app_info)
            .map_err(|e| anyhow!("failed to serialize application info: {e}"))?;
        let schema = v
            .get("params")
            .and_then(|p| {
                p.get("local-state-schema")
                    .or_else(|| p.get("local_state_schema"))
            })
            .ok_or_else(|| anyhow!("local-state-schema missing for app_id {app_id}"))?;
        let num_uints = schema
            .get("num-uint")
            .or_else(|| schema.get("num_uint"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let num_byte_slices = schema
            .get("num-byte-slice")
            .or_else(|| schema.get("num_byte_slice"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        Ok((num_uints, num_byte_slices))
    }

    pub fn local_state_for_account(
        &self,
        app_id: u64,
        account_address: &str,
    ) -> Result<Option<Vec<(String, String)>>> {
        let client = self.algod_client()?;
        let address = Self::parse_address(account_address)?;
        let info = match self.algod_call(|| client.account(&address)) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&anyhow!(e.to_string())) => {
                return Err(AlgoError::unreachable("account_information", &e.to_string()).into());
            }
            Err(_) => return Ok(None),
        };

        algo_log!("Retrieved account info for address: {}", account_address);
        // Next log is huge
        // algo_log!("Account info: {:#?}", info);

        let v = serde_json::to_value(&info)
            .map_err(|e| anyhow!("failed to serialize account info: {e}"))?;

        let als = match Self::json_get(&v, "apps_local_state", "apps-local-state")
            .and_then(|x| x.as_array())
        {
            Some(a) => a,
            None => return Ok(None),
        };
        for st in als {
            let id = st.get("id").and_then(|x| x.as_u64());
            if id == Some(app_id) {
                let keyvals_vec: Vec<serde_json::Value> =
                    Self::json_get(st, "key_value", "key-value")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                let out = Self::decode_state_entries(&keyvals_vec);
                return Ok(Some(out));
            }
        }
        Ok(None)
    }

    pub fn send_algo(&self, to_address: &str, amount_algos: f64) -> Result<()> {
        // Validate amount
        if amount_algos <= 0.0 {
            bail!("amount must be positive");
        }
        // Require account access (private key) and valid addresses
        let sk = self.private_key_bytes()?;
        let from = self.require_address()?;
        let to = Self::parse_address(to_address)?; // invalid -> early error

        // Algod client
        let client = self.algod_client()?;

        // Fetch suggested params
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Build payment transaction
        let micro = (amount_algos * 1_000_000.0).round() as u64;
        let tx = algonaut::transaction::Pay::new(from, to, algonaut::core::MicroAlgos(micro))
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build transaction: {e}"))?;

        // Validate secret key length (32 bytes)
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;

        // Sign using algonaut account helper
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        // Submit raw transaction via algod
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;

        // Wait for confirmation up to a default timeout (e.g., 10 rounds)
        self.wait_for_confirmation(&tx_id, 10)?;
        Ok(())
    }

    pub fn create_asset(&self, name: &str, units_in_issue: u64) -> Result<Option<u64>> {
        // Validate inputs
        if name.trim().is_empty() {
            bail!("asset name must not be empty");
        }
        if units_in_issue == 0 {
            bail!("units_in_issue must be > 0");
        }

        // Require account access and issuer address
        let sk = self.private_key_bytes()?;
        let issuer = self.require_address()?;

        // Algod client and suggested params
        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Build CreateAsset transaction: minimal: total=units_in_issue, decimals=0
        // Set manager, reserve, and clawback to issuer so we can later reconfigure if needed
        let tx = algonaut::transaction::CreateAsset::new(issuer, units_in_issue, 0, false)
            .manager(issuer)
            .reserve(issuer)
            .clawback(issuer)
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build asset create transaction: {e}"))?;

        // Sign
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset create transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        // Submit and wait
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)?;

        // Retrieve created asset id from pending transaction info
        let tx_id_obj = algonaut::core::TransactionId::from(tx_id.as_str());
        let info = self
            .algod_call(|| client.pending_transaction(&tx_id_obj))
            .map_err(|e| anyhow!("failed to fetch pending transaction info for asset id: {e}"))?;
        Ok(info.asset_index.or(Some(0)).filter(|id| *id != 0))
    }

    /// Create an ASA with explicit reserve and clawback addresses.
    ///
    /// The caller (`self`) is the ASA manager (the only account that can later reconfigure it).
    /// `reserve_addr` and `clawback_addr` are Algorand address strings. decimals=0.
    pub fn create_asset_configured(
        &self,
        name: &str,
        units_in_issue: u64,
        manager_addr: &str,
        reserve_addr: &str,
        clawback_addr: &str,
        freeze_addr: &str,
    ) -> Result<Option<u64>> {
        if name.trim().is_empty() {
            bail!("asset name must not be empty");
        }
        if units_in_issue == 0 {
            bail!("units_in_issue must be > 0");
        }

        let sk = self.private_key_bytes()?;
        let issuer = self.require_address()?;
        let manager = Self::parse_address(manager_addr)?;
        let reserve = Self::parse_address(reserve_addr)?;
        let clawback = Self::parse_address(clawback_addr)?;
        let freeze = Self::parse_address(freeze_addr)?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let tx = algonaut::transaction::CreateAsset::new(issuer, units_in_issue, 0, false)
            .manager(manager)
            .reserve(reserve)
            .clawback(clawback)
            .freeze(freeze)
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build asset create transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset create transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)?;

        let tx_id_obj = algonaut::core::TransactionId::from(tx_id.as_str());
        let info = self
            .algod_call(|| client.pending_transaction(&tx_id_obj))
            .map_err(|e| anyhow!("failed to fetch pending transaction info for asset id: {e}"))?;
        Ok(info.asset_index.or(Some(0)).filter(|id| *id != 0))
    }

    /// Create an ASA with the reserve and clawback addresses both set to the application address for `app_id`.
    /// Manager remains the issuer for future reconfiguration; decimals=0.
    pub fn create_asset_with_reserve_app(
        &self,
        name: &str,
        units_in_issue: u64,
        app_id: u64,
    ) -> Result<Option<u64>> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let app_addr = self.contract_address(app_id)?;
        let issuer_addr = self.address_str()?;
        self.create_asset_configured(
            name,
            units_in_issue,
            &issuer_addr,
            &app_addr,
            &app_addr,
            &issuer_addr,
        )
    }

    /// Check whether `account_address` has opted-in to `asset_id`.
    pub fn is_account_opted_in_to_asset(
        &self,
        account_address: &str,
        asset_id: u64,
    ) -> Result<bool> {
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        let client = self.algod_client()?;
        let address = Self::parse_address(account_address)?;
        let info = match self.algod_call(|| client.account(&address)) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let v = serde_json::to_value(&info)
            .map_err(|e| anyhow!("failed to serialize account info: {e}"))?;
        let assets_arr = v
            .get("assets")
            .or_else(|| v.get("assets"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for a in assets_arr {
            let id = a
                .get("asset-id")
                .and_then(|x| x.as_u64())
                .or_else(|| a.get("asset_id").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            if id == asset_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the holding amount of a specific asset for a given account.
    pub fn asset_holding(&self, account_address: &str, asset_id: u64) -> Result<u64> {
        let client = self.algod_client()?;
        let address = Self::parse_address(account_address)?;
        let info = self
            .algod_call(|| client.account(&address))
            .map_err(|e| anyhow!("failed to fetch account information: {e}"))?;
        let v = serde_json::to_value(&info)
            .map_err(|e| anyhow!("failed to serialize account info: {e}"))?;
        Ok(Self::parse_holding_amount_from_account_value(&v, asset_id))
    }

    /// Returns the µALGO balance of any on-chain address (need not be the signer).
    pub fn microalgos_at(&self, account_address: &str) -> Result<u64> {
        let client = self.algod_client()?;
        let address = Self::parse_address(account_address)?;
        let info = self.algod_call(|| client.account(&address)).map_err(|e| {
            anyhow!("failed to fetch account information for {account_address}: {e}")
        })?;
        Ok(info.amount)
    }

    /// Return the last committed round (algod `GET /v2/status` → `last-round`).
    ///
    /// Backs a node's "current round". Routed through `algod_call` for retry + blocking; a
    /// [`AlgoErrorKind::HostUnreachable`](crate::error::AlgoErrorKind::HostUnreachable) error is
    /// surfaced so a consumer can skip while the node is down.
    pub fn round(&self) -> Result<u64> {
        let client = self.algod_client()?;
        let status = match self.algod_call(|| client.status()) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(AlgoError::unreachable("node_status", &e.to_string()).into());
            }
            Err(e) => return Err(anyhow!("failed to get node status: {e}")),
        };
        Ok(status.last_round.0)
    }

    /// Return the 32-byte VRF block seed for `round` (algod `GET /v2/blocks/{round}` →
    /// `block.seed`). Backs seed-based selection. Same unreachable-node behaviour as [`round`](Self::round).
    ///
    /// The seed is decoded from the block model, so no `algonaut` types cross the boundary.
    pub fn block_seed(&self, round: u64) -> Result<Vec<u8>> {
        let client = self.algod_client()?;
        let block = match self.algod_call(|| client.block(round)) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(AlgoError::unreachable("block", &e.to_string()).into());
            }
            Err(e) => return Err(anyhow!("failed to fetch block {round}: {e}")),
        };
        let seed = block
            .block
            .seed
            .ok_or_else(|| anyhow!("block {round} did not contain a seed"))?
            .0;
        if seed.len() != 32 {
            bail!("block {round} seed is {} bytes, expected 32", seed.len());
        }
        Ok(seed)
    }

    /// Return the suggested transaction params as a neutral [`AlgoSuggestedParams`]
    /// (algod `GET /v2/transactions/params`). Plain types only; same unreachable-node
    /// behaviour as [`round`](Self::round).
    pub fn suggested_params(&self) -> Result<AlgoSuggestedParams> {
        let client = self.algod_client()?;
        let params = match self.algod_call(|| client.suggested_params()) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(AlgoError::unreachable("suggested_params", &e.to_string()).into());
            }
            Err(e) => return Err(anyhow!("failed to fetch suggested params: {e}")),
        };
        Ok(AlgoSuggestedParams {
            last_round: params.last_round.0,
            min_fee: params.min_fee.0,
            genesis_hash: params.genesis_hash.0,
            genesis_id: params.genesis_id,
        })
    }

    /// Submit an already-signed, MessagePack-encoded transaction (algod
    /// `POST /v2/transactions`, raw-transaction broadcast) and return its transaction id.
    ///
    /// The caller builds and signs with its own SDK, so only bytes cross the boundary — this
    /// keeps the primitive independent of `algo_ops`'s `algonaut` version. Routed through
    /// `algod_call` for retry + blocking; surfaces `AlgoError::HostUnreachable` when the node
    /// is down. Unlike the high-level builders, this does not wait for confirmation — poll with
    /// [`confirmed_transaction`](Self::confirmed_transaction) or
    /// [`wait_for_confirmation`](Self::wait_for_confirmation).
    pub fn submit_signed(&self, signed_txn: &[u8]) -> Result<String> {
        if signed_txn.is_empty() {
            bail!("signed_txn must not be empty");
        }
        let client = self.algod_client()?;
        let resp = match self.algod_call(|| client.send_raw(signed_txn)) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(AlgoError::unreachable("send_raw", &e.to_string()).into());
            }
            Err(e) => return Err(anyhow!("send_raw failed: {e}")),
        };
        Ok(resp.tx_id)
    }

    /// Read a pending or confirmed transaction (algod `GET /v2/transactions/pending/{txid}`),
    /// exposing the confirmed round and the decoded note as a neutral [`ConfirmedTxn`].
    ///
    /// Returns `Ok(None)` when the node no longer knows the txid (dropped/expired/not yet seen);
    /// while still pending the transaction is known but `confirmed_round == 0`. Backs reading
    /// anchored bytes back from the chain and confirming an anchor landed. Surfaces
    /// `AlgoError::HostUnreachable` when the node is down.
    pub fn confirmed_transaction(&self, txid: &str) -> Result<Option<ConfirmedTxn>> {
        if txid.trim().is_empty() {
            bail!("txid must not be empty");
        }
        let client = self.algod_client()?;
        let tx_id_obj = algonaut::core::TransactionId::from(txid);
        let resp = match self.algod_call(|| client.pending_transaction(&tx_id_obj)) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(AlgoError::unreachable("pending_transaction", &e.to_string()).into());
            }
            // The node does not know this txid (404) or a non-fatal read error: report "not
            // found" so callers can poll without special-casing the node's absent-txn response.
            Err(_) => return Ok(None),
        };

        let confirmed_round = resp.confirmed_round.unwrap_or(0);
        // The inner `txn` is an internally-tagged enum whose every variant carries a base64
        // `note`; serialize it and read that field rather than matching all transaction types.
        let note = match &resp.txn.txn {
            Some(txn) => {
                let v = serde_json::to_value(txn)
                    .map_err(|e| anyhow!("failed to serialize pending transaction: {e}"))?;
                v.get("note")
                    .and_then(|x| x.as_str())
                    .and_then(|s| general_purpose::STANDARD.decode(s).ok())
            }
            None => None,
        };
        Ok(Some(ConfirmedTxn {
            confirmed_round,
            note,
        }))
    }

    /// Scan the indexer's note-prefix results for the first confirmed transaction whose note
    /// satisfies `matches`, returned as a neutral [`ConfirmedTxn`], or `Ok(None)` if none does.
    ///
    /// Shared by [`AlgoOps::find_transaction_by_note`] and
    /// [`AlgoOps::find_transaction_by_note_prefix`]. The indexer only supports a note *prefix* filter
    /// (it base64-encodes the raw bytes and matches whole leading bytes — there is no sub-byte
    /// matching), so both callers pass the same `query` bytes as the server-side prefix and narrow the
    /// candidates with `matches`: full-note equality for the exact lookup, `starts_with` for the
    /// prefix lookup.
    ///
    /// Result pages are walked via the indexer's `next` token until a match is found or the results
    /// are exhausted, so the wanted hit is found even when many transactions share `query` as a prefix
    /// and it does not fall on the first page. `query` must be non-empty (an empty prefix matches every
    /// note); the callers enforce that. Surfaces `AlgoError::HostUnreachable` when the indexer is down.
    fn find_confirmed_note_matching(
        &self,
        query: &[u8],
        matches: impl Fn(&[u8]) -> bool,
    ) -> Result<Option<ConfirmedTxn>> {
        let client = self.indexer_client()?;
        // The indexer expects the note-prefix query parameter base64-encoded.
        let note_prefix = general_purpose::STANDARD.encode(query);
        let mut next: Option<String> = None;
        loop {
            let (candidates, next_token) =
                self.confirmed_notes_page(&client, &note_prefix, next.as_deref())?;
            // The server-side filter already restricts to notes starting with `query`; `matches` is
            // the caller's narrowing (exact equality, or a defensive `starts_with` re-check).
            if let Some((confirmed_round, note)) =
                candidates.into_iter().find(|(_, note)| matches(note))
            {
                return Ok(Some(ConfirmedTxn {
                    confirmed_round,
                    note: Some(note),
                }));
            }
            // Advance to the next page, or stop when the indexer reports no more results.
            match next_token {
                Some(token) => next = Some(token),
                None => return Ok(None),
            }
        }
    }

    /// Collect *every* confirmed transaction whose note satisfies `matches` across all indexer
    /// note-prefix result pages, each as a neutral [`ConfirmedTxn`], in the indexer's order.
    ///
    /// The list counterpart of [`AlgoOps::find_confirmed_note_matching`]: same base64 note-prefix
    /// query and the same confirmed-and-`matches` narrowing, but it accumulates all hits instead of
    /// returning the first. Walks all pages via the `next` token so a caller aggregating over the
    /// results (for example the maximum confirmed round) sees matches beyond the first page.
    /// `query` must be non-empty (the callers enforce that). Surfaces `AlgoError::HostUnreachable`
    /// when the indexer is down.
    fn collect_confirmed_notes_matching(
        &self,
        query: &[u8],
        matches: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<ConfirmedTxn>> {
        let client = self.indexer_client()?;
        let note_prefix = general_purpose::STANDARD.encode(query);
        let mut found = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let (candidates, next_token) =
                self.confirmed_notes_page(&client, &note_prefix, next.as_deref())?;
            found.extend(
                candidates
                    .into_iter()
                    .filter(|(_, note)| matches(note))
                    .map(|(confirmed_round, note)| ConfirmedTxn {
                        confirmed_round,
                        note: Some(note),
                    }),
            );
            match next_token {
                Some(token) => next = Some(token),
                None => return Ok(found),
            }
        }
    }

    /// Fetch one page of the indexer note-prefix search: `note_prefix` (already base64) as the
    /// server-side filter, starting from the `next` pagination token. Returns the page's confirmed,
    /// note-bearing candidates as `(confirmed_round, note)` pairs and the next-page token (`None`
    /// when the indexer reports no more results). Shared by the find-first and collect-all scanners
    /// so the 19-argument `search_for_transactions` call lives in one place. Surfaces
    /// `AlgoError::HostUnreachable` when the indexer is down.
    fn confirmed_notes_page(
        &self,
        client: &algonaut::Indexer,
        note_prefix: &str,
        next: Option<&str>,
    ) -> Result<(Vec<(u64, Vec<u8>)>, Option<String>)> {
        // `algod_call` is the shared async runner (current-thread runtime + retry/backoff); despite
        // the name it drives any algonaut future, indexer calls included.
        let resp = match self.algod_call(|| {
            client.search_for_transactions(
                None,              // limit
                next,              // next (pagination token)
                Some(note_prefix), // note_prefix
                None,              // tx_type
                None,              // sig_type
                None,              // transaction_id
                None,              // round
                None,              // min_round
                None,              // max_round
                None,              // asset_id
                None,              // before_time
                None,              // after_time
                None,              // currency_greater_than
                None,              // currency_less_than
                None,              // address
                None,              // address_role
                None,              // exclude_close_to
                None,              // rekey_to
                None,              // app_id
            )
        }) {
            Ok(v) => v,
            Err(e) if AlgoError::is_host_unreachable(&e) => {
                return Err(
                    AlgoError::unreachable("search_for_transactions", &e.to_string()).into(),
                );
            }
            Err(e) => return Err(e),
        };

        // Keep only confirmed (`confirmed_round > 0`), note-bearing rows; the caller narrows further
        // with its `matches` predicate.
        let candidates = resp
            .transactions
            .into_iter()
            .filter_map(|txn| {
                let confirmed_round = txn.confirmed_round.filter(|r| *r > 0)?;
                let note = txn.note.map(|b| b.0)?;
                Some((confirmed_round, note))
            })
            .collect();
        let next_token = match resp.next_token {
            Some(token) if !token.is_empty() => Some(token),
            _ => None,
        };
        Ok((candidates, next_token))
    }

    /// Find a confirmed transaction whose note exactly equals `note` (indexer
    /// `GET /v2/transactions?note-prefix=...`), returned as a neutral [`ConfirmedTxn`], or `Ok(None)`.
    ///
    /// The indexer only supports a note *prefix* filter, so this asks for the base64-encoded note as
    /// the prefix and keeps only a candidate whose full note bytes equal `note` — a transaction whose
    /// note merely starts with `note` is rejected. Backs a peer confirming "does a confirmed
    /// transaction with this note exist?" for a transaction it did not submit. Walks all result pages
    /// (see `find_confirmed_note_matching`) so the exact match is found even behind a run of longer
    /// notes sharing it as a prefix; surfaces `AlgoError::HostUnreachable` when the indexer is down.
    pub fn find_transaction_by_note(&self, note: &[u8]) -> Result<Option<ConfirmedTxn>> {
        if note.is_empty() {
            bail!("note must not be empty");
        }
        self.find_confirmed_note_matching(note, |candidate| candidate == note)
    }

    /// Find a confirmed transaction whose note *starts with* `prefix` — a **byte** prefix, not a bit
    /// prefix — returned as a neutral [`ConfirmedTxn`], or `Ok(None)` when none is found.
    ///
    /// The byte-prefix sibling of [`AlgoOps::find_transaction_by_note`]: same indexer note-prefix
    /// query (the indexer base64-encodes the raw bytes and matches whole leading bytes — there is no
    /// sub-byte matching), but a note *longer* than `prefix` is a valid match, provided its leading
    /// bytes equal `prefix` (a defensive `starts_with` re-check of the server-side match). Callers
    /// wanting a field-aligned prefix must lay the note out on byte boundaries (e.g. sidewinder's
    /// fixed-width 8-byte big-endian anchor round). Walks all result pages (see
    /// `find_confirmed_note_matching`) and surfaces `AlgoError::HostUnreachable` when the indexer is
    /// down.
    ///
    /// This delivers the single-hit "is there *any* confirmed transaction with this note prefix?"
    /// primitive (`is_some()`); returning all matches or the lowest-`confirmed_round` match is
    /// deliberately out of scope.
    pub fn find_transaction_by_note_prefix(&self, prefix: &[u8]) -> Result<Option<ConfirmedTxn>> {
        // An empty prefix would match every note, so reject it (as the exact method rejects an empty
        // note).
        if prefix.is_empty() {
            bail!("prefix must not be empty");
        }
        self.find_confirmed_note_matching(prefix, |candidate| candidate.starts_with(prefix))
    }

    /// Every confirmed transaction whose note *starts with* `prefix` — a **byte** prefix, not a bit
    /// prefix — each as a neutral [`ConfirmedTxn`], in the indexer's result order (this method does
    /// not sort or deduplicate). Returns `Ok(vec![])` when nothing matches.
    ///
    /// The list sibling of [`AlgoOps::find_transaction_by_note_prefix`]: the same indexer note-prefix
    /// query (the indexer base64-encodes the raw bytes and matches whole leading bytes — there is no
    /// sub-byte matching) and the same defensive `starts_with` re-check, but it collects *every*
    /// confirmed match rather than stopping at the first. That lets a caller aggregate over the set —
    /// for sidewinder's cold-start / long-partition rejoin, the maximum round across all anchor
    /// transactions, whose notes are laid out `tag ‖ round_be(8) ‖ root` so every anchor shares the
    /// `tag` prefix. Callers wanting a field-aligned prefix must lay the note out on byte boundaries.
    ///
    /// Walks all indexer result pages (see `collect_confirmed_notes_matching`), so a caller taking a
    /// maximum over the results does not miss matches beyond the first page. `prefix` must be
    /// non-empty (an empty prefix matches every note). Surfaces `AlgoError::HostUnreachable` when the
    /// indexer is down.
    pub fn find_transactions_by_note_prefix(&self, prefix: &[u8]) -> Result<Vec<ConfirmedTxn>> {
        // An empty prefix would match every note, so reject it (as the single-match method does).
        if prefix.is_empty() {
            bail!("prefix must not be empty");
        }
        self.collect_confirmed_notes_matching(prefix, |candidate| candidate.starts_with(prefix))
    }

    pub fn set_asset_clawback_to_app(&self, app_id: u64, asset_id: u64) -> Result<()> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }

        let client = self.algod_client()?;

        // Identify the caller address (signer)
        let caller = self.require_address()?;

        // Authorization check: the caller must be the asset manager (on-chain authority for UpdateAsset).
        let asset_info = self
            .algod_call(|| client.asset(algonaut::core::AssetId(asset_id)))
            .map_err(|e| anyhow!("failed to fetch asset information: {e}"))?;
        let v_asset = serde_json::to_value(&asset_info)
            .map_err(|e| anyhow!("failed to serialize asset info: {e}"))?;
        let asset_manager_str = v_asset
            .get("params")
            .and_then(|p| p.get("manager").and_then(|x| x.as_str()))
            .ok_or_else(|| anyhow!("asset {} info did not contain manager field", asset_id))?;
        let asset_manager = Self::parse_address(asset_manager_str)?;
        if caller != asset_manager {
            bail!(
                "Only the asset manager ({}) can set asset clawback, but called by {}",
                asset_manager_str,
                caller
            );
        }

        // Fetch application address
        let app_addr_str = self.contract_address(app_id)?;
        let app_addr = Self::parse_address(&app_addr_str)?;

        // Fetch suggested params
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Manager must sign this transaction; use caller as it is verified to be the manager.
        // Build asset reconfiguration: explicitly keep manager as the caller; set clawback and reserve to app address.
        let tx = algonaut::transaction::builder::UpdateAsset::new(
            caller,
            algonaut::core::AssetId(asset_id),
        )
        .manager(caller)
        .reserve(app_addr)
        .clawback(app_addr)
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build asset config transaction: {e}"))?;

        // Sign and submit
        let sk = self.private_key_bytes()?;
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset config transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;

        self.wait_for_confirmation(&tx_id, 10)?;
        algo_log!(
            "Successfully set asset {} clawback and reserve to app address {}",
            asset_id,
            app_addr
        );
        Ok(())
    }

    /// Change an ASA's reserve address using an AssetConfiguration (reconfigure) transaction.
    /// Requires the caller to be the asset creator (manager) to succeed on-chain.
    /// Additionally, after updating the reserve address, transfer the caller's current
    /// holding of the asset to the new reserve address (if any balance is held).
    pub fn change_asset_reserve_address(&self, asset_id: u64, reserve_address: &str) -> Result<()> {
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        // Parse target reserve address early
        let new_reserve = Self::parse_address(reserve_address)
            .map_err(|e| anyhow!("invalid reserve address: {e}"))?;

        // We must sign as the asset manager/creator
        let sk = self.private_key_bytes()?;
        let signer_addr = self.require_address()?;

        // Verify the caller is the asset creator by querying asset information
        let client = self.algod_client()?;
        let asset_info = self
            .algod_call(|| client.asset(algonaut::core::AssetId(asset_id)))
            .map_err(|e| anyhow!("failed to fetch asset information: {e}"))?;
        let v = serde_json::to_value(&asset_info)
            .map_err(|e| anyhow!("failed to serialize asset info: {e}"))?;
        // Try to read creator from params or top-level
        let creator_str = v
            .get("params")
            .and_then(|p| p.get("creator").and_then(|x| x.as_str()))
            .or_else(|| v.get("creator").and_then(|x| x.as_str()))
            .or_else(|| {
                v.get("params").and_then(|p| {
                    p.get("creator-address")
                        .or_else(|| p.get("creator_address"))
                        .and_then(|x| x.as_str())
                })
            })
            .ok_or_else(|| anyhow!("asset info did not contain creator field"))?;
        let caller_str = {
            use std::str::FromStr;
            algonaut::core::Address::from_str(
                self.address
                    .as_ref()
                    .ok_or_else(|| anyhow!("This operation needs an address"))?,
            )
            .map_err(|e| anyhow!("invalid caller address: {e}"))?
            .to_string()
        };
        if creator_str != caller_str {
            bail!("caller must be the asset creator to change the reserve address");
        }

        // Suggested params
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Build UpdateAsset setting reserve and clawback to the same new address; keep manager unchanged (set to signer to be explicit)
        let tx = algonaut::transaction::builder::UpdateAsset::new(
            signer_addr,
            algonaut::core::AssetId(asset_id),
        )
        .manager(signer_addr)
        .reserve(new_reserve)
        .clawback(new_reserve)
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build asset config transaction: {e}"))?;
        algo_log!("[change_asset_reserve_address] tx: {:#?}", tx);

        // Sign and submit
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset config transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        // Wait for reconfiguration confirmation
        self.wait_for_confirmation(&tx_id, 10)?;

        // After reserve update, transfer creator's current holdings to the new reserve address
        // 1) Determine creator's balance of this asset
        let acct_info = self
            .algod_call(|| client.account(&signer_addr))
            .map_err(|e| anyhow!("failed to fetch creator account information: {e}"))?;
        let va = serde_json::to_value(&acct_info)
            .map_err(|e| anyhow!("failed to serialize creator account info: {e}"))?;
        let mut creator_amount: u64 = 0;
        if let Some(arr) = va.get("assets").and_then(|x| x.as_array()) {
            for holding in arr {
                let id = holding
                    .get("asset-id")
                    .and_then(|x| x.as_u64())
                    .or_else(|| holding.get("asset_id").and_then(|x| x.as_u64()))
                    .unwrap_or(0);
                if id == asset_id {
                    creator_amount = holding.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                    break;
                }
            }
        }
        if creator_amount == 0 {
            algo_log!(
                "[change_asset_reserve_address] creator has no balance of asset {}",
                asset_id
            );
            return Ok(()); // nothing to move
        }

        // 2) Ensure the new reserve address is opted-in to receive the asset
        if !self.is_account_opted_in_to_asset(reserve_address, asset_id)? {
            bail!("new reserve address is not opted-in to asset {}", asset_id);
        }

        // 3) Transfer entire balance to the new reserve address
        self.send_asset(asset_id, creator_amount, reserve_address)
    }

    pub fn send_asset(&self, asset_id: u64, amount: u64, to_address: &str) -> Result<()> {
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        if amount == 0 {
            bail!("amount must be > 0");
        }

        // Validate env and addresses
        let sk = self.private_key_bytes()?;
        let from = self.require_address()?;
        let to = Self::parse_address(to_address)?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Build asset transfer transaction
        let tx = algonaut::transaction::TransferAsset::new(
            from,
            algonaut::core::AssetId(asset_id),
            amount,
            to,
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build asset transfer transaction: {e}"))?;

        algo_log!("[send_asset] tx: {:#?}", tx);

        // Sign and submit
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset transfer transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;

        self.wait_for_confirmation(&tx_id, 10)
    }

    pub fn opt_in_to_asset(&self, asset_id: u64) -> Result<()> {
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        // Ensure we have account access
        let sk = self.private_key_bytes()?;
        let addr = self.require_address()?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Opt-in is a zero-amount transfer from self to self
        let tx = algonaut::transaction::TransferAsset::new(
            addr,
            algonaut::core::AssetId(asset_id),
            0,
            addr,
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build asset opt-in transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign asset opt-in transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;

        self.wait_for_confirmation(&tx_id, 10)
    }

    /// Extract (creator, reserve) addresses from an asset_information JSON value. Returns None if fields missing.
    ///
    /// Production helper used by `recover_reserve_balance`; `pub(crate)`, and re-exported
    /// publicly under `test-support` so the reserve-helper tests can exercise the parsing.
    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    pub(crate) fn parse_creator_reserve_from_asset_info_value(
        v: &serde_json::Value,
    ) -> Option<(String, String)> {
        let params = v.get("params");
        let creator = params
            .and_then(|p| p.get("creator").and_then(|x| x.as_str()))
            .or_else(|| v.get("creator").and_then(|x| x.as_str()))?;
        let reserve = params.and_then(|p| {
            p.get("reserve").and_then(|x| x.as_str()).or_else(|| {
                p.get("reserve-address")
                    .or_else(|| p.get("reserve_address"))
                    .and_then(|x| x.as_str())
            })
        })?;
        Some((creator.to_string(), reserve.to_string()))
    }

    /// From an account_information JSON value, find the holding amount for the given asset id.
    ///
    /// Production helper used by `asset_holding` / `recover_reserve_balance`; `pub(crate)`, and
    /// re-exported publicly under `test-support` so the reserve-helper tests can exercise it.
    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    pub(crate) fn parse_holding_amount_from_account_value(
        v: &serde_json::Value,
        asset_id: u64,
    ) -> u64 {
        if let Some(arr) = v.get("assets").and_then(|x| x.as_array()) {
            for holding in arr {
                let id = holding
                    .get("asset-id")
                    .and_then(|x| x.as_u64())
                    .or_else(|| holding.get("asset_id").and_then(|x| x.as_u64()))
                    .unwrap_or(0);
                if id == asset_id {
                    return holding.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                }
            }
        }
        0
    }

    /// Transfer the entire reserve balance of an ASA to the creator. The caller must control the reserve address.
    pub fn recover_reserve_balance(&self, asset_id: u64) -> Result<()> {
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        let client = self.algod_client()?;
        // Fetch asset info
        let asset_info = self
            .algod_call(|| client.asset(algonaut::core::AssetId(asset_id)))
            .map_err(|e| anyhow!("failed to fetch asset information: {e}"))?;
        let v = serde_json::to_value(&asset_info)
            .map_err(|e| anyhow!("failed to serialize asset info: {e}"))?;
        let (creator_str, reserve_str) = match Self::parse_creator_reserve_from_asset_info_value(&v)
        {
            Some(t) => t,
            None => {
                return Err(anyhow!(
                    "asset information did not contain creator/reserve fields"
                ));
            }
        };
        // Ensure we are the reserve account
        let caller_addr = self
            .address
            .as_ref()
            .ok_or_else(|| anyhow!("This operation needs an address"))?
            .clone();
        if caller_addr != reserve_str {
            bail!("caller must be the current reserve address to recover the reserve balance");
        }
        // Ensure creator is opted-in to receive the asset
        if !self.is_account_opted_in_to_asset(&creator_str, asset_id)? {
            bail!("creator address is not opted-in to asset {asset_id}");
        }
        // Get reserve account holdings
        let reserve_addr = Self::parse_address(&reserve_str)?;
        let acct_info = self
            .algod_call(|| client.account(&reserve_addr))
            .map_err(|e| anyhow!("failed to fetch reserve account information: {e}"))?;
        let va = serde_json::to_value(&acct_info)
            .map_err(|e| anyhow!("failed to serialize reserve account info: {e}"))?;
        let amount = Self::parse_holding_amount_from_account_value(&va, asset_id);
        if amount == 0 {
            algo_log!("[recover_reserve_balance] reserve has zero balance for asset {asset_id}");
            return Ok(());
        }
        // Transfer to creator
        self.send_asset(asset_id, amount, &creator_str)
    }

    pub fn compile_teal(&self, source: &str) -> Result<Vec<u8>> {
        if source.is_empty() {
            bail!("source must not be empty");
        }
        // If already provided as base64 compiled program, allow it for convenience.
        if let Some(rest) = source.strip_prefix("base64:") {
            let bytes = general_purpose::STANDARD
                .decode(rest)
                .map_err(|e| anyhow!("invalid base64 program: {e}"))?;
            return Ok(bytes);
        }
        let client = self.algod_client()?;
        let resp =
            self.algod_call(|| client.teal_compile(source.as_bytes(), algonaut::SourceMap::Skip))?;
        // The compiled bytes are in the tuple struct directly
        Ok(resp.0)
    }

    // Compute 4-byte ARC-4 method selector from a signature string.
    pub fn arc4_selector(sig: &str) -> [u8; 4] {
        use sha2::{Digest, Sha512_256};
        let mut hasher = Sha512_256::new();
        hasher.update(sig.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    #[inline]
    fn estimate_fee_for_programs(
        params: &algonaut::model::algod::SuggestedParams,
        sizes: &[usize],
    ) -> algonaut::core::MicroAlgos {
        let total_size: usize = sizes.iter().copied().sum();
        let per_byte = params.fee; // MicroAlgos per byte
        let min_fee = params.min_fee; // MicroAlgos
        let sized = per_byte * (total_size as u64);
        if sized > min_fee { sized } else { min_fee }
    }

    #[inline]
    fn estimate_fee_for_signed_size(
        params: &algonaut::model::algod::SuggestedParams,
        est_size: u64,
    ) -> algonaut::core::MicroAlgos {
        let per_byte = params.fee; // MicroAlgos
        let min_fee = params.min_fee; // MicroAlgos
        let sized = per_byte * est_size;
        if sized > min_fee { sized } else { min_fee }
    }

    /// Parse the global and local `StateSchema` from an ARC-56 app spec's `state/schema`.
    fn state_schema_from_arc56(
        arc56_json: &str,
    ) -> Result<(
        algonaut::transaction::transaction::StateSchema,
        algonaut::transaction::transaction::StateSchema,
    )> {
        let spec: serde_json::Value = serde_json::from_str(arc56_json)
            .map_err(|e| anyhow!("failed to parse ARC-56 app spec json: {e}"))?;
        let schema = spec
            .get("state")
            .and_then(|s| s.get("schema"))
            .ok_or_else(|| anyhow!("ARC-56 app spec missing state/schema"))?;
        let read = |section: &str, field: &str| -> Result<u64> {
            schema
                .get(section)
                .and_then(|v| v.get(field))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| {
                    anyhow!("ARC-56 app spec missing state/schema/{}/{}", section, field)
                })
        };
        let global = algonaut::transaction::transaction::StateSchema {
            number_ints: read("global", "ints")?,
            number_byteslices: read("global", "bytes")?,
        };
        let local = algonaut::transaction::transaction::StateSchema {
            number_ints: read("local", "ints")?,
            number_byteslices: read("local", "bytes")?,
        };
        Ok((global, local))
    }

    /// Deploy a new Algorand application.
    ///
    /// - `asset_id`: if `Some`, the app is opted into this ASA immediately after creation.
    /// - `method`: ARC-4 method signature to include in the create transaction (e.g.
    ///   `"create(address,address)void"`). Required when the contract uses
    ///   `@abimethod(create="require")`. Pass `None` for bare-create contracts.
    /// - `args`: ABI-encoded arguments for `method`. Must match the method signature.
    /// - `opt_in_method_name`: name of the method on the creator that opts the app in using Teal, signature opt_in(app_id)
    ///   Use `AppArg::Bytes(32-byte pk)` for `address` parameters.
    /// - `arc56_json`: text of the contract's ARC-56 app spec (the `*.arc56.json` that sits
    ///   alongside the TEAL). The global/local state schema is read from its `state/schema`.
    pub fn deploy_app(
        &self,
        approval_program: &[u8],
        clear_state_program: &[u8],
        asset_id: Option<u64>,
        method: Option<&str>,
        args: &[AppArg],
        opt_in_method_name: &str,
        arc56_json: &str,
    ) -> Result<Option<u64>> {
        if approval_program.is_empty() {
            bail!("approval_program must not be empty");
        }
        if clear_state_program.is_empty() {
            bail!("clear_state_program must not be empty");
        }
        // Ensure we have account access
        let sk = self.private_key_bytes()?;
        let sender = self.require_address()?;

        // Build programs and derive the state schema from the ARC-56 app spec (state/schema)
        // so the allocation stays in sync with the contract rather than being hardcoded.
        let approval = algonaut::core::CompiledTeal(approval_program.to_vec());
        let clear = algonaut::core::CompiledTeal(clear_state_program.to_vec());
        let (gs, ls) = Self::state_schema_from_arc56(arc56_json)?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Before building/sending, estimate the cost of the CreateApplication and ensure we have funds
        // Estimate bytes using CompiledTeal.bytes_to_sign per requirement
        let est_prog_size: usize = approval.bytes_to_sign().len() + clear.bytes_to_sign().len();
        let est_fee = Self::estimate_fee_for_programs(&params, &[est_prog_size]);
        let est_fee_micro: u64 = est_fee.0; // microAlgos

        let balance_algos = self
            .account_balance()? // Always validate Option succeeds per guideline
            .ok_or_else(|| anyhow!("Unable to determine account balance from algod; the account may not be funded or node unreachable"))?;
        let balance_micro = (balance_algos * 1_000_000.0).floor() as u64;
        if balance_micro < est_fee_micro {
            let need_algos = est_fee_micro as f64 / 1_000_000.0;
            return Err(anyhow!(
                "Insufficient funds to create application: balance {:.6} ALGO, estimated required fee {:.6} ALGO. Please fund the creator account and retry.",
                balance_algos,
                need_algos
            ));
        }

        // Print estimated fee components and current balance for visibility
        let per_byte = params.fee;
        let min_fee = params.min_fee;
        algo_log!(
            "Preflight: min_fee={} µAlgos, fee_per_byte={} µAlgos/byte, est_prog_size={} bytes, estimated fee: {:.6} ALGO ({} µAlgos); current balance: {:.6} ALGO ({} µAlgos)",
            min_fee.0,
            per_byte.0,
            est_prog_size,
            est_fee_micro as f64 / 1_000_000.0,
            est_fee_micro,
            balance_algos,
            balance_micro
        );

        // Build ABI args for the create method if provided.
        let mut app_args: Vec<Vec<u8>> = Vec::new();
        if let Some(sig) = method {
            app_args.push(Self::arc4_selector(sig).to_vec());
        }
        app_args.extend(args.iter().map(|a| a.to_bytes()));

        // Build create application transaction
        let mut builder =
            algonaut::transaction::CreateApplication::new(sender, approval, clear, gs, ls);
        if let Some(aid) = asset_id {
            builder = builder.foreign_assets(vec![algonaut::core::AssetId(aid)]);
        }
        if !app_args.is_empty() {
            builder = builder.app_arguments(app_args);
        }
        let tx = builder
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build app create transaction: {e}"))?;

        // Sign and submit
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app create transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;

        self.wait_for_confirmation(&tx_id, 10)?;

        // Retrieve created application id from pending tx info (robust JSON-based extraction)
        let tx_id_obj = algonaut::core::TransactionId::from(tx_id.as_str());
        let info = self
            .algod_call(|| client.pending_transaction(&tx_id_obj))
            .map_err(|e| anyhow!("failed to fetch pending transaction info for app id: {e}"))?;
        {
            let v = serde_json::to_value(&info)
                .map_err(|e| anyhow!("failed to serialize pending tx info: {e}"))?;
            let app_id = v
                .get("application-index")
                .and_then(|x| x.as_u64())
                .or_else(|| v.get("application_index").and_then(|x| x.as_u64()))
                .unwrap_or(0);

            if app_id != 0 {
                // After successful creation, fund the app account with 3.21 ALGO from the creator
                if let Ok(app_addr) = self.contract_address(app_id) {
                    // Best-effort funding; bubble up error if funding fails
                    self.send_algo(&app_addr, 3.21)?;
                }
                // If an asset id was provided, opt the app address in via the dApp admin method
                if let Some(aid) = asset_id {
                    // Propagate any error from the admin call; ignore returned tx id
                    let _ = self.opt_in_app_to_asset(app_id, aid, opt_in_method_name)?;

                    // Additionally set the reserve and clawback addresses to the application address
                    self.set_asset_clawback_to_app(app_id, aid)?;
                }
            }
            Ok((app_id != 0).then_some(app_id))
        }
    }

    pub fn update_app(
        &self,
        app_id: u64,
        approval_program: &[u8],
        clear_state_program: &[u8],
        asset_id: Option<u64>,
    ) -> Result<Option<u64>> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        if approval_program.is_empty() {
            bail!("approval_program must not be empty");
        }
        if clear_state_program.is_empty() {
            bail!("clear_state_program must not be empty");
        }
        let sk = self.private_key_bytes()?;
        let sender = self.require_address()?;

        let approval = algonaut::core::CompiledTeal(approval_program.to_vec());
        let clear = algonaut::core::CompiledTeal(clear_state_program.to_vec());

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Estimate fee using helper and params
        let est_prog_size: usize = approval.bytes_to_sign().len() + clear.bytes_to_sign().len();
        let est_fee = Self::estimate_fee_for_programs(&params, &[est_prog_size]);
        let per_byte = params.fee;
        let min_fee = params.min_fee;
        algo_log!(
            "Update preflight: min_fee={} µAlgos, fee_per_byte={} µAlgos/byte, est_prog_size={} bytes, estimated fee: {:.6} ALGO ({} µAlgos)",
            min_fee.0,
            per_byte.0,
            est_prog_size,
            est_fee.0 as f64 / 1_000_000.0,
            est_fee.0
        );

        // Note: Application state schemas (global/local) are immutable after creation on Algorand.
        // Do NOT attempt to change schemas in an update; only approval/clear programs (and other updatable
        // fields supported by the protocol) can be changed. Therefore, we build a plain UpdateApplication
        // with the new programs and do not set schemas here.
        let mut builder = algonaut::transaction::builder::UpdateApplication::new(
            sender,
            algonaut::core::AppId(app_id),
            approval,
            clear,
        );
        if let Some(aid) = asset_id {
            builder = builder.foreign_assets(vec![algonaut::core::AssetId(aid)]);
        }
        let tx = builder
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build app update transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app update transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;

        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)?;
        Ok(Some(app_id))
    }

    pub fn call_app(
        &self,
        app_id: u64,
        asset_id: Option<u64>,
        method: Option<&str>,
        args: &[AppArg],
    ) -> Result<(String, Vec<Vec<u8>>)> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        // Build tx
        let tx = self.build_call_app_tx(app_id, asset_id, method, args)?;
        algo_log!(
            "[call_app] method={:?} app_id={} asset_id={:?} args_len={}",
            method,
            app_id,
            asset_id,
            args.len()
        );
        algo_log!("[call_app] tx={:?}", tx);
        let sk = self.private_key_bytes()?;
        let client = self.algod_client()?;
        // Sign, submit, wait
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app call transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)?;
        // Fetch logs
        let tx_id_obj = algonaut::core::TransactionId::from(tx_id.as_str());
        let p = self
            .algod_call(|| client.pending_transaction(&tx_id_obj))
            .map_err(|e| anyhow!("failed to fetch pending transaction info: {e}"))?;
        let v = serde_json::to_value(&p)
            .map_err(|e| anyhow!("failed to serialize pending tx info: {e}"))?;
        let logs_arr = v
            .get("logs")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let mut logs: Vec<Vec<u8>> = Vec::new();
        for l in logs_arr {
            if let Some(s) = l.as_str()
                && let Ok(bytes) = general_purpose::STANDARD.decode(s)
            {
                logs.push(bytes);
            }
        }
        Ok((tx_id, logs))
    }

    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    pub(crate) fn build_call_app_tx(
        &self,
        app_id: u64,
        asset_id: Option<u64>,
        method: Option<&str>,
        args: &[AppArg],
    ) -> Result<algonaut::transaction::transaction::Transaction> {
        self.build_call_app_tx_inner(app_id, asset_id, &[], method, args)
    }

    // No in-crate caller: a `test-support`-only escape hatch for downstream tests.
    #[cfg_attr(feature = "test-support", visibility::make(pub))]
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    pub(crate) fn build_call_app_tx_with_foreign_apps(
        &self,
        app_id: u64,
        asset_id: Option<u64>,
        foreign_app_ids: &[u64],
        method: Option<&str>,
        args: &[AppArg],
    ) -> Result<algonaut::transaction::transaction::Transaction> {
        self.build_call_app_tx_inner(app_id, asset_id, foreign_app_ids, method, args)
    }

    pub fn call_app_with_foreign_app(
        &self,
        app_id: u64,
        foreign_app_id: u64,
        asset_id: Option<u64>,
        method: Option<&str>,
        args: &[AppArg],
    ) -> Result<(String, Vec<Vec<u8>>)> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        if foreign_app_id == 0 {
            bail!("foreign_app_id must be > 0");
        }
        let tx = self.build_call_app_tx_inner(app_id, asset_id, &[foreign_app_id], method, args)?;
        algo_log!(
            "[call_app_with_foreign_app] method={:?} app_id={} foreign_app_id={}",
            method,
            app_id,
            foreign_app_id
        );
        let sk = self.private_key_bytes()?;
        let client = self.algod_client()?;
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app call transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)?;
        let tx_id_obj = algonaut::core::TransactionId::from(tx_id.as_str());
        let p = self
            .algod_call(|| client.pending_transaction(&tx_id_obj))
            .map_err(|e| anyhow!("failed to fetch pending transaction info: {e}"))?;
        let v = serde_json::to_value(&p)
            .map_err(|e| anyhow!("failed to serialize pending tx info: {e}"))?;
        let logs_arr = v
            .get("logs")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let mut logs: Vec<Vec<u8>> = Vec::new();
        for l in logs_arr {
            if let Some(s) = l.as_str()
                && let Ok(bytes) = general_purpose::STANDARD.decode(s)
            {
                logs.push(bytes);
            }
        }
        Ok((tx_id, logs))
    }

    fn build_call_app_tx_inner(
        &self,
        app_id: u64,
        asset_id: Option<u64>,
        foreign_app_ids: &[u64],
        method: Option<&str>,
        args: &[AppArg],
    ) -> Result<algonaut::transaction::transaction::Transaction> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let client = self.algod_client()?;
        let app_info = self
            .algod_call(|| client.app(algonaut::core::AppId(app_id)))
            .map_err(|e| anyhow!("failed to fetch application information: {e}"))?;
        let app_info_v = serde_json::to_value(&app_info)
            .map_err(|e| anyhow!("failed to serialize application info: {e}"))?;
        let creator_str = app_info_v
            .get("params")
            .and_then(|p| p.get("creator").and_then(|x| x.as_str()))
            .or_else(|| app_info_v.get("creator").and_then(|x| x.as_str()))
            .ok_or_else(|| anyhow!("application info did not contain creator field"))?;
        let creator = Self::parse_address(creator_str)?;
        let sender = self.require_address()?;

        let mut app_args: Vec<Vec<u8>> = Vec::new();
        if let Some(sig) = method {
            app_args.push(Self::arc4_selector(sig).to_vec());
        }
        app_args.extend(args.iter().map(|a| a.to_bytes()));

        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let mut accounts: Vec<algonaut::core::Address> = vec![creator];
        if let Some(sig) = method
            && (sig == "set_allow_static(address,uint64)void"
                || sig == "set_allow_relay(address,uint64)void")
            && let Some(first) = args.first()
            && let AppArg::Bytes(b) = first
            && b.len() == 32
        {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&b[..32]);
            if let Ok(addr_str) = byte_key_to_address(&pk)
                && let Ok(target) = Self::parse_address(&addr_str)
            {
                accounts.insert(0, target);
            }
        }
        let fapps: Vec<algonaut::core::AppId> = foreign_app_ids
            .iter()
            .map(|&id| algonaut::core::AppId(id))
            .collect();
        let make_builder = || {
            let mut b = algonaut::transaction::builder::CallApplication::new(
                sender,
                algonaut::core::AppId(app_id),
            )
            .accounts(accounts.clone())
            .app_arguments(app_args.clone());
            if let Some(aid) = asset_id {
                b = b.foreign_assets(vec![algonaut::core::AssetId(aid)]);
            }
            if !fapps.is_empty() {
                b = b.foreign_apps(fapps.clone());
            }
            b
        };
        let tx_zero_fee = make_builder()
            .fee(algonaut::core::MicroAlgos(0))
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build app call transaction for fee estimation: {e}"))?;
        let est_size = tx_zero_fee
            .estimate_basic_sig_size()
            .map_err(|e| anyhow!("failed to estimate signed tx size: {e}"))?;
        let est_fee = Self::estimate_fee_for_signed_size(&params, est_size);
        let tx = make_builder()
            .fee(est_fee)
            .note(Self::unique_note())
            .build(&params)
            .map_err(|e| anyhow!("failed to build app call transaction: {e}"))?;
        Ok(tx)
    }

    pub fn opt_in_app(&self, app_id: u64) -> Result<()> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        // If already opted-in to local state for this app, nothing to do.
        // Always validate that Option succeeds per guidelines.
        let addr_str = self
            .address
            .as_ref()
            .ok_or_else(|| anyhow!("This operation needs an address"))?;
        if let Some(_entries) = self.local_state_for_account(app_id, addr_str)? {
            return Ok(());
        }

        let sender = self.require_address()?;
        let sk = self.private_key_bytes()?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let tx = algonaut::transaction::builder::OptInApplication::new(
            sender,
            algonaut::core::AppId(app_id),
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build app opt-in transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app opt-in transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)
    }

    pub fn clear_state_app(&self, app_id: u64) -> Result<()> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let sender = self.require_address()?;
        let sk = self.private_key_bytes()?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let tx = algonaut::transaction::builder::ClearApplication::new(
            sender,
            algonaut::core::AppId(app_id),
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build app clear transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app clear transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)
    }

    pub fn close_out_app(&self, app_id: u64) -> Result<()> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let sender = self.require_address()?;
        let sk = self.private_key_bytes()?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let tx = algonaut::transaction::builder::CloseApplication::new(
            sender,
            algonaut::core::AppId(app_id),
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build app close-out transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app close-out transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)
    }

    pub fn delete_app(&self, app_id: u64) -> Result<()> {
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        let sender = self.require_address()?;
        let sk = self.private_key_bytes()?;

        let client = self.algod_client()?;
        let params = self
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        let tx = algonaut::transaction::builder::DeleteApplication::new(
            sender,
            algonaut::core::AppId(app_id),
        )
        .note(Self::unique_note())
        .build(&params)
        .map_err(|e| anyhow!("failed to build app delete transaction: {e}"))?;

        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let signed_tx = account
            .sign(tx)
            .map_err(|e| anyhow!("failed to sign app delete transaction: {e}"))?;
        let signed = signed_tx
            .to_msg_pack()
            .map_err(|e| anyhow!("failed to encode signed transaction: {e}"))?;
        let tx_id = self
            .algod_call(|| client.send_raw(&signed))
            .map_err(|e| anyhow!("send_raw failed: {e}"))?
            .tx_id;
        self.wait_for_confirmation(&tx_id, 10)
    }

    /// Admin method: Opt the application account into the given ASA by a method on the creator
    /// like "opt_(app_id)" which opts the app in using Teal
    /// Returns the transaction id of the app call when an opt-in was required; if the
    /// app was already opted in, returns Ok("") without making a call.
    /// opt_in_method_name must be a method on the creator like "opt_(app_id)" which opts the app in using Teal
    pub fn opt_in_app_to_asset(
        &self,
        app_id: u64,
        asset_id: u64,
        opt_in_method_name: &str,
    ) -> Result<String> {
        tracing::info!("opt_in_app_to_asset: app_id={}", app_id);
        if app_id == 0 {
            bail!("app_id must be > 0");
        }
        if asset_id == 0 {
            bail!("asset_id must be > 0");
        }
        // If the app address already holds the asset, nothing to do
        let app_addr_str = self.contract_address(app_id)?;
        if self.is_account_opted_in_to_asset(&app_addr_str, asset_id)? {
            return Ok(String::new());
        }
        // Call the admin method on the contract; this must be signed by the creator
        let (tx_id, _logs) = self.call_app(
            app_id,
            Some(asset_id),
            Some(opt_in_method_name),
            &[AppArg::Uint(asset_id)],
        )?;
        // Return tx id to signal a call occurred; fetch from tuple index 0
        Ok(tx_id)
    }

    /// Wait for a transaction to be confirmed up to `timeout_rounds` rounds.
    /// Follows the Kotlin logic: poll pending tx info and wait for next rounds.
    pub fn wait_for_confirmation(&self, tx_id: &str, timeout_rounds: u64) -> Result<()> {
        if timeout_rounds == 0 {
            bail!("timeout_rounds must be > 0");
        }
        let client = self.algod_client()?;

        // Get starting round
        let status = self
            .algod_call(|| client.status())
            .map_err(|e| anyhow!("failed to get node status: {e}"))?;
        let start_round = status.last_round.0 + 1;
        let end_round = start_round + timeout_rounds;

        let mut current_round = start_round;
        while current_round < end_round {
            // Check pending transaction info
            let tx_id_obj = algonaut::core::TransactionId::from(tx_id);
            match self.algod_call(|| client.pending_transaction(&tx_id_obj)) {
                Ok(p) => {
                    if let Some(cr) = p.confirmed_round
                        && cr > 0
                    {
                        return Ok(());
                    }
                    if !p.pool_error.is_empty() {
                        bail!("Transaction rejected with pool error: {}", p.pool_error);
                    }
                }
                Err(e) => {
                    if AlgoError::is_host_unreachable(&anyhow!(e.to_string())) {
                        return Err(
                            AlgoError::unreachable("pending_transaction", &e.to_string()).into(),
                        );
                    }
                    // If the node no longer remembers the tx or transient error, continue waiting until timeout
                }
            }

            // Wait for next round
            self.algod_call(|| client.status_after_block(algonaut::core::Round(current_round)))
                .map_err(|e| anyhow!("status_after_block failed: {e}"))?;
            current_round += 1;
        }
        Err(anyhow!(
            "Transaction not confirmed after {} rounds",
            timeout_rounds
        ))
    }

    /// Begin building an atomic transaction group signed and sent by this account.
    ///
    /// Legs are added in order — [`payment`](TransactionGroupBuilder::payment),
    /// [`asset_transfer`](TransactionGroupBuilder::asset_transfer), and
    /// [`call_app`](TransactionGroupBuilder::call_app) — then
    /// [`sign_and_send`](TransactionGroupBuilder::sign_and_send) assigns a shared group id,
    /// signs every leg with this account, broadcasts them atomically, waits for confirmation,
    /// and returns the group's representative transaction id. This keeps `algonaut` group
    /// types out of the public surface, replacing the sealed `build_call_app_tx` escape hatch.
    ///
    /// ```no_run
    /// # use algo_ops::AlgoOps;
    /// # fn f(ops: &AlgoOps, app_address: &str, price_microalgos: u64, app_id: u64, asset_id: u64) -> anyhow::Result<()> {
    /// let tx_id = ops
    ///     .transaction_group()
    ///     .payment(app_address, price_microalgos)          // Pay: ops account -> app_address
    ///     .call_app(app_id, Some("buy_bingle()void"), &[]) // ABI app-call
    ///     .foreign_asset(asset_id)                         // per-leg option, applies to the app-call
    ///     .sign_and_send()?;                               // group id + sign all + broadcast + wait
    /// # let _ = tx_id;
    /// # Ok(())
    /// # }
    /// ```
    pub fn transaction_group(&self) -> TransactionGroupBuilder<'_> {
        TransactionGroupBuilder {
            ops: self,
            legs: Vec::new(),
            error: None,
        }
    }
}

/// A single leg of an atomic transaction group. All legs are signed by the ops account.
#[derive(Debug, Clone)]
enum GroupLeg {
    /// `Pay` from the ops account to `to` for `micro_algos` microALGOs.
    Payment { to: String, micro_algos: u64 },
    /// ASA transfer of `amount` base units of `asset_id` from the ops account to `to`.
    AssetTransfer {
        asset_id: u64,
        amount: u64,
        to: String,
    },
    /// ABI app-call on `app_id`, with an optional foreign asset / foreign app.
    AppCall {
        app_id: u64,
        method: Option<String>,
        args: Vec<AppArg>,
        foreign_asset: Option<u64>,
        foreign_app: Option<u64>,
    },
}

/// Fluent builder for an atomic transaction group, created by [`AlgoOps::transaction_group`].
///
/// Every leg is signed by the single ops account (single-signer groups). Per-leg option
/// methods ([`foreign_asset`](Self::foreign_asset) / [`foreign_app`](Self::foreign_app)) apply
/// to the most recently added [`call_app`](Self::call_app) leg. A misuse (e.g. a per-leg option
/// with no preceding app-call, or an empty group) is recorded and surfaced by
/// [`sign_and_send`](Self::sign_and_send) rather than panicking.
#[derive(Debug)]
pub struct TransactionGroupBuilder<'a> {
    ops: &'a AlgoOps,
    legs: Vec<GroupLeg>,
    error: Option<String>,
}

impl<'a> TransactionGroupBuilder<'a> {
    // Record the first misuse; later calls keep the original message.
    fn set_error(&mut self, msg: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(msg.into());
        }
    }

    /// Add a payment leg: `Pay` from the ops account to `to_address` for `micro_algos` microALGOs.
    pub fn payment(mut self, to_address: &str, micro_algos: u64) -> Self {
        self.legs.push(GroupLeg::Payment {
            to: to_address.to_string(),
            micro_algos,
        });
        self
    }

    /// Add an asset-transfer leg: move `amount` base units of `asset_id` from the ops account
    /// to `to_address`.
    pub fn asset_transfer(mut self, asset_id: u64, amount: u64, to_address: &str) -> Self {
        self.legs.push(GroupLeg::AssetTransfer {
            asset_id,
            amount,
            to: to_address.to_string(),
        });
        self
    }

    /// Add an ABI app-call leg on `app_id` with the given `method` signature and `args`.
    /// Attach an optional foreign asset / foreign app with [`foreign_asset`](Self::foreign_asset)
    /// / [`foreign_app`](Self::foreign_app) immediately after this call.
    pub fn call_app(mut self, app_id: u64, method: Option<&str>, args: &[AppArg]) -> Self {
        if app_id == 0 {
            self.set_error("call_app() requires app_id > 0");
        }
        self.legs.push(GroupLeg::AppCall {
            app_id,
            method: method.map(|s| s.to_string()),
            args: args.to_vec(),
            foreign_asset: None,
            foreign_app: None,
        });
        self
    }

    /// Attach a foreign asset to the most recently added [`call_app`](Self::call_app) leg.
    pub fn foreign_asset(mut self, asset_id: u64) -> Self {
        match self.legs.last_mut() {
            Some(GroupLeg::AppCall { foreign_asset, .. }) => *foreign_asset = Some(asset_id),
            _ => self.set_error("foreign_asset() must follow a call_app() leg"),
        }
        self
    }

    /// Attach a foreign app to the most recently added [`call_app`](Self::call_app) leg.
    pub fn foreign_app(mut self, foreign_app_id: u64) -> Self {
        match self.legs.last_mut() {
            Some(GroupLeg::AppCall { foreign_app, .. }) => *foreign_app = Some(foreign_app_id),
            _ => self.set_error("foreign_app() must follow a call_app() leg"),
        }
        self
    }

    /// Assign a shared group id to every leg, sign each with the ops account, broadcast the group
    /// atomically, wait for confirmation, and return the group's representative transaction id.
    ///
    /// Fails (before any network I/O) if a builder misuse was recorded or if no legs were added.
    pub fn sign_and_send(self) -> Result<String> {
        if let Some(err) = self.error {
            bail!("{err}");
        }
        if self.legs.is_empty() {
            bail!("transaction group must contain at least one transaction");
        }

        let ops = self.ops;
        let sk = ops.private_key_bytes()?;
        let seed: [u8; 32] = sk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Secret key must be 32 bytes"))?;
        let sender = ops.require_address()?;
        let client = ops.algod_client()?;
        let params = ops
            .algod_call(|| client.suggested_params())
            .map_err(|e| anyhow!("failed to fetch suggested params: {e}"))?;

        // Build each leg into an unsigned transaction, preserving order.
        let mut txns: Vec<algonaut::transaction::transaction::Transaction> =
            Vec::with_capacity(self.legs.len());
        for leg in &self.legs {
            let tx = match leg {
                GroupLeg::Payment { to, micro_algos } => {
                    let to_addr = AlgoOps::parse_address(to)?;
                    algonaut::transaction::Pay::new(
                        sender,
                        to_addr,
                        algonaut::core::MicroAlgos(*micro_algos),
                    )
                    .note(AlgoOps::unique_note())
                    .build(&params)
                    .map_err(|e| anyhow!("failed to build payment transaction: {e}"))?
                }
                GroupLeg::AssetTransfer {
                    asset_id,
                    amount,
                    to,
                } => {
                    let to_addr = AlgoOps::parse_address(to)?;
                    algonaut::transaction::TransferAsset::new(
                        sender,
                        algonaut::core::AssetId(*asset_id),
                        *amount,
                        to_addr,
                    )
                    .note(AlgoOps::unique_note())
                    .build(&params)
                    .map_err(|e| anyhow!("failed to build asset transfer transaction: {e}"))?
                }
                GroupLeg::AppCall {
                    app_id,
                    method,
                    args,
                    foreign_asset,
                    foreign_app,
                } => {
                    let fapps: Vec<u64> = foreign_app.iter().copied().collect();
                    ops.build_call_app_tx_inner(
                        *app_id,
                        *foreign_asset,
                        &fapps,
                        method.as_deref(),
                        args,
                    )?
                }
            };
            txns.push(tx);
        }

        // Assign the shared group id across all legs.
        let group = algonaut::transaction::group::TransactionGroup::try_from(txns)
            .map_err(|e| anyhow!("failed to assign group id: {e}"))?;

        // Sign every leg with the ops account.
        let account = algonaut::transaction::account::Account::from_seed(seed);
        let mut signed: Vec<algonaut::transaction::SignedTransaction> = Vec::new();
        for tx in group.into_transactions() {
            let stx = account
                .sign(tx)
                .map_err(|e| anyhow!("failed to sign grouped transaction: {e}"))?;
            signed.push(stx);
        }

        // Broadcast the group atomically and wait for confirmation.
        let tx_id = ops
            .algod_call(|| client.send_transactions(&signed))
            .map_err(|e| anyhow!("failed to broadcast transaction group: {e}"))?
            .tx_id;
        ops.wait_for_confirmation(&tx_id, 10)?;
        Ok(tx_id)
    }
}

/// Application argument type, similar to Kotlin variant handling.
///
/// This is the Algorand application-arguments / Application Binary Interface (ABI) convention, which
/// the Sidewinder client also packs operation arguments with (see `sidewinder_ops`): each argument
/// is encoded on its own — a `Uint` as 8 big-endian bytes (an Algorand Request for Comments 4,
/// ARC-4, `uint64`), and `Bytes` / `Utf8` as their raw bytes (the argument boundary carries the
/// length, so no length prefix is added).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArg {
    Bytes(Vec<u8>),
    Utf8(String),
    Uint(u64),
}

impl AppArg {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            AppArg::Bytes(b) => b.clone(),
            AppArg::Utf8(s) => s.as_bytes().to_vec(),
            AppArg::Uint(v) => v.to_be_bytes().to_vec(),
        }
    }
}

/// Decode first 32 bytes of an Algorand address' base32 to get the public key.
pub fn address_to_byte_key(address: &str) -> Result<[u8; 32]> {
    // Algorand addresses use RFC4648 base32 without padding and include checksum.
    let decoded = BASE32_NOPAD
        .decode(address.as_bytes())
        .map_err(|e| anyhow!("Invalid base32 address: {e}"))?;
    if decoded.len() < 32 {
        bail!("Decoded address is shorter than 32 bytes");
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&decoded[..32]);
    Ok(pk)
}

/// Build an Algorand address from a 32-byte public key.
pub fn byte_key_to_address(byte_public_key: &[u8; 32]) -> Result<String> {
    use sha2::{Digest, Sha512_256};
    // Compute checksum: SHA512/256 over public key, take last 4 bytes
    let mut hasher = Sha512_256::new();

    hasher.update(byte_public_key);
    let hash = hasher.finalize();
    let checksum = &hash[hash.len() - 4..];

    let mut addr_bytes = [0u8; 36];
    addr_bytes[..32].copy_from_slice(byte_public_key);
    addr_bytes[32..].copy_from_slice(checksum);

    let addr = BASE32_NOPAD.encode(&addr_bytes);
    Ok(addr)
}

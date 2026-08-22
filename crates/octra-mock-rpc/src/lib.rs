//! In-memory mock of the Octra JSON-RPC surface OctraVPN exercises.
//!
//! v1 model (per `docs/aml-gap-analysis.md`): operator bonding +
//! stake-gated registration, single-hop sessions with validator-only
//! settle, HFHE-backed encrypted earnings, governance slashing.
//!
//! Each accepted submission advances `epoch` by one so epoch-driven
//! logic (grace windows, unbonding) can be exercised in tests.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use octra_core::coverage as cov;

pub mod aml;
pub mod cheats;
pub mod methods;

mod coverage {
    pub(crate) fn record(method: &str, branch: &str) {
        super::cov::record(method, branch);
    }
}

// =====================================================================
// JSON-RPC error envelope
//
// The node's error codes are a fixed, documented table
// (`lib/core/rpc.ml:28-43`) and every one of them is load-bearing for a
// client: 101 means "resign", 102 means "refetch the nonce", 104 means
// "you are broke". This mock used to flatten all of them into a single
// `-32000` with a free-text message, so no Tier-1 test could ever assert
// on the code a real client branches on.
//
// Verified live against the node in `octra-local-node-octra-node-1`
// (`octra_balance` on an unknown address -> `{"code":100,"message":
// "sender not found"}`; `octra_submit` with a junk signature ->
// `{"code":101,...}`; `octra_transaction` on an unknown hash ->
// `{"code":112,"message":"not found","data":"transaction not found"}`).
// =====================================================================

/// A JSON-RPC error in the node's own shape (`lib/core/rpc.ml:4-8`,
/// rendered by `response_json`, `rpc.ml:45-52`).
#[derive(Clone, Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }

    // --- the node's numbered table, `rpc.ml:28-43` -------------------
    #[must_use]
    pub fn sender_not_found() -> Self {
        Self::new(100, "sender not found", None)
    }
    #[must_use]
    pub fn invalid_signature() -> Self {
        Self::new(101, "invalid signature", None)
    }
    #[must_use]
    pub fn invalid_nonce() -> Self {
        Self::new(102, "invalid nonce", None)
    }
    #[must_use]
    pub fn nonce_too_far() -> Self {
        Self::new(103, "nonce too far ahead", None)
    }
    #[must_use]
    pub fn insufficient_balance() -> Self {
        Self::new(104, "insufficient balance", None)
    }
    #[must_use]
    pub fn malformed_tx(msg: impl Into<String>) -> Self {
        Self::new(105, "malformed transaction", Some(json!(msg.into())))
    }
    #[must_use]
    pub fn duplicate_tx() -> Self {
        Self::new(106, "duplicate transaction", None)
    }
    #[must_use]
    pub fn staging_full() -> Self {
        Self::new(107, "staging full", None)
    }
    #[must_use]
    pub fn self_transfer() -> Self {
        Self::new(108, "self transfer", None)
    }
    #[must_use]
    pub fn invalid_address(msg: impl Into<String>) -> Self {
        Self::new(109, "invalid address", Some(json!(msg.into())))
    }
    #[must_use]
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(112, "not found", Some(json!(msg.into())))
    }

    // --- JSON-RPC standard codes, `rpc.ml:21-24` ---------------------
    #[must_use]
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, "invalid params", Some(json!(msg.into())))
    }
    #[must_use]
    pub fn method_not_found(m: &str) -> Self {
        Self::new(-32601, format!("method not found: {m}"), None)
    }

    /// The node's catch-all for a program-execution failure surfaced by
    /// a read path (`contract_rpc.ml:903` -> `Rpc.err (-32000)`).
    /// Confirmed live: a `contract_call` against a non-contract address
    /// answers `{"code":-32000,"message":"bytecode not found"}`.
    #[must_use]
    pub fn execution(msg: impl Into<String>) -> Self {
        Self::new(-32000, msg, None)
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut o = serde_json::Map::new();
        o.insert("code".into(), json!(self.code));
        o.insert("message".into(), json!(self.message));
        if let Some(d) = &self.data {
            o.insert("data".into(), d.clone());
        }
        Value::Object(o)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.data.as_ref().and_then(Value::as_str) {
            Some(d) if !d.is_empty() => write!(f, "{}: {}", self.message, d),
            _ => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for RpcError {}

/// Legacy free-text errors from the `apply_*` handlers become `-32000`,
/// the same bucket the node uses for program-execution failures. This
/// keeps every existing `?` in those handlers compiling unchanged.
impl From<String> for RpcError {
    fn from(s: String) -> Self {
        Self::execution(s)
    }
}

impl From<&str> for RpcError {
    fn from(s: &str) -> Self {
        Self::execution(s)
    }
}

// =====================================================================
// Canonical transaction encoding
//
// A byte-exact local port of the node's signing preimage and tx hash.
// The authority is `lib/core/transaction.ml:309-326` (preimage) and
// `:482-497` (hash); the reviewed Rust port lives at
// `octra-foundry/crates/octra-chain-backend/src/canonical_tx.rs` and at
// `octra/crates/octravpn-core/src/tx_signer.rs`.
//
// It is duplicated here rather than depended on because this crate's
// `Cargo.toml` is owned elsewhere and cannot gain a dependency in this
// change. The golden vector in `tests::preimage_matches_node_layout`
// pins it to the same bytes the other two ports assert.
// =====================================================================
mod canonical {
    use sha2::{Digest, Sha256};

    /// Yojson's `write_string_body` escaping (`yojson/lib/write.ml:27-47`).
    fn push_yojson_string(out: &mut String, s: &str) {
        use std::fmt::Write as _;
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0C}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 || c == '\u{7F}' => {
                    let _ = write!(out, "\\u00{:02x}", c as u32);
                }
                c => out.push(c),
            }
        }
    }

    fn push_kv_raw(out: &mut String, k: &str, v: &str, first: bool) {
        if !first {
            out.push(',');
        }
        out.push('"');
        out.push_str(k);
        out.push_str("\":");
        out.push_str(v);
    }

    fn push_kv_str(out: &mut String, k: &str, v: &str, first: bool) {
        push_kv_raw(out, k, "\"", first);
        push_yojson_string(out, v);
        out.push('"');
    }

    /// `opt_json` (`transaction.ml:480`): string when present, `null` when not.
    fn push_kv_opt(out: &mut String, k: &str, v: Option<&str>) {
        match v {
            Some(v) => push_kv_str(out, k, v, false),
            None => push_kv_raw(out, k, "null", false),
        }
    }

    fn strip_trailing_fraction_zeros(s: &str) -> &str {
        if !s.contains('.') {
            return s;
        }
        s.trim_end_matches('0').trim_end_matches('.')
    }

    /// C `printf("%.Pg", x)` for finite `x`, `P >= 1`.
    fn format_g(x: f64, p: i32) -> String {
        let sig = usize::try_from(p - 1).expect("p >= 1");
        let e_form = format!("{x:.sig$e}");
        let e_at = e_form.rfind('e').expect("exponential form has an 'e'");
        let exp: i32 = e_form[e_at + 1..].parse().expect("exponent is an int");
        if exp < -4 || exp >= p {
            let mantissa = strip_trailing_fraction_zeros(&e_form[..e_at]);
            let sign = if exp < 0 { '-' } else { '+' };
            format!("{mantissa}e{sign}{:02}", exp.abs())
        } else {
            let frac = usize::try_from(p - 1 - exp).expect("exp < p in this branch");
            let f_form = format!("{x:.frac$}");
            strip_trailing_fraction_zeros(&f_form).to_string()
        }
    }

    /// `Yojson.Safe.to_string` float rendering (`yojson/lib/write.ml:90-119`).
    #[must_use]
    pub(crate) fn yojson_float(x: f64) -> String {
        if x.is_nan() {
            return "NaN".to_string();
        }
        if x.is_infinite() {
            return (if x > 0.0 { "Infinity" } else { "-Infinity" }).to_string();
        }
        let s16 = format_g(x, 16);
        let s = if s16.parse::<f64>().map(f64::to_bits) == Ok(x.to_bits()) {
            s16
        } else {
            format_g(x, 17)
        };
        if s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            s + ".0"
        } else {
            s
        }
    }

    /// A transaction in the node's wire layout (`transaction.ml:241-253`).
    #[derive(Clone, Debug, Default)]
    pub(crate) struct WireTx {
        pub from: String,
        /// Wire key is `to_` — trailing underscore, always.
        pub to: String,
        pub amount: u64,
        pub nonce: u64,
        pub ou: u64,
        pub timestamp: f64,
        pub op_type: String,
        pub encrypted_data: Option<String>,
        pub message: Option<String>,
        pub signature: Option<String>,
        pub public_key: Option<String>,
    }

    impl WireTx {
        /// The exact bytes the node verifies ed25519 over
        /// (`transaction.ml:309-326`). There is NO `chain_id` field.
        #[must_use]
        pub(crate) fn signing_preimage(&self) -> String {
            let mut s = String::with_capacity(192);
            s.push('{');
            push_kv_str(&mut s, "from", &self.from, true);
            push_kv_str(&mut s, "to_", &self.to, false);
            push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
            push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
            push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
            push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
            let op = if self.op_type.is_empty() {
                "standard"
            } else {
                &self.op_type
            };
            push_kv_str(&mut s, "op_type", op, false);
            if let Some(ed) = &self.encrypted_data {
                push_kv_str(&mut s, "encrypted_data", ed, false);
            }
            if let Some(m) = &self.message {
                push_kv_str(&mut s, "message", m, false);
            }
            s.push('}');
            s
        }

        /// The chain's tx hash (`transaction.ml:482-497`): sha256 of a
        /// DIFFERENT 11-field JSON — `signature` slots in after
        /// `timestamp`, and the three optional fields appear
        /// unconditionally at the tail, `null` when absent.
        #[must_use]
        pub(crate) fn tx_hash(&self) -> String {
            let mut s = String::with_capacity(256);
            s.push('{');
            push_kv_str(&mut s, "from", &self.from, true);
            push_kv_str(&mut s, "to_", &self.to, false);
            push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
            push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
            push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
            push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
            push_kv_str(
                &mut s,
                "signature",
                self.signature.as_deref().unwrap_or(""),
                false,
            );
            let op = if self.op_type.is_empty() {
                "standard"
            } else {
                &self.op_type
            };
            push_kv_str(&mut s, "op_type", op, false);
            push_kv_opt(&mut s, "public_key", self.public_key.as_deref());
            push_kv_opt(&mut s, "message", self.message.as_deref());
            push_kv_opt(&mut s, "encrypted_data", self.encrypted_data.as_deref());
            s.push('}');
            hex::encode(Sha256::digest(s.as_bytes()))
        }
    }
}

/// Hash-precommit join token state, per tailnet.
pub type JoinTokenCommits = HashMap<u64, HashSet<String>>;

#[derive(Clone, Default)]
pub struct ChainState {
    pub epoch: u64,
    /// Addresses currently registered as protocol-level Octra
    /// validators. Kept on the RPC surface for clients that still
    /// resolve identity via Octra; the OctraVPN AML does not gate on
    /// this in v1 (uses `endpoint_stake` instead).
    pub octra_validators: HashSet<String>,
    pub endpoints: HashMap<String, EndpointRow>,
    /// In-program operator stake. Required for `register_endpoint`.
    pub endpoint_stake: HashMap<String, u64>,
    /// In-flight unbonding requests: `(stake, unlock_epoch)`.
    pub endpoint_unbonding: HashMap<String, (u64, u64)>,
    /// Permanent slashed flag — once set, that address can never
    /// re-register or re-bond.
    pub endpoint_slashed: HashSet<String>,
    /// Program treasury (Tier 2 protocol fee + burn share of slashes).
    pub program_treasury: u64,
    /// Tailnets keyed by their counter id (string-encoded for
    /// JSON-RPC convenience; value parses as u64).
    pub tailnets: HashMap<u64, TailnetRow>,
    /// Self-incrementing tailnet counter — matches `tailnet_count`
    /// in the AML.
    pub tailnet_count: u64,
    /// Sessions keyed by their counter id.
    pub sessions: HashMap<u64, SessionRow>,
    pub session_count: u64,
    /// device_addr → wallet_addr that owns it (multi-device per identity).
    pub device_owner: HashMap<String, String>,
    pub balances: HashMap<String, u64>,
    pub txs: HashMap<String, TxRow>,
    /// Encrypted earnings ledger, mock-cleartext as u64. On real
    /// Octra this is an HFHE ciphertext under each operator's
    /// pubkey; the mock simulates the linear-additive structure
    /// the program assumes.
    pub earnings: HashMap<String, u64>,
    /// Program owner (set by ctor). Used for governance gates.
    pub owner: Option<String>,
    /// Join token hashes pre-committed by tailnet owners. Keyed
    /// by `tailnet_id -> set of hex(sha256(preimage))`.
    pub join_token_commits: JoinTokenCommits,
    /// Set of token hashes already redeemed. Hex-encoded sha256.
    pub join_token_redeemed: HashSet<String>,

    // ============================================================
    // v2 (Circle-native) state.
    //
    // v2 keeps a parallel set of tables so v1 callers see no changes
    // and v2 callers see a v2-only world. The two never mix:
    //   - v1 sessions live in `sessions`, keyed by v1 `session_count`.
    //   - v2 sessions live in `sessions_v2`, keyed by `session_count_v2`.
    //
    // The dispatcher routes by method name (`open_session` vs
    // `open_session_v2`), so the same RPC endpoint serves both. The
    // v2 AML schema is `program/main-v2.aml`.
    // ============================================================
    /// Authorized proxies per tailnet: tid -> set of proxy addresses.
    /// Replaces v1's `exits` (which was tracked on `TailnetRow`).
    pub authorized_proxies_v2: HashMap<u64, HashSet<String>>,
    /// Per-tailnet "charge internal traffic" toggle. 1 = bill internal
    /// traffic at settle, 0 = treat internal-class settle as free.
    /// Default 0 (free) per the v2 AML.
    pub charge_internal_traffic_v2: HashMap<u64, u8>,
    /// v2 sessions keyed by their own counter.
    pub sessions_v2: HashMap<u64, SessionRowV2>,
    pub session_count_v2: u64,
    /// HFHE pubkey registration flag for proxies. Mirrors v1
    /// endpoint registration of an HFHE key, but keyed by proxy
    /// address rather than operator address.
    pub proxy_pk_set_v2: HashMap<String, bool>,
    pub proxy_pk_v2: HashMap<String, String>,
    pub proxy_zero_ct_v2: HashMap<String, String>,
    /// Encrypted earnings for v2 proxies. Mock-cleartext as u64,
    /// same simplification as v1's `earnings`.
    pub enc_earnings_v2: HashMap<String, u64>,

    // ============================================================
    // v3 (Circles-as-IEE) state.
    //
    // Plaintext byte store backing the `circle_asset` RPC. Keyed by
    // `(circle_id, path)` → raw bytes. Tests and downstream callers
    // populate via `AppState::insert_circle_asset`; the `circle_asset`
    // dispatch arm reads from here. Sealed (ciphertext) assets do not
    // live here — those are fetched via the v2-era
    // `circle_asset_ciphertext_by_resource_key` RPC, which is keyed
    // differently and not modelled by this mock.
    // ============================================================
    pub circle_assets: HashMap<(String, String), Vec<u8>>,

    /// PVAC pubkey registry, keyed by owner address. Populated by
    /// `octra_registerPvacPubkey` (and seeded by tests). This is what
    /// `aml::host_fhe::fhe_load_pk` queries. Storing the parsed
    /// `PvacPubkey` rather than the raw wire bytes keeps the host-call
    /// hot path off the JSON-RPC parse cost.
    pub pvac_pubkeys: HashMap<String, aml::host_fhe::PvacPubkey>,

    // ============================================================
    // Chain lifecycle state.
    //
    // Everything above this line is *program* state — what the AML
    // would own. Everything below is *chain* state, and it exists
    // because the mock used to have none: `octra_submit` wrote a
    // `status:"confirmed"` row and bumped `epoch` in the same
    // breath, which is the single largest reason a green Tier-1 run
    // meant nothing. The real node only STAGES on submit
    // (`node_runtime/submit_rpc.ml:19-28`) and applies staged txs at
    // an epoch boundary, every 10s (`epoch_time.ml:10-11`).
    // ============================================================
    /// The chain account ledger — distinct from `balances`, which is
    /// the AML's own payout map. `octra_balance` reads THIS.
    pub accounts: HashMap<String, Account>,
    /// True once any account has been seeded (see [`AppState::fund`]).
    ///
    /// While false, this mock instance has no account ledger at all,
    /// so the ledger-dependent admission checks — 100 sender-not-found,
    /// 104 insufficient-balance and the 101 signature check — cannot be
    /// evaluated and are SKIPPED. That skip is recorded under the
    /// `admission/no_ledger` coverage branch precisely so it shows up
    /// as an absence in a coverage report rather than passing silently.
    /// Seed a ledger and the mock enforces all of them.
    pub ledger_enforced: bool,
    /// Transactions accepted into staging but not yet applied. Ordered:
    /// an epoch applies them front to back.
    pub staged: Vec<StagedTx>,
    /// Contract execution receipts, keyed by tx hash. This — not
    /// `octra_transaction` — is where the chain puts execution results
    /// (`contract_rpc.ml:765-780`).
    pub receipts: HashMap<String, Value>,
    /// Terminal `rejected` rows (`tx_view.ml:107-121`), keyed by hash.
    pub rejected_txs: HashMap<String, Value>,
    /// Terminal `dropped` rows (`tx_view.ml:123-136`), keyed by hash.
    pub dropped_txs: HashMap<String, Value>,
    /// Program storage KV, keyed by `(contract_address, key)`. The mock
    /// runs no VM, so nothing populates this by execution; it exists so
    /// `octra_contractStorage` and `contract_call`'s storage envelope
    /// can be exercised against real bytes via
    /// [`AppState::insert_contract_storage`]. Empty by default, which
    /// is the honest answer for an interpreter-free mock.
    pub contract_storage: HashMap<(String, String), String>,
}

/// A chain account (`lib/core/ledger.ml`, account record).
#[derive(Clone, Debug, Default)]
pub struct Account {
    /// Balance in OU (micro-OCT). The node renders this two ways:
    /// `balance` (formatted, 6dp) and `balance_raw`.
    pub balance: u64,
    /// Last CONFIRMED nonce. The next acceptable nonce is `nonce + 1`
    /// (`ledger.ml:241`).
    pub nonce: u64,
    /// Registered ed25519 public key, base64. `has_public_key` on the
    /// `octra_balance` response reports whether this is set.
    pub public_key: Option<String>,
}

/// A transaction sitting in staging, waiting for an epoch.
#[derive(Clone, Debug)]
pub struct StagedTx {
    pub hash: String,
    /// The submitted envelope, verbatim.
    pub raw: Value,
    /// The normalized working tx the `apply_*` handlers read.
    pub working: Value,
    pub method: String,
    pub op_type: String,
    pub from: String,
    pub nonce: u64,
    pub ou: u64,
    pub amount: u64,
    pub to: String,
    pub timestamp: f64,
    pub message: Option<String>,
}

/// Default operator bond floor mirrored from `program/main.aml`.
pub const MIN_ENDPOINT_STAKE: u64 = 1_000_000_000;
pub const UNBOND_GRACE_EPOCHS: u64 = 10_000;
pub const SLASH_BURN_BPS: u64 = 9_000;
pub const SLASH_BOUNTY_BPS: u64 = 1_000;
pub const PROTOCOL_FEE_BPS: u64 = 50;

#[derive(Clone)]
pub struct EndpointRow {
    pub addr: String,
    pub active: bool,
    pub endpoint: String,
    pub wg_pubkey: String,
    /// Operator's HFHE pubkey (hex). Used as the encryption key for
    /// `enc_earnings` arithmetic.
    pub hfhe_pubkey: String,
    /// Pre-stored `enc_pk(0)` ciphertext (hex). In the mock this is
    /// just an opaque blob; on real Octra it's the canonical zero
    /// ciphertext for cheap `fhe_add_const`.
    pub initial_enc_zero: String,
    pub region: String,
    pub price_per_mb: u64,
    pub registered_at: u64,
    pub reputation: i64,
    /// Ed25519 pubkey (base64 or hex) the operator uses to sign
    /// off-chain receipts. Empty if not yet registered. Used by
    /// `slash_double_sign` to verify equivocation proofs.
    pub receipt_pubkey: String,
}

#[derive(Clone)]
pub struct TailnetRow {
    pub id: u64,
    pub owner: String,
    pub treasury: u64,
    pub members: HashSet<String>,
    pub exits: HashSet<String>,
    pub acl_policy: String,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct SessionRow {
    pub tailnet_id: u64,
    /// The single configured exit for this session.
    pub exit: String,
    /// The address that called `open_session`. Only this address
    /// can later call `settle_confirm`.
    pub opener: String,
    pub deposit: u64,
    pub opened_at: u64,
    pub status: u8, // 0 open, 1 settled, 2 refunded
    /// Operator's settlement claim: (bytes_used, claimed_at_epoch).
    /// `None` until the operator calls settle_claim.
    pub operator_claim: Option<(u64, u64)>,
    /// Client's settlement confirmation. `None` until the opener
    /// calls settle_confirm.
    pub client_confirm: Option<(u64, u64)>,
}

/// v2 session row. Differs from v1 in three places: `exit` →
/// `proxy` (semantically the same — the address that settles), plus
/// new `class` + `price_per_mb` fields stamped at open time. The v2
/// AML can then compute `total_paid` at settle without consulting
/// the proxy for a price.
#[derive(Clone)]
pub struct SessionRowV2 {
    pub tailnet_id: u64,
    /// The Circle's proxy contract address (the v2 settler).
    pub proxy: String,
    /// The address that called `open_session_v2`. Only this address
    /// can later call `settle_confirm_v2`.
    pub opener: String,
    pub deposit: u64,
    pub opened_at: u64,
    /// 0 = shared exit, 1 = internal subnet. See `program/main-v2.aml`
    /// `CLASS_SHARED`/`CLASS_INTERNAL`.
    pub class: u8,
    /// Tariff stamped at open. Settled `total_paid` is
    /// `bytes_used * price_per_mb`, subject to the internal-traffic
    /// override.
    pub price_per_mb: u64,
    pub status: u8, // 0 open, 1 settled, 2 refunded
    /// Proxy's settlement claim: (bytes_used, claimed_at_epoch).
    pub proxy_claim: Option<(u64, u64)>,
    /// Client's settlement confirmation. `None` until the opener
    /// calls `settle_confirm_v2`.
    pub client_confirm: Option<(u64, u64)>,
}

#[derive(Clone)]
pub struct TxRow {
    pub method: String,
    pub from: String,
    /// The mock's internal event records (`{"name":…, …}`). These are
    /// NOT what `octra_transaction` returns — the chain's tx view has
    /// no `events` field at all (`tx_view.ml:93-136`). They are the
    /// source the `contract_receipt` view is rendered from.
    pub events: Vec<Value>,
    pub status: String,
    /// Epoch this tx was applied in.
    pub epoch: u64,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub ou: u64,
    pub timestamp: f64,
    pub op_type: String,
    pub message: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<RwLock<ChainState>>,
    pub program_addr: String,
    /// Optional expected `chain_id` (v2 tx-envelope binding).
    ///
    /// # MOCK FICTION — this gate does not exist on the chain
    ///
    /// The Octra transaction envelope has NO `chain_id` field. The
    /// parser (`lib/core/transaction.ml:273-325`) reads exactly
    /// `from`, `to_`, `amount`, `nonce`, `ou`, `timestamp`, `op_type`,
    /// `signature`, `public_key`, `message`, `encrypted_data`, and the
    /// signing preimage (`:309-326`) covers a subset of those. A
    /// `chain_id` in the envelope is ignored on submit and, if it was
    /// signed over, guarantees code 101 — which is why
    /// `octra-chain-backend`'s `canonical_tx_from_call` rejects one
    /// outright rather than passing it through.
    ///
    /// So a green test against this gate proves the MOCK enforces a
    /// binding; it proves nothing about cross-chain replay on Octra.
    /// It is retained only because `tests/chain_id_binding.rs` asserts
    /// on it. It must never be treated as money-path coverage, and it
    /// cannot be reproduced at Tier 2 or Tier 3.
    pub expected_chain_id: Option<String>,
}

impl AppState {
    /// Test helper: mark `addr` as an Octra protocol validator.
    /// Kept for RPC parity; AML no longer gates on this.
    pub fn add_octra_validator(&self, addr: impl Into<String>) {
        self.state.write().octra_validators.insert(addr.into());
    }

    pub fn remove_octra_validator(&self, addr: &str) {
        self.state.write().octra_validators.remove(addr);
    }

    /// Test helper: seed operator stake without routing through
    /// `bond_endpoint`. Used by harnesses that want to skip the
    /// bonding tx and exercise post-bond entrypoints directly.
    pub fn seed_endpoint_stake(&self, addr: impl Into<String>, amount: u64) {
        let addr = addr.into();
        let mut s = self.state.write();
        *s.endpoint_stake.entry(addr).or_insert(0) += amount;
    }

    /// Test helper: set the program owner (governance wallet). Used
    /// for tests that exercise governance-only entrypoints.
    pub fn set_owner(&self, addr: impl Into<String>) {
        self.state.write().owner = Some(addr.into());
    }

    /// Seed a plaintext asset for `circle_asset(circle_id, path)`
    /// lookups. Mirrors the in-test fixture stores v3 client tests
    /// have been carrying as a workaround.
    pub fn insert_circle_asset(
        &self,
        circle_id: impl Into<String>,
        path: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) {
        let key = (circle_id.into(), path.into());
        self.state.write().circle_assets.insert(key, bytes.into());
    }

    /// Seed a chain account: credit `amount` OU and (optionally)
    /// register a base64 ed25519 public key.
    ///
    /// The first call flips `ledger_enforced`, after which submission
    /// admission evaluates 100 sender-not-found, 104
    /// insufficient-balance and the 101 signature check for real. A
    /// mock with no seeded ledger cannot answer those questions and
    /// says so (see `ChainState::ledger_enforced`) rather than
    /// inventing a balance.
    pub fn fund(&self, addr: impl Into<String>, amount: u64, public_key: Option<String>) {
        let addr = addr.into();
        let mut s = self.state.write();
        s.ledger_enforced = true;
        let a = s.accounts.entry(addr).or_default();
        a.balance = a.balance.saturating_add(amount);
        if public_key.is_some() {
            a.public_key = public_key;
        }
    }

    /// Read a chain account.
    #[must_use]
    pub fn account(&self, addr: &str) -> Option<Account> {
        self.state.read().accounts.get(addr).cloned()
    }

    /// Seed a program storage key. The mock runs no VM, so this is the
    /// only way `octra_contractStorage` and `contract_call`'s storage
    /// envelope get anything to return.
    pub fn insert_contract_storage(
        &self,
        contract: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let k = (contract.into(), key.into());
        self.state.write().contract_storage.insert(k, value.into());
    }

    /// Enable v2 tx-envelope chain_id enforcement. Once set, every
    /// `octra_submit` whose tx `chain_id` doesn't match `id` is
    /// rejected with a JSON-RPC error. Used by adversarial harnesses
    /// that pin the Lean
    /// `chain_id_binding_rejects_replay` claim.
    pub fn set_expected_chain_id(&mut self, id: impl Into<String>) {
        self.expected_chain_id = Some(id.into());
    }
}

pub fn build_router(app: AppState) -> Router {
    Router::new()
        .route("/rpc", post(rpc_handler))
        .with_state(app)
}

#[derive(Deserialize)]
struct RpcReq {
    #[serde(default)]
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

async fn rpc_handler(State(app): State<AppState>, Json(req): Json<RpcReq>) -> impl IntoResponse {
    let _ = req.jsonrpc;
    match dispatch(&app, &req.method, &req.params) {
        Ok(r) => Json(json!({"jsonrpc": "2.0", "id": req.id, "result": r})),
        Err(e) => Json(json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "error": e.to_json(),
        })),
    }
}

/// Route one `(method, params)` pair — the single dispatch table.
///
/// A method the mock answers is either in [`methods::NODE_METHODS`] or
/// in [`cheats::MOCK_CHEATS`]. Fiction (`octra_isValidator`, the
/// `octra_fhe*` wrappers) is [`RpcError::method_not_found`], matching
/// the real node. Cheats are gated by [`cheats::cheats_enabled`].
pub fn dispatch(app: &AppState, method: &str, params: &Value) -> Result<Value, RpcError> {
    match cheats::classify(method) {
        cheats::Surface::Unknown => return Err(RpcError::method_not_found(method)),
        cheats::Surface::Cheat(_) if !cheats::cheats_enabled() => {
            return Err(RpcError::method_not_found(method));
        }
        cheats::Surface::Node | cheats::Surface::Cheat(_) => {}
    }
    match method {
        "node_status" => Ok(node_status(app)),
        "octra_runtimeVersion" => Ok(json!({
            "chain_id": "octra-foundry-mock",
            "network_version": "mock-1.0",
        })),
        "octra_balance" => octra_balance(app, params),
        "octra_recommendedFee" => Ok(json!({
            "min": 1, "base": 5, "recommended": 10, "fast": 25
        })),
        "octra_submit" => octra_submit(app, params),
        "octra_transaction" => octra_transaction(app, params),
        "contract_receipt" => contract_receipt(app, params),
        "octra_contractStorage" => octra_contract_storage(app, params),
        "octra_listContracts" => Ok(octra_list_contracts(app)),
        "contract_call" => contract_call(app, params),
        "octra_compileAml" => octra_compile_aml(params).map_err(RpcError::from),
        "octra_compileAmlMulti" => octra_compile_aml_multi(params).map_err(RpcError::from),
        "epoch_get" => Ok(epoch_get(app, params)),
        "circle_asset" => circle_asset(app, params).map_err(RpcError::from),
        "octra_registerPvacPubkey" => {
            octra_register_pvac_pubkey(app, params).map_err(RpcError::from)
        }
        "octra_pvacPubkey" => octra_pvac_pubkey(app, params).map_err(RpcError::from),
        "octra_test_grantValidator" => {
            if let Some(addr) = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(Value::as_str)
            {
                app.add_octra_validator(addr);
            }
            Ok(json!(true))
        }
        "octra_test_revokeValidator" => {
            if let Some(addr) = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(Value::as_str)
            {
                app.remove_octra_validator(addr);
            }
            Ok(json!(true))
        }
        "octra_test_bondEndpoint" => {
            let arr = params
                .as_array()
                .ok_or_else(|| RpcError::invalid_params("params not array"))?;
            let addr = arr
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params("addr"))?;
            let amount = arr
                .get(1)
                .and_then(Value::as_u64)
                .unwrap_or(MIN_ENDPOINT_STAKE);
            app.seed_endpoint_stake(addr, amount);
            Ok(json!(true))
        }
        "octra_test_setOwner" => {
            if let Some(addr) = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(Value::as_str)
            {
                app.set_owner(addr);
            }
            Ok(json!(true))
        }
        other if methods::is_node_method(other) => Err(RpcError::execution(format!(
            "{other} is a real node method the mock has not implemented"
        ))),
        other => Err(RpcError::method_not_found(other)),
    }
}

/// `octra_listContracts` (`contract_rpc.ml:436-442`). The mock used to
/// answer a bare array of `{address, name}`; the node answers an object
/// with a `count` and rows carrying `owner` / `code_hash` / `version` /
/// `balance` — confirmed live against the local node.
fn octra_list_contracts(app: &AppState) -> Value {
    let s = app.state.read();
    let owner = s.owner.clone().unwrap_or_default();
    json!({
        "contracts": [{
            "address": app.program_addr,
            "owner": owner,
            "code_hash": hex::encode(Sha256::digest(app.program_addr.as_bytes())),
            "version": "1.0 Rehovot",
            "balance": format_balance(0),
        }],
        "count": 1,
    })
}

fn node_status(app: &AppState) -> Value {
    let s = app.state.read();
    json!({
        "epoch": s.epoch,
        "validator": null,
        "state_root": "00".repeat(32),
        "timestamp": 0,
        "network_version": "mock-1.0",
    })
}

/// `circle_asset(circle_id, path)` — v3 plaintext asset fetch.
///
/// Wire-equivalent to the production RPC dispatched by
/// `cast circle asset` (see `octra-cli/src/cast/circle.rs::asset`).
/// Returns one of the response shapes the v3 client's
/// `fetch_circle_asset_bytes` tolerates: `{"plaintext": <utf8>}` on
/// hit, JSON `null` on miss. Bytes are expected to be UTF-8 (v3's
/// canonical assets are JSON); non-UTF-8 fixtures will surface as an
/// RPC error rather than silently mangle.
fn circle_asset(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let circle_id = arr
        .first()
        .and_then(Value::as_str)
        .ok_or("circle_id missing")?
        .to_string();
    let path = arr
        .get(1)
        .and_then(Value::as_str)
        .ok_or("path missing")?
        .to_string();
    let s = app.state.read();
    match s.circle_assets.get(&(circle_id, path)) {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| format!("circle_asset bytes not utf-8: {e}"))?;
            Ok(json!({ "plaintext": text }))
        }
        None => Ok(Value::Null),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Honest mock-HFHE RPC surface (see crates/octra-mock-rpc/src/aml/host_fhe.rs)
// ─────────────────────────────────────────────────────────────────────

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// `octra_registerPvacPubkey([addr])` — register a PVAC pubkey for
/// `addr`. The mock derives the (deterministic) blob from `addr`
/// itself; production `octra_registerPvacPubkey` accepts the operator-
/// computed ~4 MiB blob directly. Returning the base64 blob lets
/// callers round-trip via `octra_pvacPubkey`.
fn octra_register_pvac_pubkey(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let addr = arr
        .first()
        .and_then(Value::as_str)
        .ok_or("addr missing")?
        .to_string();
    let pk = aml::host_fhe::keygen_for_addr(&addr);
    let blob = pk.as_bytes().to_vec();
    app.state.write().pvac_pubkeys.insert(addr.clone(), pk);
    Ok(json!({
        "addr": addr,
        "pubkey_b64": B64.encode(&blob),
    }))
}

fn octra_pvac_pubkey(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let addr = arr.first().and_then(Value::as_str).ok_or("addr missing")?;
    let s = app.state.read();
    match s.pvac_pubkeys.get(addr) {
        Some(pk) => Ok(json!({ "pubkey_b64": B64.encode(pk.as_bytes()) })),
        None => Ok(Value::Null),
    }
}

/// `Octra_core.Denomination.format_balance` — the node renders a
/// balance as a fixed 6-decimal string (`rpc_view.ml:241,325`).
/// Confirmed live: `10000036500000` -> `"10000036.500000"`.
#[must_use]
pub fn format_balance(raw: u64) -> String {
    format!("{}.{:06}", raw / 1_000_000, raw % 1_000_000)
}

/// `octra_balance` (`account_read_rpc.ml:382` -> `account_rpc.ml:18-26`
/// -> `rpc_view.ml:322-330`).
///
/// Two repairs here. The key set is the node's — `address`, `balance`,
/// `balance_raw`, `nonce`, `pending_nonce`, `has_public_key` — not the
/// mock's invented `formatted`/`raw`/`public_key`. And an address the
/// ledger has never seen is error 100, not a fabricated 1 000 000 000:
/// `account_of_params` (`account_rpc.ml:7-16`) returns
/// `Rpc.sender_not_found` when `find_account` misses, which the live
/// node confirms verbatim.
fn octra_balance(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let addr = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let s = app.state.read();
    let Some(account) = s.accounts.get(addr) else {
        coverage::record("octra_balance", "sender_not_found");
        return Err(RpcError::sender_not_found());
    };
    coverage::record("octra_balance", "found");
    // `pending_nonce` is the staging-aware nonce
    // (`tx_staging.ml:172-174`): the highest nonce staged for this
    // address, falling back to the confirmed nonce.
    let pending_nonce = s
        .staged
        .iter()
        .filter(|t| t.from == addr)
        .map(|t| t.nonce)
        .max()
        .unwrap_or(account.nonce);
    Ok(json!({
        "address": addr,
        "balance": format_balance(account.balance),
        "balance_raw": account.balance.to_string(),
        "nonce": account.nonce,
        "pending_nonce": pending_nonce,
        "has_public_key": account.public_key.is_some(),
    }))
}

/// Normalize a submitted transaction to a working `Value` that the
/// per-method `apply_*` handlers can read. Accepts two shapes:
///
///   1. **Legacy in-workspace shape** — `{"kind":"contract_call",
///      "method":..., "params":..., "value":..., "fee":..., "from":...}`.
///      Used unchanged.
///   2. **Octra wire envelope** — `{"from","to_","amount","ou","nonce",
///      "timestamp","op_type","encrypted_data",...}` (signed or not).
///      For `op_type == "call"` we parse `encrypted_data` as
///      `{"method","params"}` and inject those at the top level so the
///      existing handlers find them. `amount` (string) is mapped to
///      `value` (u64) for handlers that read `value` for in-flow funds
///      (`bond_endpoint`, `create_tailnet`, `deposit_to_tailnet`).
///
/// Returns `(working_tx, method, op_type)`. For `op_type == "deploy"`
/// the method is the special token `"__deploy__"` and the working tx
/// is the unmodified envelope (no apply_* dispatch will fire).
fn normalize_submission(tx: &Value) -> Result<(Value, String, String), String> {
    let obj = tx.as_object().ok_or("tx must be a JSON object")?;
    // (1) Legacy in-workspace shape: top-level `method`. Just use it.
    if let Some(m) = obj.get("method").and_then(|x| x.as_str()) {
        let op = obj
            .get("op_type")
            .and_then(|x| x.as_str())
            .unwrap_or("call")
            .to_string();
        return Ok((tx.clone(), m.to_string(), op));
    }
    // (2) Real Octra wire envelope: dispatch by `op_type` + decoded
    //     `encrypted_data`.
    let op = obj
        .get("op_type")
        .and_then(|x| x.as_str())
        .ok_or("missing method or op_type")?
        .to_string();

    // Build a working tx for the handlers. Start from the envelope and
    // splice in legacy-style fields the handlers expect.
    let mut working = serde_json::Map::with_capacity(obj.len() + 4);
    for (k, v) in obj {
        working.insert(k.clone(), v.clone());
    }
    // `from` is already there. Add `value` from `amount` for handlers
    // that read `tx["value"]` (bond_endpoint, create_tailnet, deposit_to_tailnet).
    let amount = match obj.get("amount") {
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        _ => 0,
    };
    working.insert("value".into(), json!(amount));

    let method = if op == "deploy" {
        "__deploy__".to_string()
    } else if op == "call" {
        // Real Octra contract-call envelope: encrypted_data is the
        // bare method name, message is the JSON-encoded params array.
        let m = obj
            .get("encrypted_data")
            .and_then(|x| x.as_str())
            .ok_or("call envelope missing encrypted_data (method)")?
            .to_string();
        let params = obj.get("message").and_then(|x| x.as_str()).map_or_else(
            || Value::Array(vec![]),
            |s| serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::Array(vec![])),
        );
        working.insert("method".into(), json!(m));
        working.insert("params".into(), params);
        m
    } else {
        // Non-call, non-deploy op_types (standard, stealth, claim, …)
        // are no-ops in this mock — they don't dispatch to apply_*
        // handlers, just get accepted and recorded.
        op.clone()
    };
    Ok((Value::Object(working), method, op))
}

/// Synthesize a deployed-contract address. Mirrors what the real chain
/// does via `octra_computeContractAddress` (bytecode + deployer + nonce),
/// but the mock isn't a real VM, so we just produce a deterministic
/// `oct…` string from the inputs. Pads with leading '1' the way Base58
/// addresses do so the result is the right length.
fn synthesize_deploy_address(from: &str, bytecode: &str, nonce: u64) -> String {
    let mut h = Sha256::new();
    h.update(from.as_bytes());
    h.update(b"::deploy::");
    h.update(bytecode.as_bytes());
    h.update(nonce.to_le_bytes());
    let digest = h.finalize();
    let body = hex::encode(digest);
    // Trim/pad to 44 chars so the result is `oct` + 44 = 47 chars, the
    // approximate length of real Octra addresses. The mock doesn't
    // require exact length parity; consumers just round-trip the value.
    let padded = if body.len() >= 44 {
        body[..44].to_string()
    } else {
        let mut s = String::with_capacity(44);
        for _ in body.len()..44 {
            s.push('1');
        }
        s.push_str(&body);
        s
    };
    format!("oct{padded}")
}

// =====================================================================
// Submission -> staging -> epoch
//
// This is the repair that matters most. The old `octra_submit` ran the
// `apply_*` handler inline, wrote `status:"confirmed"`, bumped `epoch`
// and returned `{"hash":…,"status":"confirmed"}`. No such thing happens
// on the chain:
//
//   * `octra_submit` validates and STAGES, then returns
//     `{tx_hash, status:"accepted", nonce, ou_cost}`
//     (`submit_rpc.ml:19-28` -> `rpc_view.ml:706-712`). The word
//     "confirmed" never appears on this path.
//   * Staged txs are applied by an epoch, which in Single mode fires on
//     a hardcoded 10-second timer (`epoch_time.ml:10-11`,
//     `consensus_tick_plan.ml:115-123`).
//
// Everything a client does between those two moments — read a balance,
// read contract storage, read the tx — sees the PRE-transaction world.
// That gap is the premature-read failure mode that has bitten this
// workspace on devnet more than once, and until now Tier 1 could not
// express it.
// =====================================================================

/// How far ahead of the confirmed nonce staging will accept
/// (`tx_staging.ml:191`).
pub const NONCE_LOOKAHEAD: u64 = 1_000;

/// Maximum tolerated wall-clock drift on a submitted tx, in seconds
/// (`tx_view.ml:1125-1129`; the node's default is 300).
pub const MAX_TIMESTAMP_DRIFT_SECS: f64 = 300.0;

/// Parse a submitted object into the node's wire layout, or `None` when
/// it is the workspace's legacy in-process shape (top-level `method`,
/// no signature, no `ou`, no `timestamp`).
///
/// A legacy-shape object is not an Octra transaction and never was; the
/// distinction is kept explicit rather than papered over, because the
/// admission rules below only mean something for a real envelope.
fn parse_wire(tx: &Value) -> Option<canonical::WireTx> {
    let obj = tx.as_object()?;
    if obj.contains_key("method") {
        return None;
    }
    obj.get("op_type")?;
    let s = |k: &str| obj.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let opt = |k: &str| {
        obj.get(k)
            .and_then(Value::as_str)
            .map(std::string::ToString::to_string)
    };
    let num = |k: &str| -> u64 {
        match obj.get(k) {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(Value::String(t)) => t.parse::<u64>().unwrap_or(0),
            _ => 0,
        }
    };
    Some(canonical::WireTx {
        from: s("from"),
        to: obj
            .get("to_")
            .or_else(|| obj.get("to"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        amount: num("amount"),
        nonce: num("nonce"),
        ou: num("ou"),
        timestamp: obj.get("timestamp").and_then(Value::as_f64).unwrap_or(0.0),
        op_type: s("op_type"),
        encrypted_data: opt("encrypted_data"),
        message: opt("message"),
        signature: opt("signature"),
        public_key: opt("public_key"),
    })
}

/// Verify the ed25519 signature over the node's own preimage
/// (`tx_view.ml:1139-1148` -> `transaction.ml:335-341`). One byte of
/// rendering drift here is code 101 on the real chain, so the mock
/// reconstructs the preimage the same way and reaches the same verdict.
fn verify_wire_signature(
    w: &canonical::WireTx,
    registered_pk: Option<&str>,
) -> Result<(), RpcError> {
    // `submission_pubkey` (`tx_view.ml:1134-1137`): the account's
    // registered key wins; the envelope's key is the fallback for a
    // first-ever submission.
    let pk_b64 = registered_pk
        .map(std::string::ToString::to_string)
        .or_else(|| w.public_key.clone())
        .ok_or_else(RpcError::invalid_signature)?;
    let Some(vk) = decode_ed25519_pubkey(&pk_b64) else {
        return Err(RpcError::invalid_signature());
    };
    let Some(sig_b64) = w.signature.as_deref() else {
        return Err(RpcError::invalid_signature());
    };
    let Some(sig) = decode_ed25519_sig(sig_b64) else {
        return Err(RpcError::invalid_signature());
    };
    use ed25519_dalek::Verifier as _;
    vk.verify(w.signing_preimage().as_bytes(), &sig)
        .map_err(|_| RpcError::invalid_signature())
}

/// `octra_submit` — validate and stage. Never applies, never confirms.
///
/// The accepted response is `rpc_view.ml:706-712` exactly:
/// `{tx_hash, status:"accepted", nonce, ou_cost}`. Rejections carry the
/// node's numbered codes (`tx_view.ml:362-381`).
fn octra_submit(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let tx = arr
        .first()
        .ok_or_else(|| RpcError::invalid_params("missing transaction object"))?;

    // ---- chain_id gate (MOCK FICTION, retained under protest) -------
    // The real envelope has no `chain_id` field at all
    // (`transaction.ml:273-325`); `canonical_tx.rs` rejects one
    // outright because signing over it guarantees code 101 on-chain.
    // This gate is therefore a Tier-1-only invention and cannot be
    // reproduced by Tier 2 or Tier 3. It is left wired only because
    // `tests/chain_id_binding.rs` — owned elsewhere — asserts on it;
    // see the audit note in this change's report.
    if let Some(expected) = app.expected_chain_id.as_deref() {
        let tx_chain_id = tx.get("chain_id").and_then(|v| v.as_str());
        match tx_chain_id {
            None => {
                coverage::record("octra_submit", "chain_id_missing_rejected");
                return Err(RpcError::execution(format!(
                    "chain_id mismatch: tx missing chain_id, expected {expected}"
                )));
            }
            Some(got) if got != expected => {
                coverage::record("octra_submit", "chain_id_mismatch_rejected");
                return Err(RpcError::execution(format!(
                    "chain_id mismatch: tx chain_id={got}, expected {expected}"
                )));
            }
            Some(_) => {
                coverage::record("octra_submit", "chain_id_accepted");
            }
        }
    }

    let staged = admit(app, tx)?;
    let response = json!({
        "tx_hash": staged.hash,
        "status": "accepted",
        "nonce": staged.nonce,
        "ou_cost": staged.ou.to_string(),
    });
    app.state.write().staged.push(staged);
    Ok(response)
}

/// Admission: everything the node checks before a tx is allowed into
/// staging. Returns the staged row, or the node's own error code.
fn admit(app: &AppState, tx: &Value) -> Result<StagedTx, RpcError> {
    let (working, method, op_type) = normalize_submission(tx).map_err(RpcError::malformed_tx)?;
    let from = working
        .get("from")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let wire = parse_wire(tx);
    let s = app.state.read();
    let ledger_enforced = s.ledger_enforced;
    let account = s.accounts.get(&from).cloned();
    // `tx_staging.ml:188-191` bases the window on the CONFIRMED nonce.
    let base_nonce = account.as_ref().map_or(0, |a| a.nonce);
    let staged_nonces: Vec<u64> = s
        .staged
        .iter()
        .filter(|t| t.from == from)
        .map(|t| t.nonce)
        .collect();
    let staged_hashes: HashSet<String> = s.staged.iter().map(|t| t.hash.clone()).collect();
    let confirmed_hashes_len = s.txs.len();
    drop(s);
    let _ = confirmed_hashes_len;

    let (hash, nonce, ou, amount, to, timestamp, message) = if let Some(w) = &wire {
        coverage::record("admission", "wire_envelope");
        // --- 105 malformed: the fields the node requires ------------
        if w.from.is_empty() {
            return Err(RpcError::invalid_address("missing from"));
        }
        // `sender_admission` (`tx_view.ml:1150-1155`): OU must be > 0.
        if w.ou == 0 {
            return Err(RpcError::malformed_tx("OU must be greater than zero"));
        }
        // `pre_route_admission` (`tx_view.ml:1118-1129`). A zero
        // timestamp means the submitter omitted it; the node reads that
        // as 1970 and rejects on drift, so we do too.
        let now = unix_now();
        let drift = (w.timestamp - now).abs();
        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(RpcError::malformed_tx(format!(
                "timestamp drift {drift:.0}s exceeds {}s limit",
                MAX_TIMESTAMP_DRIFT_SECS as i64
            )));
        }
        // --- 100 sender, then 101 signature -------------------------
        // Order matters and is the node's: `sender_admission` is the
        // last step of `submit_pre_signature_admission`
        // (`tx_view.ml:1150-1181`), so a nonexistent sender answers 100
        // BEFORE the signature is ever looked at; `add_smart`'s nonce
        // and balance rules (102/103/104/106) only run after 101
        // passes. Getting this order wrong makes a mock that reports
        // the wrong remedy to the client.
        if ledger_enforced {
            if account.is_none() {
                coverage::record("admission", "sender_not_found");
                return Err(RpcError::sender_not_found());
            }
            verify_wire_signature(w, account.as_ref().and_then(|a| a.public_key.as_deref()))?;
            coverage::record("admission", "signature_verified");
        } else {
            coverage::record("admission", "no_ledger");
        }
        (
            w.tx_hash(),
            w.nonce,
            w.ou,
            w.amount,
            w.to.clone(),
            w.timestamp,
            w.message.clone(),
        )
    } else {
        // Legacy in-process shape. Not a chain transaction: it carries
        // no signature, no OU and no timestamp, so the signature and
        // fee admission rules have nothing to evaluate. It still goes
        // through staging, so the lifecycle is identical.
        coverage::record("admission", "mock_legacy_envelope");
        // Legacy tests historically sent `nonce: 0`. The chain's next
        // nonce is `confirmed + 1`, so treat 0 / missing as "assign the
        // next one" rather than as a spent nonce.
        let nonce = working
            .get("nonce")
            .and_then(Value::as_u64)
            .filter(|&n| n > 0)
            .unwrap_or_else(|| {
                staged_nonces
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(base_nonce)
                    .saturating_add(1)
            });
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&working).unwrap_or_default());
        h.update(nonce.to_le_bytes());
        (
            hex::encode(h.finalize()),
            nonce,
            working.get("fee").and_then(Value::as_u64).unwrap_or(0),
            working.get("value").and_then(Value::as_u64).unwrap_or(0),
            working
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            unix_now(),
            None,
        )
    };

    // --- 106 duplicate ----------------------------------------------
    if staged_hashes.contains(&hash) || app.state.read().txs.contains_key(&hash) {
        coverage::record("admission", "duplicate_tx");
        return Err(RpcError::duplicate_tx());
    }

    // --- 104 insufficient balance ----------------------------------
    if let Some(acct) = account.as_ref().filter(|_| ledger_enforced) {
        // `add_smart` (`tx_staging.ml:216-218`) charges amount + fee
        // against the balance already committed by staged txs.
        let staged_cost: u64 = {
            let st = app.state.read();
            st.staged
                .iter()
                .filter(|t| t.from == from)
                .map(|t| t.amount.saturating_add(t.ou))
                .sum()
        };
        let need = amount.saturating_add(ou).saturating_add(staged_cost);
        if need > acct.balance {
            coverage::record("admission", "insufficient_balance");
            return Err(RpcError::insufficient_balance());
        }
    }

    // --- 102 / 103 nonce (`tx_staging.ml:188-191`) ------------------
    // "next = confirmed + 1". A nonce at or below the confirmed one is
    // spent (102); more than the lookahead ahead is 103.
    if nonce <= base_nonce {
        coverage::record("admission", "invalid_nonce");
        return Err(RpcError::invalid_nonce());
    }
    if nonce > base_nonce + NONCE_LOOKAHEAD {
        coverage::record("admission", "nonce_too_far");
        return Err(RpcError::nonce_too_far());
    }
    if staged_nonces.contains(&nonce) {
        // The node allows a fee-rate bump replacement here
        // (`tx_staging.ml:194-198`); without one it is a duplicate.
        coverage::record("admission", "duplicate_nonce");
        return Err(RpcError::duplicate_tx());
    }

    coverage::record("admission", "accepted");
    Ok(StagedTx {
        hash,
        raw: tx.clone(),
        working,
        method,
        op_type,
        from,
        nonce,
        ou,
        amount,
        to,
        timestamp,
        message,
    })
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Apply every staged transaction and close the epoch.
///
/// This is the step the mock never had. It is deliberately NOT exposed
/// as a JSON-RPC method: the node has no such method — there is no
/// `octra_test_*` namespace anywhere in `rpc_dispatch.ml` — and putting
/// one on the wire would be a mock-only cheat that Tier 2 could not
/// honour. It is an in-process Rust API, plus the timer that
/// [`serve`] runs on the node's own 10s cadence.
///
/// Returns the hashes applied, in order.
pub fn advance_epoch(app: &AppState) -> Vec<String> {
    let batch: Vec<StagedTx> = std::mem::take(&mut app.state.write().staged);
    let epoch = {
        let mut s = app.state.write();
        s.epoch += 1;
        s.epoch
    };
    let mut applied = Vec::with_capacity(batch.len());
    for staged in batch {
        applied.push(staged.hash.clone());
        apply_staged(app, &staged, epoch);
    }
    applied
}

/// Run one staged tx against program state and record its terminal row.
fn apply_staged(app: &AppState, staged: &StagedTx, epoch: u64) {
    let tx = &staged.working;
    let from = staged.from.as_str();

    // op_type=deploy has no `apply_*` handler; the mock synthesizes an
    // address the way `octra_computeContractAddress` would.
    if staged.op_type == "deploy" {
        let bytecode = tx
            .get("encrypted_data")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let address = synthesize_deploy_address(from, bytecode, staged.nonce);
        let event = json!({ "name": "ContractDeployed", "address": &address });
        commit_tx(app, staged, epoch, "confirmed", vec![event], None);
        return;
    }

    let outcome = match staged.method.as_str() {
        "register_device" => apply_register_device(app, tx, from),
        "revoke_device" => apply_revoke_device(app, tx, from),
        "bond_endpoint" => apply_bond_endpoint(app, tx, from),
        "unbond_endpoint" => apply_unbond_endpoint(app, from),
        "finalize_unbond" => apply_finalize_unbond(app, from),
        "gov_slash_operator" => apply_gov_slash_operator(app, tx, from),
        "slash_double_sign" => apply_slash_double_sign(app, tx, from),
        "register_endpoint" => apply_register_endpoint(app, tx, from),
        "update_endpoint" => apply_update_endpoint(app, tx, from),
        "rotate_keys" => apply_rotate_keys(app, tx, from),
        "retire_endpoint" => apply_retire_endpoint(app, from),
        "create_tailnet" => apply_create_tailnet(app, tx, from, &staged.hash),
        "add_member" => apply_add_member(app, tx, from),
        "remove_member" => apply_remove_member(app, tx, from),
        "deposit_to_tailnet" => apply_deposit_to_tailnet(app, tx, from),
        "configure_tailnet_exit" => apply_configure_tailnet_exit(app, tx, from),
        "update_acl" => apply_update_acl(app, tx, from),
        "open_session" => apply_open_session(app, tx, from, &staged.hash),
        "settle_claim" => apply_settle_claim(app, tx, from),
        "settle_confirm" => apply_settle_confirm(app, tx, from),
        "precommit_join_token" => apply_precommit_join_token(app, tx, from),
        "redeem_join_token" => apply_redeem_join_token(app, tx, from),
        "claim_no_show" => apply_claim_no_show(app, tx),
        "sweep_expired_session" => apply_sweep_expired_session(app, tx, from),
        "claim_earnings" => apply_claim_earnings(app, tx, from),
        "withdraw_program_treasury" => apply_withdraw_treasury(app, tx, from),
        // ----- v2 (Circle-native) entrypoints -----
        "authorize_proxy" => apply_authorize_proxy_v2(app, tx, from),
        "revoke_proxy" => apply_revoke_proxy_v2(app, tx, from),
        "set_charge_internal_traffic" => apply_set_charge_internal_traffic_v2(app, tx, from),
        "open_session_v2" => apply_open_session_v2(app, tx, from),
        "settle_claim_v2" => apply_settle_claim_v2(app, tx, from),
        "settle_confirm_v2" => apply_settle_confirm_v2(app, tx, from),
        "proxy_register_keys" => apply_proxy_register_keys_v2(app, tx, from),
        "claim_earnings_v2" => apply_claim_earnings_v2(app, tx, from),
        _ => Ok(Vec::new()),
    };

    match outcome {
        Ok(events) => commit_tx(app, staged, epoch, "confirmed", events, None),
        Err(reason) => {
            // `require()` failures land in `rejected_txs` with the
            // reason verbatim (`tx_view.ml:107-121`,
            // `history_read_rpc.ml:141-144`). A rejected tx still
            // burns its nonce on the real chain, so we advance it.
            commit_tx(app, staged, epoch, "rejected", Vec::new(), Some(&reason));
        }
    }
}

/// Record the terminal state of an applied tx: the `txs` row, the
/// account nonce/balance movement, and — for a program call — the
/// contract receipt.
fn commit_tx(
    app: &AppState,
    staged: &StagedTx,
    epoch: u64,
    status: &str,
    events: Vec<Value>,
    error: Option<&str>,
) {
    let success = error.is_none();
    let mut s = app.state.write();

    // Nonce burns and fees are charged whether or not execution
    // succeeded — the tx was included. Always record the nonce even
    // when no ledger row existed yet: otherwise a legacy (unfunded)
    // sender reuses nonce 1 forever and identical payloads collide
    // as duplicate_tx (106) after the first apply.
    {
        let acct = s.accounts.entry(staged.from.clone()).or_default();
        acct.nonce = staged.nonce;
        acct.balance = acct.balance.saturating_sub(staged.ou);
        if success {
            acct.balance = acct.balance.saturating_sub(staged.amount);
        }
    }
    if success && !staged.to.is_empty() && staged.amount > 0 {
        if let Some(dest) = s.accounts.get_mut(&staged.to) {
            dest.balance = dest.balance.saturating_add(staged.amount);
        }
    }

    if status == "rejected" {
        let reason = error.unwrap_or_default();
        let row = json!({
            "status": "rejected",
            "tx_hash": staged.hash,
            "epoch": epoch,
            "error": { "type": "execution_reverted", "reason": reason },
            "from": staged.from,
            "to": staged.to,
            "amount": staged.amount.to_string(),
            "nonce": staged.nonce,
            "rejected_at": unix_now(),
            "source": "rejected_txs",
        });
        s.rejected_txs.insert(staged.hash.clone(), row);
    }

    // A contract call (or a deploy's constructor) produces a receipt; a
    // plain transfer does not — `contract_rpc.ml:765-780` reads a
    // stored receipt blob and answers 112 "receipt not found" when
    // there is none, which the live node confirms.
    if staged.op_type == "call" || staged.op_type == "deploy" {
        let program = app.program_addr.clone();
        let receipt = json!({
            "program": program,
            "contract": program,
            "method": staged.method,
            "success": success,
            "effort": 0,
            "events": events
                .iter()
                .map(|e| program_event_json(&program, e))
                .collect::<Vec<_>>(),
            "error": match error { Some(e) => json!(e), None => Value::Null },
            "epoch": epoch,
            "ts": unix_now(),
        });
        s.receipts.insert(staged.hash.clone(), receipt);
    }

    s.txs.insert(
        staged.hash.clone(),
        TxRow {
            method: staged.method.clone(),
            from: staged.from.clone(),
            events,
            status: status.to_string(),
            epoch,
            to: staged.to.clone(),
            amount: staged.amount,
            nonce: staged.nonce,
            ou: staged.ou,
            timestamp: staged.timestamp,
            op_type: staged.op_type.clone(),
            message: staged.message.clone(),
        },
    );
}

/// Render one of the mock's internal `{"name":…, …}` event records in
/// the chain's own event shape (`receipt_view.ml:67-76`,
/// `program_event_json`): `{program, contract, depth, event, values}`.
///
/// The chain's `values` is a positional list of VM values; the mock's
/// records are named maps, so the remaining fields are emitted in key
/// order. The KEYS of the receipt envelope are the node's; the payload
/// is as faithful as an interpreter-free mock can make it.
fn program_event_json(program: &str, e: &Value) -> Value {
    let name = e.get("name").and_then(Value::as_str).unwrap_or("");
    let values: Vec<Value> = e
        .as_object()
        .map(|o| {
            let mut keys: Vec<&String> = o.keys().filter(|k| k.as_str() != "name").collect();
            keys.sort();
            keys.into_iter().map(|k| o[k].clone()).collect()
        })
        .unwrap_or_default();
    json!({
        "program": program,
        "contract": program,
        "depth": 0,
        "event": name,
        "values": values,
    })
}

// ------------------------ device handlers ------------------------

fn apply_register_device(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let device = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("device addr missing")?
        .to_string();
    let mut s = app.state.write();
    if let Some(existing) = s.device_owner.get(&device) {
        if existing == from {
            return Ok(Vec::new());
        }
        return Err("device already attached to another wallet".into());
    }
    s.device_owner.insert(device.clone(), from.to_string());
    Ok(vec![json!({
        "name": "DeviceRegistered",
        "wallet": from,
        "device": device,
    })])
}

fn apply_revoke_device(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let device = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("device addr missing")?
        .to_string();
    let mut s = app.state.write();
    match s.device_owner.get(&device) {
        Some(owner) if owner == from => {
            s.device_owner.remove(&device);
            Ok(vec![json!({
                "name": "DeviceRevoked",
                "wallet": from,
                "device": device,
            })])
        }
        Some(_) => Err("not device owner".into()),
        None => Err("device not registered".into()),
    }
}

// ------------------------ endpoint handlers ------------------------

fn apply_register_endpoint(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let endpoint = p[0].as_str().unwrap_or("").to_string();
    let wg = p[1].as_str().unwrap_or("").to_string();
    let hfhe = p[2].as_str().unwrap_or("").to_string();
    let initial_zero = p[3].as_str().unwrap_or("").to_string();
    let region = p[4].as_str().unwrap_or("").to_string();
    let price = p[5].as_u64().unwrap_or(0);
    // Optional 7th param (v1.1+): receipt_pubkey used for off-chain
    // dual-signed receipt slashing via `slash_double_sign`. Pre-v1.1
    // callers omit it; we accept either shape and default to empty.
    let receipt_pk = p.get(6).and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut s = app.state.write();
    coverage::record("register_endpoint", "require[1]"); // not slashed
    if s.endpoint_slashed.contains(from) {
        return Err("previously slashed".into());
    }
    coverage::record("register_endpoint", "require[2]"); // has stake
    if s.endpoint_stake.get(from).copied().unwrap_or(0) < MIN_ENDPOINT_STAKE {
        return Err("must bond_endpoint first".into());
    }
    coverage::record("register_endpoint", "require[3]"); // not already registered
    if s.endpoints.contains_key(from) {
        return Err("already registered".into());
    }
    coverage::record("register_endpoint", "require[4]"); // price > 0
    if price == 0 {
        return Err("price must be > 0".into());
    }
    coverage::record("register_endpoint", "require[5]"); // hfhe pubkey required
    if hfhe.is_empty() {
        return Err("hfhe pubkey required".into());
    }
    coverage::record("register_endpoint", "require[6]"); // initial enc(0) required
    if initial_zero.is_empty() {
        return Err("initial enc(0) required".into());
    }
    let epoch = s.epoch;
    s.endpoints.insert(
        from.to_string(),
        EndpointRow {
            addr: from.to_string(),
            active: true,
            endpoint: endpoint.clone(),
            wg_pubkey: wg,
            hfhe_pubkey: hfhe,
            initial_enc_zero: initial_zero,
            region: region.clone(),
            price_per_mb: price,
            registered_at: epoch,
            reputation: 0,
            receipt_pubkey: receipt_pk,
        },
    );
    // Initialise encrypted earnings ledger at zero. Mock-cleartext.
    s.earnings.insert(from.to_string(), 0);
    Ok(vec![json!({
        "name": "EndpointRegistered",
        "addr": from,
        "endpoint": endpoint,
        "region": region,
    })])
}

fn apply_update_endpoint(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let endpoint = p[0].as_str().unwrap_or("").to_string();
    let region = p[1].as_str().unwrap_or("").to_string();
    let price = p[2].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    if !ep.active {
        return Err("endpoint retired".into());
    }
    if price == 0 {
        return Err("price must be > 0".into());
    }
    ep.endpoint = endpoint;
    ep.region = region;
    ep.price_per_mb = price;
    Ok(vec![json!({ "name": "EndpointUpdated", "addr": from })])
}

fn apply_rotate_keys(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let new_wg = p[0].as_str().unwrap_or("").to_string();
    let new_hfhe = p[1].as_str().unwrap_or("").to_string();
    let new_zero = p[2].as_str().unwrap_or("").to_string();
    if new_hfhe.is_empty() || new_zero.is_empty() {
        return Err("hfhe pubkey + initial enc(0) required".into());
    }
    let mut s = app.state.write();
    // Refuse rotation while earnings are non-zero (would be encrypted
    // under the old key).
    if s.earnings.get(from).copied().unwrap_or(0) != 0 {
        return Err("claim earnings before rotating keys".into());
    }
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    if !ep.active {
        return Err("endpoint retired".into());
    }
    ep.wg_pubkey = new_wg;
    ep.hfhe_pubkey = new_hfhe;
    ep.initial_enc_zero = new_zero;
    Ok(vec![json!({ "name": "KeysRotated", "addr": from })])
}

fn apply_retire_endpoint(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    ep.active = false;
    Ok(vec![json!({ "name": "EndpointRetired", "addr": from })])
}

// ------------------------- stake / slashing handlers -------------------------

fn apply_bond_endpoint(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let amount = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if amount == 0 {
        return Err("no value".into());
    }
    let mut s = app.state.write();
    if s.endpoint_slashed.contains(from) {
        return Err("previously slashed".into());
    }
    if s.endpoint_unbonding.contains_key(from) {
        return Err("unbonding in progress".into());
    }
    let cur = s.endpoint_stake.get(from).copied().unwrap_or(0);
    let new_stake = cur.checked_add(amount).ok_or("stake overflow")?;
    s.endpoint_stake.insert(from.to_string(), new_stake);
    Ok(vec![json!({
        "name": "StakeBonded",
        "addr": from,
        "amount": amount,
        "new_stake": new_stake,
    })])
}

fn apply_unbond_endpoint(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let amt = s.endpoint_stake.get(from).copied().unwrap_or(0);
    if amt == 0 {
        return Err("no stake".into());
    }
    if s.endpoint_unbonding.contains_key(from) {
        return Err("already unbonding".into());
    }
    let unlock = s.epoch + UNBOND_GRACE_EPOCHS;
    s.endpoint_unbonding.insert(from.to_string(), (amt, unlock));
    s.endpoint_stake.insert(from.to_string(), 0);
    let mut events = Vec::with_capacity(2);
    if let Some(ep) = s.endpoints.get_mut(from) {
        if ep.active {
            ep.active = false;
            events.push(json!({ "name": "EndpointRetired", "addr": from }));
        }
    }
    events.push(json!({
        "name": "StakeUnbondingStarted",
        "addr": from,
        "stake": amt,
        "unlock_epoch": unlock,
    }));
    Ok(events)
}

fn apply_finalize_unbond(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let (amt, unlock) = s
        .endpoint_unbonding
        .get(from)
        .copied()
        .ok_or("no unbonding")?;
    if s.epoch < unlock {
        return Err("grace not elapsed".into());
    }
    s.endpoint_unbonding.remove(from);
    *s.balances.entry(from.to_string()).or_insert(0) += amt;
    Ok(vec![json!({
        "name": "StakeUnbondingFinalized",
        "addr": from,
        "amount": amt,
    })])
}

/// Governance slash. Replaces in-AML cryptographic-evidence slashing.
/// Only the program owner may call. Off-chain evidence verification
/// is the owner's responsibility (`octravpn slash-evidence verify`).
fn apply_gov_slash_operator(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let operator = p[0].as_str().unwrap_or("").to_string();
    let reason = p
        .get(1)
        .and_then(|x| x.as_str())
        .unwrap_or("unspecified")
        .to_string();

    let mut s = app.state.write();
    let owner = s.owner.as_deref().ok_or("owner not set")?;
    if owner != from {
        return Err("not owner".into());
    }
    if s.endpoint_slashed.contains(&operator) {
        return Err("already slashed".into());
    }
    let live = s.endpoint_stake.get(&operator).copied().unwrap_or(0);
    let unb = s
        .endpoint_unbonding
        .get(&operator)
        .map_or(0, |(amt, _)| *amt);
    let total = live.checked_add(unb).ok_or("stake overflow")?;
    if total == 0 {
        return Err("no stake to slash".into());
    }
    let burn_amt = total.checked_mul(SLASH_BURN_BPS).ok_or("overflow burn")? / 10_000;
    let bounty_amt = total - burn_amt;

    s.endpoint_stake.insert(operator.clone(), 0);
    s.endpoint_unbonding.remove(&operator);
    s.endpoint_slashed.insert(operator.clone());
    if let Some(ep) = s.endpoints.get_mut(&operator) {
        ep.active = false;
    }
    s.program_treasury = s
        .program_treasury
        .checked_add(burn_amt)
        .ok_or("overflow treasury")?;
    if bounty_amt > 0 {
        *s.balances.entry(from.to_string()).or_insert(0) += bounty_amt;
    }
    Ok(vec![json!({
        "name": "OperatorSlashed",
        "addr": operator,
        "stake": total,
        "burn_amt": burn_amt,
        "bounty_amt": bounty_amt,
        "reason": reason,
    })])
}

/// Decode an ed25519 pubkey from base64 (Octra's wire form) or hex
/// (test-friendly form). Returns None on invalid input.
/// Decode a 32-byte value from hex (preferred) or base64. Hex is
/// tried first because 64 hex chars happen to be valid base64 too,
/// but decode to ~48 bytes and would silently mis-parse.
fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let hex_len = N * 2;
    let bytes = if s.len() == hex_len {
        hex::decode(s).ok()?
    } else {
        STANDARD.decode(s).ok()?
    };
    if bytes.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn decode_ed25519_pubkey(s: &str) -> Option<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(&decode_fixed::<32>(s)?).ok()
}

fn decode_ed25519_sig(s: &str) -> Option<ed25519_dalek::Signature> {
    Some(ed25519_dalek::Signature::from_bytes(&decode_fixed::<64>(
        s,
    )?))
}

/// Off-chain receipt equivocation slash. Mirrors v1.1 AML
/// `slash_double_sign(operator_addr, session_id, payload_a, sig_a,
/// payload_b, sig_b)`. Verifies both sigs under the operator's
/// stored `receipt_pubkey`; any two distinct signed payloads are
/// slashable evidence.
fn apply_slash_double_sign(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let operator = p[0].as_str().unwrap_or("").to_string();
    let _session_id = p.get(1).and_then(Value::as_u64).unwrap_or(0);
    let payload_a = p.get(2).and_then(Value::as_str).unwrap_or("");
    let sig_a = p.get(3).and_then(Value::as_str).unwrap_or("");
    let payload_b = p.get(4).and_then(Value::as_str).unwrap_or("");
    let sig_b = p.get(5).and_then(Value::as_str).unwrap_or("");

    coverage::record("slash_double_sign", "require[1]"); // not slashed
    coverage::record("slash_double_sign", "require[2]"); // distinct payloads
    coverage::record("slash_double_sign", "require[3]"); // receipt pubkey present
    coverage::record("slash_double_sign", "require[4]"); // sig_a verifies
    coverage::record("slash_double_sign", "require[5]"); // sig_b verifies

    if payload_a == payload_b {
        return Err("payloads identical".into());
    }
    let mut s = app.state.write();
    if s.endpoint_slashed.contains(&operator) {
        return Err("already slashed".into());
    }
    let receipt_pk_str = s
        .endpoints
        .get(&operator)
        .map(|e| e.receipt_pubkey.clone())
        .unwrap_or_default();
    if receipt_pk_str.is_empty() {
        return Err("operator has no receipt pubkey".into());
    }
    let pk = decode_ed25519_pubkey(&receipt_pk_str).ok_or("operator receipt_pubkey malformed")?;
    let sa = decode_ed25519_sig(sig_a).ok_or("sig_a malformed")?;
    let sb = decode_ed25519_sig(sig_b).ok_or("sig_b malformed")?;
    if pk.verify_strict(payload_a.as_bytes(), &sa).is_err() {
        return Err("sig_a invalid".into());
    }
    if pk.verify_strict(payload_b.as_bytes(), &sb).is_err() {
        return Err("sig_b invalid".into());
    }

    let live = s.endpoint_stake.get(&operator).copied().unwrap_or(0);
    let unb = s
        .endpoint_unbonding
        .get(&operator)
        .map_or(0, |(amt, _)| *amt);
    let total = live.checked_add(unb).ok_or("stake overflow")?;
    if total == 0 {
        return Err("no stake to slash".into());
    }
    let burn_amt = total.checked_mul(SLASH_BURN_BPS).ok_or("overflow burn")? / 10_000;
    let bounty_amt = total - burn_amt;

    s.endpoint_stake.insert(operator.clone(), 0);
    s.endpoint_unbonding.remove(&operator);
    s.endpoint_slashed.insert(operator.clone());
    if let Some(ep) = s.endpoints.get_mut(&operator) {
        ep.active = false;
    }
    s.program_treasury = s
        .program_treasury
        .checked_add(burn_amt)
        .ok_or("overflow treasury")?;
    if bounty_amt > 0 {
        *s.balances.entry(from.to_string()).or_insert(0) += bounty_amt;
    }
    Ok(vec![json!({
        "name": "OperatorSlashed",
        "addr": operator,
        "stake": total,
        "burn_amt": burn_amt,
        "bounty_amt": bounty_amt,
        "reason": "double-sign",
    })])
}

// ------------------------- tailnet handlers -------------------------

fn apply_create_tailnet(
    app: &AppState,
    tx: &Value,
    from: &str,
    _hash: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let acl_policy = p.first().and_then(|x| x.as_str()).unwrap_or("").to_string();
    let deposit = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if deposit == 0 {
        return Err("tailnet deposit required".into());
    }

    let mut s = app.state.write();
    let tid = s.tailnet_count;
    s.tailnet_count += 1;
    let created_at = s.epoch;
    let mut members = HashSet::new();
    members.insert(from.to_string());
    s.tailnets.insert(
        tid,
        TailnetRow {
            id: tid,
            owner: from.to_string(),
            treasury: deposit,
            members,
            exits: HashSet::new(),
            acl_policy,
            created_at,
        },
    );

    Ok(vec![
        json!({
            "name": "TailnetCreated",
            "tailnet_id": tid,
            "owner": from,
        }),
        json!({
            "name": "TailnetMemberAdded",
            "tailnet_id": tid,
            "member": from,
        }),
    ])
}

fn apply_add_member(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let member = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if t.members.contains(&member) {
        return Err("already member".into());
    }
    t.members.insert(member.clone());
    Ok(vec![json!({
        "name": "TailnetMemberAdded",
        "tailnet_id": tid,
        "member": member,
    })])
}

fn apply_remove_member(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let member = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if member == t.owner {
        return Err("cannot remove owner".into());
    }
    if !t.members.remove(&member) {
        return Err("not member".into());
    }
    Ok(vec![json!({
        "name": "TailnetMemberRemoved",
        "tailnet_id": tid,
        "member": member,
    })])
}

fn apply_deposit_to_tailnet(app: &AppState, tx: &Value, _from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let amount = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if amount == 0 {
        return Err("no value".into());
    }
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    t.treasury += amount;
    let new_treasury = t.treasury;
    Ok(vec![json!({
        "name": "TailnetDeposit",
        "tailnet_id": tid,
        "amount": amount,
        "new_treasury": new_treasury,
    })])
}

fn apply_configure_tailnet_exit(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let exit_addr = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let exit_active = s.endpoints.get(&exit_addr).is_some_and(|e| e.active);
    if !exit_active {
        return Err("exit not registered or inactive".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if !t.exits.insert(exit_addr.clone()) {
        return Err("already configured".into());
    }
    Ok(vec![json!({
        "name": "TailnetExitConfigured",
        "tailnet_id": tid,
        "exit_addr": exit_addr,
    })])
}

fn apply_update_acl(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let new_acl = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    t.acl_policy.clone_from(&new_acl);
    Ok(vec![json!({
        "name": "TailnetAclUpdated",
        "tailnet_id": tid,
        "acl_policy": new_acl,
    })])
}

// ------------------------- session handlers --------------------------

fn apply_open_session(
    app: &AppState,
    tx: &Value,
    from: &str,
    _hash: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let exit_addr = p[1].as_str().unwrap_or("").to_string();
    let max_pay = p[2].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    let opened_at = s.epoch;
    coverage::record("open_session", "require[1]"); // tailnet found
    let device_owner = s.device_owner.get(from).cloned();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    coverage::record("open_session", "require[2]"); // member check
    let direct = t.members.contains(from);
    let via_device = device_owner
        .as_deref()
        .is_some_and(|w| t.members.contains(w));
    if !direct && !via_device {
        return Err("not a member".into());
    }
    coverage::record("open_session", "require[3]"); // exit configured
    if !t.exits.contains(&exit_addr) {
        return Err("exit not configured for tailnet".into());
    }
    coverage::record("open_session", "require[4]"); // deposit > 0
    if max_pay == 0 {
        return Err("deposit must be > 0".into());
    }
    coverage::record("open_session", "require[5]"); // treasury sufficient
    if t.treasury < max_pay {
        return Err("treasury insufficient".into());
    }
    coverage::record("open_session", "require[6]"); // exit active (verified below)
    let exit_has_stake =
        s.endpoint_stake.get(&exit_addr).copied().unwrap_or(0) >= MIN_ENDPOINT_STAKE;
    let exit_slashed = s.endpoint_slashed.contains(&exit_addr);
    let exit_active_ep = s.endpoints.get(&exit_addr).is_some_and(|e| e.active);
    if !exit_active_ep || exit_slashed || !exit_has_stake {
        return Err("exit inactive".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    t.treasury -= max_pay;

    let sid = s.session_count;
    s.session_count += 1;
    s.sessions.insert(
        sid,
        SessionRow {
            tailnet_id: tid,
            exit: exit_addr.clone(),
            opener: from.to_string(),
            deposit: max_pay,
            opened_at,
            status: 0,
            operator_claim: None,
            client_confirm: None,
        },
    );

    Ok(vec![json!({
        "name": "SessionOpened",
        "session_id": sid,
        "tailnet_id": tid,
        "exit": exit_addr,
        "deposit": max_pay,
        "opened_at": opened_at,
    })])
}

/// Operator-side `settle_claim`. Records the operator's claim or,
/// if they've already claimed a DIFFERENT value, slashes them
/// atomically for equivocation.
fn apply_settle_claim(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let bytes_used = p[1].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    coverage::record("settle_claim", "require[1]"); // status == open
    coverage::record("settle_claim", "require[2]"); // caller is exit
    let (tid, deposit, prev_claim) = {
        let sess = s.sessions.get(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        if sess.exit != from {
            return Err("not the session's exit operator".into());
        }
        let ep = s
            .endpoints
            .get(&sess.exit)
            .ok_or("operator not registered")?;
        let has_stake =
            s.endpoint_stake.get(&sess.exit).copied().unwrap_or(0) >= MIN_ENDPOINT_STAKE;
        let slashed = s.endpoint_slashed.contains(&sess.exit);
        if !ep.active || slashed || !has_stake {
            return Err("operator inactive".into());
        }
        (sess.tailnet_id, sess.deposit, sess.operator_claim)
    };

    if let Some((prev_bytes, _)) = prev_claim {
        if prev_bytes == bytes_used {
            // Idempotent re-submission (network retry).
            return Ok(vec![]);
        }
        // Equivocation: same operator, same session, different bytes.
        // Slash atomically + refund the session deposit (no settlement).
        coverage::record("settle_claim", "equivocation");
        let live = s.endpoint_stake.get(from).copied().unwrap_or(0);
        let unb = s.endpoint_unbonding.get(from).map_or(0, |(amt, _)| *amt);
        let total = live.checked_add(unb).ok_or("overflow")?;
        let burn_amt = total.checked_mul(SLASH_BURN_BPS).ok_or("overflow burn")? / 10_000;
        let bounty_amt = total - burn_amt;
        s.endpoint_stake.insert(from.to_string(), 0);
        s.endpoint_unbonding.remove(from);
        s.endpoint_slashed.insert(from.to_string());
        if let Some(ep) = s.endpoints.get_mut(from) {
            ep.active = false;
        }
        // Whole stake burned (bounty also flows to treasury since
        // the only "submitter" is the bad-actor operator themselves).
        s.program_treasury = s
            .program_treasury
            .checked_add(total)
            .ok_or("overflow treasury")?;
        // Refund the session deposit; no settlement happens.
        if let Some(sess) = s.sessions.get_mut(&sid) {
            sess.status = 2;
        }
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += deposit;
        }
        return Ok(vec![
            json!({
                "name": "OperatorSlashed",
                "addr": from,
                "stake": total,
                "burn_amt": burn_amt,
                "bounty_amt": bounty_amt,
                "reason": "equivocation",
            }),
            json!({
                "name": "SessionRefunded",
                "session_id": sid,
                "reason": "operator-equivocation",
            }),
        ]);
    }

    let claimed_at = s.epoch;
    if let Some(sess) = s.sessions.get_mut(&sid) {
        sess.operator_claim = Some((bytes_used, claimed_at));
    }
    Ok(vec![json!({
        "name": "SettleClaimed",
        "session_id": sid,
        "exit": from,
        "bytes_used": bytes_used,
    })])
}

/// Client-side `settle_confirm`. Only the session opener can call.
/// On match → settlement applies. On mismatch → public dispute is
/// recorded; settlement does NOT apply.
fn apply_settle_confirm(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let bytes_used = p[1].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    let (tid, deposit, exit, price, op_bytes) = {
        let sess = s.sessions.get(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        if sess.opener != from {
            return Err("not the session opener".into());
        }
        let (ob, _) = sess.operator_claim.ok_or("operator has not claimed yet")?;
        let ep = s.endpoints.get(&sess.exit).ok_or("operator missing")?;
        let has_stake =
            s.endpoint_stake.get(&sess.exit).copied().unwrap_or(0) >= MIN_ENDPOINT_STAKE;
        let slashed = s.endpoint_slashed.contains(&sess.exit);
        if !ep.active || slashed || !has_stake {
            return Err("operator inactive".into());
        }
        (
            sess.tailnet_id,
            sess.deposit,
            sess.exit.clone(),
            ep.price_per_mb,
            ob,
        )
    };

    let confirmed_at = s.epoch;
    if op_bytes != bytes_used {
        coverage::record("settle_confirm", "dispute");
        if let Some(sess) = s.sessions.get_mut(&sid) {
            sess.client_confirm = Some((bytes_used, confirmed_at));
        }
        return Ok(vec![json!({
            "name": "SettleDispute",
            "session_id": sid,
            "operator_bytes": op_bytes,
            "client_bytes": bytes_used,
        })]);
    }

    let total_paid = bytes_used.checked_mul(price).ok_or("overflow pay")?;
    if total_paid > deposit {
        return Err("claim exceeds escrow".into());
    }
    let protocol_fee = total_paid
        .checked_mul(PROTOCOL_FEE_BPS)
        .ok_or("overflow fee")?
        / 10_000;
    let net_pay = total_paid - protocol_fee;
    let refund = deposit - total_paid;

    if let Some(sess) = s.sessions.get_mut(&sid) {
        sess.status = 1;
        sess.client_confirm = Some((bytes_used, confirmed_at));
    }
    if net_pay > 0 {
        *s.earnings.entry(exit.clone()).or_insert(0) += net_pay;
    }
    if let Some(ep) = s.endpoints.get_mut(&exit) {
        ep.reputation += 1;
    }
    if protocol_fee > 0 {
        s.program_treasury = s
            .program_treasury
            .checked_add(protocol_fee)
            .ok_or("overflow treasury")?;
    }
    if refund > 0 {
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += refund;
        }
    }
    Ok(vec![
        json!({
            "name": "SettleConfirmed",
            "session_id": sid,
            "opener": from,
            "bytes_used": bytes_used,
        }),
        json!({
            "name": "SessionSettled",
            "session_id": sid,
            "exit": exit,
            "bytes_used": bytes_used,
            "total_paid": total_paid,
            "refund": refund,
        }),
    ])
}

fn apply_precommit_join_token(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let token_hash = p[1].as_str().unwrap_or("").to_string();
    if token_hash.len() != 64 {
        return Err("token hash must be 64 hex chars (sha256)".into());
    }
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if s.join_token_redeemed.contains(&token_hash) {
        return Err("hash already used".into());
    }
    let entry = s.join_token_commits.entry(tid).or_default();
    if !entry.insert(token_hash.clone()) {
        return Err("already committed".into());
    }
    Ok(vec![json!({
        "name": "JoinTokenPrecommitted",
        "tailnet_id": tid,
        "token_hash": token_hash,
    })])
}

fn apply_redeem_join_token(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let preimage_hex = p[1].as_str().unwrap_or("");
    if preimage_hex.is_empty() {
        return Err("preimage required".into());
    }
    let preimage = hex::decode(preimage_hex).map_err(|e| format!("preimage hex: {e}"))?;
    let mut h = Sha256::new();
    h.update(&preimage);
    let token_hash = hex::encode(h.finalize());

    let mut s = app.state.write();
    if s.join_token_redeemed.contains(&token_hash) {
        return Err("already redeemed".into());
    }
    let known = s
        .join_token_commits
        .get(&tid)
        .is_some_and(|set| set.contains(&token_hash));
    if !known {
        return Err("unknown token".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.members.contains(from) {
        return Err("already member".into());
    }
    t.members.insert(from.to_string());
    s.join_token_redeemed.insert(token_hash.clone());
    Ok(vec![
        json!({
            "name": "TailnetMemberAdded",
            "tailnet_id": tid,
            "member": from,
        }),
        json!({
            "name": "JoinTokenRedeemed",
            "tailnet_id": tid,
            "member": from,
            "token_hash": token_hash,
        }),
    ])
}

fn apply_claim_no_show(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let mut s = app.state.write();
    let (tid, deposit) = {
        let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        sess.status = 2;
        (sess.tailnet_id, sess.deposit)
    };
    if let Some(t) = s.tailnets.get_mut(&tid) {
        t.treasury += deposit;
    }
    Ok(vec![json!({
        "name": "SessionRefunded",
        "session_id": sid,
        "reason": "no-show",
    })])
}

fn apply_sweep_expired_session(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let mut s = app.state.write();
    let (tid, deposit) = {
        let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        sess.status = 2;
        (sess.tailnet_id, sess.deposit)
    };
    let bounty = deposit / 100;
    let refund = deposit - bounty;
    if bounty > 0 {
        *s.balances.entry(from.to_string()).or_insert(0) += bounty;
    }
    if refund > 0 {
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += refund;
        }
    }
    Ok(vec![json!({
        "name": "SessionSwept",
        "session_id": sid,
    })])
}

/// Two-step claim per `program/main.aml::claim_earnings`. Verifies
/// the operator's claim exactly matches the encrypted-earnings
/// balance (the mock simplifies the FHE zero-proof to direct
/// equality), then transfers plaintext OU. Stealth follow-up tx is
/// the operator's wallet's responsibility (off-AML).
fn apply_claim_earnings(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let claimed = p[0].as_u64().unwrap_or(0);
    let proof = p.get(1).and_then(|x| x.as_str()).unwrap_or("").to_string();

    if claimed == 0 {
        return Err("amount>0".into());
    }
    if proof.is_empty() {
        return Err("proof required".into());
    }

    let mut s = app.state.write();
    if s.endpoint_slashed.contains(from) {
        return Err("operator slashed".into());
    }
    let balance = s.earnings.get(from).copied().unwrap_or(0);
    // Mock FHE zero-proof verification: exact match.
    if balance != claimed {
        return Err("bad opening".into());
    }
    s.earnings.insert(from.to_string(), 0);
    *s.balances.entry(from.to_string()).or_insert(0) += claimed;
    Ok(vec![json!({
        "name": "EarningsClaimed",
        "operator": from,
        "amount": claimed,
    })])
}

fn apply_withdraw_treasury(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let to = p[0].as_str().unwrap_or("").to_string();
    let amount = p[1].as_u64().unwrap_or(0);
    if amount == 0 {
        return Err("amount>0".into());
    }
    let mut s = app.state.write();
    let owner = s.owner.as_deref().ok_or("owner not set")?;
    if owner != from {
        return Err("not owner".into());
    }
    if s.program_treasury < amount {
        return Err("treasury insufficient".into());
    }
    s.program_treasury -= amount;
    *s.balances.entry(to.clone()).or_insert(0) += amount;
    Ok(vec![json!({
        "name": "ProgramTreasuryWithdrawn",
        "to": to,
        "amount": amount,
    })])
}

// ===============================================================
// v2 (Circle-native) handlers.
//
// Live alongside the v1 handlers above. The two worlds share
// `tailnets`, `members`, balances, epoch — but use disjoint session
// + earnings tables (`sessions_v2`, `enc_earnings_v2`, etc.) so a
// v2 settle never touches v1 state and vice versa.
// ===============================================================

/// Owner authorizes a Circle's proxy contract to settle sessions for
/// `tailnet_id`. v2 replacement for v1's `configure_tailnet_exit`
/// (which gated on protocol-level operator registration). v2 does
/// NOT inspect the proxy — operators are Circles and main-net sees
/// only their proxy address.
fn apply_authorize_proxy_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let proxy = p
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or("proxy addr missing")?
        .to_string();
    if proxy.is_empty() {
        return Err("invalid proxy".into());
    }
    let mut s = app.state.write();
    let t = s.tailnets.get(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    s.authorized_proxies_v2
        .entry(tid)
        .or_default()
        .insert(proxy.clone());
    Ok(vec![json!({
        "name": "ProxyAuthorized",
        "tailnet_id": tid,
        "proxy": proxy,
    })])
}

fn apply_revoke_proxy_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let proxy = p
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or("proxy addr missing")?
        .to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if let Some(set) = s.authorized_proxies_v2.get_mut(&tid) {
        set.remove(&proxy);
    }
    Ok(vec![json!({
        "name": "ProxyRevoked",
        "tailnet_id": tid,
        "proxy": proxy,
    })])
}

fn apply_set_charge_internal_traffic_v2(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let charge = p
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or("charge missing")?;
    if charge != 0 && charge != 1 {
        return Err("charge must be 0 or 1".into());
    }
    let mut s = app.state.write();
    let t = s.tailnets.get(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    s.charge_internal_traffic_v2.insert(tid, charge as u8);
    Ok(vec![json!({
        "name": "TailnetChargeInternalSet",
        "tailnet_id": tid,
        "charge": charge,
    })])
}

const V2_CLASS_SHARED: u8 = 0;
const V2_CLASS_INTERNAL: u8 = 1;
/// Mirror of the v2 AML's `min_session_deposit`. Kept in sync with
/// the existing `get_params` default of `10` so consumers can use
/// the same constant for both surfaces.
const V2_MIN_SESSION_DEPOSIT: u64 = 10;

fn apply_open_session_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_u64().ok_or("tailnet_id u64")?;
    let proxy = p
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or("proxy addr missing")?
        .to_string();
    let class = p
        .get(2)
        .and_then(serde_json::Value::as_u64)
        .ok_or("class missing")? as u8;
    let price_per_mb = p
        .get(3)
        .and_then(serde_json::Value::as_u64)
        .ok_or("price missing")?;
    let max_pay = p
        .get(4)
        .and_then(serde_json::Value::as_u64)
        .ok_or("max_pay missing")?;

    if class != V2_CLASS_SHARED && class != V2_CLASS_INTERNAL {
        return Err("invalid class".into());
    }
    if max_pay < V2_MIN_SESSION_DEPOSIT {
        return Err("deposit below minimum".into());
    }

    let mut s = app.state.write();
    let opened_at = s.epoch;
    // Device-multi-addr resolution mirrors v1's `open_session`.
    let device_owner = s.device_owner.get(from).cloned();
    let authorized = s
        .authorized_proxies_v2
        .get(&tid)
        .is_some_and(|set| set.contains(&proxy));
    if !authorized {
        return Err("proxy not authorized".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    let direct = t.members.contains(from);
    let via_device = device_owner
        .as_deref()
        .is_some_and(|w| t.members.contains(w));
    if !direct && !via_device {
        return Err("not a tailnet member".into());
    }
    if t.treasury < max_pay {
        return Err("tailnet treasury insufficient".into());
    }
    t.treasury -= max_pay;

    let sid = s.session_count_v2 + 1;
    s.session_count_v2 = sid;
    s.sessions_v2.insert(
        sid,
        SessionRowV2 {
            tailnet_id: tid,
            proxy: proxy.clone(),
            opener: from.to_string(),
            deposit: max_pay,
            opened_at,
            class,
            price_per_mb,
            status: 0,
            proxy_claim: None,
            client_confirm: None,
        },
    );

    Ok(vec![json!({
        "name": "SessionOpened",
        "session_id": sid,
        "tailnet_id": tid,
        "proxy": proxy,
        "class": class,
        "price_per_mb": price_per_mb,
        "deposit": max_pay,
        "opened_at": opened_at,
    })])
}

/// Proxy submits its claim. Equivocation refunds the deposit and
/// emits `ProxyBondSlashed` — the mock has no real bond to slash
/// (the bond lives in the proxy contract per litepaper §4.4.2),
/// so the event uses `amount: 0` and we just refund + mark
/// `status = 2` (refunded).
fn apply_settle_claim_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let bytes_used = p
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or("bytes_used u64")?;

    let mut s = app.state.write();
    let (tid, deposit, prev_claim, proxy) = {
        let sess = s.sessions_v2.get(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        if sess.proxy != from {
            return Err("caller is not the session proxy".into());
        }
        (
            sess.tailnet_id,
            sess.deposit,
            sess.proxy_claim,
            sess.proxy.clone(),
        )
    };
    // Authorization is checked again at claim time: if the proxy was
    // revoked between open and claim, the claim fails.
    let still_authorized = s
        .authorized_proxies_v2
        .get(&tid)
        .is_some_and(|set| set.contains(&proxy));
    if !still_authorized {
        return Err("proxy not authorized".into());
    }

    if let Some((prev_bytes, _)) = prev_claim {
        if prev_bytes == bytes_used {
            // Idempotent retry.
            return Ok(vec![]);
        }
        // Equivocation: refund + slash event.
        if let Some(sess) = s.sessions_v2.get_mut(&sid) {
            sess.status = 2;
        }
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += deposit;
        }
        return Ok(vec![
            json!({
                "name": "ProxyBondSlashed",
                "proxy": from,
                // Mock has no proxy-side bond resource; the real
                // chain would `proxy.slash_bond(deposit, ...)`.
                "amount": 0,
                "reason": "equivocation",
            }),
            json!({
                "name": "SessionRefunded",
                "session_id": sid,
                "reason": "operator-equivocation",
            }),
        ]);
    }

    let claimed_at = s.epoch;
    if let Some(sess) = s.sessions_v2.get_mut(&sid) {
        sess.proxy_claim = Some((bytes_used, claimed_at));
    }
    Ok(vec![json!({
        "name": "SettleClaimed",
        "session_id": sid,
        "proxy": from,
        "bytes_used": bytes_used,
    })])
}

fn apply_settle_confirm_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_u64().ok_or("session_id u64")?;
    let bytes_used = p
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or("bytes_used u64")?;

    let mut s = app.state.write();
    let (tid, deposit, proxy, class, price, op_bytes) = {
        let sess = s.sessions_v2.get(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        if sess.opener != from {
            return Err("not session opener".into());
        }
        let (ob, _) = sess.proxy_claim.ok_or("proxy has not claimed yet")?;
        (
            sess.tailnet_id,
            sess.deposit,
            sess.proxy.clone(),
            sess.class,
            sess.price_per_mb,
            ob,
        )
    };

    let confirmed_at = s.epoch;
    if op_bytes != bytes_used {
        if let Some(sess) = s.sessions_v2.get_mut(&sid) {
            sess.client_confirm = Some((bytes_used, confirmed_at));
        }
        return Ok(vec![json!({
            "name": "SettleDispute",
            "session_id": sid,
            "operator_bytes": op_bytes,
            "client_bytes": bytes_used,
        })]);
    }

    // Internal-class + tailnet says don't charge → enforce free.
    let charge = s.charge_internal_traffic_v2.get(&tid).copied().unwrap_or(0);
    let total_paid = if class == V2_CLASS_INTERNAL && charge == 0 {
        0u64
    } else {
        bytes_used.checked_mul(price).ok_or("overflow pay")?
    };
    if total_paid > deposit {
        return Err("claim exceeds escrow".into());
    }
    let protocol_fee = total_paid
        .checked_mul(PROTOCOL_FEE_BPS)
        .ok_or("overflow fee")?
        / 10_000;
    let net_pay = total_paid - protocol_fee;
    let refund = deposit - total_paid;

    if let Some(sess) = s.sessions_v2.get_mut(&sid) {
        sess.status = 1;
        sess.client_confirm = Some((bytes_used, confirmed_at));
    }
    if net_pay > 0 && s.proxy_pk_set_v2.get(&proxy).copied().unwrap_or(false) {
        // Mirrors v1's `enc_earnings += net_pay`. Mock-cleartext.
        *s.enc_earnings_v2.entry(proxy.clone()).or_insert(0) += net_pay;
    }
    if protocol_fee > 0 {
        s.program_treasury = s
            .program_treasury
            .checked_add(protocol_fee)
            .ok_or("overflow treasury")?;
    }
    if refund > 0 {
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += refund;
        }
    }
    Ok(vec![
        json!({
            "name": "SettleConfirmed",
            "session_id": sid,
            "opener": from,
            "bytes_used": bytes_used,
        }),
        json!({
            "name": "SessionSettled",
            "session_id": sid,
            "proxy": proxy,
            "class": class,
            "bytes_used": bytes_used,
            "total_paid": total_paid,
            "refund": refund,
        }),
    ])
}

fn apply_proxy_register_keys_v2(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let hfhe = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("hfhe_pubkey missing")?
        .to_string();
    let initial_zero = p
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or("initial_enc_zero missing")?
        .to_string();
    if hfhe.is_empty() || initial_zero.is_empty() {
        return Err("hfhe pubkey + initial enc(0) required".into());
    }
    let mut s = app.state.write();
    if s.proxy_pk_set_v2.get(from).copied().unwrap_or(false) {
        return Err("already registered".into());
    }
    s.proxy_pk_v2.insert(from.to_string(), hfhe);
    s.proxy_zero_ct_v2.insert(from.to_string(), initial_zero);
    s.enc_earnings_v2.insert(from.to_string(), 0);
    s.proxy_pk_set_v2.insert(from.to_string(), true);
    // v2 AML emits nothing here; matching that behavior.
    Ok(Vec::new())
}

/// v2 earnings claim, keyed by proxy address. Same mock-FHE
/// simplification as v1: `proof_ct` must exactly equal the
/// outstanding cleartext balance.
fn apply_claim_earnings_v2(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let claimed = p[0].as_u64().unwrap_or(0);
    let proof = p.get(1).and_then(|x| x.as_str()).unwrap_or("").to_string();

    if claimed == 0 {
        return Err("amount>0".into());
    }
    if proof.is_empty() {
        return Err("proof required".into());
    }

    let mut s = app.state.write();
    if !s.proxy_pk_set_v2.get(from).copied().unwrap_or(false) {
        return Err("no keys registered".into());
    }
    let balance = s.enc_earnings_v2.get(from).copied().unwrap_or(0);
    // Honest HFHE path: when OCTRAVPN_E2E_USE_HFHE_MOCK is set, expect
    // `proof` to be a base64-encoded mock-HFHE zero-proof over the
    // delta ciphertext `enc(balance) - enc(claimed)`. Verifies via
    // `aml::host_fhe::fhe_verify_zero` against the proxy's PVAC
    // pubkey. Without the flag we keep the legacy plaintext check.
    if std::env::var("OCTRAVPN_E2E_USE_HFHE_MOCK").is_ok() {
        let pk = s
            .pvac_pubkeys
            .get(from)
            .cloned()
            .ok_or("pubkey not registered")?;
        let bal_ct = aml::host_fhe::encrypt_const(&pk, balance);
        let neg_claim = (!claimed).wrapping_add(1);
        let delta =
            aml::host_fhe::fhe_add_const(&pk, &bal_ct, neg_claim).map_err(|e| e.to_string())?;
        let pf_bytes = B64.decode(&proof).map_err(|e| format!("proof b64: {e}"))?;
        let zp = aml::host_fhe::ZeroProof::from_bytes(&pf_bytes).map_err(|e| e.to_string())?;
        let ok = aml::host_fhe::fhe_verify_zero(&pk, &delta, &zp).map_err(|e| e.to_string())?;
        if !ok {
            return Err("bad opening".into());
        }
    } else if balance != claimed {
        return Err("bad opening".into());
    }
    s.enc_earnings_v2.insert(from.to_string(), 0);
    *s.balances.entry(from.to_string()).or_insert(0) += claimed;
    Ok(vec![json!({
        "name": "EarningsClaimed",
        "proxy": from,
        "amount": claimed,
    })])
}

/// The transaction-shaped fields every `octra_transaction` status
/// carries (`tx_view.ml:60-75`, `tx_fields`).
fn tx_fields(row: &TxRow) -> Vec<(String, Value)> {
    vec![
        ("from".into(), json!(row.from)),
        ("to".into(), json!(row.to)),
        ("amount".into(), json!(format_balance(row.amount))),
        ("amount_raw".into(), json!(row.amount.to_string())),
        ("nonce".into(), json!(row.nonce)),
        ("ou".into(), json!(row.ou.to_string())),
        ("timestamp".into(), json!(row.timestamp)),
        ("op_type".into(), json!(row.op_type)),
        (
            "message".into(),
            match &row.message {
                Some(m) => json!(m),
                None => Value::Null,
            },
        ),
    ]
}

fn staged_tx_fields(t: &StagedTx) -> Vec<(String, Value)> {
    vec![
        ("from".into(), json!(t.from)),
        ("to".into(), json!(t.to)),
        ("amount".into(), json!(format_balance(t.amount))),
        ("amount_raw".into(), json!(t.amount.to_string())),
        ("nonce".into(), json!(t.nonce)),
        ("ou".into(), json!(t.ou.to_string())),
        ("timestamp".into(), json!(t.timestamp)),
        ("op_type".into(), json!(t.op_type)),
        (
            "message".into(),
            match &t.message {
                Some(m) => json!(m),
                None => Value::Null,
            },
        ),
    ]
}

fn assemble(head: Vec<(String, Value)>, tail: Vec<(String, Value)>) -> Value {
    let mut o = serde_json::Map::new();
    for (k, v) in head.into_iter().chain(tail) {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// `octra_transaction` (`history_read_rpc.ml:131-175` ->
/// `tx_view.ml:93-136`).
///
/// TWO repairs. First, there is no `events` array — the chain's tx view
/// has never had one, and every consumer that read execution results
/// from here was reading a field the real node does not emit. Results
/// live in `contract_receipt`. Second, the four terminal statuses are
/// now distinct: `pending` (still in staging, `epoch: null`),
/// `confirmed`, `rejected` (with `error.type` / `error.reason` carrying
/// the `require()` text verbatim) and `dropped`. The old mock only ever
/// produced `confirmed`, so no Tier-1 test could see a revert.
fn octra_transaction(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let hash = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing hash"))?;
    let s = app.state.read();

    // Lookup order is the node's (`history_read_rpc.ml:134-161`):
    // staging first, then confirmed, then rejected, then dropped.
    if let Some(t) = s.staged.iter().find(|t| t.hash == hash) {
        coverage::record("octra_transaction", "pending");
        return Ok(assemble(
            vec![
                ("status".into(), json!("pending")),
                ("tx_hash".into(), json!(hash)),
                ("epoch".into(), Value::Null),
            ],
            staged_tx_fields(t),
        ));
    }
    if let Some(row) = s.txs.get(hash) {
        if row.status == "confirmed" {
            coverage::record("octra_transaction", "confirmed");
            return Ok(assemble(
                vec![
                    ("status".into(), json!("confirmed")),
                    ("tx_hash".into(), json!(hash)),
                    ("epoch".into(), json!(row.epoch)),
                ],
                tx_fields(row),
            ));
        }
    }
    if let Some(row) = s.rejected_txs.get(hash) {
        coverage::record("octra_transaction", "rejected");
        return Ok(row.clone());
    }
    if let Some(row) = s.dropped_txs.get(hash) {
        coverage::record("octra_transaction", "dropped");
        return Ok(row.clone());
    }
    coverage::record("octra_transaction", "not_found");
    Err(RpcError::not_found("transaction not found"))
}

/// `contract_receipt` (`contract_rpc.ml:765-780`). The chain stores a
/// receipt blob per contract-call tx and answers 112 "receipt not
/// found" otherwise — confirmed live against the node.
///
/// Key set: `{contract, effort, epoch, error, events, method, program,
/// success, ts}` (`receipt_view.ml:177-196`, `direct_receipt_json`).
fn contract_receipt(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let hash = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing hash"))?;
    let s = app.state.read();
    s.receipts.get(hash).cloned().map_or_else(
        || {
            coverage::record("contract_receipt", "not_found");
            Err(RpcError::not_found("receipt not found"))
        },
        |r| {
            coverage::record("contract_receipt", "found");
            Ok(r)
        },
    )
}

/// The node's display slice for a storage value inside the
/// `contract_call` envelope (`node_rpc_server.ml:299` pins
/// `Rpc_view.storage_assoc ~limit:4096`).
pub const STORAGE_DISPLAY_LIMIT: usize = 4096;

/// `Contract_vm.max_storage_value_len` (`contract_vm.ml:265`) — the cap
/// `octra_contractStorage`'s `"full"` mode raises the slice to.
pub const STORAGE_MAX_VALUE_LEN: usize = 4_194_304;

/// `octra_contractStorage` (`contract_rpc.ml:444-508`).
///
/// Present key: `{key, value, size, truncated, limit}`. MISSING key:
/// `{key, value: null, size: 0, truncated: false}` — note the absent
/// `limit`, which the node really does omit (`contract_rpc.ml:472-478`,
/// confirmed live). Third param picks the slice: `"full"` raises it to
/// 4 194 304, an integer sets it (clamped to that same cap), anything
/// else falls back to 4096.
fn octra_contract_storage(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let addr = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let key = arr
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing key"))?;
    let limit = storage_read_limit(arr.get(2));
    let s = app.state.read();
    let Some(value) = s.contract_storage.get(&(addr.to_string(), key.to_string())) else {
        coverage::record("octra_contractStorage", "missing");
        return Ok(json!({
            "key": key, "value": Value::Null, "size": 0, "truncated": false,
        }));
    };
    coverage::record("octra_contractStorage", "hit");
    Ok(storage_value_json(key, value, limit))
}

/// `storage_read_limit` (`contract_rpc.ml:446-458`).
fn storage_read_limit(arg: Option<&Value>) -> usize {
    match arg {
        Some(Value::String(v)) if v == "full" => STORAGE_MAX_VALUE_LEN,
        Some(Value::String(v)) => v
            .parse::<usize>()
            .map_or(STORAGE_DISPLAY_LIMIT, |n| n.min(STORAGE_MAX_VALUE_LEN)),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map_or(STORAGE_DISPLAY_LIMIT, |n| n.min(STORAGE_MAX_VALUE_LEN)),
        _ => STORAGE_DISPLAY_LIMIT,
    }
}

/// `storage_value` (`contract_rpc.ml:464-472`). The slice is by BYTES —
/// `String.length` upstream is a byte count.
fn storage_value_json(key: &str, value: &str, limit: usize) -> Value {
    let size = value.len();
    let visible = if size > limit {
        // Cut on a char boundary at or below `limit` so the result is
        // still valid UTF-8; the node is byte-oriented, but a JSON
        // string has to be well-formed either way.
        let mut end = limit;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    } else {
        value
    };
    json!({
        "key": key,
        "value": visible,
        "size": size,
        "truncated": size > limit,
        "limit": limit,
    })
}

/// The mock's hand-written stand-in for a view call's RETURN VALUE.
///
/// This is the part of `contract_call` that no amount of shape repair
/// can make true: the node runs the program
/// (`contract_rpc.ml:882-903`, `Contract.execute_view_call`), and this
/// mock runs a `match` on method names. What the repair below CAN fix
/// is everything around it — the response envelope, the contract
/// address, the storage slice — so a client written against the mock
/// still parses a real node's answer.
fn contract_view_value(app: &AppState, method: &str, pp: &[Value]) -> Result<Value, String> {
    match method {
        "list_active_endpoints" => {
            let offset = pp.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
            let limit = pp.get(1).and_then(serde_json::Value::as_u64).unwrap_or(50);
            let s = app.state.read();
            let mut active: Vec<String> = s
                .endpoints
                .values()
                .filter(|e| {
                    e.active
                        && !s.endpoint_slashed.contains(&e.addr)
                        && s.endpoint_stake.get(&e.addr).copied().unwrap_or(0) >= MIN_ENDPOINT_STAKE
                })
                .map(|e| e.addr.clone())
                .collect();
            active.sort();
            let end = (offset + limit).min(active.len() as u64) as usize;
            let start = (offset as usize).min(end);
            Ok(json!(&active[start..end]))
        }
        "list_tailnets" => {
            let offset = pp.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
            let limit = pp.get(1).and_then(serde_json::Value::as_u64).unwrap_or(50);
            let s = app.state.read();
            let mut ids: Vec<u64> = s.tailnets.keys().copied().collect();
            ids.sort_unstable();
            let end = (offset + limit).min(ids.len() as u64) as usize;
            let start = (offset as usize).min(end);
            Ok(json!(&ids[start..end]))
        }
        "get_endpoint" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            match s.endpoints.get(addr) {
                Some(e) => Ok(json!({
                    "active": i32::from(e.active),
                    "endpoint": e.endpoint,
                    "wg_pubkey": e.wg_pubkey,
                    "hfhe_pubkey": e.hfhe_pubkey,
                    "region": e.region,
                    "price_per_mb": e.price_per_mb,
                    "registered_at": e.registered_at,
                    "reputation": e.reputation,
                })),
                None => Ok(json!({"active": 0})),
            }
        }
        "get_endpoint_stake" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s.endpoint_stake.get(addr).copied().unwrap_or(0)))
        }
        "get_endpoint_unbonding" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            match s.endpoint_unbonding.get(addr) {
                Some((stake, unlock)) => Ok(json!({
                    "stake": stake,
                    "unlock_epoch": unlock,
                })),
                None => Ok(json!({"stake": 0, "unlock_epoch": 0})),
            }
        }
        "is_endpoint_slashed" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s.endpoint_slashed.contains(addr)))
        }
        "get_tailnet" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let s = app.state.read();
            match s.tailnets.get(&tid) {
                Some(t) => Ok(json!({
                    "owner": t.owner,
                    "treasury": t.treasury,
                    "member_count": t.members.len(),
                    "acl_policy": t.acl_policy,
                    "created_at": t.created_at,
                    "exit_count": t.exits.len(),
                    "charge_internal_traffic": s
                        .charge_internal_traffic_v2
                        .get(&tid)
                        .copied()
                        .unwrap_or(0),
                })),
                None => Ok(json!(null)),
            }
        }
        "is_tailnet_member" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let addr = pp.get(1).and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s
                .tailnets
                .get(&tid)
                .is_some_and(|t| t.members.contains(addr))))
        }
        "get_device_owner" => {
            let device = pp.first().and_then(|x| x.as_str()).ok_or("device")?;
            let s = app.state.read();
            Ok(json!(s
                .device_owner
                .get(device)
                .cloned()
                .unwrap_or_default()))
        }
        "is_device_of" => {
            let device = pp.first().and_then(|x| x.as_str()).ok_or("device")?;
            let wallet = pp.get(1).and_then(|x| x.as_str()).ok_or("wallet")?;
            let s = app.state.read();
            Ok(json!(
                s.device_owner.get(device).map(String::as_str) == Some(wallet)
            ))
        }
        "is_tailnet_exit" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let addr = pp.get(1).and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s
                .tailnets
                .get(&tid)
                .is_some_and(|t| t.exits.contains(addr))))
        }
        "get_session" => {
            let sid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("sid u64")?;
            let s = app.state.read();
            match s.sessions.get(&sid) {
                Some(sess) => Ok(json!({
                    "tailnet_id": sess.tailnet_id,
                    "exit": sess.exit,
                    "opener": sess.opener,
                    "deposit": sess.deposit,
                    "opened_at": sess.opened_at,
                    "status": sess.status,
                    "operator_claim": sess.operator_claim.map(|(b, t)| json!({"bytes_used": b, "claimed_at": t})),
                    "client_confirm": sess.client_confirm.map(|(b, t)| json!({"bytes_used": b, "confirmed_at": t})),
                })),
                None => Ok(json!(null)),
            }
        }
        "get_encrypted_earnings" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            let amount = s.earnings.get(addr).copied().unwrap_or(0);
            // Mock representation: prefix + zero-padded hex of u64.
            // Production AML returns the actual HFHE ciphertext bytes.
            Ok(json!(format!("hfhe_v1|mock|{amount:016x}")))
        }
        "get_program_treasury" => {
            let s = app.state.read();
            Ok(json!(s.program_treasury))
        }
        // ----- v2 views -----
        "get_session_v2" => {
            let sid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("sid u64")?;
            let s = app.state.read();
            match s.sessions_v2.get(&sid) {
                Some(sess) => Ok(json!({
                    "tailnet_id": sess.tailnet_id,
                    "proxy": sess.proxy,
                    "opener": sess.opener,
                    "deposit": sess.deposit,
                    "opened_at": sess.opened_at,
                    "class": sess.class,
                    "price_per_mb": sess.price_per_mb,
                    "status": sess.status,
                    "proxy_claim": sess.proxy_claim.map(|(b, t)| json!({"bytes_used": b, "claimed_at": t})),
                    "client_confirm": sess.client_confirm.map(|(b, t)| json!({"bytes_used": b, "confirmed_at": t})),
                })),
                None => Ok(json!(null)),
            }
        }
        "is_proxy_authorized" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let proxy = pp.get(1).and_then(|x| x.as_str()).ok_or("proxy")?;
            let s = app.state.read();
            let authorized = s
                .authorized_proxies_v2
                .get(&tid)
                .is_some_and(|set| set.contains(proxy));
            Ok(json!(i32::from(authorized)))
        }
        "get_authorized_proxies" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let s = app.state.read();
            let mut list: Vec<String> = s
                .authorized_proxies_v2
                .get(&tid)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            list.sort();
            Ok(json!(list))
        }
        "get_charge_internal_traffic" => {
            let tid = pp
                .first()
                .and_then(serde_json::Value::as_u64)
                .ok_or("tailnet_id u64")?;
            let s = app.state.read();
            Ok(json!(s
                .charge_internal_traffic_v2
                .get(&tid)
                .copied()
                .unwrap_or(0)))
        }
        "get_encrypted_earnings_v2" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            let amount = s.enc_earnings_v2.get(addr).copied().unwrap_or(0);
            Ok(json!(format!("hfhe_v2|mock|{amount:016x}")))
        }
        "get_params" => Ok(json!({
            "min_session_deposit": 10,
            "min_tailnet_deposit": 100,
            "session_grace_epochs": 100,
            "sweep_grace_multiplier": 10,
            "sweep_bounty_bps": 100,
            "min_endpoint_stake": MIN_ENDPOINT_STAKE,
            "unbond_grace_epochs": UNBOND_GRACE_EPOCHS,
            "slash_burn_bps": SLASH_BURN_BPS,
            "slash_bounty_bps": SLASH_BOUNTY_BPS,
            "protocol_fee_bps": PROTOCOL_FEE_BPS,
        })),
        other => Err(format!("unknown read method {other}")),
    }
}

/// `contract_call` (`contract_rpc.ml:852-935` -> `call_result`,
/// `:852-861`).
///
/// Three repairs, all confirmed against the running node:
///
///   1. The result is WRAPPED: `{"result": …}`, plus `"storage"` when
///      storage is included. The mock used to return the bare value, so
///      every client written against it read `result` one level too
///      high and would have crashed on the real chain. Live:
///      `contract_call(get_pokes)` answers
///      `{"result":"0","storage":{"blob":"0","pokes":"0"}}`.
///   2. The contract ADDRESS is honoured. The mock ignored `params[0]`
///      entirely and answered for the one program it knows, so a test
///      could call a typo'd or nonexistent address and still pass. The
///      node answers `{"code":-32000,"message":"bytecode not found"}`
///      — verified live against a plain wallet address.
///   3. Storage rides in the same `4096`-byte slice the node applies
///      (`node_rpc_server.ml:299`).
///
/// `include_storage` defaults to true for every method except
/// `balance_of` (`call_plan.ml:241-242`), and `params[4]` overrides it.
fn contract_call(app: &AppState, params: &Value) -> Result<Value, RpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("params not array"))?;
    let addr = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let method = arr
        .get(1)
        .and_then(|x| x.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing method"))?;
    let pp = arr
        .get(2)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    // (2) The mock knows exactly one deployed program. Any other
    //     address has no bytecode, which is what the node says.
    if addr != app.program_addr {
        coverage::record("contract_call", "bytecode_not_found");
        return Err(RpcError::execution("bytecode not found"));
    }

    let value = contract_view_value(app, method, &pp).map_err(RpcError::execution)?;

    let include_storage = arr
        .get(4)
        .and_then(Value::as_bool)
        .unwrap_or(method != "balance_of");
    if !include_storage {
        coverage::record("contract_call", "no_storage");
        return Ok(json!({ "result": value }));
    }
    coverage::record("contract_call", "with_storage");
    let s = app.state.read();
    let mut storage = serde_json::Map::new();
    for ((contract, key), val) in &s.contract_storage {
        if contract == addr {
            let visible = if val.len() > STORAGE_DISPLAY_LIMIT {
                let mut end = STORAGE_DISPLAY_LIMIT;
                while end > 0 && !val.is_char_boundary(end) {
                    end -= 1;
                }
                &val[..end]
            } else {
                val.as_str()
            };
            storage.insert(key.clone(), json!(visible));
        }
    }
    Ok(json!({ "result": value, "storage": Value::Object(storage) }))
}

/// Fake AML compile: hashes the source and synthesizes a deterministic
/// bytecode/ABI shape. Real Octra returns real compiler output via
/// `octra_compileAml`; this stub keeps local tests + the offline mode
/// of `forge build` exercising the same code path without a live node.
fn octra_compile_aml(params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let source = arr.first().and_then(|x| x.as_str()).ok_or("source")?;
    let name = arr
        .get(1)
        .and_then(|x| x.as_str())
        .unwrap_or("Program")
        .to_string();
    Ok(compile_one(&name, source))
}

fn octra_compile_aml_multi(params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let files = arr.first().and_then(|x| x.as_object()).ok_or("files")?;
    let mut out = serde_json::Map::new();
    for (path, val) in files {
        let source = val.as_str().unwrap_or_default();
        let name = infer_program_name_from(path, source);
        out.insert(path.clone(), compile_one(&name, source));
    }
    Ok(Value::Object(out))
}

fn infer_program_name_from(path: &str, source: &str) -> String {
    let stripped = strip_aml_comments(source);
    let bytes = stripped.as_bytes();
    let keywords: &[&[u8]] = &[b"contract ", b"program "];
    let mut i = 0;
    while i < bytes.len() {
        for kw in keywords {
            if i + kw.len() > bytes.len() {
                continue;
            }
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if before_ok && &bytes[i..i + kw.len()] == *kw {
                let mut j = i + kw.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                let name_start = j;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > name_start {
                    return stripped[name_start..j].to_string();
                }
            }
        }
        i += 1;
    }
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Program")
        .to_string()
}

fn strip_aml_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"//" {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && &bytes[i..i + 2] == b"/*" {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = i.saturating_add(2);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn compile_one(name: &str, source: &str) -> Value {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"::");
    h.update(source.as_bytes());
    let digest = hex::encode(h.finalize());
    let methods = extract_methods(source);
    let events = extract_events(source);
    let abi: Vec<Value> = methods
        .into_iter()
        .map(|m| json!({
            "name": m.name,
            "kind": if m.is_view { "view" } else { "call" },
            "inputs": m.inputs.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>(),
        }))
        .chain(events.into_iter().map(|e| json!({"name": e, "kind": "event"})))
        .collect();
    json!({
        "name": name,
        "abi": abi,
        "bytecode": format!("0x{digest}"),
        "assembly": format!("; mock AML bytecode for {name}\n; sha256(source) = {digest}\n"),
        "source_hash": digest,
        "compiler": "mock-aml-0.1",
    })
}

struct MethodSig {
    name: String,
    is_view: bool,
    inputs: Vec<(String, String)>,
}

fn extract_methods(source: &str) -> Vec<MethodSig> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"fn ") && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let prefix_end = i;
            let is_view = back_word_is(source, prefix_end, "view");
            let mut j = i + 3;
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = source[name_start..j].to_string();
            while j < bytes.len() && bytes[j] != b'(' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let params_start = j + 1;
            let mut depth = 1;
            j += 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let params_str = &source[params_start..j - 1];
            let inputs = parse_params(params_str);
            if !name.is_empty() && !is_private(source, prefix_end) {
                out.push(MethodSig {
                    name,
                    is_view,
                    inputs,
                });
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn back_word_is(source: &str, end: usize, word: &str) -> bool {
    let s = source[..end].trim_end();
    s.ends_with(word) && {
        let before = s.len() - word.len();
        before == 0 || !source.as_bytes()[before - 1].is_ascii_alphanumeric()
    }
}

fn is_private(source: &str, end: usize) -> bool {
    back_word_is(source, end, "private") || back_word_is(source, end, "view private")
}

fn parse_params(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            let (n, t) = chunk.split_once(':')?;
            Some((n.trim().to_string(), t.trim().to_string()))
        })
        .collect()
}

fn extract_events(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("event ") {
            if let Some((name, _)) = rest.split_once('(') {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

/// `epoch_get`. The node's row (confirmed live) carries the commit
/// chain, not a bare `timestamp`: `{epoch_id, tx_count, finalized_by,
/// finalized_at, parent_commit, state_root, tree_hash, fees_total, …}`.
fn epoch_get(app: &AppState, params: &Value) -> Value {
    let id = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_u64);
    let s = app.state.read();
    let epoch = id.unwrap_or(s.epoch);
    let root = hex::encode(Sha256::digest(epoch.to_le_bytes()));
    json!({
        "epoch_id": epoch,
        "tx_count": s.txs.values().filter(|r| r.epoch == epoch).count(),
        "finalized_by": Value::Null,
        "finalized_at": 0.0,
        "parent_commit": hex::encode(Sha256::digest(epoch.saturating_sub(1).to_le_bytes())),
        "state_root": root,
        "tree_hash": root,
        "fees_total": "0",
        "fees_burned": "0",
    })
}

/// Stage a transaction in-process — the exact `octra_submit` path,
/// returning the node's accepted envelope. Nothing is applied and no
/// state moves until [`advance_epoch`] runs.
///
/// This is the honest two-step. Reach for it whenever the test is about
/// the money path, so the read-after-submit gap is visible.
pub fn stage_tx(app: &AppState, tx: &Value) -> Result<Value, RpcError> {
    octra_submit(app, &json!([tx]))
}

/// Stage a transaction and immediately close an epoch, returning
/// `(tx_hash, events)`.
///
/// This is a COMPOSITION of two real chain steps — `octra_submit` then
/// an epoch — not a single one, and it exists because most in-process
/// callers are exercising program semantics rather than the submission
/// lifecycle. If your test is about funds, nonces, or what a client
/// observes between submit and inclusion, use [`stage_tx`] and
/// [`advance_epoch`] separately; collapsing them is exactly the
/// conflation that let four money-path bugs through.
///
/// The `events` returned are the mock's internal records. The chain
/// does not put events on the tx view at all; their wire form is the
/// `contract_receipt` for the same hash.
///
/// A tx that reverts during apply returns `Err` with the `require()`
/// reason, mirroring the old behaviour so existing callers still see
/// the failure — the chain would show it as a `rejected` tx row plus a
/// receipt with `success:false`, both of which are also recorded.
pub fn submit_tx(app: &AppState, tx: &Value) -> Result<(String, Vec<Value>), String> {
    let accepted = stage_tx(app, tx).map_err(|e| e.to_string())?;
    let hash = accepted
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .ok_or("missing tx_hash")?
        .to_string();
    advance_epoch(app);
    let s = app.state.read();
    let row = s.txs.get(&hash).ok_or("tx vanished during apply")?;
    if row.status == "rejected" {
        let reason = s
            .rejected_txs
            .get(&hash)
            .and_then(|r| r.pointer("/error/reason"))
            .and_then(Value::as_str)
            .unwrap_or("execution reverted")
            .to_string();
        return Err(reason);
    }
    Ok((hash, row.events.clone()))
}

/// In-process equivalent of a `contract_call` view.
///
/// Returns the BARE return value, i.e. what the node puts under
/// `result`. The wire shape is the `{"result": …}` envelope that
/// [`contract_call`] builds; this helper unwraps it so in-process
/// callers keep reading a plain value.
pub fn read_call(app: &AppState, method: &str, params: &[Value]) -> Result<Value, String> {
    let p = json!([app.program_addr.clone(), method, params, Value::Null, false]);
    contract_call(app, &p)
        .map(|v| v.get("result").cloned().unwrap_or(Value::Null))
        .map_err(|e| e.to_string())
}

pub async fn serve(addr: SocketAddr, program_addr: String) -> anyhow::Result<()> {
    serve_with_chain_id(addr, program_addr, None).await
}

/// Variant of [`serve`] that pins a v2 chain-id binding (P1-5b). Every
/// incoming `octra_submit` whose `chain_id` doesn't match `chain_id`
/// is rejected. Used by adversarial harnesses for the
/// `chain_id_binding_rejects_replay` Lean theorem.
pub async fn serve_with_chain_id(
    addr: SocketAddr,
    program_addr: String,
    chain_id: Option<String>,
) -> anyhow::Result<()> {
    let app = AppState {
        state: Arc::new(RwLock::new(ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr,
        expected_chain_id: chain_id,
    };
    // Epochs advance on a timer, because that is the only way they
    // advance on the chain: Single mode applies staged txs from a
    // hardcoded 10-second tick (`epoch_time.ml:10-11`,
    // `consensus_tick_plan.ml:115-123`), and there is no RPC anywhere
    // in `rpc_dispatch.ml` to force one. A served mock therefore has
    // the node's cadence by default; `OCTRA_MOCK_EPOCH_MS` shortens it
    // for tests that cannot wait, which is a knob on SPEED only — the
    // staging gap itself is never skippable over the wire.
    let ticker = app.clone();
    let interval_ms: u64 = std::env::var("OCTRA_MOCK_EPOCH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
        loop {
            tick.tick().await;
            advance_epoch(&ticker);
        }
    });
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{circle_asset, AppState, ChainState};
    use parking_lot::RwLock;
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn make_app() -> AppState {
        AppState {
            state: Arc::new(RwLock::new(ChainState {
                epoch: 1,
                ..Default::default()
            })),
            program_addr: "octPROGRAM".to_string(),
            expected_chain_id: None,
        }
    }

    #[test]
    fn circle_asset_returns_plaintext_when_seeded() {
        let app = make_app();
        app.insert_circle_asset("octCIRCLE", "/policy.json", br#"{"v":1}"#.to_vec());

        let v = circle_asset(&app, &json!(["octCIRCLE", "/policy.json"]))
            .expect("circle_asset succeeds");
        assert_eq!(v, json!({ "plaintext": r#"{"v":1}"# }));
    }

    #[test]
    fn circle_asset_returns_null_when_unseeded() {
        let app = make_app();
        // Nothing seeded — miss must be `null`, matching the in-test
        // v3 mock the canonical implementation is replacing.
        let v = circle_asset(&app, &json!(["octCIRCLE", "/policy.json"]))
            .expect("circle_asset succeeds");
        assert_eq!(v, Value::Null);

        // Wrong path on a seeded circle is still a miss.
        app.insert_circle_asset("octCIRCLE", "/policy.json", b"x".to_vec());
        let v = circle_asset(&app, &json!(["octCIRCLE", "/state-root.json"]))
            .expect("circle_asset succeeds");
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn circle_asset_isolates_circles() {
        let app = make_app();
        app.insert_circle_asset("octA", "/policy.json", b"alpha".to_vec());
        app.insert_circle_asset("octB", "/policy.json", b"bravo".to_vec());

        let a =
            circle_asset(&app, &json!(["octA", "/policy.json"])).expect("circle_asset(A) succeeds");
        let b =
            circle_asset(&app, &json!(["octB", "/policy.json"])).expect("circle_asset(B) succeeds");

        assert_eq!(a, json!({ "plaintext": "alpha" }));
        assert_eq!(b, json!({ "plaintext": "bravo" }));
        assert_ne!(a, b);
    }

    #[test]
    fn circle_asset_isolates_paths() {
        let app = make_app();
        app.insert_circle_asset("octCIRCLE", "/policy.json", b"P".to_vec());
        app.insert_circle_asset("octCIRCLE", "/state-root.json", b"S".to_vec());

        let p = circle_asset(&app, &json!(["octCIRCLE", "/policy.json"]))
            .expect("circle_asset(policy) succeeds");
        let s = circle_asset(&app, &json!(["octCIRCLE", "/state-root.json"]))
            .expect("circle_asset(state-root) succeeds");

        assert_eq!(p, json!({ "plaintext": "P" }));
        assert_eq!(s, json!({ "plaintext": "S" }));
        assert_ne!(p, s);
    }

    #[test]
    fn circle_asset_rejects_malformed_params() {
        let app = make_app();
        // Non-array params → error string.
        let err = circle_asset(&app, &json!({"circle_id": "x"})).unwrap_err();
        assert!(err.contains("not array"), "{err}");

        // Missing path.
        let err = circle_asset(&app, &json!(["octCIRCLE"])).unwrap_err();
        assert!(err.contains("path missing"), "{err}");

        // Missing circle_id.
        let err = circle_asset(&app, &json!([])).unwrap_err();
        assert!(err.contains("circle_id missing"), "{err}");
    }
}

/// Shape tests for the three structural repairs. Every expected value
/// in here was read off the node — either its source (file:line cited
/// on the assertion) or a live probe against the containerised node.
#[cfg(test)]
mod chain_shape_tests {
    use super::{
        advance_epoch, canonical, contract_call, contract_receipt, octra_balance,
        octra_contract_storage, octra_transaction, stage_tx, AppState, ChainState,
        STORAGE_DISPLAY_LIMIT, STORAGE_MAX_VALUE_LEN,
    };
    use parking_lot::RwLock;
    use serde_json::{json, Value};
    use std::sync::Arc;

    const PROGRAM: &str = "octPROGRAM";
    const ALICE: &str = "octALICE";

    fn app() -> AppState {
        AppState {
            state: Arc::new(RwLock::new(ChainState {
                epoch: 1,
                ..Default::default()
            })),
            program_addr: PROGRAM.to_string(),
            expected_chain_id: None,
        }
    }

    fn legacy_tx(from: &str, method: &str, params: &Value) -> Value {
        json!({ "method": method, "from": from, "params": params, "value": 0 })
    }

    /// A deterministic ed25519 keypair for the wire-envelope tests.
    fn keypair() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn pubkey_b64() -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.encode(keypair().verifying_key().to_bytes())
    }

    /// Build a wire envelope and sign it over the node's real preimage.
    /// Signing for real is the point: an unsigned envelope is 101 on
    /// the chain, so a test that wants to reach the nonce or balance
    /// rules has to get past the signature first — exactly as a client
    /// does.
    fn signed_wire(from: &str, nonce: u64, amount: u64, ou: u64) -> Value {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use ed25519_dalek::Signer as _;
        let w = canonical::WireTx {
            from: from.into(),
            to: PROGRAM.into(),
            amount,
            nonce,
            ou,
            timestamp: super::unix_now(),
            op_type: "standard".into(),
            ..canonical::WireTx::default()
        };
        let sig = B64.encode(keypair().sign(w.signing_preimage().as_bytes()).to_bytes());
        json!({
            "from": w.from, "to_": w.to,
            "amount": w.amount.to_string(), "ou": w.ou.to_string(),
            "nonce": w.nonce, "timestamp": w.timestamp, "op_type": w.op_type,
            "signature": sig, "public_key": pubkey_b64(),
        })
    }

    // ---- 1. staging lifecycle --------------------------------------

    /// `rpc_view.ml:706-712`: `{tx_hash, status:"accepted", nonce,
    /// ou_cost}`. The word "confirmed" must not appear.
    #[test]
    fn submit_returns_accepted_not_confirmed() {
        let app = app();
        let r = stage_tx(
            &app,
            &legacy_tx(ALICE, "register_device", &json!(["octDEV"])),
        )
        .expect("staged");
        assert_eq!(r["status"], json!("accepted"));
        assert!(r["tx_hash"].as_str().is_some_and(|h| h.len() == 64));
        assert!(r.get("nonce").is_some(), "accepted carries nonce: {r}");
        assert!(r["ou_cost"].is_string(), "ou_cost is a decimal string: {r}");
        assert!(r.get("hash").is_none(), "the key is tx_hash, not hash");
    }

    /// The premature read. A staged tx is `pending` with `epoch: null`
    /// and has NOT touched program state; only an epoch applies it.
    /// This is the failure mode the old mock could not express.
    #[test]
    fn staged_tx_is_pending_until_an_epoch_applies_it() {
        let app = app();
        let staged = stage_tx(
            &app,
            &legacy_tx(ALICE, "register_device", &json!(["octDEV"])),
        )
        .expect("staged");
        let hash = staged["tx_hash"].as_str().expect("hash").to_string();

        let pending = octra_transaction(&app, &json!([hash])).expect("pending lookup");
        assert_eq!(pending["status"], json!("pending"));
        assert_eq!(pending["epoch"], Value::Null);
        assert!(
            app.state.read().device_owner.is_empty(),
            "staging must not mutate program state"
        );

        advance_epoch(&app);
        let confirmed = octra_transaction(&app, &json!([hash])).expect("confirmed lookup");
        assert_eq!(confirmed["status"], json!("confirmed"));
        assert!(confirmed["epoch"].as_u64().is_some());
        assert_eq!(
            app.state
                .read()
                .device_owner
                .get("octDEV")
                .map(String::as_str),
            Some(ALICE)
        );
    }

    /// `tx_staging.ml:188-191`: next acceptable nonce is
    /// `confirmed + 1`; at-or-below is 102, beyond the 1000 lookahead
    /// is 103. Codes from `rpc.ml:30-31`.
    #[test]
    fn nonce_window_uses_the_node_codes() {
        let app = app();
        app.fund(ALICE, 1_000_000_000, Some(pubkey_b64()));
        // Confirmed nonce is 0, so nonce 0 is already spent.
        assert_eq!(
            stage_tx(&app, &signed_wire(ALICE, 0, 0, 1_000))
                .unwrap_err()
                .code,
            102
        );
        assert_eq!(
            stage_tx(&app, &signed_wire(ALICE, 5_000, 0, 1_000))
                .unwrap_err()
                .code,
            103
        );
        assert!(stage_tx(&app, &signed_wire(ALICE, 1, 0, 1_000)).is_ok());
        // Same nonce twice is a duplicate (`tx_staging.ml:194-198`).
        assert_eq!(
            stage_tx(&app, &signed_wire(ALICE, 1, 0, 1_000))
                .unwrap_err()
                .code,
            106
        );
    }

    /// `tx_view.ml:1139-1148` verifies ed25519 over the node's own
    /// preimage. A junk signature is 101 — confirmed live.
    #[test]
    fn bad_signature_is_101() {
        let app = app();
        app.fund(ALICE, 1_000_000_000, Some(pubkey_b64()));
        // A well-formed envelope whose signature is junk.
        let mut tx = signed_wire(ALICE, 1, 0, 1_000);
        tx["signature"] = json!("AAAA");
        assert_eq!(stage_tx(&app, &tx).unwrap_err().code, 101);

        // And the sharper case: a VALID signature over the WRONG
        // bytes. Tampering with `amount` after signing is what a
        // preimage bug looks like from the node's side, and it is
        // still 101 — the whole reason the preimage is ported byte for
        // byte rather than approximated.
        let mut tampered = signed_wire(ALICE, 1, 0, 1_000);
        tampered["amount"] = json!("999");
        assert_eq!(stage_tx(&app, &tampered).unwrap_err().code, 101);
    }

    /// `tx_staging.ml:216-218` — amount + fee against the balance.
    /// Code 104 (`rpc.ml:32`).
    #[test]
    fn overspend_is_104() {
        let app = app();
        app.fund(ALICE, 500, Some(pubkey_b64()));
        assert_eq!(
            stage_tx(&app, &signed_wire(ALICE, 1, 1_000, 1_000))
                .unwrap_err()
                .code,
            104
        );
    }

    /// A sender with no ledger row is 100 (`account_rpc.ml:7-16`), and
    /// it lands BEFORE the signature check
    /// (`tx_view.ml:1150-1181` — `sender_admission` is pre-signature).
    #[test]
    fn unknown_sender_is_100_once_a_ledger_exists() {
        let app = app();
        app.fund("octSOMEONE", 1_000, None);
        assert_eq!(
            stage_tx(&app, &signed_wire(ALICE, 1, 0, 1_000))
                .unwrap_err()
                .code,
            100
        );
    }

    /// `tx_view.ml:1125-1129`: more than 300s of drift is 105.
    #[test]
    fn stale_timestamp_is_105() {
        let app = app();
        let tx = json!({
            "from": ALICE, "to_": PROGRAM, "amount": "0", "ou": "1000",
            "nonce": 1, "timestamp": 0.0, "op_type": "standard",
        });
        let e = stage_tx(&app, &tx).unwrap_err();
        assert_eq!(e.code, 105);
        assert_eq!(e.message, "malformed transaction");
    }

    /// The preimage is `transaction.ml:309-326`: compact yojson in
    /// field order `from,to_,amount,nonce,ou,timestamp,op_type` with
    /// the optional tail, and NO `chain_id`. This golden string is the
    /// same one `octra-chain-backend`'s port asserts.
    #[test]
    fn preimage_matches_node_layout() {
        let w = canonical::WireTx {
            from: "octA".into(),
            to: "octB".into(),
            amount: 1_500_000,
            nonce: 7,
            ou: 1_000,
            timestamp: 1_787_000_000.5,
            op_type: "call".into(),
            encrypted_data: Some("open_session".into()),
            message: Some("[1,2]".into()),
            ..canonical::WireTx::default()
        };
        assert_eq!(
            w.signing_preimage(),
            "{\"from\":\"octA\",\"to_\":\"octB\",\"amount\":\"1500000\",\"nonce\":7,\
             \"ou\":\"1000\",\"timestamp\":1787000000.5,\"op_type\":\"call\",\
             \"encrypted_data\":\"open_session\",\"message\":\"[1,2]\"}"
        );
        assert!(!w.signing_preimage().contains("chain_id"));
        assert_eq!(w.tx_hash().len(), 64);
        // The hash preimage is a DIFFERENT document (`:482-497`).
        assert_ne!(
            w.tx_hash(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(w.signing_preimage()))
        );
    }

    // ---- 2. no events, ever ----------------------------------------

    /// `tx_view.ml:93-136` — the confirmed tx view has no `events`
    /// field. Execution results live in `contract_receipt`.
    #[test]
    fn transaction_view_has_no_events_and_receipt_does() {
        let app = app();
        let staged = stage_tx(
            &app,
            &legacy_tx(ALICE, "register_device", &json!(["octDEV"])),
        )
        .expect("staged");
        let hash = staged["tx_hash"].as_str().expect("hash").to_string();
        advance_epoch(&app);

        let tx = octra_transaction(&app, &json!([hash])).expect("tx");
        assert!(
            tx.get("events").is_none(),
            "chain tx view carries no events: {tx}"
        );
        for k in [
            "status",
            "tx_hash",
            "epoch",
            "from",
            "to",
            "amount",
            "amount_raw",
            "nonce",
            "ou",
            "timestamp",
            "op_type",
            "message",
        ] {
            assert!(tx.get(k).is_some(), "missing {k} in {tx}");
        }

        // `receipt_view.ml:177-196` key set.
        let r = contract_receipt(&app, &json!([hash])).expect("receipt");
        let mut keys: Vec<&str> = r
            .as_object()
            .expect("obj")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "contract", "effort", "epoch", "error", "events", "method", "program", "success",
                "ts"
            ]
        );
        assert_eq!(r["success"], json!(true));
        assert_eq!(r["error"], Value::Null);
        // Events are in the chain's own shape (`receipt_view.ml:67-76`).
        let ev = &r["events"][0];
        for k in ["program", "contract", "depth", "event", "values"] {
            assert!(ev.get(k).is_some(), "missing {k} in event {ev}");
        }
    }

    /// A `require()` failure becomes a `rejected` row carrying the
    /// reason verbatim (`tx_view.ml:107-121`), plus a receipt with
    /// `success:false`. The old mock had no way to show either.
    #[test]
    fn revert_surfaces_as_rejected_with_the_reason() {
        let app = app();
        // `add_member` on a tailnet that does not exist reverts.
        let staged = stage_tx(
            &app,
            &legacy_tx(ALICE, "add_member", &json!([99, "octBOB"])),
        )
        .expect("staged");
        let hash = staged["tx_hash"].as_str().expect("hash").to_string();
        advance_epoch(&app);

        let tx = octra_transaction(&app, &json!([hash])).expect("tx");
        assert_eq!(tx["status"], json!("rejected"));
        assert_eq!(tx["error"]["type"], json!("execution_reverted"));
        let reason = tx["error"]["reason"].as_str().expect("reason");
        assert!(!reason.is_empty(), "reject reason is verbatim, not empty");
        assert_eq!(tx["source"], json!("rejected_txs"));

        let r = contract_receipt(&app, &json!([hash])).expect("receipt");
        assert_eq!(r["success"], json!(false));
        assert_eq!(r["error"], json!(reason));
    }

    /// `contract_rpc.ml:778-779` — 112 with `data:"receipt not found"`,
    /// confirmed live.
    #[test]
    fn missing_receipt_and_tx_are_112() {
        let app = app();
        let zero = "0".repeat(64);
        let e = contract_receipt(&app, &json!([zero.as_str()])).unwrap_err();
        assert_eq!(e.code, 112);
        assert_eq!(e.data, Some(json!("receipt not found")));
        let e = octra_transaction(&app, &json!([zero])).unwrap_err();
        assert_eq!(e.code, 112);
        assert_eq!(e.data, Some(json!("transaction not found")));
    }

    // ---- 3. contract_call / storage shapes -------------------------

    /// `call_result` (`contract_rpc.ml:852-861`). Live: `{"result":
    /// "0","storage":{...}}`.
    #[test]
    fn contract_call_wraps_result_and_honours_the_address() {
        let app = app();
        let r = contract_call(&app, &json!([PROGRAM, "list_tailnets", []])).expect("call");
        assert!(r.get("result").is_some(), "result is wrapped: {r}");
        assert!(r.get("storage").is_some(), "storage included by default");

        // A non-program address has no bytecode — verified live.
        let e = contract_call(&app, &json!(["octNOTACONTRACT", "list_tailnets", []])).unwrap_err();
        assert_eq!(e.code, -32000);
        assert_eq!(e.message, "bytecode not found");

        // include_storage=false drops the storage key
        // (`call_plan.ml:249-250`).
        let r = contract_call(
            &app,
            &json!([PROGRAM, "list_tailnets", [], Value::Null, false]),
        )
        .expect("call");
        assert!(r.get("storage").is_none());
    }

    /// `contract_rpc.ml:444-478` plus the live probe: a hit carries
    /// `limit`, a miss does not, and `"full"` raises the slice.
    #[test]
    fn contract_storage_slices_at_4096_and_full_at_4mib() {
        let app = app();
        let big = "x".repeat(STORAGE_DISPLAY_LIMIT + 100);
        app.insert_contract_storage(PROGRAM, "blob", big.clone());

        let r = octra_contract_storage(&app, &json!([PROGRAM, "blob"])).expect("storage");
        assert_eq!(r["limit"], json!(STORAGE_DISPLAY_LIMIT));
        assert_eq!(r["size"], json!(big.len()));
        assert_eq!(r["truncated"], json!(true));
        assert_eq!(
            r["value"].as_str().expect("value").len(),
            STORAGE_DISPLAY_LIMIT
        );

        let r = octra_contract_storage(&app, &json!([PROGRAM, "blob", "full"])).expect("storage");
        assert_eq!(r["limit"], json!(STORAGE_MAX_VALUE_LEN));
        assert_eq!(r["truncated"], json!(false));
        assert_eq!(r["value"], json!(big));

        // Miss: `value:null`, no `limit` key at all.
        let r = octra_contract_storage(&app, &json!([PROGRAM, "nope"])).expect("storage");
        assert_eq!(r["value"], Value::Null);
        assert_eq!(r["size"], json!(0));
        assert_eq!(r["truncated"], json!(false));
        assert!(r.get("limit").is_none(), "a miss omits limit: {r}");
    }

    // ---- 4. balance ------------------------------------------------

    /// `rpc_view.ml:322-330` key set; unknown address is 100, NOT a
    /// fabricated 1e9. Both confirmed live.
    #[test]
    fn balance_key_set_and_unknown_account() {
        let app = app();
        assert_eq!(octra_balance(&app, &json!([ALICE])).unwrap_err().code, 100);

        app.fund(ALICE, 10_000_036_500_000, Some("cGs=".into()));
        let b = octra_balance(&app, &json!([ALICE])).expect("balance");
        let mut keys: Vec<&str> = b
            .as_object()
            .expect("obj")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "address",
                "balance",
                "balance_raw",
                "has_public_key",
                "nonce",
                "pending_nonce"
            ]
        );
        // The live node rendered exactly this for this raw value.
        assert_eq!(b["balance"], json!("10000036.500000"));
        assert_eq!(b["balance_raw"], json!("10000036500000"));
        assert_eq!(b["has_public_key"], json!(true));
        assert!(b.get("formatted").is_none(), "no invented `formatted` key");
        assert!(b.get("raw").is_none(), "no invented `raw` key");
    }

    /// `pending_nonce` (`tx_staging.ml:172-174`) tracks staging while
    /// `nonce` stays at the confirmed value.
    #[test]
    fn pending_nonce_reflects_staging() {
        let app = app();
        app.fund(ALICE, 1_000_000_000, Some(pubkey_b64()));
        stage_tx(&app, &signed_wire(ALICE, 1, 0, 1_000)).expect("staged");
        let b = octra_balance(&app, &json!([ALICE])).expect("balance");
        assert_eq!(b["nonce"], json!(0), "confirmed nonce has not moved");
        assert_eq!(b["pending_nonce"], json!(1));

        advance_epoch(&app);
        let b = octra_balance(&app, &json!([ALICE])).expect("balance");
        assert_eq!(b["nonce"], json!(1));
        // The fee was charged on inclusion.
        assert_eq!(b["balance_raw"], json!("999999000"));
    }

    /// Fiction the mock used to serve: the node answers `-32601`.
    #[test]
    fn invented_methods_are_method_not_found() {
        let app = app();
        for fake in [
            "octra_isValidator",
            "octra_fheLoadPk",
            "octra_fheEncrypt",
            "octra_fheAdd",
        ] {
            let err = super::dispatch(&app, fake, &json!([])).unwrap_err();
            assert_eq!(err.code, -32601, "{fake}");
            assert_eq!(err.message, format!("method not found: {fake}"));
        }
    }
}

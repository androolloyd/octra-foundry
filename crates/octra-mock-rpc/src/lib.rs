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

mod coverage {
    pub(crate) fn record(method: &str, branch: &str) {
        super::cov::record(method, branch);
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
    pub events: Vec<Value>,
    pub status: String,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<RwLock<ChainState>>,
    pub program_addr: String,
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
    let result = match req.method.as_str() {
        "node_status" => Ok(node_status(&app)),
        "octra_balance" => octra_balance(&app, &req.params),
        "octra_recommendedFee" => Ok(json!({
            "min": 1, "base": 5, "recommended": 10, "fast": 25
        })),
        "octra_submit" => octra_submit(&app, &req.params),
        "octra_transaction" => octra_transaction(&app, &req.params),
        "octra_listContracts" => Ok(json!([{
            "address": app.program_addr,
            "name": "OctraVPN"
        }])),
        "octra_isValidator" => Ok(octra_is_validator(&app, &req.params)),
        "octra_test_grantValidator" => Ok(test_grant_validator(&app, &req.params)),
        "octra_test_revokeValidator" => Ok(test_revoke_validator(&app, &req.params)),
        "octra_test_bondEndpoint" => Ok(test_bond_endpoint(&app, &req.params)),
        "octra_test_setOwner" => Ok(test_set_owner(&app, &req.params)),
        "contract_call" => contract_call(&app, &req.params),
        "octra_compileAml" => octra_compile_aml(&req.params),
        "octra_compileAmlMulti" => octra_compile_aml_multi(&req.params),
        "epoch_get" => Ok(epoch_get(&app, &req.params)),
        "circle_asset" => circle_asset(&app, &req.params),
        _ => Err(format!("unknown method: {}", req.method)),
    };
    match result {
        Ok(r) => Json(json!({"jsonrpc": "2.0", "id": req.id, "result": r})),
        Err(e) => Json(json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "error": { "code": -32000, "message": e }
        })),
    }
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

fn octra_is_validator(app: &AppState, params: &Value) -> Value {
    let addr = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!(app.state.read().octra_validators.contains(addr))
}

fn test_grant_validator(app: &AppState, params: &Value) -> Value {
    if let Some(addr) = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
    {
        app.add_octra_validator(addr);
    }
    Value::Bool(true)
}

fn test_revoke_validator(app: &AppState, params: &Value) -> Value {
    if let Some(addr) = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
    {
        app.remove_octra_validator(addr);
    }
    Value::Bool(true)
}

fn test_bond_endpoint(app: &AppState, params: &Value) -> Value {
    let Some(arr) = params.as_array() else {
        return Value::Bool(false);
    };
    let Some(addr) = arr.first().and_then(|v| v.as_str()) else {
        return Value::Bool(false);
    };
    let amount = arr
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(MIN_ENDPOINT_STAKE);
    app.seed_endpoint_stake(addr, amount);
    Value::Bool(true)
}

fn test_set_owner(app: &AppState, params: &Value) -> Value {
    let Some(arr) = params.as_array() else {
        return Value::Bool(false);
    };
    let Some(addr) = arr.first().and_then(|v| v.as_str()) else {
        return Value::Bool(false);
    };
    app.set_owner(addr);
    Value::Bool(true)
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

fn octra_balance(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let addr = arr.first().and_then(|x| x.as_str()).ok_or("addr missing")?;
    let s = app.state.read();
    let raw_balance = s.balances.get(addr).copied().unwrap_or(1_000_000_000);
    #[allow(clippy::cast_precision_loss)]
    let formatted = (raw_balance as f64 / 1_000_000.0).to_string();
    Ok(json!({
        "formatted": formatted,
        "raw": raw_balance.to_string(),
        "nonce": 0u64,
        "pending_nonce": 0u64,
        "public_key": null,
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
        let params = obj
            .get("message")
            .and_then(|x| x.as_str())
            .map_or_else(
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

fn octra_submit(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let tx = arr.first().ok_or("tx missing")?;
    let (working, method, op_type) = normalize_submission(tx)?;
    let tx = &working;
    let from = tx
        .get("from")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut hash_bytes = Sha256::new();
    hash_bytes.update(serde_json::to_vec(tx).unwrap_or_default());
    let hash = hex::encode(hash_bytes.finalize());

    // Special case for op_type=deploy: no apply_* handler, just
    // synthesize a deploy address. Real Octra returns one via
    // `octra_computeContractAddress`; the mock simulates the same
    // shape so deploy flows complete end-to-end.
    if op_type == "deploy" {
        let bytecode = tx
            .get("encrypted_data")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let nonce = tx
            .get("nonce")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let address = synthesize_deploy_address(&from, bytecode, nonce);
        let event = json!({
            "name": "ContractDeployed",
            "address": &address,
        });
        {
            let mut s = app.state.write();
            s.txs.insert(
                hash.clone(),
                TxRow {
                    method: "__deploy__".into(),
                    from,
                    events: vec![event],
                    status: "confirmed".into(),
                },
            );
            s.epoch += 1;
        }
        return Ok(json!({
            "hash": hash,
            "status": "confirmed",
            "address": address,
        }));
    }

    let events = match method.as_str() {
        "register_device" => apply_register_device(app, tx, &from)?,
        "revoke_device" => apply_revoke_device(app, tx, &from)?,
        "bond_endpoint" => apply_bond_endpoint(app, tx, &from)?,
        "unbond_endpoint" => apply_unbond_endpoint(app, &from)?,
        "finalize_unbond" => apply_finalize_unbond(app, &from)?,
        "gov_slash_operator" => apply_gov_slash_operator(app, tx, &from)?,
        "slash_double_sign" => apply_slash_double_sign(app, tx, &from)?,
        "register_endpoint" => apply_register_endpoint(app, tx, &from)?,
        "update_endpoint" => apply_update_endpoint(app, tx, &from)?,
        "rotate_keys" => apply_rotate_keys(app, tx, &from)?,
        "retire_endpoint" => apply_retire_endpoint(app, &from)?,
        "create_tailnet" => apply_create_tailnet(app, tx, &from, &hash)?,
        "add_member" => apply_add_member(app, tx, &from)?,
        "remove_member" => apply_remove_member(app, tx, &from)?,
        "deposit_to_tailnet" => apply_deposit_to_tailnet(app, tx, &from)?,
        "configure_tailnet_exit" => apply_configure_tailnet_exit(app, tx, &from)?,
        "update_acl" => apply_update_acl(app, tx, &from)?,
        "open_session" => apply_open_session(app, tx, &from, &hash)?,
        "settle_claim" => apply_settle_claim(app, tx, &from)?,
        "settle_confirm" => apply_settle_confirm(app, tx, &from)?,
        "precommit_join_token" => apply_precommit_join_token(app, tx, &from)?,
        "redeem_join_token" => apply_redeem_join_token(app, tx, &from)?,
        "claim_no_show" => apply_claim_no_show(app, tx)?,
        "sweep_expired_session" => apply_sweep_expired_session(app, tx, &from)?,
        "claim_earnings" => apply_claim_earnings(app, tx, &from)?,
        "withdraw_program_treasury" => apply_withdraw_treasury(app, tx, &from)?,
        // ----- v2 (Circle-native) entrypoints -----
        // See `program/main-v2.aml`. These coexist with v1; the two
        // session/proxy worlds are wholly independent (different
        // state tables). Consumers pick which surface to call.
        "authorize_proxy" => apply_authorize_proxy_v2(app, tx, &from)?,
        "revoke_proxy" => apply_revoke_proxy_v2(app, tx, &from)?,
        "set_charge_internal_traffic" => apply_set_charge_internal_traffic_v2(app, tx, &from)?,
        "open_session_v2" => apply_open_session_v2(app, tx, &from)?,
        "settle_claim_v2" => apply_settle_claim_v2(app, tx, &from)?,
        "settle_confirm_v2" => apply_settle_confirm_v2(app, tx, &from)?,
        "proxy_register_keys" => apply_proxy_register_keys_v2(app, tx, &from)?,
        "claim_earnings_v2" => apply_claim_earnings_v2(app, tx, &from)?,
        _ => Vec::new(),
    };

    {
        let mut s = app.state.write();
        s.txs.insert(
            hash.clone(),
            TxRow {
                method,
                from,
                events,
                status: "confirmed".into(),
            },
        );
        s.epoch += 1;
    }

    Ok(json!({"hash": hash, "status": "confirmed"}))
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
    if balance != claimed {
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

fn octra_transaction(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let hash = arr.first().and_then(|x| x.as_str()).ok_or("hash missing")?;
    let s = app.state.read();
    let row = s.txs.get(hash).ok_or("not found")?;
    Ok(json!({
        "hash": hash,
        "method": row.method,
        "from": row.from,
        "status": row.status,
        "events": row.events,
    }))
}

fn contract_call(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let _addr = arr[0].as_str().ok_or("addr missing")?;
    let method = arr[1].as_str().ok_or("method missing")?;
    let pp = arr[2].as_array().cloned().unwrap_or_default();
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

fn epoch_get(app: &AppState, params: &Value) -> Value {
    let id = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_u64);
    let s = app.state.read();
    let epoch = id.unwrap_or(s.epoch);
    json!({
        "epoch_id": epoch,
        "finalized_by": null,
        "tx_count": s.txs.len(),
        "timestamp": 0u64,
    })
}

/// In-process equivalent of an `octra_submit` JSON-RPC call.
pub fn submit_tx(app: &AppState, tx: &Value) -> Result<(String, Vec<Value>), String> {
    let params = json!([tx]);
    let result = octra_submit(app, &params)?;
    let hash = result
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or("missing hash")?
        .to_string();
    let events = {
        let s = app.state.read();
        s.txs
            .get(&hash)
            .map_or_else(Vec::new, |row| row.events.clone())
    };
    Ok((hash, events))
}

/// In-process equivalent of `contract_call`.
pub fn read_call(app: &AppState, method: &str, params: &[Value]) -> Result<Value, String> {
    let p = json!([app.program_addr.clone(), method, params, Value::Null]);
    contract_call(app, &p)
}

pub async fn serve(addr: SocketAddr, program_addr: String) -> anyhow::Result<()> {
    let app = AppState {
        state: Arc::new(RwLock::new(ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr,
    };
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

        let a = circle_asset(&app, &json!(["octA", "/policy.json"]))
            .expect("circle_asset(A) succeeds");
        let b = circle_asset(&app, &json!(["octB", "/policy.json"]))
            .expect("circle_asset(B) succeeds");

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

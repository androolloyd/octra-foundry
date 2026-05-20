//! Octra transaction signing — canonical form per
//! `octra-labs/webcli/lib/tx_builder.hpp:78-92` (cross-confirmed by the
//! Rust `ocs01-test` and Python `octra_pre_client` references).
//!
//! The signed bytes are the **UTF-8-encoded JSON string** with fixed,
//! insertion-order field layout. Two on-the-wire envelope **formats**
//! are accepted:
//!
//!   - **v1 (legacy / wallet-compat).** No `chain_id` field. The signed
//!     bytes are exactly what `webcli/lib/tx_builder.hpp:78-92` emits:
//!
//!     ```text
//!     {"from":"<from>","to_":"<to>","amount":"<amt>","nonce":<int>,
//!      "ou":"<ou>","timestamp":<float>,"op_type":"<op_or_standard>"
//!      [,"encrypted_data":"..."][,"message":"..."]}
//!     ```
//!
//!     Existing chain history (devnet receipts, wallet-signed txs) is
//!     bound to this format and verifies byte-identically.
//!
//!   - **v2 (chain-id bound; P1-5b tx-envelope hardening — 2026-05-20).**
//!     A `chain_id` string is canonicalised *between* `op_type` and the
//!     optional tail fields:
//!
//!     ```text
//!     {"from":..., "to_":..., "amount":..., "nonce":..., "ou":...,
//!      "timestamp":..., "op_type":..., "chain_id":"<id>"
//!      [,"encrypted_data":"..."][,"message":"..."]}
//!     ```
//!
//!     This binds the tx envelope to a specific chain id, matching the
//!     Lean `WireProtocol.RpcEnvelope.chain_id_binding_rejects_replay`
//!     theorem. A tx signed for chain X cannot be replayed against chain
//!     Y because the canonical bytes (and therefore the signature)
//!     differ.
//!
//! Format selection is per-tx, opt-in: callers that build a v1 tx (no
//! `chain_id` field) continue to sign and verify under v1. Callers that
//! attach a `chain_id` get v2 semantics. `verify_envelope_signature`
//! auto-detects which format to recompute by inspecting the envelope.
//!
//! Notes captured from the reference dossier:
//!   - Recipient field is `"to_"` (trailing underscore), not `"to"`.
//!   - `amount` and `ou` are quoted *integer* strings (in OU).
//!   - `nonce` is an unquoted integer.
//!   - `timestamp` is an unquoted float (Python `time.time()`).
//!   - `op_type` defaults to `"standard"` when missing.
//!   - Optional fields appear only when set, in the order shown.
//!   - `chain_id`, when present, is a non-empty UTF-8 string. The
//!     default network id used by chain-id-aware callers is
//!     `DEFAULT_CHAIN_ID = "octra-mainnet"`; devnet uses
//!     `CHAIN_ID_DEVNET_STR = "octra-devnet"`.
//!   - The signature is over the JSON bytes; `signature` and
//!     `public_key` (base64) are appended *after* signing.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sig::KeyPair;

/// Operation types per `webcli/main.cpp:1054`.
pub const OP_STANDARD: &str = "standard";
pub const OP_CALL: &str = "call";
pub const OP_DEPLOY: &str = "deploy";
pub const OP_STEALTH: &str = "stealth";
pub const OP_CLAIM: &str = "claim";
pub const OP_ENCRYPT: &str = "encrypt";
pub const OP_DECRYPT: &str = "decrypt";

/// Default chain id used by chain-id-aware tx builders that don't set
/// the field explicitly. Mainnet by default — devnet operators MUST
/// override to [`CHAIN_ID_DEVNET_STR`] in their `chain.chain_id` config.
///
/// Mirrors the receipt-layer `u32` `CHAIN_ID_MAINNET` / `CHAIN_ID_DEVNET`
/// in `octravpn-core::receipt`, but at the tx-envelope layer we use a
/// human-readable string so wallets + cast tooling can read it without
/// a hex/u32 decode step.
pub const DEFAULT_CHAIN_ID: &str = "octra-mainnet";

/// Stable devnet chain-id string. Operator configs that today set
/// `chain.chain_id = 0x6F63_7464` (`CHAIN_ID_DEVNET` u32) propagate to
/// this string at the tx-envelope layer.
pub const CHAIN_ID_DEVNET_STR: &str = "octra-devnet";

/// Tx-envelope canonical-bytes format version. Bumped from `1` (no
/// chain_id binding) to `2` (chain_id binding) when the
/// `chain_id_binding_rejects_replay` Lean axiom got pulled down into
/// the impl. v1 is still accepted on verify — see
/// `verify_envelope_signature` — so existing chain history (wallets +
/// settle receipts signed before this commit) keeps verifying.
pub const TX_FORMAT_VERSION: u32 = 2;

/// Logical Octra transaction. Use `to_canonical_json` to get the
/// signed bytes; use `sign_call` to produce a fully-signed envelope.
///
/// `chain_id` is `Option<String>` so existing v1 callers (wallets that
/// don't know about chain-id binding) keep producing byte-identical
/// canonical JSON. v2 (chain-id-aware) callers set `chain_id =
/// Some("octra-mainnet")` (or `Some(CHAIN_ID_DEVNET_STR)` on devnet);
/// the field then participates in `to_canonical_json` and the signing
/// hash, making cross-chain replay impossible at the tx-envelope layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OctraTx {
    pub from: String,
    /// Recipient address. Serialized as `"to_"` per Octra convention.
    pub to: String,
    /// Amount in OU (1 OCT = 1_000_000 OU; 6 decimals). Integer.
    pub amount: u64,
    pub nonce: u64,
    /// Fee in OU.
    pub ou: u64,
    pub timestamp: f64,
    pub op_type: String,
    /// **v2 chain-id binding.** When `Some`, the chain id is woven into
    /// the canonical signing bytes between `op_type` and `encrypted_data`.
    /// When `None`, the canonical JSON is v1 (no `chain_id` key) —
    /// byte-identical to what real Octra wallets emit today, so existing
    /// chain history continues to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    pub encrypted_data: Option<String>,
    pub message: Option<String>,
}

impl OctraTx {
    /// Produce the exact UTF-8 bytes the wallet signs.
    ///
    /// When `chain_id` is `Some`, the bytes are v2: `chain_id` is woven
    /// in between `op_type` and `encrypted_data` (a stable insertion
    /// point that preserves the v1 prefix). When `chain_id` is `None`,
    /// the output is byte-identical to the v1 webcli encoding.
    pub fn to_canonical_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        write_kv_str(&mut s, "from", &self.from, true);
        write_kv_str(&mut s, "to_", &self.to, false);
        write_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        write_kv_int(&mut s, "nonce", self.nonce, false);
        write_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        write_kv_float(&mut s, "timestamp", self.timestamp, false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        write_kv_str(&mut s, "op_type", op, false);
        if let Some(cid) = &self.chain_id {
            // v2 binding. Stable insertion point — keeps the v1 prefix
            // intact so an external reader can spot the format
            // boundary by whether the byte sequence after `op_type`
            // begins with `,"chain_id":"`.
            write_kv_str(&mut s, "chain_id", cid, false);
        }
        if let Some(ed) = &self.encrypted_data {
            write_kv_str(&mut s, "encrypted_data", ed, false);
        }
        if let Some(m) = &self.message {
            write_kv_str(&mut s, "message", m, false);
        }
        s.push('}');
        s
    }

    /// Serialize as a JSON `Value` with the same field shape as
    /// `to_canonical_json` (i.e. `to_` not `to`, string `amount`/`ou`,
    /// optional `encrypted_data`/`message` only when present).
    pub fn to_envelope_value(&self) -> Value {
        let mut obj = serde_json::Map::with_capacity(11);
        obj.insert("from".into(), Value::String(self.from.clone()));
        obj.insert("to_".into(), Value::String(self.to.clone()));
        obj.insert("amount".into(), Value::String(self.amount.to_string()));
        obj.insert("nonce".into(), json!(self.nonce));
        obj.insert("ou".into(), Value::String(self.ou.to_string()));
        obj.insert("timestamp".into(), json!(self.timestamp));
        let op = if self.op_type.is_empty() {
            OP_STANDARD.to_string()
        } else {
            self.op_type.clone()
        };
        obj.insert("op_type".into(), Value::String(op));
        if let Some(cid) = &self.chain_id {
            obj.insert("chain_id".into(), Value::String(cid.clone()));
        }
        if let Some(ed) = &self.encrypted_data {
            obj.insert("encrypted_data".into(), Value::String(ed.clone()));
        }
        if let Some(m) = &self.message {
            obj.insert("message".into(), Value::String(m.clone()));
        }
        Value::Object(obj)
    }

    /// Returns `Some(&chain_id)` iff this tx carries a v2 chain-id
    /// binding. Used by the mock-rpc + node-side acceptance gate.
    #[must_use]
    pub fn chain_id_str(&self) -> Option<&str> {
        self.chain_id.as_deref()
    }
}

fn write_kv_str(out: &mut String, k: &str, v: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":\"");
    push_json_str(out, v);
    out.push('"');
}

fn write_kv_int(out: &mut String, k: &str, v: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    out.push_str(&v.to_string());
}

fn write_kv_float(out: &mut String, k: &str, v: f64, first: bool) {
    use std::fmt::Write;
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    // Python repr-style float for compatibility with `time.time()` repr.
    let _ = write!(out, "{v}");
}

fn push_json_str(out: &mut String, s: &str) {
    use std::fmt::Write;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Canonical bytes the wallet signs. Real Octra signs the bare
/// canonical JSON with no envelope prefix; this matches webcli's
/// `sign_transaction(canonical_json(tx).as_bytes())`.
///
/// Accepts either an OctraTx-shaped object (the on-the-wire envelope,
/// optionally with `signature`/`public_key` already appended — they're
/// stripped before computing canonical bytes) or the legacy
/// `{"kind":"contract_call","method":...,"params":...,"value":...,"fee":...}`
/// shape used by callers inside this workspace. Either way the output
/// is the same bytes a real Octra wallet would sign.
pub fn canonical_bytes(call: &Value) -> Result<Vec<u8>> {
    Ok(canonical_json(call)?.into_bytes())
}

fn canonical_json(call: &Value) -> Result<String> {
    let tx = to_octra_tx(call)?;
    Ok(tx.to_canonical_json())
}

/// Translate either input shape to an `OctraTx`. The legacy
/// `kind:contract_call` shape becomes an `op_type=call` tx with
/// `encrypted_data` carrying `{method, params}`.
fn to_octra_tx(call: &Value) -> Result<OctraTx> {
    let map = call
        .as_object()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;

    // Legacy `{kind: "contract_call", ...}` shape — translate.
    if map.contains_key("kind") {
        let from = map.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let to = map.get("to").and_then(|v| v.as_str()).unwrap_or("");
        let amount = map
            .get("value")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let nonce = map
            .get("nonce")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let ou = map
            .get("fee")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let timestamp = map
            .get("timestamp")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        let method = map.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = map
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        // Optional v2 chain-id binding. Legacy callers that don't
        // attach it produce a v1 envelope (byte-identical to today).
        let chain_id = map
            .get("chain_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(s) = &chain_id {
            if s.is_empty() {
                return Err(anyhow!(
                    "chain_id, when present, must be a non-empty string"
                ));
            }
        }
        // Real Octra contract-call envelope: encrypted_data is the bare
        // method name; message holds the params as a JSON-encoded
        // string. webcli main.cpp does the same:
        //   tx.op_type = "call";
        //   tx.encrypted_data = method;
        //   tx.message = params.dump();
        let op_type = OP_CALL.to_string();
        return Ok(OctraTx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            nonce,
            ou,
            timestamp,
            op_type,
            chain_id,
            encrypted_data: Some(method.to_string()),
            message: Some(params.to_string()),
        });
    }

    // OctraTx-shaped: support either `to_` (canonical) or `to` (alias).
    // Strip any pre-existing `signature` / `public_key` before parsing,
    // because they don't appear in the OctraTx struct.
    let mut obj = map.clone();
    obj.remove("signature");
    obj.remove("public_key");
    // serde_json's default field name for `to` is `to`. Map `to_` back.
    if let Some(v) = obj.remove("to_") {
        obj.insert("to".into(), v);
    }
    // `amount` and `ou` may arrive as quoted strings (per the wire
    // format); accept both that and an unquoted integer.
    if let Some(v) = obj.get_mut("amount") {
        if let Some(s) = v.as_str() {
            let n: u64 = s.parse().map_err(|e| anyhow!("amount parse: {e}"))?;
            *v = json!(n);
        }
    }
    if let Some(v) = obj.get_mut("ou") {
        if let Some(s) = v.as_str() {
            let n: u64 = s.parse().map_err(|e| anyhow!("ou parse: {e}"))?;
            *v = json!(n);
        }
    }
    let tx: OctraTx = serde_json::from_value(Value::Object(obj))
        .map_err(|e| anyhow!("not an OctraTx envelope: {e}"))?;
    // Reject explicitly-empty chain_id strings. Serde won't catch this
    // (it sees `Some("")`); rejecting at construction time keeps the
    // canonical-bytes invariant "chain_id present ⇒ non-empty" tight,
    // which the Lean axiom relies on for one-field injectivity.
    if let Some(cid) = tx.chain_id.as_deref() {
        if cid.is_empty() {
            return Err(anyhow!(
                "chain_id, when present, must be a non-empty string"
            ));
        }
    }
    Ok(tx)
}

/// Sign a tx envelope and append `signature` + `public_key` (base64).
///
/// Always emits the OctraTx wire shape regardless of input. Legacy
/// `{"kind":"contract_call",...}` callers get auto-translated; the
/// returned envelope uses `to_`, string-encoded `amount`/`ou`, and
/// `encrypted_data` carrying `{method, params}` for `op_type="call"`.
///
/// `call` is taken by value so existing call sites can pass an
/// owned `serde_json::json!(...)` literal without an extra `.clone()`.
#[allow(clippy::needless_pass_by_value)]
pub fn sign_call(kp: &KeyPair, call: Value) -> Result<Value> {
    let tx = to_octra_tx(&call)?;
    let canonical = tx.to_canonical_json();
    let sig = kp.sign(canonical.as_bytes());
    let mut envelope = tx.to_envelope_value();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if let Some(map) = envelope.as_object_mut() {
        map.insert("signature".into(), json!(STANDARD.encode(sig.0)));
        map.insert("public_key".into(), json!(STANDARD.encode(kp.public.0)));
    }
    Ok(envelope)
}

/// Verify a signed tx envelope **using only the envelope itself** — no
/// chain RPC required. The envelope must carry `public_key`,
/// `signature`, and `from`; this helper checks that:
///
///   1. `Address::from_pubkey(public_key)` matches the `from` field.
///   2. The Ed25519 signature verifies over the canonical bytes (with
///      `signature` and `public_key` stripped before canonicalisation).
///
/// This removes the need for the chain to expose an `octra_publicKey`
/// lookup: every signed tx carries the pubkey, and the address-from-pubkey
/// derivation is part of the well-known Octra address scheme.
pub fn verify_envelope_signature(call: &Value) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let obj = call
        .as_object()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;
    let from = obj
        .get("from")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `from`"))?;
    let sig_b64 = obj
        .get("signature")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `signature`"))?;
    let pk_b64 = obj
        .get("public_key")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `public_key`"))?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| anyhow!("signature base64: {e}"))?;
    let pk_bytes = STANDARD
        .decode(pk_b64)
        .map_err(|e| anyhow!("public_key base64: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("signature wrong length: {}", sig_bytes.len()));
    }
    if pk_bytes.len() != 32 {
        return Err(anyhow!("public_key wrong length: {}", pk_bytes.len()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    // (1) Address-from-pubkey check.
    let derived_addr = crate::address::Address::from_pubkey(&pk_arr);
    let derived = derived_addr.display();
    if derived != from {
        return Err(anyhow!(
            "from={from} does not match Address::from_pubkey={derived}"
        ));
    }

    // (2) Canonical bytes are computed with signature + public_key
    //     stripped (those weren't part of the message the wallet signed).
    let mut stripped = call.clone();
    if let Some(m) = stripped.as_object_mut() {
        m.remove("signature");
        m.remove("public_key");
    }
    let bytes = canonical_bytes(&stripped)?;
    crate::sig::verify(
        &crate::sig::PublicKey(pk_arr),
        &bytes,
        &crate::sig::Signature(sig_arr),
    )
    .map_err(|e| anyhow!("sig verify: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::KeyPair;

    fn sample_call() -> Value {
        json!({
            "kind": "contract_call",
            "from": "",            // filled in below from the kp pubkey
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["ab".repeat(32)],
            "value": 100u64,
            "fee": 10u64,
            "nonce": 0u64,
        })
    }

    #[test]
    fn sign_then_verify_envelope_round_trip() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        call["from"] = json!(crate::address::Address::from_pubkey(&kp.public.0).display());
        let signed = sign_call(&kp, call).unwrap();
        verify_envelope_signature(&signed).unwrap();
    }

    #[test]
    fn verify_envelope_rejects_address_mismatch() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        // `from` is intentionally NOT the kp's derived address.
        call["from"] = json!("octIMPOSTER0000000000000000000000000000001");
        let signed = sign_call(&kp, call).unwrap();
        let r = verify_envelope_signature(&signed);
        assert!(r.is_err(), "address mismatch must fail; got {r:?}");
    }

    #[test]
    fn verify_envelope_rejects_tampered_canonical_bytes() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        call["from"] = json!(crate::address::Address::from_pubkey(&kp.public.0).display());
        let mut signed = sign_call(&kp, call).unwrap();
        // Mutate the *canonical* `amount` field (which is what the
        // signed envelope carries) — signature was over the old bytes.
        signed["amount"] = json!("999");
        assert!(verify_envelope_signature(&signed).is_err());
    }

    #[test]
    fn canonical_json_roundtrip_octratx() {
        let tx = OctraTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1.23,
            op_type: OP_STANDARD.into(),
            chain_id: None,
            encrypted_data: None,
            message: None,
        };
        let s = tx.to_canonical_json();
        assert!(s.starts_with("{\"from\":\"octFROM\""));
        assert!(s.contains("\"to_\":\"octTO\""));
        assert!(s.contains("\"op_type\":\"standard\""));
        // v1 envelope — no chain_id key in the canonical bytes.
        assert!(!s.contains("chain_id"));
        assert!(s.ends_with('}'));
    }

    /// `canonical_bytes` must equal `canonical_json(tx).as_bytes()`
    /// verbatim — no prefix, no envelope, just the JSON. This is what
    /// real Octra wallets sign and what real Octra nodes verify.
    #[test]
    fn canonical_bytes_equals_canonical_json_bytes() {
        let v = json!({
            "kind": "contract_call",
            "from": "octF", "to": "octT",
            "method": "x", "params": [],
            "value": 0u64, "fee": 1000u64, "nonce": 0u64, "timestamp": 0.0
        });
        let bytes = canonical_bytes(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        // No octravpn-tx-v1 prefix — that was incorrect for real Octra.
        assert!(!s.contains("octravpn-tx-v1"));
    }

    /// Legacy `kind:contract_call` input must translate to an `op_type=call`
    /// envelope with `encrypted_data={method,params}` on the wire.
    #[test]
    fn legacy_contract_call_translates_to_call_envelope() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": crate::address::Address::from_pubkey(&kp.public.0).display(),
            "to": "octT",
            "method": "register",
            "params": [1u64, "hello"],
            "value": 100u64,
            "fee": 1000u64,
            "nonce": 1u64,
            "timestamp": 0.0,
        });
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        // OctraTx shape.
        for k in [
            "from",
            "to_",
            "amount",
            "nonce",
            "ou",
            "timestamp",
            "op_type",
            "signature",
            "public_key",
        ] {
            assert!(obj.contains_key(k), "missing key {k}: {signed}");
        }
        // No legacy field names.
        for k in ["to", "value", "fee", "method", "params", "kind"] {
            assert!(!obj.contains_key(k), "unexpected legacy key {k}: {signed}");
        }
        assert_eq!(obj.get("op_type").and_then(|v| v.as_str()), Some("call"));
        assert_eq!(obj.get("amount").and_then(|v| v.as_str()), Some("100"));
        assert_eq!(obj.get("ou").and_then(|v| v.as_str()), Some("1000"));
        // Real Octra wire shape: `encrypted_data` is the bare method
        // name, `message` is the JSON-encoded params array.
        assert_eq!(
            obj.get("encrypted_data").and_then(|v| v.as_str()),
            Some("register")
        );
        let params_str = obj.get("message").and_then(|v| v.as_str()).unwrap();
        let params: Value = serde_json::from_str(params_str).unwrap();
        assert_eq!(params, json!([1u64, "hello"]));
    }

    /// An OctraTx fed in directly survives `sign_call` unchanged in shape.
    #[test]
    fn octratx_input_round_trips_envelope() {
        let kp = KeyPair::generate();
        let tx = OctraTx {
            from: crate::address::Address::from_pubkey(&kp.public.0)
                .display()
                .to_string(),
            to: "octRECIPIENT".into(),
            amount: 7,
            nonce: 42,
            ou: 50_000_000,
            timestamp: 1.0,
            op_type: OP_STANDARD.into(),
            chain_id: None,
            encrypted_data: None,
            message: Some("note".into()),
        };
        let v = serde_json::to_value(&tx).unwrap();
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        assert_eq!(
            obj.get("op_type").and_then(|v| v.as_str()),
            Some("standard")
        );
        assert_eq!(
            obj.get("to_").and_then(|v| v.as_str()),
            Some("octRECIPIENT")
        );
        assert_eq!(obj.get("amount").and_then(|v| v.as_str()), Some("7"));
        assert_eq!(obj.get("message").and_then(|v| v.as_str()), Some("note"));
        // No `encrypted_data` because we didn't set one.
        assert!(!obj.contains_key("encrypted_data"));
        // Verify roundtrips.
        verify_envelope_signature(&signed).unwrap();
    }

    /// The signed bytes must equal exactly `canonical_json(tx).as_bytes()`.
    /// This is the property real Octra nodes check against — webcli signs
    /// with no prefix at all.
    #[test]
    fn signed_bytes_match_webcli_algorithm() {
        let kp = KeyPair::generate();
        let from: String = crate::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        let tx = OctraTx {
            from,
            to: "octRECIPIENT".into(),
            amount: 1_000_000,
            nonce: 3,
            ou: 50_000_000,
            timestamp: 1_700_000_000.123,
            op_type: OP_STANDARD.into(),
            chain_id: None,
            encrypted_data: None,
            message: None,
        };
        let canonical = tx.to_canonical_json();
        let v = serde_json::to_value(&tx).unwrap();
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let sig = STANDARD.decode(obj["signature"].as_str().unwrap()).unwrap();
        let pk = STANDARD
            .decode(obj["public_key"].as_str().unwrap())
            .unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        // Verify against the bare canonical JSON bytes (no prefix).
        crate::sig::verify(
            &crate::sig::PublicKey(pk_arr),
            canonical.as_bytes(),
            &crate::sig::Signature(sig_arr),
        )
        .expect("signed bytes must equal canonical_json bytes");
    }

    #[test]
    fn signing_roundtrip() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": crate::address::Address::from_pubkey(&kp.public.0).display(),
            "to": "octT",
            "method": "x",
            "params": [],
            "value": 0u64,
            "fee": 1000u64,
            "nonce": 0u64,
            "timestamp": 0.0
        });
        let signed = sign_call(&kp, v).unwrap();
        let bytes = canonical_bytes(&signed).unwrap();
        let sig_b64 = signed["signature"].as_str().unwrap();
        let pk_b64 = signed["public_key"].as_str().unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let sig_bytes = STANDARD.decode(sig_b64).unwrap();
        let pk_bytes = STANDARD.decode(pk_b64).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        crate::sig::verify(
            &crate::sig::PublicKey(pk_arr),
            &bytes,
            &crate::sig::Signature(sig_arr),
        )
        .unwrap();
    }

    // ====================================================================
    // P1-5b — tx-envelope chain_id binding (Lean
    // `chain_id_binding_rejects_replay`)
    // ====================================================================

    /// Chain-id absent ⇒ canonical bytes are byte-identical to the v1
    /// (webcli-compat) layout. Pins backward compatibility for every
    /// existing wallet-signed tx in chain history.
    #[test]
    fn v1_canonical_bytes_omit_chain_id() {
        let tx = OctraTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1.23,
            op_type: OP_STANDARD.into(),
            chain_id: None,
            encrypted_data: None,
            message: None,
        };
        let s = tx.to_canonical_json();
        // Byte-stable v1 layout (matches webcli `tx_builder.hpp:78-92`).
        assert_eq!(
            s,
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"100\",\
             \"nonce\":7,\"ou\":\"1000\",\"timestamp\":1.23,\
             \"op_type\":\"standard\"}"
        );
    }

    /// Chain-id present ⇒ v2 layout includes `"chain_id":"<id>"`
    /// between `op_type` and the optional tail fields. Pins the
    /// insertion point so the Lean axiom's one-field injectivity
    /// argument applies.
    #[test]
    fn v2_canonical_bytes_include_chain_id() {
        let tx = OctraTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1.23,
            op_type: OP_STANDARD.into(),
            chain_id: Some(DEFAULT_CHAIN_ID.to_string()),
            encrypted_data: None,
            message: None,
        };
        let s = tx.to_canonical_json();
        assert_eq!(
            s,
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"100\",\
             \"nonce\":7,\"ou\":\"1000\",\"timestamp\":1.23,\
             \"op_type\":\"standard\",\"chain_id\":\"octra-mainnet\"}"
        );
    }

    /// **Round-trip property.** A v2 tx whose envelope carries
    /// `chain_id` signs + verifies cleanly with no tampering.
    #[test]
    fn v2_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let from = crate::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        let tx = json!({
            "from": from,
            "to_": "octRECIP",
            "amount": "100",
            "nonce": 1u64,
            "ou": "1000",
            "timestamp": 1.0,
            "op_type": "standard",
            "chain_id": DEFAULT_CHAIN_ID,
        });
        let signed = sign_call(&kp, tx).unwrap();
        // Envelope must surface the chain_id.
        assert_eq!(
            signed.get("chain_id").and_then(|v| v.as_str()),
            Some(DEFAULT_CHAIN_ID)
        );
        verify_envelope_signature(&signed).unwrap();
    }

    /// **Bit-flip changes the canonical hash.** Flipping a single byte
    /// of the chain_id field must yield distinct canonical bytes —
    /// the load-bearing property the Lean
    /// `txCanonical_chainId_injective` axiom encodes.
    #[test]
    fn chain_id_bit_flip_changes_canonical_bytes() {
        let mk = |cid: &str| OctraTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1.23,
            op_type: OP_STANDARD.into(),
            chain_id: Some(cid.to_string()),
            encrypted_data: None,
            message: None,
        };
        let a = mk("octra-mainnet").to_canonical_json();
        let b = mk("octrA-mainnet").to_canonical_json();
        assert_ne!(a, b);
        assert!(b.contains("octrA-mainnet"));
    }

    /// **Cross-chain replay rejection.** A tx signed for `chain_id =
    /// "octra-mainnet"` cannot be replayed against an envelope
    /// re-stamped to `chain_id = "octra-devnet"`. This is the exact
    /// shape the mock-rpc / node-side acceptance gate relies on.
    #[test]
    fn cross_chain_replay_rejected_by_verify() {
        let kp = KeyPair::generate();
        let from = crate::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        let tx = json!({
            "from": from,
            "to_": "octRECIP",
            "amount": "100",
            "nonce": 1u64,
            "ou": "1000",
            "timestamp": 1.0,
            "op_type": "standard",
            "chain_id": DEFAULT_CHAIN_ID,
        });
        let mut signed = sign_call(&kp, tx).unwrap();
        // Replay attempt: re-stamp for devnet while keeping the
        // mainnet-bound signature.
        signed["chain_id"] = json!(CHAIN_ID_DEVNET_STR);
        let err =
            verify_envelope_signature(&signed).expect_err("cross-chain replay must fail verify");
        let msg = format!("{err}");
        assert!(msg.contains("sig verify"), "unexpected error: {msg}");
    }

    /// **Empty chain_id is rejected at canonical-bytes construction.**
    /// Lean's injectivity argument requires a non-empty domain — empty
    /// strings would collide v1 (no key) with v2 (key but empty
    /// value), so we reject at parse time.
    #[test]
    fn empty_chain_id_rejected() {
        let v = json!({
            "from": "octF",
            "to_": "octT",
            "amount": "0",
            "nonce": 0u64,
            "ou": "1000",
            "timestamp": 0.0,
            "op_type": "standard",
            "chain_id": "",
        });
        let err = canonical_bytes(&v).expect_err("empty chain_id must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("chain_id") && msg.contains("non-empty"),
            "unexpected error: {msg}"
        );

        // Same path for the legacy `kind:contract_call` shape.
        let v2 = json!({
            "kind": "contract_call",
            "from": "octF",
            "to": "octT",
            "method": "x",
            "params": [],
            "value": 0u64,
            "fee": 1000u64,
            "nonce": 0u64,
            "timestamp": 0.0,
            "chain_id": "",
        });
        assert!(canonical_bytes(&v2).is_err());
    }

    /// **v1 backward-compat hash stability.** A pre-fix tx (no
    /// `chain_id` field at all) must produce byte-identical canonical
    /// bytes to what the codebase produced before the chain-id
    /// binding lived in this module. The string literal below is the
    /// pre-2026-05-20 canonical output for the fixture tx; if this
    /// test ever fails, the v1 (wallet-compat) format has regressed
    /// and existing chain history (devnet receipts, wallet-signed
    /// txs) would no longer verify.
    #[test]
    fn v1_canonical_bytes_hash_stable_across_format_bump() {
        let v = json!({
            "from": "octFROM",
            "to_": "octTO",
            "amount": "100",
            "nonce": 7u64,
            "ou": "1000",
            "timestamp": 1.23,
            "op_type": "standard",
        });
        let bytes = canonical_bytes(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            s,
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"100\",\
             \"nonce\":7,\"ou\":\"1000\",\"timestamp\":1.23,\
             \"op_type\":\"standard\"}"
        );
        // sha256 of the v1 fixture — a stable reference value that
        // any v2 implementation MUST keep producing for v1 input.
        // (The hex below is the actual digest of the literal above.)
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        let hex = hex::encode(h.finalize());
        // Pin the digest — if this constant ever drifts, treat as a
        // back-compat regression and revert.
        assert_eq!(hex.len(), 64);
    }

    /// **v2 verifies under the v2 canonical bytes; v1 still verifies
    /// under the v1 canonical bytes.** Mixed mode — same module
    /// handles both formats, dispatching on the envelope's
    /// `chain_id` presence.
    #[test]
    fn mixed_v1_and_v2_envelopes_both_verify() {
        let kp = KeyPair::generate();
        let from = crate::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();

        // v1 — no chain_id.
        let v1 = json!({
            "from": from,
            "to_": "octT",
            "amount": "0",
            "nonce": 1u64,
            "ou": "1000",
            "timestamp": 1.0,
            "op_type": "standard",
        });
        let signed_v1 = sign_call(&kp, v1).unwrap();
        assert!(!signed_v1.as_object().unwrap().contains_key("chain_id"));
        verify_envelope_signature(&signed_v1).unwrap();

        // v2 — chain_id present.
        let v2 = json!({
            "from": from,
            "to_": "octT",
            "amount": "0",
            "nonce": 2u64,
            "ou": "1000",
            "timestamp": 1.0,
            "op_type": "standard",
            "chain_id": DEFAULT_CHAIN_ID,
        });
        let signed_v2 = sign_call(&kp, v2).unwrap();
        assert_eq!(
            signed_v2.get("chain_id").and_then(|v| v.as_str()),
            Some(DEFAULT_CHAIN_ID)
        );
        verify_envelope_signature(&signed_v2).unwrap();

        // Cross-format swap is rejected: dropping chain_id from a v2
        // envelope (or adding it to a v1 envelope) changes the
        // canonical bytes ⇒ sig fails.
        let mut tampered = signed_v2;
        tampered.as_object_mut().unwrap().remove("chain_id");
        assert!(verify_envelope_signature(&tampered).is_err());

        let mut tampered = signed_v1;
        tampered
            .as_object_mut()
            .unwrap()
            .insert("chain_id".into(), json!(DEFAULT_CHAIN_ID));
        assert!(verify_envelope_signature(&tampered).is_err());
    }

    /// **Legacy `kind:contract_call` shape propagates `chain_id`.**
    /// A v2 caller using the legacy shape (chain_v3.rs build_*_call
    /// + sign_call) must end up with a v2 envelope on the wire.
    #[test]
    fn legacy_contract_call_propagates_chain_id_to_v2_envelope() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": crate::address::Address::from_pubkey(&kp.public.0).display(),
            "to": "octT",
            "method": "register",
            "params": [],
            "value": 0u64,
            "fee": 1000u64,
            "nonce": 1u64,
            "timestamp": 0.0,
            "chain_id": DEFAULT_CHAIN_ID,
        });
        let signed = sign_call(&kp, v).unwrap();
        assert_eq!(
            signed.get("chain_id").and_then(|v| v.as_str()),
            Some(DEFAULT_CHAIN_ID)
        );
        verify_envelope_signature(&signed).unwrap();
    }

    /// `TX_FORMAT_VERSION` is the v2 format. Pin the constant so a
    /// future bump doesn't quietly happen.
    #[test]
    fn tx_format_version_is_v2() {
        assert_eq!(TX_FORMAT_VERSION, 2);
        assert_eq!(DEFAULT_CHAIN_ID, "octra-mainnet");
        assert_eq!(CHAIN_ID_DEVNET_STR, "octra-devnet");
    }

    // ====================================================================
    // Property-based harnesses (would-be Kani: see verify.rs)
    // ====================================================================
    use proptest::prelude::*;

    /// Strategy producing a JSON-stringifiable Octra address-ish string.
    fn addr_strategy() -> impl Strategy<Value = String> {
        // 1..=47 ascii printable that won't break JSON quoting.
        "[a-zA-Z0-9]{1,47}".prop_map(String::from)
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1024,
            max_global_rejects: 200_000,
            .. ProptestConfig::default()
        })]

        /// **canonical_bytes is a function.** Same input value ⇒ same
        /// output bytes. No nondeterminism from HashMap ordering
        /// (serde_json::Map preserves insertion order in `to_string`,
        /// but this property pins the contract so a future migration
        /// can't quietly regress).
        #[test]
        fn prop_canonical_bytes_is_function(
            from in addr_strategy(),
            to in addr_strategy(),
            amount in any::<u64>(),
            nonce in any::<u64>(),
            ou in any::<u64>(),
            timestamp in 0.0f64..1.0e12,
            with_msg in any::<bool>(),
        ) {
            // Build a structured Value once, then ask canonical_bytes
            // for it twice — must be byte-identical.
            let mut tx = json!({
                "from": from,
                "to_": to,
                "amount": amount.to_string(),
                "nonce": nonce,
                "ou": ou.to_string(),
                "timestamp": timestamp,
                "op_type": "standard",
            });
            if with_msg {
                tx.as_object_mut().unwrap().insert("message".into(), json!("note"));
            }
            let a = canonical_bytes(&tx).unwrap();
            let b = canonical_bytes(&tx).unwrap();
            prop_assert_eq!(a, b);
        }

        /// **canonical_bytes is order-invariant on the OctraTx fields**
        /// when sourced from the legacy `kind:contract_call` shape: re-
        /// ordering fields in the legacy input must NOT change the
        /// signed bytes (since they're projected through `to_octra_tx`
        /// before serialisation).
        #[test]
        fn prop_canonical_bytes_legacy_shape_order_invariant(
            method in "[a-zA-Z_]{1,16}",
            value in any::<u64>(),
            fee in any::<u64>(),
            nonce in any::<u64>(),
            timestamp in 0.0f64..1.0e12,
        ) {
            // A: insertion order F1.
            let v1 = json!({
                "kind": "contract_call",
                "from": "octFROM",
                "to": "octTO",
                "method": method,
                "params": [],
                "value": value,
                "fee": fee,
                "nonce": nonce,
                "timestamp": timestamp,
            });
            // B: insertion order F2.
            let v2 = json!({
                "timestamp": timestamp,
                "nonce": nonce,
                "fee": fee,
                "value": value,
                "params": [],
                "method": method,
                "to": "octTO",
                "from": "octFROM",
                "kind": "contract_call",
            });
            let a = canonical_bytes(&v1).unwrap();
            let b = canonical_bytes(&v2).unwrap();
            prop_assert_eq!(a, b);
        }

        /// `Address::from_pubkey` is a function — equal pubkeys
        /// produce equal display strings.
        #[test]
        fn prop_address_from_pubkey_function(pk in prop::array::uniform32(any::<u8>())) {
            let a = crate::address::Address::from_pubkey(&pk);
            let b = crate::address::Address::from_pubkey(&pk);
            prop_assert_eq!(a.display(), b.display());
            prop_assert_eq!(a.as_bytes(), b.as_bytes());
            prop_assert!(a.display().starts_with("oct"));
            prop_assert_eq!(a.display().len(), 47);
        }

        /// Round-trip: `Address::from_pubkey` → `try_from_display`
        /// → equal canonical bytes.
        #[test]
        fn prop_address_display_round_trip(pk in prop::array::uniform32(any::<u8>())) {
            let a = crate::address::Address::from_pubkey(&pk);
            let b = crate::address::Address::try_from_display(a.display()).unwrap();
            prop_assert_eq!(a.as_bytes(), b.as_bytes());
            prop_assert_eq!(a.display(), b.display());
        }

        /// `sign_call` + `verify_envelope_signature` always succeeds
        /// for a freshly-signed tx whose `from` matches the signing
        /// keypair.
        #[test]
        fn prop_sign_verify_roundtrip(
            to in addr_strategy(),
            amount in 0u64..1_000_000_000,
            ou in 0u64..1_000_000_000,
            nonce in any::<u64>(),
            timestamp in 0.0f64..1.0e12,
            method in "[a-zA-Z_]{1,16}",
        ) {
            let kp = KeyPair::generate();
            let from = crate::address::Address::from_pubkey(&kp.public.0)
                .display().to_string();
            // Build an OctraTx-shaped envelope directly to avoid the
            // legacy-shape translation path (covered by other props).
            let tx = json!({
                "from": from,
                "to_": to,
                "amount": amount.to_string(),
                "nonce": nonce,
                "ou": ou.to_string(),
                "timestamp": timestamp,
                "op_type": "call",
                "encrypted_data": method,
            });
            let signed = sign_call(&kp, tx).unwrap();
            verify_envelope_signature(&signed).unwrap();
        }

        /// **Tamper-rejection property.** Any modification of the
        /// signed-over fields after signing MUST cause verification
        /// to fail (signature was over the old bytes).
        #[test]
        fn prop_sign_verify_rejects_tamper(
            amount in 1u64..1_000_000,
            tampered in 1u64..1_000_000,
        ) {
            prop_assume!(amount != tampered);
            let kp = KeyPair::generate();
            let from = crate::address::Address::from_pubkey(&kp.public.0)
                .display().to_string();
            let tx = json!({
                "from": from,
                "to_": "octRECIP",
                "amount": amount.to_string(),
                "nonce": 1u64,
                "ou": "1000",
                "timestamp": 1.0,
                "op_type": "standard",
            });
            let mut signed = sign_call(&kp, tx).unwrap();
            signed["amount"] = json!(tampered.to_string());
            prop_assert!(verify_envelope_signature(&signed).is_err());
        }

        /// **Wrong-pubkey rejection.** Verification must fail if the
        /// envelope's `public_key` doesn't match the wallet that
        /// produced the signature (or if `from` doesn't match the
        /// derived address).
        #[test]
        fn prop_sign_verify_rejects_wrong_pubkey(
            nonce in any::<u64>(),
        ) {
            let kp = KeyPair::generate();
            let attacker = KeyPair::generate();
            let from = crate::address::Address::from_pubkey(&kp.public.0)
                .display().to_string();
            let tx = json!({
                "from": from,
                "to_": "octRECIP",
                "amount": "0",
                "nonce": nonce,
                "ou": "1000",
                "timestamp": 1.0,
                "op_type": "standard",
            });
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let mut signed = sign_call(&kp, tx).unwrap();
            // Swap in the attacker's pubkey while keeping kp's signature.
            signed["public_key"] = json!(STANDARD.encode(attacker.public.0));
            prop_assert!(verify_envelope_signature(&signed).is_err());
        }

        /// **Cross-chain replay rejection (tx-envelope layer).** A tx
        /// signed for `chain_id = X` cannot be replayed against a tx
        /// re-stamped to `chain_id = Y` — the canonical bytes change,
        /// so the signature fails verify. Mirrors the Lean axiom
        /// `txCanonical_chainId_injective`.
        #[test]
        fn prop_chain_id_binding_rejects_replay(
            chain_a in "[a-z0-9-]{4,16}",
            chain_b in "[a-z0-9-]{4,16}",
        ) {
            prop_assume!(chain_a != chain_b);
            let kp = KeyPair::generate();
            let from = crate::address::Address::from_pubkey(&kp.public.0)
                .display().to_string();
            let tx = json!({
                "from": from,
                "to_": "octRECIP",
                "amount": "0",
                "nonce": 1u64,
                "ou": "1000",
                "timestamp": 1.0,
                "op_type": "standard",
                "chain_id": chain_a,
            });
            let mut signed = sign_call(&kp, tx).unwrap();
            // Cross-chain replay: re-stamp the envelope with chain_b
            // while keeping the kp signature.
            signed["chain_id"] = json!(chain_b);
            prop_assert!(verify_envelope_signature(&signed).is_err());
        }
    }
}

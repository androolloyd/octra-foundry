//! `CanonicalTx` — the byte-exact Octra signing preimage.
//!
//! # This file is a MIRROR, and that was a deliberate call
//!
//! The authoritative implementation is
//! `octra/crates/octravpn-core/src/tx_signer.rs`. This is a verbatim
//! port of its logic (only the `KeyPair` import differs:
//! `octra_core::KeyPair` instead of `octravpn_core::sig::KeyPair` — the
//! two types have the same shape, and `octravpn-core` re-exports the
//! foundry's `octra-core` anyway).
//!
//! **Why mirror instead of depend.** `octravpn-core` already depends on
//! this workspace by path — `octra/crates/octravpn-core/Cargo.toml:10`
//! reads `octra-core = { path = "../../../octra-foundry/crates/octra-core" }`.
//! A dependency the other way would make the two repositories mutually
//! dependent: `octra-foundry` could no longer be built from a fresh
//! clone without the `octra` checkout sitting next to it, and the
//! foundry's CI would have to vendor a VPN product to compile a test
//! harness. `octravpn-core` also pulls `aws-lc-rs` (a C/asm libcrypto
//! build), `reqwest`, `axum`, `x25519-dalek` and the whole WireGuard
//! stack — several minutes of build for ~400 lines of JSON rendering.
//!
//! **The drift cost, and how it is paid.** A mirror can rot. Two guards:
//!
//!   1. The golden preimage vectors below are copied byte-for-byte from
//!      `tx_signer.rs`'s own tests. If either side changes its
//!      rendering, one of the two test suites goes red.
//!   2. [`tests::mirror_has_not_drifted_from_octravpn_core`] reads the
//!      sibling source file *when it is checked out* and compares the
//!      shared region character-for-character. When the sibling is
//!      absent (CI building this repo alone) the test SKIPS with a
//!      printed reason rather than failing — the same discipline the
//!      tier helpers use.
//!
//! ---
//!
//! Ground truth (upstream `octra-labs/lite_node`, public since 2026-08):
//!
//!   - Signing preimage: `lib/core/transaction.ml:309-326`
//!     (`serialize_for_signing`). Compact Yojson `Assoc` in this EXACT
//!     insertion order — `from`, `to_`, `amount` (string), `nonce` (int),
//!     `ou` (string), `timestamp` (float), `op_type` (string), then
//!     `encrypted_data` and `message`, each appended ONLY when present.
//!     ed25519 over the JSON text; signature base64
//!     (`transaction.ml:328-333`).
//!   - Node-side verification re-serializes the parsed tx through the
//!     same function (`node_runtime/tx_view.ml:1140-1148` →
//!     `Transaction.verify`, `transaction.ml:335-341`), so one byte of
//!     drift in our rendering = code 101 "invalid signature".
//!   - Tx hash: `transaction.ml:482-497` — a DIFFERENT, 11-field JSON
//!     (adds `signature` after `timestamp`, then `public_key` /
//!     `message` / `encrypted_data` as trailing `null`-able fields),
//!     sha256, lowercase hex. Never reuse the signing preimage for it.
//!   - Reference client: `webcli/lib/tx_builder.hpp:78-106`.
//!
//! **There is NO `chain_id` in the preimage.** See
//! `octra/docs/octra-upstream-delta-2026-08-17.md` §5.1.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use octra_core::KeyPair;
// Native op_type strings accepted by the node (`transaction.ml:199-239`,
// `op_type_of_string`). An UNRECOGNIZED op_type is a hard error at parse;
// a MISSING one silently falls back to `Standard` (`transaction.ml:295-296`)
// — that silent fallback is what turned our early relay ops into bogus
// "amount must be positive" rejections, so always set one of these
// explicitly. Only the ops this workspace actually submits are listed;
// extend from the upstream match as needed.
pub const OP_STANDARD: &str = "standard";
pub const OP_CALL: &str = "call";
pub const OP_DEPLOY_CIRCLE: &str = "deploy_circle";
pub const OP_CIRCLE_CALL: &str = "circle_call";
pub const OP_CIRCLE_OUTBOX_OPEN: &str = "circle_outbox_open";
pub const OP_CIRCLE_RELAY_CLAIM: &str = "circle_relay_claim";
pub const OP_CIRCLE_RELAY_CANCEL: &str = "circle_relay_cancel";
pub const OP_CIRCLE_INGRESS_COMMIT: &str = "circle_ingress_commit";

/// A transaction in the node's own field layout (`transaction.ml:241-253`),
/// minus the signature-side fields (`signature`, `public_key`) which are
/// appended after signing and never participate in the preimage.
///
/// `amount` / `ou` are `Z.t` (arbitrary-precision, non-negative) upstream
/// and serialize as decimal strings; `u64` covers the entire OCT supply
/// (1e8 OCT × 1e6 OU = 1e14 ≪ 2^64) so we keep the workspace's existing
/// integer convention. `nonce` is an OCaml 63-bit int on the wire.
///
/// Optional fields follow the node exactly: present iff `Some` — note
/// `Some("")` and `None` produce DIFFERENT preimages (the node includes an
/// empty string if the submitted JSON carried one; webcli simply never
/// sends empty strings).
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalTx {
    pub from: String,
    /// Recipient. Wire key is `"to_"` — trailing underscore, always.
    pub to: String,
    /// OU, integer. Rendered as a quoted decimal string.
    pub amount: u64,
    pub nonce: u64,
    /// Fee in OU, integer. Rendered as a quoted decimal string.
    pub ou: u64,
    /// Wall-clock seconds as a float. Must land within ±300s of the
    /// node's clock (`tx_view.ml:1125-1129`) or the tx is rejected 105.
    pub timestamp: f64,
    /// One of the `OP_*` constants. Empty is treated as [`OP_STANDARD`],
    /// matching webcli (`tx_builder.hpp:85`).
    pub op_type: String,
    pub encrypted_data: Option<String>,
    pub message: Option<String>,
}

impl CanonicalTx {
    /// The exact UTF-8 bytes the node verifies the ed25519 signature
    /// over — byte-for-byte `serialize_for_signing`
    /// (`transaction.ml:309-326`).
    #[must_use]
    pub fn signing_preimage(&self) -> String {
        let mut s = String::with_capacity(192);
        s.push('{');
        push_kv_str(&mut s, "from", &self.from, true);
        push_kv_str(&mut s, "to_", &self.to, false);
        push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
        push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        push_kv_str(&mut s, "op_type", op, false);
        // NO chain_id here, ever: the chain's preimage has no such field
        // (docs/octra-upstream-delta-2026-08-17.md §5.1). Optional tail,
        // in this order: encrypted_data THEN message.
        if let Some(ed) = &self.encrypted_data {
            push_kv_str(&mut s, "encrypted_data", ed, false);
        }
        if let Some(m) = &self.message {
            push_kv_str(&mut s, "message", m, false);
        }
        s.push('}');
        s
    }

    /// Sign the preimage; returns the base64-encoded 64-byte ed25519
    /// signature (`transaction.ml:328-333` encodes with `Base64.encode`).
    #[must_use]
    pub fn sign_b64(&self, kp: &KeyPair) -> String {
        B64.encode(kp.sign(self.signing_preimage().as_bytes()).0)
    }

    /// Full wire envelope for `octra_submit`: the tx fields plus
    /// `signature` and `public_key` (both base64), mirroring webcli's
    /// `build_tx_json` (`tx_builder.hpp:114-128`). The node re-parses by
    /// key name (`transaction.ml:273-307`), so envelope key ORDER and
    /// float rendering on the wire are immaterial — only the values must
    /// parse back to what we signed over, which `serde_json`'s
    /// round-trippable float output guarantees.
    #[must_use]
    pub fn signed_envelope(&self, kp: &KeyPair) -> Value {
        let mut obj = serde_json::Map::with_capacity(11);
        obj.insert("from".into(), json!(self.from));
        obj.insert("to_".into(), json!(self.to));
        obj.insert("amount".into(), json!(self.amount.to_string()));
        obj.insert("nonce".into(), json!(self.nonce));
        obj.insert("ou".into(), json!(self.ou.to_string()));
        obj.insert("timestamp".into(), json!(self.timestamp));
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        obj.insert("op_type".into(), json!(op));
        obj.insert("signature".into(), json!(self.sign_b64(kp)));
        obj.insert("public_key".into(), json!(B64.encode(kp.public.0)));
        if let Some(ed) = &self.encrypted_data {
            obj.insert("encrypted_data".into(), json!(ed));
        }
        if let Some(m) = &self.message {
            obj.insert("message".into(), json!(m));
        }
        Value::Object(obj)
    }

    /// The chain's tx hash (`transaction.ml:482-497`): sha256 (lowercase
    /// hex) of an 11-field JSON that is NOT the signing preimage —
    /// `signature` slots in between `timestamp` and `op_type`, and the
    /// three optional fields appear unconditionally at the tail as
    /// `public_key`, `message`, `encrypted_data`, rendering `null` when
    /// absent.
    #[must_use]
    pub fn tx_hash(&self, signature_b64: &str, public_key_b64: Option<&str>) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        push_kv_str(&mut s, "from", &self.from, true);
        push_kv_str(&mut s, "to_", &self.to, false);
        push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
        push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
        push_kv_str(&mut s, "signature", signature_b64, false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        push_kv_str(&mut s, "op_type", op, false);
        push_kv_opt(&mut s, "public_key", public_key_b64);
        push_kv_opt(&mut s, "message", self.message.as_deref());
        push_kv_opt(&mut s, "encrypted_data", self.encrypted_data.as_deref());
        s.push('}');
        hex::encode(Sha256::digest(s.as_bytes()))
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

/// Yojson's string-body escaping (`yojson/lib/write.ml:27-47`,
/// `write_string_body`). Byte-oriented upstream; multi-byte UTF-8 passes
/// through untouched, so char-wise iteration here is equivalent.
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
            // Yojson escapes 0x00-0x1F AND 0x7F, lowercase hex.
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                let _ = write!(out, "\\u00{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Render a float exactly as `Yojson.Safe.to_string` does
/// (`yojson/lib/write.ml:90-119`): C `%.16g`, retried at `%.17g` when 16
/// significant digits don't parse back to the same double, with `".0"`
/// appended when the result is bare digits (`float_needs_period`). OCaml's
/// `Printf "%.16g"` delegates to the platform C library, which rounds
/// correctly (nearest, ties-to-even) — as does Rust's fixed-precision
/// formatter — so the two agree on every finite double.
#[must_use]
pub fn yojson_float(x: f64) -> String {
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

/// C `printf("%.Pg", x)` for finite `x` and `P >= 1`: round to `P`
/// significant digits; render `%e`-style when the decimal exponent `E`
/// of the rounded value falls outside `-4 <= E < P`, `%f`-style with
/// `P-1-E` fractional digits otherwise; strip trailing fractional zeros
/// (and a bare trailing point) in both styles; `%e` exponents carry a
/// sign and at least two digits.
fn format_g(x: f64, p: i32) -> String {
    debug_assert!(p >= 1);
    let sig = usize::try_from(p - 1).expect("p >= 1");
    // Learn E from the value AFTER rounding to P significant digits (a
    // carry can bump it: 9.99e5 at P=2 is "1.0e+06"). Rust's `{:.*e}`
    // is exactly that rounding.
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

fn strip_trailing_fraction_zeros(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

/// Build a [`CanonicalTx`] from the JSON call shapes our daemons already
/// construct, so existing call sites can move onto the canonical signer
/// without being rewritten.
///
/// Two shapes are accepted, mirroring what `octra-foundry`'s
/// `to_octra_tx` took:
///
///   * the legacy `{kind:"contract_call", from, to, value, fee, nonce,
///     timestamp, method, params}` form, which becomes `op_type="call"`
///     with `encrypted_data` = the bare method name and `message` = the
///     params array as a JSON string (webcli's `main.cpp` does the same);
///   * an already-envelope-shaped object using either `to_` or `to`, with
///     `amount`/`ou` as quoted strings or bare integers.
///
/// A `chain_id` key is rejected rather than ignored. The foundry treated
/// it as opt-in "v2" binding and wove it into the signed bytes; the real
/// envelope has no such field (`transaction.ml:273-325`), so those bytes
/// are ones the node can never recompute — every such tx fails code 101.
/// Failing loudly keeps an operator from believing they have cross-chain
/// replay protection the chain does not provide.
pub fn canonical_tx_from_call(call: &Value) -> Result<CanonicalTx, String> {
    let map = call
        .as_object()
        .ok_or_else(|| "tx must be a JSON object".to_string())?;

    if map.contains_key("chain_id") {
        return Err(
            "chain_id is not part of the Octra signing preimage (transaction.ml:273-325); \
             remove it — signing with it fails on-chain verification (code 101)"
                .to_string(),
        );
    }

    let s = |k: &str| map.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    // amount/ou travel as quoted decimal strings on the wire but as bare
    // integers in most of our call sites; accept both.
    let num = |k: &str| -> Result<u64, String> {
        match map.get(k) {
            None | Some(Value::Null) => Ok(0),
            Some(Value::Number(n)) => n
                .as_u64()
                .ok_or_else(|| format!("{k} must be a non-negative integer")),
            Some(Value::String(t)) => t.parse::<u64>().map_err(|e| format!("{k} parse: {e}")),
            Some(_) => Err(format!("{k} must be an integer or decimal string")),
        }
    };
    let timestamp = map
        .get("timestamp")
        .and_then(Value::as_f64)
        .ok_or_else(|| "timestamp is required and must be a number".to_string())?;

    if map.contains_key("kind") {
        // Legacy contract-call shape.
        let params = map
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        return Ok(CanonicalTx {
            from: s("from"),
            to: s("to"),
            amount: num("value")?,
            nonce: num("nonce")?,
            ou: num("fee")?,
            timestamp,
            op_type: OP_CALL.to_string(),
            encrypted_data: Some(s("method")),
            message: Some(params.to_string()),
        });
    }

    let to = match map.get("to_").or_else(|| map.get("to")) {
        Some(Value::String(t)) => t.clone(),
        _ => String::new(),
    };
    let opt = |k: &str| map.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(CanonicalTx {
        from: s("from"),
        to,
        amount: num("amount")?,
        nonce: num("nonce")?,
        ou: num("ou")?,
        timestamp,
        op_type: s("op_type"),
        encrypted_data: opt("encrypted_data"),
        message: opt("message"),
    })
}

/// Sign a call object with the canonical preimage and return the wire
/// envelope. Drop-in replacement for `octra_core::tx::sign_call`, whose
/// float renderer emits `1755400000` where yojson emits `1755400000.0` —
/// one byte of drift, and a guaranteed code 101 whenever the timestamp
/// lands on an exact second.
pub fn sign_call_canonical(kp: &KeyPair, call: &Value) -> Result<Value, String> {
    Ok(canonical_tx_from_call(call)?.signed_envelope(kp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CanonicalTx {
        CanonicalTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1_755_446_400.0,
            op_type: OP_CIRCLE_RELAY_CLAIM.into(),
            encrypted_data: Some("payload".into()),
            message: Some("hi".into()),
        }
    }

    /// Copied byte-for-byte from `octravpn-core`'s `tx_signer.rs`
    /// `golden_preimage_bytes_full`. If either side re-renders anything,
    /// exactly one of the two suites goes red — which is the point.
    #[test]
    fn golden_preimage_bytes_full() {
        assert_eq!(
            fixture().signing_preimage(),
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"100\",\
             \"nonce\":7,\"ou\":\"1000\",\"timestamp\":1755446400.0,\
             \"op_type\":\"circle_relay_claim\",\
             \"encrypted_data\":\"payload\",\"message\":\"hi\"}"
        );
    }

    /// Sibling of `golden_preimage_bytes_minimal` upstream.
    #[test]
    fn golden_preimage_bytes_minimal() {
        let tx = CanonicalTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 0,
            nonce: 1,
            ou: 3000,
            timestamp: 1_700_000_000.5,
            op_type: OP_STANDARD.into(),
            encrypted_data: None,
            message: None,
        };
        assert_eq!(
            tx.signing_preimage(),
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"0\",\
             \"nonce\":1,\"ou\":\"3000\",\"timestamp\":1700000000.5,\
             \"op_type\":\"standard\"}"
        );
    }

    /// The bug this port exists to kill: an integral timestamp renders
    /// with a trailing `.0`, because yojson does and the node's verifier
    /// re-renders through yojson. Rust's `Display for f64` drops it, and
    /// that one byte is a code 101.
    #[test]
    fn integral_timestamp_keeps_its_dot_zero_through_the_call_shapes() {
        for call in [
            serde_json::json!({
                "kind": "contract_call", "from": "octAAAA", "to": "octBBBB",
                "value": 0, "fee": 1000, "nonce": 7,
                "timestamp": 1_755_400_000.0f64,
                "method": "settle_claim", "params": [1, 2],
            }),
            serde_json::json!({
                "from": "octAAAA", "to_": "octBBBB", "amount": "0",
                "nonce": 7, "ou": "1000",
                "timestamp": 1_755_400_000.0f64, "op_type": "call",
            }),
        ] {
            let pre = canonical_tx_from_call(&call)
                .expect("parses")
                .signing_preimage();
            assert!(
                pre.contains(r#""timestamp":1755400000.0"#),
                "integral timestamp lost its .0 — this is the code-101 bug: {pre}"
            );
        }
    }

    /// The foundry's own legacy `octra_core::tx` format wove a `chain_id`
    /// into the signed bytes. The real envelope has no such field
    /// (`transaction.ml:273-325`), so those bytes are ones the node can
    /// never recompute. Refuse rather than silently drop: an operator who
    /// set it believes they have replay binding the chain does not give.
    #[test]
    fn call_shape_rejects_chain_id() {
        let call = serde_json::json!({
            "from": "octAAAA", "to_": "octBBBB", "amount": "0", "nonce": 1,
            "ou": "1000", "timestamp": 1_755_400_000.5f64, "op_type": "call",
            "chain_id": "octra-devnet-9871-cluster",
        });
        let err = canonical_tx_from_call(&call).expect_err("must reject");
        assert!(err.contains("chain_id"), "{err}");
    }

    #[test]
    fn preimage_has_no_chain_id() {
        assert!(!fixture().signing_preimage().contains("chain_id"));
    }

    /// The tx hash is a DIFFERENT document from the signing preimage:
    /// `signature` sits between `timestamp` and `op_type`, and the three
    /// optional fields always appear at the tail, `null` when absent.
    #[test]
    fn tx_hash_is_not_the_signing_preimage() {
        let tx = fixture();
        let h = tx.tx_hash("c2ln", Some("cGs="));
        assert_eq!(h.len(), 64, "sha256 hex");
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn signed_envelope_carries_to_underscore_and_string_amounts() {
        let kp = KeyPair::from_secret_bytes(&[7u8; 32]);
        let env = fixture().signed_envelope(&kp);
        assert!(env.get("to_").is_some(), "wire key is `to_`, always");
        assert!(env.get("to").is_none());
        assert_eq!(env["amount"], serde_json::json!("100"));
        assert_eq!(env["ou"], serde_json::json!("1000"));
        assert!(env["nonce"].is_u64(), "nonce stays a bare int");
        assert!(env.get("signature").and_then(Value::as_str).is_some());
        assert!(env.get("public_key").and_then(Value::as_str).is_some());
        assert!(env.get("chain_id").is_none());
    }

    /// Anti-drift guard for the mirror. Reads the authoritative file out
    /// of the sibling `octra` checkout and compares the shared body. When
    /// the sibling is not present — a CI job that clones only this repo —
    /// the test SKIPS loudly instead of failing.
    #[test]
    fn mirror_has_not_drifted_from_octravpn_core() {
        let Some(upstream) = upstream_tx_signer_source() else {
            eprintln!(
                "SKIP mirror_has_not_drifted_from_octravpn_core: sibling checkout \
                 ../octra/crates/octravpn-core/src/tx_signer.rs not found. \
                 The mirror is unverified in this build; run this test in a \
                 workspace where both repos are checked out."
            );
            return;
        };
        let ours = include_str!("canonical_tx.rs");
        // Compare from the first item declaration (past both headers and
        // the differing `use` blocks) to the start of each file's tests.
        let cut = |s: &str| -> String {
            let start = s
                .find("// Native op_type strings accepted by the node")
                .expect("both files carry the op_type constant block");
            let end = s.find("#[cfg(test)]").expect("both files have tests");
            s[start..end].to_string()
        };
        assert_eq!(
            cut(ours),
            cut(&upstream),
            "octra-chain-backend/src/canonical_tx.rs has drifted from \
             octravpn-core/src/tx_signer.rs. The signer is byte-critical: \
             re-sync the mirror (the authoritative copy is octravpn-core's)."
        );
    }

    fn upstream_tx_signer_source() -> Option<String> {
        // CARGO_MANIFEST_DIR = <...>/octra-foundry/crates/octra-chain-backend
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let sibling = manifest
            .parent()? // crates
            .parent()? // octra-foundry
            .parent()? // dev root
            .join("octra/crates/octravpn-core/src/tx_signer.rs");
        std::fs::read_to_string(sibling).ok()
    }
}

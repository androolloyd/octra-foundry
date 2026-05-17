//! Circle primitive helpers — Octra "Circles" (Isolated Execution
//! Environments) wire format.
//!
//! Mirrors the reference JS impl shipped in `octra-labs/webcli`
//! commit `f9c73e1` (`static/circles.html`). Surface here is:
//!
//!   - [`circle_id_of_deploy`] — predict the `oct…` circle id from
//!     `(deployer, nonce, payload)` BEFORE submitting the deploy tx.
//!     Equivalent of EVM `CREATE2`.
//!   - [`resource_key`]         — content-addressed key for an
//!     encrypted asset inside a circle, used by the by-key RPC so
//!     the path stays private from chain observers.
//!   - [`default_deploy_payload`] — the defaults the webcli ships
//!     when the user clicks "deploy" without overriding fields.
//!
//! Tag framing is TupleHash-style:
//!
//! ```text
//! h256(tag, parts) = sha256( utf8(tag) || 0x00
//!                          || (u32be(len(p)) || p) for p in parts )
//! ```
//!
//! The "circle_id" then base58-encodes the 32-byte seed, cycles the
//! result up to 44 chars (matches the JS quirk), and prefixes the
//! literal `oct` so the id looks just like an Octra wallet address.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `h256_raw('tag', parts) -> [u8; 32]` — the TupleHash-style framed
/// SHA-256 used everywhere in the circles wire format.
pub fn h256_raw(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0u8]);
    for p in parts {
        let len = u32::try_from(p.len()).expect("part length fits in u32");
        hasher.update(len.to_be_bytes());
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// Hex-encoded variant of [`h256_raw`] (matches `h256Hex` in the
/// reference JS).
pub fn h256_hex(tag: &str, parts: &[&[u8]]) -> String {
    hex::encode(h256_raw(tag, parts))
}

/// Resource key for an encrypted asset inside a circle. Use the
/// `circle_asset_ciphertext_by_resource_key` RPC with this so chain
/// observers can't see which `canonical_path` you requested.
pub fn resource_key(circle_id: &str, canonical_path: &str) -> String {
    h256_hex(
        "octra:circle_resource_key:v1",
        &[circle_id.as_bytes(), canonical_path.as_bytes()],
    )
}

/// The 32 MiB / 64 KiB limits the webcli ships by default.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeployLimits {
    pub max_stable_bytes: String,
    pub max_assets_bytes: String,
    pub max_inline_value: String,
    pub max_wasm_bytes: String,
}

impl Default for DeployLimits {
    fn default() -> Self {
        Self {
            max_stable_bytes: "33554432".into(),
            max_assets_bytes: "33554432".into(),
            max_inline_value: "65536".into(),
            max_wasm_bytes: "33554432".into(),
        }
    }
}

/// The deploy payload. Field order here matches the reference JS
/// `payload` object so `serde_json::to_string` produces the same
/// canonical bytes that `JSON.stringify(payload)` produces — the
/// payload-hash agrees byte-for-byte. Optional fields serialize as
/// explicit `null` (not omitted) for the same reason.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircleDeployPayload {
    pub runtime: String,
    pub privacy_class: String,
    pub browser_mode: String,
    pub resource_mode: String,
    pub code_b64: Option<String>,
    pub policy_hash: Option<String>,
    pub members_root: Option<String>,
    pub export_policy: Option<String>,
    pub limits: DeployLimits,
}

impl Default for CircleDeployPayload {
    fn default() -> Self {
        Self {
            runtime: "octb".into(),
            privacy_class: "sealed".into(),
            browser_mode: "native_sealed".into(),
            resource_mode: "sealed_read".into(),
            code_b64: None,
            policy_hash: None,
            members_root: None,
            export_policy: None,
            limits: DeployLimits::default(),
        }
    }
}

/// What the JS sends when the user clicks "deploy" with no overrides.
pub fn default_deploy_payload() -> CircleDeployPayload {
    CircleDeployPayload::default()
}

/// Canonical JSON of the deploy payload — byte-equivalent to the
/// reference JS `JSON.stringify(payload)`. Field order is pinned by
/// the struct definition (serde derives preserve source order); the
/// inner `limits` object is similarly source-ordered.
pub fn canonical_payload_json(payload: &CircleDeployPayload) -> String {
    serde_json::to_string(payload).expect("payload serializable")
}

/// Predict the circle id from `(deployer, nonce, payload)`. Match
/// the reference JS `circleIdOfDeploy` byte-for-byte: returns an
/// `oct…` string padded/cycled to 47 chars total ("oct" + 44 base58).
pub fn circle_id_of_deploy(
    deployer: &str,
    nonce: u64,
    payload: &CircleDeployPayload,
) -> String {
    let payload_json = canonical_payload_json(payload);
    let payload_hash_hex = h256_hex("octra:circle_deploy_payload:v1", &[payload_json.as_bytes()]);
    let seed = h256_raw(
        "octra:circle_deploy_id:v1",
        &[
            deployer.as_bytes(),
            &nonce.to_be_bytes(),
            payload_hash_hex.as_bytes(),
        ],
    );
    let b58 = bs58::encode(seed).into_string();
    let part = if b58.len() >= 44 {
        b58[..44].to_string()
    } else if b58.is_empty() {
        "1".repeat(44)
    } else {
        let need = (44 - b58.len() + b58.len() - 1) / b58.len();
        let mut s = b58.clone();
        for _ in 0..need {
            s.push_str(&b58);
        }
        s[..44].to_string()
    };
    format!("oct{part}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h256_raw_is_deterministic_and_tag_separated() {
        let a = h256_raw("tag.a", &[b"hello".as_slice()]);
        let b = h256_raw("tag.b", &[b"hello".as_slice()]);
        let a2 = h256_raw("tag.a", &[b"hello".as_slice()]);
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefix_means_concat_does_not_collide() {
        // ['ab', 'cd'] must not hash to the same thing as ['abcd'].
        let split = h256_raw("t", &[b"ab".as_slice(), b"cd".as_slice()]);
        let joined = h256_raw("t", &[b"abcd".as_slice()]);
        assert_ne!(split, joined);
    }

    #[test]
    fn resource_key_matches_js_shape() {
        let k = resource_key("oct1234", "/index.html");
        assert_eq!(k.len(), 64); // hex of 32-byte sha256
    }

    #[test]
    fn default_payload_canonical_json_includes_nulls() {
        let p = CircleDeployPayload::default();
        let j = canonical_payload_json(&p);
        eprintln!("canonical_payload_json -> {j}");
        // Mirror the JS payload field order + explicit nulls. We
        // can't easily test byte-for-byte against the JS without a
        // captured reference; sanity-check the structure instead.
        assert!(j.starts_with(r#"{"runtime":"octb""#), "got: {j}");
        assert!(j.contains(r#""code_b64":null"#));
        assert!(j.contains(r#""policy_hash":null"#));
        assert!(j.contains(r#""members_root":null"#));
        assert!(j.contains(r#""export_policy":null"#));
        assert!(j.contains(r#""limits":{"max_stable_bytes":"33554432""#));
    }

    #[test]
    fn circle_id_is_oct_prefixed_47_chars() {
        let id = circle_id_of_deploy(
            "oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm",
            1,
            &CircleDeployPayload::default(),
        );
        assert!(id.starts_with("oct"));
        assert_eq!(id.len(), 47); // "oct" + 44 chars
    }

    #[test]
    fn circle_id_changes_with_nonce() {
        let p = CircleDeployPayload::default();
        let id1 = circle_id_of_deploy("octABC", 1, &p);
        let id2 = circle_id_of_deploy("octABC", 2, &p);
        assert_ne!(id1, id2);
    }
}

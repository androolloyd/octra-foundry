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

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Sealed-asset envelope magic prefix (matches webcli `sealedMagic`).
const SEALED_MAGIC: &[u8; 5] = b"OCRS1";
/// PBKDF2-SHA256 iteration count, matches reference webcli.
const PBKDF2_ITERS: u32 = 120_000;
/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

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
pub fn circle_id_of_deploy(deployer: &str, nonce: u64, payload: &CircleDeployPayload) -> String {
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
        let need = (44 - b58.len()).div_ceil(b58.len());
        let mut s = b58.clone();
        for _ in 0..need {
            s.push_str(&b58);
        }
        s[..44].to_string()
    };
    format!("oct{part}")
}

// ============================================================
// Sealed asset envelope (sealed_read circles)
// ============================================================

/// Padding class for sealed assets. Matches webcli `paddingClass`.
/// `None` means no padding (frame ships at its natural length).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PaddingClass {
    None,
    K4,
    K16,
    K32,
    K128,
}

impl PaddingClass {
    /// `None`, "4k", "16k", "32k", "128k" — case-insensitive.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "" | "none" => Self::None,
            "4k" => Self::K4,
            "16k" => Self::K16,
            "32k" => Self::K32,
            "128k" => Self::K128,
            _ => return None,
        })
    }

    /// String form used in the on-chain `padding_class` field. Empty
    /// string for `None` so the asset_put_encrypted message just
    /// omits it via `if !padding_class.empty()`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::K4 => "4k",
            Self::K16 => "16k",
            Self::K32 => "32k",
            Self::K128 => "128k",
        }
    }

    fn target_bytes(self) -> usize {
        match self {
            Self::None => 0,
            Self::K4 => 4096,
            Self::K16 => 16_384,
            Self::K32 => 32_768,
            Self::K128 => 131_072,
        }
    }
}

/// Frame the plaintext with a u32be length prefix, then pad to the
/// requested class with random bytes. Matches webcli `paddedFrame`.
fn padded_frame(plaintext: &[u8], padding: PaddingClass) -> Vec<u8> {
    let mut bare = Vec::with_capacity(4 + plaintext.len());
    let len = u32::try_from(plaintext.len()).expect("plaintext < 4 GiB");
    bare.extend_from_slice(&len.to_be_bytes());
    bare.extend_from_slice(plaintext);
    let target = padding.target_bytes();
    if target == 0 {
        return bare;
    }
    let aligned = bare.len().div_ceil(target) * target;
    if aligned <= bare.len() {
        return bare;
    }
    let pad = aligned - bare.len();
    let mut out = bare;
    let start = out.len();
    out.resize(start + pad, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
    out
}

/// Derive the AES-GCM read-key for an `(circle_id, key_id, passphrase)`
/// tuple. Matches the webcli `deriveReadKey`:
///
/// ```text
/// salt = "octra:circle:sealed_read:v1:" + circle_id + ":" + key_id
/// key  = PBKDF2-HMAC-SHA256(passphrase, salt, 120_000, 32)
/// ```
///
/// The return type is `Zeroizing<[u8; 32]>` so callers can't
/// accidentally leak the AES-256 key by copying it into a plain
/// `[u8; 32]`. `Zeroizing` derefs to `[u8; 32]`, so existing call
/// sites that pass `&*key` to `Aes256Gcm::new_from_slice` keep
/// working unchanged.
pub fn derive_sealed_read_key(
    circle_id: &str,
    key_id: &str,
    passphrase: &str,
) -> Zeroizing<[u8; 32]> {
    let salt = format!("octra:circle:sealed_read:v1:{circle_id}:{key_id}");
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<sha2::Sha256>(
        passphrase.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERS,
        &mut *key,
    );
    key
}

/// Encrypt a plaintext blob into the sealed-asset envelope format.
/// Returns `(ciphertext_b64, plaintext_hash_hex)` — exactly the two
/// fields the `circle_asset_put_encrypted` tx needs.
///
/// Envelope wire: `"OCRS1" || nonce[12] || AES-GCM(key, nonce, paddedFrame(plaintext))`.
pub fn encrypt_sealed_bytes(
    circle_id: &str,
    key_id: &str,
    passphrase: &str,
    plaintext: &[u8],
    padding: PaddingClass,
) -> Result<(String, String)> {
    let key = derive_sealed_read_key(circle_id, key_id, passphrase);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|e| anyhow!("aes key: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let frame = padded_frame(plaintext, padding);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &frame,
                aad: &[],
            },
        )
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;
    let mut envelope = Vec::with_capacity(SEALED_MAGIC.len() + NONCE_LEN + ct.len());
    envelope.extend_from_slice(SEALED_MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ct);
    Ok((B64.encode(envelope), hex::encode(Sha256::digest(plaintext))))
}

/// Inverse of [`encrypt_sealed_bytes`]. Verifies the plaintext hash
/// matches the metadata.
pub fn decrypt_sealed_bytes(
    circle_id: &str,
    key_id: &str,
    passphrase: &str,
    ciphertext_b64: &str,
    expected_plaintext_hash_hex: &str,
) -> Result<Vec<u8>> {
    let envelope = B64
        .decode(ciphertext_b64.trim())
        .context("base64 decode envelope")?;
    if envelope.len() < SEALED_MAGIC.len() + NONCE_LEN {
        return Err(anyhow!("sealed envelope too short"));
    }
    if &envelope[..SEALED_MAGIC.len()] != SEALED_MAGIC {
        return Err(anyhow!("invalid sealed envelope magic"));
    }
    let nonce_bytes = &envelope[SEALED_MAGIC.len()..SEALED_MAGIC.len() + NONCE_LEN];
    let cipher_bytes = &envelope[SEALED_MAGIC.len() + NONCE_LEN..];
    let key = derive_sealed_read_key(circle_id, key_id, passphrase);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|e| anyhow!("aes key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let frame = cipher
        .decrypt(
            nonce,
            Payload {
                msg: cipher_bytes,
                aad: &[],
            },
        )
        .map_err(|e| anyhow!("aes-gcm decrypt (wrong passphrase / key_id / circle_id?): {e}"))?;
    if frame.len() < 4 {
        return Err(anyhow!("frame too short"));
    }
    let plain_len = u32::from_be_bytes(frame[..4].try_into().expect("4-byte prefix")) as usize;
    if plain_len > frame.len() - 4 {
        return Err(anyhow!("frame length prefix exceeds payload"));
    }
    let plaintext = frame[4..4 + plain_len].to_vec();
    let actual_hash = hex::encode(Sha256::digest(&plaintext));
    if !actual_hash.eq_ignore_ascii_case(expected_plaintext_hash_hex.trim()) {
        return Err(anyhow!(
            "plaintext hash mismatch (got {actual_hash}, expected {expected_plaintext_hash_hex})"
        ));
    }
    Ok(plaintext)
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

    #[test]
    fn sealed_envelope_roundtrips() {
        let plaintext = b"hello operator policy";
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            "octABC",
            "default",
            "correct horse battery staple",
            plaintext,
            PaddingClass::None,
        )
        .expect("encrypt");
        let recovered = decrypt_sealed_bytes(
            "octABC",
            "default",
            "correct horse battery staple",
            &ct_b64,
            &ph_hex,
        )
        .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn sealed_envelope_wrong_passphrase_fails() {
        let (ct, ph) =
            encrypt_sealed_bytes("octABC", "k1", "right", b"secret", PaddingClass::K4).unwrap();
        assert!(decrypt_sealed_bytes("octABC", "k1", "wrong", &ct, &ph).is_err());
    }

    #[test]
    fn sealed_envelope_starts_with_magic() {
        let (ct_b64, _) = encrypt_sealed_bytes("c", "k", "p", b"x", PaddingClass::None).unwrap();
        let bytes = B64.decode(ct_b64).unwrap();
        assert_eq!(&bytes[..5], b"OCRS1");
    }

    #[test]
    fn padding_class_round_trip() {
        for s in ["", "4k", "16k", "32k", "128k"] {
            let pc = PaddingClass::from_str_opt(s).unwrap();
            assert_eq!(pc.as_str(), if s == "none" { "" } else { s });
        }
        assert!(PaddingClass::from_str_opt("bogus").is_none());
    }

    #[test]
    fn padded_frame_pads_to_class() {
        let bare = padded_frame(b"hi", PaddingClass::None);
        assert_eq!(bare.len(), 6); // u32be(2) + "hi"
        let padded = padded_frame(b"hi", PaddingClass::K4);
        assert_eq!(padded.len(), 4096);
        let oversize = padded_frame(&vec![0u8; 5000], PaddingClass::K4);
        assert_eq!(oversize.len(), 8192); // aligned up to next 4k boundary
    }

    // ====================================================================
    // Property-based harness (mirrors the would-be Kani harnesses; today
    // shipped as proptest since Kani is not installed — see verify.rs).
    // ====================================================================
    use proptest::prelude::*;

    /// Strategy for ASCII tag strings — Kani-friendly small bound.
    fn small_tag() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_:.\\-]{1,16}".prop_map(String::from)
    }

    fn small_part() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=8)
    }

    fn small_parts() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(small_part(), 0..=3)
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // 4096 cases is overkill for the cheap hash properties but
            // each `prop_sealed_envelope_*` triggers two PBKDF2-SHA256
            // rounds at 120k iters and a real AES-GCM operation, so the
            // budget below is split: pure-hash properties take this
            // big case count, the AEAD properties override locally.
            cases: 4096,
            // Tight-enough rejection limit that filter-heavy strategies
            // don't gobble all the budget.
            max_global_rejects: 200_000,
            .. ProptestConfig::default()
        })]

        /// h256_raw is a *function* — equal inputs ⇒ equal outputs.
        /// (Proves no nondeterminism from internal state.)
        #[test]
        fn prop_h256_raw_deterministic(
            tag in small_tag(),
            parts in small_parts(),
        ) {
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let a = h256_raw(&tag, &refs);
            let b = h256_raw(&tag, &refs);
            prop_assert_eq!(a, b);
        }

        /// Tag separation: different tags on the same parts ⇒
        /// different digests (catches the framing bug class).
        #[test]
        fn prop_h256_raw_tag_separated(
            t1 in small_tag(),
            t2 in small_tag(),
            parts in small_parts(),
        ) {
            prop_assume!(t1 != t2);
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            prop_assert_ne!(h256_raw(&t1, &refs), h256_raw(&t2, &refs));
        }

        /// **Framing property**: the length-prefix means that the parts
        /// list isn't equivalent to its concatenation. This is the
        /// property that caught the v1.1 missing-length-prefix bug.
        ///
        /// We test it for *all* non-trivial splits: any split-point
        /// `i` in `1..bytes.len()` must produce a different digest
        /// than the whole as a single part.
        #[test]
        fn prop_h256_raw_split_doesnt_collide_with_joined(
            tag in small_tag(),
            bytes in prop::collection::vec(any::<u8>(), 2..=16),
            split in 1usize..16,
        ) {
            let split = split.min(bytes.len() - 1).max(1);
            let (l, r) = bytes.split_at(split);
            let joined = h256_raw(&tag, &[bytes.as_slice()]);
            let parts: [&[u8]; 2] = <[&[u8]; 2]>::from((l, r));
            let split_h = h256_raw(&tag, &parts);
            prop_assert_ne!(joined, split_h);
        }

        /// `circle_id_of_deploy` is deterministic.
        #[test]
        fn prop_circle_id_of_deploy_determinism(
            deployer in "[a-zA-Z0-9]{1,32}",
            nonce in 0u64..u64::MAX,
        ) {
            let p = CircleDeployPayload::default();
            let a = circle_id_of_deploy(&deployer, nonce, &p);
            let b = circle_id_of_deploy(&deployer, nonce, &p);
            prop_assert_eq!(a, b);
        }

        /// Different (deployer, nonce) ⇒ different circle id (with
        /// astronomical probability — SHA-256 collision boundary).
        #[test]
        fn prop_circle_id_distinct_inputs(
            d1 in "[a-zA-Z0-9]{4,32}",
            d2 in "[a-zA-Z0-9]{4,32}",
            n1 in 0u64..u64::MAX,
            n2 in 0u64..u64::MAX,
        ) {
            prop_assume!(d1 != d2 || n1 != n2);
            let p = CircleDeployPayload::default();
            prop_assert_ne!(
                circle_id_of_deploy(&d1, n1, &p),
                circle_id_of_deploy(&d2, n2, &p),
            );
        }

        /// circle_id is always 47 chars and starts with "oct".
        #[test]
        fn prop_circle_id_shape(
            deployer in "[a-zA-Z0-9]{1,64}",
            nonce in 0u64..u64::MAX,
        ) {
            let id = circle_id_of_deploy(&deployer, nonce, &CircleDeployPayload::default());
            prop_assert_eq!(id.len(), 47);
            prop_assert!(id.starts_with("oct"));
        }

        /// padded_frame length invariants:
        ///   1) output length is always >= 4 + plaintext.len()
        ///   2) when class != None, output is aligned to target_bytes
        ///   3) when class == None, output is *exactly* 4 + plaintext.len()
        #[test]
        fn prop_padded_frame_length_invariant(
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
            class_idx in 0u32..5,
        ) {
            let class = match class_idx {
                0 => PaddingClass::None,
                1 => PaddingClass::K4,
                2 => PaddingClass::K16,
                3 => PaddingClass::K32,
                _ => PaddingClass::K128,
            };
            let out = padded_frame(&plaintext, class);
            prop_assert!(out.len() >= 4 + plaintext.len());
            let target = class.target_bytes();
            if target == 0 {
                prop_assert_eq!(out.len(), 4 + plaintext.len());
            } else {
                // Aligned to target.
                prop_assert!(out.len() % target == 0 || out.len() == 4 + plaintext.len());
            }
            // The length prefix is the real plaintext length.
            let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
            prop_assert_eq!(len, plaintext.len());
            // The plaintext slice survives at the front.
            prop_assert_eq!(&out[4..4 + plaintext.len()], &plaintext[..]);
        }

    }

    // ----- Slow AEAD harness block. Each iteration drives two PBKDF2-
    // -----  SHA256-120k key derivations + an AES-GCM round-trip, so we
    // -----  intentionally run only ~32 cases per property to keep CI
    // -----  time reasonable. The shape of the property is the same;
    // -----  the proptest budget is just lower.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            max_global_rejects: 200_000,
            .. ProptestConfig::default()
        })]

        /// **The sealed-envelope round-trip property** — bounded-size
        /// fuzz. Any (plaintext, passphrase, padding) ⇒
        /// decrypt(encrypt(...)) = plaintext.
        #[test]
        fn prop_sealed_envelope_roundtrip(
            plaintext in prop::collection::vec(any::<u8>(), 0..=256),
            passphrase in "[ -~]{0,32}",
            class_idx in 0u32..5,
        ) {
            let class = match class_idx {
                0 => PaddingClass::None,
                1 => PaddingClass::K4,
                2 => PaddingClass::K16,
                3 => PaddingClass::K32,
                _ => PaddingClass::K128,
            };
            let (ct, ph) = encrypt_sealed_bytes(
                "octABC", "default", &passphrase, &plaintext, class,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let got = decrypt_sealed_bytes(
                "octABC", "default", &passphrase, &ct, &ph,
            ).map_err(|e| TestCaseError::fail(format!("decrypt: {e}")))?;
            prop_assert_eq!(got, plaintext);
        }

        /// Wrong passphrase MUST fail decryption — no false-positive
        /// decrypts permitted.
        #[test]
        fn prop_sealed_envelope_wrong_passphrase_always_fails(
            plaintext in prop::collection::vec(any::<u8>(), 1..=256),
            correct in "[ -~]{1,32}",
            wrong in "[ -~]{1,32}",
        ) {
            prop_assume!(correct != wrong);
            let (ct, ph) = encrypt_sealed_bytes(
                "octABC", "default", &correct, &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let r = decrypt_sealed_bytes(
                "octABC", "default", &wrong, &ct, &ph,
            );
            prop_assert!(r.is_err(), "wrong passphrase decrypted!");
        }

        /// Wrong key_id MUST fail decryption — different key_id
        /// derives a different AES-GCM key.
        #[test]
        fn prop_sealed_envelope_wrong_key_id_always_fails(
            plaintext in prop::collection::vec(any::<u8>(), 1..=256),
            kid1 in "[a-zA-Z0-9_-]{1,16}",
            kid2 in "[a-zA-Z0-9_-]{1,16}",
        ) {
            prop_assume!(kid1 != kid2);
            let (ct, ph) = encrypt_sealed_bytes(
                "octABC", &kid1, "passphrase", &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let r = decrypt_sealed_bytes(
                "octABC", &kid2, "passphrase", &ct, &ph,
            );
            prop_assert!(r.is_err(), "wrong key_id decrypted!");
        }

        /// Wrong circle_id MUST fail decryption — different circle
        /// derives a different AES-GCM key (the salt baked into
        /// derive_sealed_read_key changes).
        #[test]
        fn prop_sealed_envelope_wrong_circle_id_always_fails(
            plaintext in prop::collection::vec(any::<u8>(), 1..=256),
            c1 in "[a-zA-Z0-9]{4,16}",
            c2 in "[a-zA-Z0-9]{4,16}",
        ) {
            prop_assume!(c1 != c2);
            let (ct, ph) = encrypt_sealed_bytes(
                &c1, "default", "passphrase", &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let r = decrypt_sealed_bytes(
                &c2, "default", "passphrase", &ct, &ph,
            );
            prop_assert!(r.is_err(), "wrong circle_id decrypted!");
        }

        /// **Magic prefix property.** Every sealed envelope starts
        /// with the OCRS1 magic and has the documented byte structure.
        #[test]
        fn prop_sealed_envelope_starts_with_magic(
            plaintext in prop::collection::vec(any::<u8>(), 0..=128),
            passphrase in "[ -~]{0,16}",
        ) {
            let (ct_b64, _) = encrypt_sealed_bytes(
                "octABC", "kid", &passphrase, &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let raw = B64.decode(ct_b64)
                .map_err(|e| TestCaseError::fail(format!("b64: {e}")))?;
            prop_assert!(raw.len() >= 5 + 12, "envelope too short");
            prop_assert_eq!(&raw[..5], b"OCRS1");
        }

        /// **The tamper-detection property.** Flipping any single
        /// bit in the AES-GCM portion of the envelope MUST cause
        /// decryption to fail (AEAD authenticity).
        ///
        /// Bounded to small plaintexts so the proptest budget is sane.
        #[test]
        fn prop_sealed_envelope_rejects_single_bit_flip(
            plaintext in prop::collection::vec(any::<u8>(), 1..=64),
            flip_idx in 0usize..200,
        ) {
            let (ct_b64, ph) = encrypt_sealed_bytes(
                "octABC", "kid", "passphrase", &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            let mut raw = B64.decode(&ct_b64)
                .map_err(|e| TestCaseError::fail(format!("b64: {e}")))?;
            // Skip the OCRS1 magic prefix — flipping inside it triggers
            // a different (also-failing) code path; not the property we
            // care about. Stay within the ciphertext + tag region.
            let lo = 5usize; // after magic
            if raw.len() <= lo + 1 { return Ok(()); }
            let idx = lo + (flip_idx % (raw.len() - lo));
            raw[idx] ^= 0x01;
            let tampered = B64.encode(&raw);
            let r = decrypt_sealed_bytes("octABC", "kid", "passphrase", &tampered, &ph);
            prop_assert!(r.is_err(), "single-bit flip at byte {idx} decrypted!");
        }

        /// **Plaintext-hash binding property.** decrypt_sealed_bytes
        /// MUST reject when the caller-supplied plaintext_hash does
        /// not match the recovered plaintext's actual hash. Otherwise
        /// the wire commitment to the plaintext is unenforced.
        #[test]
        fn prop_sealed_envelope_rejects_wrong_plaintext_hash(
            plaintext in prop::collection::vec(any::<u8>(), 1..=128),
            tweak in prop::array::uniform32(any::<u8>()),
        ) {
            let (ct, ph) = encrypt_sealed_bytes(
                "octABC", "kid", "passphrase", &plaintext, PaddingClass::None,
            ).map_err(|e| TestCaseError::fail(format!("encrypt: {e}")))?;
            // Construct a "wrong" hash: hex of the random 32 bytes.
            // With astronomical probability this is != `ph`.
            let wrong = hex::encode(tweak);
            prop_assume!(wrong != ph);
            let r = decrypt_sealed_bytes("octABC", "kid", "passphrase", &ct, &wrong);
            prop_assert!(r.is_err(), "wrong plaintext_hash accepted!");
        }
    }
}

//! `cast register-pvac` — sign + submit `octra_registerPvacPubkey`.
//!
//! The chain's HFHE pubkey registry is populated **only** by the
//! per-wallet off-chain RPC `octra_registerPvacPubkey(addr, pk_b64,
//! sig_b64, wallet_pub_b64, kat_hex)`. The `sig` is an ed25519
//! signature over the canonical string
//!
//! ```text
//! "register_pvac|" + addr + "|" + sha256_hex(pk_blob_decoded)
//! ```
//!
//! produced by the ed25519 secret key for `addr`. Because contracts
//! and circles have no keypair, this RPC is wallet-only — see
//! `~/.claude/projects/.../memory/octra_hfhe_pubkey_per_wallet.md`
//! for the chain-side rationale and the v2 AML patch that routes
//! `fhe_load_pk` through `circles[c].owner`.
//!
//! Compared to the canonical C++ implementation in
//! `octra-labs/webcli/lib/tx_builder.hpp` (GPL'd, vendored), this is
//! a clean Rust reimplementation using only the (ed25519-dalek, sha2,
//! base64) stack that `octra-core` already brings in. Nothing here
//! borrows from GPL sources; the wire format is documented protocol
//! and re-implementable from the spec alone.
//!
//! ## Wire shape
//!
//! Request:
//!
//! ```json
//! {"jsonrpc":"2.0","id":1,"method":"octra_registerPvacPubkey",
//!  "params":[addr, pvac_pk_b64, sig_b64, wallet_pub_b64, kat_hex_or_empty]}
//! ```
//!
//! All five params are strings. `kat_hex` is an optional Known-Answer
//! Test hex blob; passing the empty string keeps the field present
//! and tells the chain "no KAT". The chain validates the signature
//! against `wallet_pub_b64`, then stores `pvac_pk_b64` keyed by `addr`.
//!
//! ## What this command does not validate
//!
//! - The PVAC pubkey blob is treated as opaque bytes. We compute its
//!   sha256 and forward it as-is. The chain checks well-formedness.
//! - The KAT blob (if supplied) is also opaque. We forward it
//!   verbatim as a hex string.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use octra_core::{address::Address, sig::KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{io as cio, rpc_client};

/// CLI args for `cast register-pvac`.
#[derive(Args, Debug)]
pub struct RegisterPvacArgs {
    /// Wallet key file (hex-encoded 32-byte ed25519 secret).
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: std::path::PathBuf,

    /// PVAC pubkey blob, base64-encoded. Comes from the operator's
    /// PVAC keygen sidecar — its internal structure is opaque to this
    /// command.
    #[arg(long = "pvac-pk")]
    pub pvac_pk: String,

    /// Optional KAT (Known-Answer Test) blob, hex-encoded. Passed
    /// through to the RPC as the final positional param. When omitted
    /// we send the empty string (the wire shape always has 5 params).
    #[arg(long = "kat-hex")]
    pub kat_hex: Option<String>,

    /// JSON-RPC endpoint to submit to.
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,

    /// Build + sign the request but do not submit. Prints the signed
    /// envelope (and the canonical message it was signed over) as
    /// JSON — useful for review or for piping into a different
    /// transport.
    #[arg(long, default_value_t = false)]
    pub print_only: bool,
}

/// The signed, ready-to-submit registration request.
///
/// Kept as a struct (not a free-form JSON Value) so tests can assert
/// on individual fields without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRegistration {
    pub addr: String,
    pub pvac_pk_b64: String,
    pub sig_b64: String,
    pub wallet_pub_b64: String,
    pub kat_hex: String,
    /// The exact UTF-8 message that was signed; surfaced so tests
    /// can assert byte-for-byte against the spec.
    pub canonical_message: String,
    /// The sha256 hex of the decoded `pvac_pk` blob, exposed for
    /// debugging.
    pub pvac_pk_sha256_hex: String,
}

impl SignedRegistration {
    /// JSON-RPC `params` array, in canonical order.
    pub fn to_params(&self) -> Value {
        json!([
            &self.addr,
            &self.pvac_pk_b64,
            &self.sig_b64,
            &self.wallet_pub_b64,
            &self.kat_hex,
        ])
    }

    /// Full pretty JSON suitable for `--print-only`. Includes the
    /// canonical message so reviewers can verify what was signed
    /// without rebuilding the string themselves.
    pub fn to_debug_json(&self) -> Value {
        json!({
            "method": "octra_registerPvacPubkey",
            "params": self.to_params(),
            "addr": &self.addr,
            "wallet_pub_b64": &self.wallet_pub_b64,
            "pvac_pk_b64": &self.pvac_pk_b64,
            "pvac_pk_sha256_hex": &self.pvac_pk_sha256_hex,
            "sig_b64": &self.sig_b64,
            "kat_hex": &self.kat_hex,
            "canonical_message": &self.canonical_message,
        })
    }
}

/// Build the signed registration without touching the network.
///
/// `pvac_pk_b64_in` and `kat_hex_in` are passed through verbatim
/// after a base64 / hex *decode-validation* step:
///
/// - `pvac_pk_b64_in` must decode as valid standard base64; otherwise
///   the chain would reject it on submit, so we fail early.
/// - `kat_hex_in` must decode as hex when non-empty; same reasoning.
pub fn build_signed_registration(
    key_path: &Path,
    pvac_pk_b64_in: &str,
    kat_hex_in: Option<&str>,
) -> Result<SignedRegistration> {
    use zeroize::Zeroize;

    let mut secret = cio::read_secret_hex(key_path)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    secret.zeroize();

    let pvac_pk_b64 = pvac_pk_b64_in.trim().to_string();
    if pvac_pk_b64.is_empty() {
        return Err(anyhow!("--pvac-pk is required and must be non-empty"));
    }
    let pvac_pk_bytes = STANDARD
        .decode(pvac_pk_b64.as_bytes())
        .context("--pvac-pk is not valid base64")?;

    let kat_hex = match kat_hex_in {
        None => String::new(),
        Some(s) => {
            let trimmed = s.trim().trim_start_matches("0x").to_string();
            if !trimmed.is_empty() {
                hex::decode(&trimmed).context("--kat-hex is not valid hex")?;
            }
            trimmed
        }
    };

    let addr = Address::from_pubkey(&kp.public.0).display().to_string();

    let pk_hash_hex = {
        let mut h = Sha256::new();
        h.update(&pvac_pk_bytes);
        hex::encode(h.finalize())
    };

    // Canonical message — **the spec**:
    //     "register_pvac|" + addr + "|" + sha256_hex(pk_blob)
    // All concatenations are utf-8 bytes; no trailing newline.
    let canonical_message = format!("register_pvac|{addr}|{pk_hash_hex}");

    let sig = kp.sign(canonical_message.as_bytes());
    let sig_b64 = STANDARD.encode(sig.0);

    // **base64**, not hex — see octra_aml_wire_format memory note:
    // ed25519_ok / AML pubkey fields take base64; only block-internal
    // serializations use hex.
    let wallet_pub_b64 = STANDARD.encode(kp.public.0);

    Ok(SignedRegistration {
        addr,
        pvac_pk_b64,
        sig_b64,
        wallet_pub_b64,
        kat_hex,
        canonical_message,
        pvac_pk_sha256_hex: pk_hash_hex,
    })
}

/// CLI entrypoint.
pub fn dispatch(args: &RegisterPvacArgs) -> Result<()> {
    let signed = build_signed_registration(
        &args.key,
        &args.pvac_pk,
        args.kat_hex.as_deref(),
    )?;

    if args.print_only {
        cio::dump_json(&signed.to_debug_json());
        return Ok(());
    }

    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let result = rpc_client::call(&endpoint, "octra_registerPvacPubkey", signed.to_params())
        .context("octra_registerPvacPubkey")?;
    cio::dump_json(&json!({
        "addr": &signed.addr,
        "pvac_pk_sha256_hex": &signed.pvac_pk_sha256_hex,
        "canonical_message": &signed.canonical_message,
        "result": result,
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for `register-pvac`. The full end-to-end submission
    //! path is covered by the integration tests in
    //! `tests/cast_register_pvac.rs`.

    use super::*;
    use octra_core::sig::{verify as ed_verify, PublicKey as OcPub, Signature as OcSig};
    use std::fs;
    use tempfile::tempdir;

    /// Known seed → deterministic keypair → deterministic registration.
    /// Locks the canonical-message format and the wire shape.
    fn fixed_keyfile(dir: &Path, name: &str, secret_hex: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        fs::write(&p, secret_hex).unwrap();
        p
    }

    /// Trivial KAT-equivalent fixture used by determinism + verify
    /// tests. The blob is arbitrary; the chain's job is to validate
    /// it, not ours.
    fn dummy_pvac_pk_b64() -> String {
        // 16 bytes, all 0xAB
        STANDARD.encode([0xABu8; 16])
    }

    #[test]
    fn deterministic_same_key_same_pk() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"11".repeat(32));
        let pk = dummy_pvac_pk_b64();
        let a = build_signed_registration(&kp, &pk, None).unwrap();
        let b = build_signed_registration(&kp, &pk, None).unwrap();
        assert_eq!(a, b, "same (key, pvac_pk) must produce identical output");
    }

    #[test]
    fn signature_verifies_under_wallet_pubkey() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"22".repeat(32));
        let pk = dummy_pvac_pk_b64();
        let reg = build_signed_registration(&kp, &pk, None).unwrap();

        let pub_bytes = STANDARD.decode(&reg.wallet_pub_b64).unwrap();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);

        let sig_bytes = STANDARD.decode(&reg.sig_b64).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ed25519 sig must be 64 bytes");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        ed_verify(
            &OcPub(pub_arr),
            reg.canonical_message.as_bytes(),
            &OcSig(sig_arr),
        )
        .expect("signature must verify under the wallet's own pubkey");
    }

    /// The canonical message MUST be exactly
    /// `"register_pvac|" + addr + "|" + sha256_hex(pk_blob)` — no
    /// trailing newline, no extra fields. Locking this is the whole
    /// point of having a per-wallet signature.
    #[test]
    fn canonical_message_format_matches_spec() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"33".repeat(32));
        let pk_bytes = [0xCDu8; 24];
        let pk_b64 = STANDARD.encode(pk_bytes);

        let reg = build_signed_registration(&kp, &pk_b64, None).unwrap();

        let mut h = Sha256::new();
        h.update(pk_bytes);
        let pk_hash = hex::encode(h.finalize());

        let expected = format!("register_pvac|{}|{}", reg.addr, pk_hash);
        assert_eq!(reg.canonical_message, expected);
        // Defensive: the hash field should also match the prefix
        // logic, so the debug JSON doesn't get out of sync with the
        // signed message.
        assert_eq!(reg.pvac_pk_sha256_hex, pk_hash);
    }

    /// `--print-only` does not touch the network: it returns a
    /// `SignedRegistration` without ever entering the rpc_client.
    /// This test inspects the produced JSON instead of calling
    /// `dispatch` (which only writes to stdout) so we can assert on
    /// individual fields.
    #[test]
    fn print_only_produces_signed_envelope_without_network() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"44".repeat(32));
        let pk = dummy_pvac_pk_b64();

        let signed = build_signed_registration(&kp, &pk, None).unwrap();
        let j = signed.to_debug_json();

        assert_eq!(j["method"], json!("octra_registerPvacPubkey"));
        let params = j["params"].as_array().unwrap();
        assert_eq!(params.len(), 5, "exactly 5 RPC params");
        assert_eq!(params[0], json!(signed.addr));
        assert_eq!(params[1], json!(signed.pvac_pk_b64));
        assert_eq!(params[2], json!(signed.sig_b64));
        assert_eq!(params[3], json!(signed.wallet_pub_b64));
        assert_eq!(params[4], json!("")); // no KAT

        // Address shape: 47 chars, `oct…` prefix — sanity check the
        // address derivation chain too.
        assert!(signed.addr.starts_with("oct"));
        assert_eq!(signed.addr.len(), 47);

        // Wallet pubkey is base64-encoded 32 bytes -> 44 chars
        // (no padding stripped).
        assert_eq!(signed.wallet_pub_b64.len(), 44);
    }

    /// KAT pass-through: when supplied, it ends up verbatim in
    /// `params[4]` (after trimming `0x` prefix + whitespace).
    #[test]
    fn kat_hex_is_passed_through_unchanged() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"55".repeat(32));
        let pk = dummy_pvac_pk_b64();
        let kat = "0xdeadbeefcafe";
        let reg = build_signed_registration(&kp, &pk, Some(kat)).unwrap();
        assert_eq!(reg.kat_hex, "deadbeefcafe");
        assert_eq!(reg.to_params()[4], json!("deadbeefcafe"));
    }

    /// Bad base64 in `--pvac-pk` should fail before signing.
    #[test]
    fn rejects_non_base64_pvac_pk() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"66".repeat(32));
        let r = build_signed_registration(&kp, "!!!this is not base64$$$", None);
        assert!(r.is_err(), "must reject non-base64 --pvac-pk");
    }

    /// Bad hex in `--kat-hex` should also fail before signing.
    #[test]
    fn rejects_non_hex_kat() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"77".repeat(32));
        let pk = dummy_pvac_pk_b64();
        let r = build_signed_registration(&kp, &pk, Some("not-hex-zzzz"));
        assert!(r.is_err(), "must reject non-hex --kat-hex");
    }

    /// Empty `--pvac-pk` fails: there's nothing to register.
    #[test]
    fn rejects_empty_pvac_pk() {
        let dir = tempdir().unwrap();
        let kp = fixed_keyfile(dir.path(), "k.hex", &"88".repeat(32));
        let r = build_signed_registration(&kp, "   ", None);
        assert!(r.is_err());
    }
}

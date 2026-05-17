//! Formal-verification harnesses for the cryptographic primitives in
//! this crate.
//!
//! ## State of the art on this machine (2026-05-17)
//!
//! Kani (https://github.com/model-checking/kani) is the upstream choice
//! for symbolic-execution-style proofs on Rust crypto primitives. It is
//! **not installed** in this environment; running `cargo kani --version`
//! returns `no such command`. The leak audit / verification task brief
//! anticipated this and asked for a proptest fallback in that case.
//!
//! Per-module property harnesses live in each module's existing
//! `#[cfg(test)] mod tests` block as `prop_*` functions (see
//! `circle.rs`, `tx.rs`, `wallet_enc.rs`, `address.rs`). They exercise
//! the same properties a Kani harness would (determinism, tag
//! separation, length-prefix framing, AEAD authenticity, envelope
//! roundtrip), just with concrete inputs sampled from `proptest`
//! strategies instead of symbolic ones.
//!
//! ## Re-enabling Kani
//!
//! When Kani lands on this machine (`cargo install --locked
//! kani-verifier && cargo kani setup`), the harnesses below become
//! live: each `#[cfg(kani)] #[kani::proof]` function compiles into a
//! goal Kani enumerates. The intended bound on each is small enough
//! that Kani can unwind it within the default 1h budget — see the
//! comments on each function.
//!
//! ## Why this module exists
//!
//! The module is empty under `#[cfg(not(kani))]`, but its mere
//! presence keeps the harness names discoverable and reviewable in
//! the source tree. CI looks for it via `scripts/verify.sh`.

#![allow(dead_code)]

#[cfg(kani)]
mod kani_harnesses {
    use crate::{
        circle::{
            canonical_payload_json, circle_id_of_deploy, decrypt_sealed_bytes,
            encrypt_sealed_bytes, h256_raw, padded_frame, CircleDeployPayload, PaddingClass,
        },
        tx::canonical_bytes,
    };

    /// h256_raw is deterministic on bounded inputs (tag ≤ 8 chars,
    /// 1 part ≤ 4 bytes). Kani can enumerate the full input space at
    /// this size in well under a minute.
    #[kani::proof]
    #[kani::unwind(5)]
    fn h256_raw_deterministic() {
        let tag_bytes: [u8; 4] = kani::any();
        let part: [u8; 4] = kani::any();
        // Make sure tag is ASCII-printable (h256_raw doesn't care, but
        // the contract says tag is a string).
        kani::assume(tag_bytes.iter().all(|b| b.is_ascii() && *b > 0x20));
        let tag = std::str::from_utf8(&tag_bytes).unwrap();
        let a = h256_raw(tag, &[&part]);
        let b = h256_raw(tag, &[&part]);
        assert_eq!(a, b);
    }

    /// **Framing property**: split([l, r]) != joined([l || r])
    /// for any bounded l, r. This catches the v1.1 missing-length-
    /// prefix class of bugs.
    #[kani::proof]
    #[kani::unwind(5)]
    fn h256_raw_split_doesnt_collide_with_joined() {
        let tag: [u8; 1] = kani::any();
        kani::assume(tag[0].is_ascii() && tag[0] > 0x20);
        let l: [u8; 2] = kani::any();
        let r: [u8; 2] = kani::any();
        let t = std::str::from_utf8(&tag).unwrap();
        let mut joined = Vec::with_capacity(4);
        joined.extend_from_slice(&l);
        joined.extend_from_slice(&r);
        assert_ne!(
            h256_raw(t, &[&l, &r]),
            h256_raw(t, &[&joined]),
        );
    }

    /// circle_id_of_deploy is deterministic.
    #[kani::proof]
    #[kani::unwind(5)]
    fn circle_id_deterministic() {
        let nonce: u64 = kani::any();
        let payload = CircleDeployPayload::default();
        // Use a fixed short deployer for bound. Kani enumerates nonce.
        let a = circle_id_of_deploy("octABC", nonce, &payload);
        let b = circle_id_of_deploy("octABC", nonce, &payload);
        assert_eq!(a, b);
    }

    /// padded_frame length invariants on a small bound.
    #[kani::proof]
    #[kani::unwind(8)]
    fn padded_frame_length_invariant() {
        let bytes: [u8; 4] = kani::any();
        let class = PaddingClass::None;
        let out = padded_frame(&bytes, class);
        // The length prefix is exact.
        assert_eq!(out.len(), 4 + bytes.len());
        let len = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(len, bytes.len());
    }

    /// canonical_bytes is a function: same input ⇒ same output.
    #[kani::proof]
    #[kani::unwind(5)]
    fn canonical_bytes_is_function() {
        let amount: u64 = kani::any();
        let nonce: u64 = kani::any();
        let tx = serde_json::json!({
            "from": "octF",
            "to_": "octT",
            "amount": amount.to_string(),
            "nonce": nonce,
            "ou": "1000",
            "timestamp": 0.0,
            "op_type": "standard",
        });
        let a = canonical_bytes(&tx).unwrap();
        let b = canonical_bytes(&tx).unwrap();
        assert_eq!(a, b);
    }
}

// Sanity entry-point so the module isn't dead code in
// `cargo test --features verification`.
#[cfg(all(not(kani), test, feature = "verification"))]
#[test]
fn verification_feature_compiles() {
    // No-op: presence of this test asserts the module compiles under
    // `--features verification`. The real coverage lives in each
    // module's `prop_*` properties.
}

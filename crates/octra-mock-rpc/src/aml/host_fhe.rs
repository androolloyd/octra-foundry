//! Honest mock implementation of Octra's HFHE AML host calls.
//!
//! # Why this exists
//!
//! The real Octra devnet currently reverts every `fhe_*` AML host call
//! (see `docs/octra-dev-questions.md` §1 and `memory/octra_aml_fhe_load_pk_blocked.md`).
//! That blocks any end-to-end exercise of the HFHE settle path that our
//! v2/v3 AML programs assume — `claim_earnings_v2` is supposed to be
//! gated by `fhe_verify_zero(pk, enc_earnings - enc(amount), proof)`,
//! but with the bridge broken the mock falls back to a plaintext
//! `balance != claimed` check.
//!
//! This module ships a **deterministic, additively-homomorphic** mock
//! HFHE scheme that is "honest enough" to:
//!
//! 1. Drive the full settle_claim_v2 → settle_confirm_v2 → claim_earnings_v2
//!    flow with real ciphertexts on the wire.
//! 2. Detect malformed ciphertexts, unregistered pubkeys, and bad
//!    zero-proofs with the same error shapes the real chain will
//!    return once its bridge is wired.
//! 3. Round-trip ciphertexts across process boundaries (deterministic
//!    serialisation, no in-memory pointers).
//!
//! # What this is NOT
//!
//! This is **not** byte-compatible with the upstream `octra-labs/HFHE`
//! ciphertext format. The real chain uses a BFV-style lattice scheme;
//! ours is "mask-by-sha256(seed‖nonce) and sum nonces on add" — an
//! information-theoretically-secure additive secret share with a public
//! mask seed, which is enough to model the algebra but obviously
//! decryptable by anyone who has the pubkey blob (the pubkey contains
//! the mask seed). The real chain's `fhe_verify_zero` checks a Schnorr
//! / sigma-protocol transcript over the BFV ciphertext; ours just
//! recomputes the prover's commitment and bit-compares. A real-chain
//! proof will NOT verify here, and vice versa — but the **shape** of
//! the host-call surface (signatures, error cases, determinism, pk
//! lookup) is the same. That makes this module the conformance test
//! for our client-side code, not for the chain.
//!
//! # Wire format
//!
//! All blobs begin with `b"OFHE"` + version byte `1` + 1-byte type tag.
//!
//! Pubkey (type `0x10`):
//!   magic(4) || ver(1) || tag(1) || addr-id(32) || mask-seed(32)
//!   = 70 bytes.
//!
//! Ciphertext (type `0x20`):
//!   magic(4) || ver(1) || tag(1) || pk-id(32) || masked-value(8 LE)
//!   || nonce-count(4 LE) || nonces(16 × n)
//!
//! ZeroProof (type `0x30`):
//!   magic(4) || ver(1) || tag(1) || pk-id(32) || claimed-value(8 LE,
//!   always 0) || commitment(32)
//!
//! # Determinism
//!
//! Every operation is a pure function of its inputs — `keygen_for_addr`
//! derives the mask seed from `sha256(b"OFHE|seed|v1" || addr_bytes)`,
//! `encrypt_const` derives the nonce from `sha256(b"OFHE|nonce|v1" ||
//! pk_id || value_le)`. No system randomness. Same inputs → byte-
//! identical outputs.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

pub const FHE_MAGIC: &[u8; 4] = b"OFHE";
pub const FHE_VERSION: u8 = 1;
pub const TAG_PK: u8 = 0x10;
pub const TAG_CT: u8 = 0x20;
pub const TAG_ZP: u8 = 0x30;

pub const PK_BLOB_LEN: usize = 4 + 1 + 1 + 32 + 32; // 70
pub const ZP_BLOB_LEN: usize = 4 + 1 + 1 + 32 + 8 + 32; // 78
const CT_HEADER_LEN: usize = 4 + 1 + 1 + 32 + 8 + 4; // 50
const NONCE_LEN: usize = 16;

/// Error returned by every honest HFHE host call. The string payload is
/// the same shape (`fhe: ...`) the real chain returns once its bridge
/// lands, so error-path tests on the client side can be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FheError(pub String);

impl std::fmt::Display for FheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fhe: {}", self.0)
    }
}
impl std::error::Error for FheError {}

fn err(msg: impl Into<String>) -> FheError {
    FheError(msg.into())
}

/// Owned pubkey blob. `id` is a 32-byte identifier derived from the
/// owner address; `seed` is the mask-derivation seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PvacPubkey {
    pub bytes: Vec<u8>,
}

impl PvacPubkey {
    /// Wire-format `bytes` view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrowed 32-byte pubkey identifier.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[6..38]);
        out
    }

    /// Borrowed 32-byte mask seed.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[38..70]);
        out
    }

    /// Parse a wire-format pubkey blob.
    pub fn from_bytes(b: &[u8]) -> Result<Self, FheError> {
        if b.len() != PK_BLOB_LEN {
            return Err(err(format!(
                "pubkey wrong length: got {}, want {PK_BLOB_LEN}",
                b.len()
            )));
        }
        check_header(b, TAG_PK)?;
        Ok(Self { bytes: b.to_vec() })
    }
}

/// Mock keygen: derive a deterministic pubkey for `addr`. In a real
/// HFHE scheme this would emit (pk, sk) with sk staying on the
/// client; here we keep everything inside the mock so verify_zero can
/// re-derive the mask seed.
#[must_use]
pub fn keygen_for_addr(addr: &str) -> PvacPubkey {
    let id_hash = Sha256::digest(format!("OFHE|id|v1|{addr}").as_bytes());
    let seed_hash = Sha256::digest(format!("OFHE|seed|v1|{addr}").as_bytes());
    let mut bytes = Vec::with_capacity(PK_BLOB_LEN);
    bytes.extend_from_slice(FHE_MAGIC);
    bytes.push(FHE_VERSION);
    bytes.push(TAG_PK);
    bytes.extend_from_slice(&id_hash);
    bytes.extend_from_slice(&seed_hash);
    debug_assert_eq!(bytes.len(), PK_BLOB_LEN);
    PvacPubkey { bytes }
}

/// Owned ciphertext blob. Stored as the wire-format `bytes` plus
/// memoised parsed view for cheap repeat access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub bytes: Vec<u8>,
}

impl Ciphertext {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 32-byte pk-id this ct is bound to.
    fn pk_id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[6..38]);
        out
    }

    fn masked_value(&self) -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&self.bytes[38..46]);
        u64::from_le_bytes(v)
    }

    fn nonce_count(&self) -> usize {
        let mut v = [0u8; 4];
        v.copy_from_slice(&self.bytes[46..50]);
        u32::from_le_bytes(v) as usize
    }

    fn nonces(&self) -> &[u8] {
        &self.bytes[CT_HEADER_LEN..]
    }

    /// Parse + validate a ciphertext blob.
    pub fn from_bytes(b: &[u8]) -> Result<Self, FheError> {
        if b.len() < CT_HEADER_LEN {
            return Err(err(format!(
                "ciphertext too short: {} < {CT_HEADER_LEN}",
                b.len()
            )));
        }
        check_header(b, TAG_CT)?;
        // Validate nonce count matches the tail length.
        let mut nc = [0u8; 4];
        nc.copy_from_slice(&b[46..50]);
        let n = u32::from_le_bytes(nc) as usize;
        let want_len = CT_HEADER_LEN + n * NONCE_LEN;
        if b.len() != want_len {
            return Err(err(format!(
                "ciphertext length mismatch: got {}, want {want_len} (nonce_count={n})",
                b.len()
            )));
        }
        Ok(Self { bytes: b.to_vec() })
    }
}

/// Owned zero-proof blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroProof {
    pub bytes: Vec<u8>,
}

impl ZeroProof {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn pk_id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[6..38]);
        out
    }

    fn commitment(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[46..78]);
        out
    }

    /// Parse + validate.
    pub fn from_bytes(b: &[u8]) -> Result<Self, FheError> {
        if b.len() != ZP_BLOB_LEN {
            return Err(err(format!(
                "zero-proof wrong length: got {}, want {ZP_BLOB_LEN}",
                b.len()
            )));
        }
        check_header(b, TAG_ZP)?;
        Ok(Self { bytes: b.to_vec() })
    }
}

fn check_header(b: &[u8], want_tag: u8) -> Result<(), FheError> {
    if &b[0..4] != FHE_MAGIC {
        return Err(err("bad magic (want OFHE)"));
    }
    if b[4] != FHE_VERSION {
        return Err(err(format!(
            "unsupported version {} (want {FHE_VERSION})",
            b[4]
        )));
    }
    if b[5] != want_tag {
        return Err(err(format!("wrong type tag {:#x} (want {want_tag:#x})", b[5])));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Mask derivation
// ─────────────────────────────────────────────────────────────────────

/// Derive a deterministic per-(pk, nonce) mask in `u64`.
fn derive_mask(seed: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> u64 {
    let mut h = Sha256::new();
    h.update(b"OFHE|mask|v1");
    h.update(seed);
    h.update(nonce);
    let d = h.finalize();
    let mut v = [0u8; 8];
    v.copy_from_slice(&d[..8]);
    u64::from_le_bytes(v)
}

/// Derive a deterministic nonce for a fresh encryption. Pure function
/// of (pk, value) — so encrypt_const(pk, 5) twice gives the SAME ct,
/// which is the determinism guarantee the brief asks for.
fn derive_nonce(pk_id: &[u8; 32], value: u64) -> [u8; NONCE_LEN] {
    let mut h = Sha256::new();
    h.update(b"OFHE|nonce|v1");
    h.update(pk_id);
    h.update(value.to_le_bytes());
    let d = h.finalize();
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&d[..NONCE_LEN]);
    out
}

// ─────────────────────────────────────────────────────────────────────
// The 6 host calls
// ─────────────────────────────────────────────────────────────────────

/// `fhe_load_pk(addr)` — look up the PVAC pubkey registered for
/// `addr`. Reverts with `pubkey not registered` if missing.
///
/// `pubkeys` is the chain-state registry (mock-rpc keeps it as
/// `pvac_pubkeys: HashMap<Address, PvacPubkey>` on `ChainState`).
pub fn fhe_load_pk<S: std::hash::BuildHasher>(
    pubkeys: &HashMap<String, PvacPubkey, S>,
    addr: &str,
) -> Result<PvacPubkey, FheError> {
    pubkeys
        .get(addr)
        .cloned()
        .ok_or_else(|| err(format!("pubkey not registered: {addr}")))
}

/// `fhe_deser(blob) -> Ciphertext`. Validates wire format.
pub fn fhe_deser(blob: &[u8]) -> Result<Ciphertext, FheError> {
    Ciphertext::from_bytes(blob)
}

/// `fhe_ser(Ciphertext) -> Vec<u8>`. Identity over the wire bytes.
#[must_use]
pub fn fhe_ser(ct: &Ciphertext) -> Vec<u8> {
    ct.bytes.clone()
}

/// `fhe_add(Ciphertext, Ciphertext) -> Ciphertext`. Adds the two
/// plaintext values modulo 2^64. The result's mask is the sum of
/// both inputs' masks — represented as the concatenation of their
/// nonce lists (decryption walks both and sums masks).
pub fn fhe_add(a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext, FheError> {
    if a.pk_id() != b.pk_id() {
        return Err(err("pubkey mismatch on add"));
    }
    let pk_id = a.pk_id();
    let masked = a.masked_value().wrapping_add(b.masked_value());
    let nonce_count = a.nonce_count() + b.nonce_count();
    let nonce_bytes_len = nonce_count * NONCE_LEN;
    let mut bytes = Vec::with_capacity(CT_HEADER_LEN + nonce_bytes_len);
    bytes.extend_from_slice(FHE_MAGIC);
    bytes.push(FHE_VERSION);
    bytes.push(TAG_CT);
    bytes.extend_from_slice(&pk_id);
    bytes.extend_from_slice(&masked.to_le_bytes());
    bytes.extend_from_slice(&(nonce_count as u32).to_le_bytes());
    bytes.extend_from_slice(a.nonces());
    bytes.extend_from_slice(b.nonces());
    Ok(Ciphertext { bytes })
}

/// `fhe_add_const(Ciphertext, u64) -> Ciphertext`. Same shape as
/// `fhe_add` but the second operand is a public constant — produces
/// a fresh encrypted-zero (mask, -mask) addend so we still grow the
/// nonce list, matching the real chain's "every add_const adds noise"
/// behaviour.
pub fn fhe_add_const(pk: &PvacPubkey, a: &Ciphertext, k: u64) -> Result<Ciphertext, FheError> {
    if pk.id() != a.pk_id() {
        return Err(err("pubkey/ciphertext mismatch on add_const"));
    }
    let b = encrypt_const(pk, k);
    fhe_add(a, &b)
}

/// `fhe_verify_zero(Ciphertext, ZeroProof) -> bool`. Returns Ok(true)
/// iff (1) the proof binds to the same pubkey as the ciphertext,
/// (2) the proof's commitment is the canonical sha256 of (pk_id ‖ ct),
/// AND (3) the ciphertext actually decrypts to 0 under the proof's
/// pk. Returns Ok(false) otherwise — host calls revert only on
/// malformed inputs, not on a bad-but-well-formed proof.
pub fn fhe_verify_zero(
    pk: &PvacPubkey,
    ct: &Ciphertext,
    proof: &ZeroProof,
) -> Result<bool, FheError> {
    if pk.id() != ct.pk_id() {
        return Err(err("pubkey/ciphertext mismatch"));
    }
    if pk.id() != proof.pk_id() {
        return Err(err("pubkey/proof mismatch"));
    }
    let expected = canonical_zero_commitment(&pk.id(), &ct.bytes);
    if proof.commitment() != expected {
        return Ok(false);
    }
    // Recompute the plaintext: subtract the mask-sum from the masked
    // value. If the result is 0, the ct really encrypts 0.
    let mut mask_sum: u64 = 0;
    let seed = pk.seed();
    for chunk in ct.nonces().chunks_exact(NONCE_LEN) {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(chunk);
        mask_sum = mask_sum.wrapping_add(derive_mask(&seed, &n));
    }
    let plaintext = ct.masked_value().wrapping_sub(mask_sum);
    Ok(plaintext == 0)
}

// ─────────────────────────────────────────────────────────────────────
// Helpers usable by mock-rpc dispatchers and tests
// ─────────────────────────────────────────────────────────────────────

/// Encrypt a u64 constant under `pk`. The mock allows anyone with the
/// pubkey to encrypt — there is no "secret-key-required" gating like
/// real BFV, but the algebra still works.
#[must_use]
pub fn encrypt_const(pk: &PvacPubkey, value: u64) -> Ciphertext {
    let pk_id = pk.id();
    let nonce = derive_nonce(&pk_id, value);
    let mask = derive_mask(&pk.seed(), &nonce);
    let masked = value.wrapping_add(mask);

    let mut bytes = Vec::with_capacity(CT_HEADER_LEN + NONCE_LEN);
    bytes.extend_from_slice(FHE_MAGIC);
    bytes.push(FHE_VERSION);
    bytes.push(TAG_CT);
    bytes.extend_from_slice(&pk_id);
    bytes.extend_from_slice(&masked.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&nonce);
    Ciphertext { bytes }
}

/// Decrypt under the mock pk (which carries the mask seed). Real
/// chain decryption requires the operator's SK; the mock simulates
/// the algebra without that asymmetry.
#[must_use]
pub fn decrypt(pk: &PvacPubkey, ct: &Ciphertext) -> u64 {
    let mut mask_sum: u64 = 0;
    let seed = pk.seed();
    for chunk in ct.nonces().chunks_exact(NONCE_LEN) {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(chunk);
        mask_sum = mask_sum.wrapping_add(derive_mask(&seed, &n));
    }
    ct.masked_value().wrapping_sub(mask_sum)
}

/// Produce a zero-proof for a ciphertext that encrypts 0. The
/// commitment is `sha256(pk_id ‖ ct_bytes)`. This is NOT the same
/// commitment shape as the real chain's zkzp_v2 proof (which is a
/// sigma-protocol transcript over the BFV ciphertext) — it's the
/// "mock-honest" stand-in.
#[must_use]
pub fn make_zero_proof(pk: &PvacPubkey, ct: &Ciphertext) -> ZeroProof {
    let pk_id = pk.id();
    let commitment = canonical_zero_commitment(&pk_id, &ct.bytes);
    let mut bytes = Vec::with_capacity(ZP_BLOB_LEN);
    bytes.extend_from_slice(FHE_MAGIC);
    bytes.push(FHE_VERSION);
    bytes.push(TAG_ZP);
    bytes.extend_from_slice(&pk_id);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&commitment);
    ZeroProof { bytes }
}

fn canonical_zero_commitment(pk_id: &[u8; 32], ct_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"OFHE|zero-commit|v1");
    h.update(pk_id);
    h.update(ct_bytes);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with(addr: &str) -> (HashMap<String, PvacPubkey>, PvacPubkey) {
        let pk = keygen_for_addr(addr);
        let mut m = HashMap::new();
        m.insert(addr.to_string(), pk.clone());
        (m, pk)
    }

    #[test]
    fn t01_load_pk_happy_path() {
        let (reg, pk) = registry_with("octAlice");
        let got = fhe_load_pk(&reg, "octAlice").unwrap();
        assert_eq!(got, pk);
        assert_eq!(got.bytes.len(), PK_BLOB_LEN);
        assert_eq!(&got.bytes[0..4], FHE_MAGIC);
        assert_eq!(got.bytes[5], TAG_PK);
    }

    #[test]
    fn t02_load_pk_unregistered_errors() {
        let (reg, _pk) = registry_with("octAlice");
        let err = fhe_load_pk(&reg, "octMallory").unwrap_err();
        assert!(err.0.contains("pubkey not registered"), "got: {}", err.0);
        assert!(err.0.contains("octMallory"));
    }

    #[test]
    fn t03_encrypt_then_deser_happy() {
        let pk = keygen_for_addr("octBob");
        let ct = encrypt_const(&pk, 42);
        let parsed = fhe_deser(ct.as_bytes()).unwrap();
        assert_eq!(parsed, ct);
        assert_eq!(decrypt(&pk, &parsed), 42);
    }

    #[test]
    fn t04_deser_malformed_short_errors() {
        let err = fhe_deser(&[0u8; 8]).unwrap_err();
        assert!(err.0.contains("too short"), "got: {}", err.0);
    }

    #[test]
    fn t05_deser_bad_magic_errors() {
        let pk = keygen_for_addr("octCarol");
        let mut blob = encrypt_const(&pk, 1).bytes;
        blob[0] = b'X';
        let err = fhe_deser(&blob).unwrap_err();
        assert!(err.0.contains("magic"), "got: {}", err.0);
    }

    #[test]
    fn t06_deser_wrong_tag_errors() {
        // Hand-craft a blob with the PK tag where CT is expected.
        let pk = keygen_for_addr("octDan");
        let mut blob = encrypt_const(&pk, 1).bytes;
        blob[5] = TAG_PK;
        let err = fhe_deser(&blob).unwrap_err();
        assert!(err.0.contains("type tag"), "got: {}", err.0);
    }

    #[test]
    fn t07_deser_nonce_length_mismatch_errors() {
        let pk = keygen_for_addr("octEve");
        let mut blob = encrypt_const(&pk, 1).bytes;
        blob.truncate(blob.len() - 4); // chop nonce mid-way
        let err = fhe_deser(&blob).unwrap_err();
        assert!(err.0.contains("length mismatch"), "got: {}", err.0);
    }

    #[test]
    fn t08_add_happy_e2e_encrypt_5_plus_3_eq_8() {
        let pk = keygen_for_addr("octFrank");
        let a = encrypt_const(&pk, 5);
        let b = encrypt_const(&pk, 3);
        let sum = fhe_add(&a, &b).unwrap();
        assert_eq!(decrypt(&pk, &sum), 8);
    }

    #[test]
    fn t09_add_three_way_e2e_1_plus_2_plus_4_eq_7() {
        let pk = keygen_for_addr("octGale");
        let a = encrypt_const(&pk, 1);
        let b = encrypt_const(&pk, 2);
        let c = encrypt_const(&pk, 4);
        let sum = fhe_add(&fhe_add(&a, &b).unwrap(), &c).unwrap();
        assert_eq!(decrypt(&pk, &sum), 7);
    }

    #[test]
    fn t10_add_pubkey_mismatch_errors() {
        let pk1 = keygen_for_addr("octHans");
        let pk2 = keygen_for_addr("octIvy");
        let a = encrypt_const(&pk1, 5);
        let b = encrypt_const(&pk2, 3);
        let err = fhe_add(&a, &b).unwrap_err();
        assert!(err.0.contains("pubkey mismatch"), "got: {}", err.0);
    }

    #[test]
    fn t11_add_const_happy() {
        let pk = keygen_for_addr("octJade");
        let a = encrypt_const(&pk, 10);
        let r = fhe_add_const(&pk, &a, 32).unwrap();
        assert_eq!(decrypt(&pk, &r), 42);
    }

    #[test]
    fn t12_add_const_pubkey_mismatch_errors() {
        let pk1 = keygen_for_addr("octK");
        let pk2 = keygen_for_addr("octL");
        let a = encrypt_const(&pk1, 1);
        let err = fhe_add_const(&pk2, &a, 1).unwrap_err();
        assert!(err.0.contains("pubkey/ciphertext mismatch"), "got: {}", err.0);
    }

    #[test]
    fn t13_ser_roundtrip_identity() {
        let pk = keygen_for_addr("octMia");
        let ct = encrypt_const(&pk, 123_456_789);
        let bytes = fhe_ser(&ct);
        let back = fhe_deser(&bytes).unwrap();
        assert_eq!(ct, back);
    }

    #[test]
    fn t14_verify_zero_happy_path() {
        let pk = keygen_for_addr("octNed");
        let z = encrypt_const(&pk, 0);
        let proof = make_zero_proof(&pk, &z);
        assert!(fhe_verify_zero(&pk, &z, &proof).unwrap());
    }

    #[test]
    fn t15_verify_zero_rejects_nonzero_ct() {
        let pk = keygen_for_addr("octOmar");
        let nz = encrypt_const(&pk, 1);
        // Even if we synthesise a proof, decrypt != 0 → false.
        let proof = make_zero_proof(&pk, &nz);
        assert!(!fhe_verify_zero(&pk, &nz, &proof).unwrap());
    }

    #[test]
    fn t16_verify_zero_rejects_swapped_pk() {
        let pk1 = keygen_for_addr("octP");
        let pk2 = keygen_for_addr("octQ");
        let z = encrypt_const(&pk1, 0);
        let proof = make_zero_proof(&pk1, &z);
        let err = fhe_verify_zero(&pk2, &z, &proof).unwrap_err();
        assert!(err.0.contains("pubkey/ciphertext mismatch"), "got: {}", err.0);
    }

    #[test]
    fn t17_verify_zero_rejects_proof_from_other_ct() {
        let pk = keygen_for_addr("octR");
        let z = encrypt_const(&pk, 0);
        let other_z = fhe_add(&z, &encrypt_const(&pk, 0)).unwrap();
        let proof_other = make_zero_proof(&pk, &other_z);
        // Proof's commitment hashes `other_z` not `z` → mismatch.
        assert!(!fhe_verify_zero(&pk, &z, &proof_other).unwrap());
    }

    #[test]
    fn t18_determinism_100_trials() {
        let pk = keygen_for_addr("octStable");
        let canonical = encrypt_const(&pk, 7).bytes;
        for _ in 0..100 {
            let again = encrypt_const(&pk, 7).bytes;
            assert_eq!(again, canonical);
        }
    }

    #[test]
    fn t19_add_is_commutative_on_wire() {
        let pk = keygen_for_addr("octT");
        let a = encrypt_const(&pk, 11);
        let b = encrypt_const(&pk, 22);
        let ab = fhe_add(&a, &b).unwrap();
        let ba = fhe_add(&b, &a).unwrap();
        // Note: bytes are NOT identical (nonce list ordering preserved).
        // But the *plaintext* must be.
        assert_eq!(decrypt(&pk, &ab), 33);
        assert_eq!(decrypt(&pk, &ba), 33);
    }

    #[test]
    fn t20_cross_process_roundtrip_via_bytes_only() {
        // Simulate "fresh process": all that crosses the boundary is
        // the raw blob and the address string. We rebuild the pk on
        // the receiving side via keygen_for_addr, exactly like a real
        // node would do via fhe_load_pk.
        let addr = "octUma";
        let pk_send = keygen_for_addr(addr);
        let ct_send = encrypt_const(&pk_send, 999);
        let ct_bytes: Vec<u8> = fhe_ser(&ct_send);
        // Drop everything but the bytes + address.
        drop(pk_send);
        drop(ct_send);
        let pk_recv = keygen_for_addr(addr);
        let ct_recv = fhe_deser(&ct_bytes).unwrap();
        assert_eq!(decrypt(&pk_recv, &ct_recv), 999);
    }

    #[test]
    fn t21_load_pk_after_keygen_matches() {
        let mut reg = HashMap::new();
        let pk = keygen_for_addr("octVic");
        reg.insert("octVic".to_string(), pk.clone());
        let loaded = fhe_load_pk(&reg, "octVic").unwrap();
        assert_eq!(loaded.bytes, pk.bytes);
    }

    #[test]
    fn t22_settle_path_simulation_5_plus_3_then_claim_8() {
        // End-to-end: simulate the mock's settle_claim_v2 →
        // settle_confirm_v2 → claim_earnings_v2 with real ciphertexts.
        let pk = keygen_for_addr("octProxy1");
        // Session 1 nets 5; session 2 nets 3.
        let s1 = encrypt_const(&pk, 5);
        let s2 = encrypt_const(&pk, 3);
        // Operator balance = s1 + s2.
        let balance = fhe_add(&s1, &s2).unwrap();
        // claim_earnings_v2 wants to prove balance - claim = 0.
        // delta = balance + encrypt(-claim). For mock convenience we
        // use balance + encrypt(2^64 - claim) via wrapping add.
        let claim: u64 = 8;
        let neg = (!claim).wrapping_add(1); // two's complement of claim
        let delta = fhe_add_const(&pk, &balance, neg).unwrap();
        let proof = make_zero_proof(&pk, &delta);
        assert!(fhe_verify_zero(&pk, &delta, &proof).unwrap());
    }

    #[test]
    fn t23_overclaim_rejected_by_verify_zero() {
        // Same setup, but the operator tries to claim more than they
        // earned. delta != 0, so verify_zero must say false.
        let pk = keygen_for_addr("octProxy2");
        let balance = fhe_add(
            &encrypt_const(&pk, 5),
            &encrypt_const(&pk, 3),
        ).unwrap();
        let bogus_claim: u64 = 100;
        let neg = (!bogus_claim).wrapping_add(1);
        let delta = fhe_add_const(&pk, &balance, neg).unwrap();
        let proof = make_zero_proof(&pk, &delta);
        assert!(!fhe_verify_zero(&pk, &delta, &proof).unwrap());
    }
}

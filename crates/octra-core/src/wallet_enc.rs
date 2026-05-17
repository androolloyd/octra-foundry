//! Passphrase-protected wallet secret on disk.
//!
//! Wire format (all binary, length-tagged, single file):
//!
//! ```text
//! "OCTRA-WALLET-V1\0" (16 bytes)
//! salt              (16 bytes, random per file)
//! nonce             (12 bytes, random per file)
//! pbkdf2_iters_be   (u32, configurable, default 200_000)
//! ciphertext        (len = secret.len() + 16; ChaCha20-Poly1305 sealed)
//! ```
//!
//! The KEK is `PBKDF2-HMAC-SHA256(passphrase, salt, iters, 32)`.
//! The plaintext is the 32-byte wallet secret.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CoreError, CoreResult};

const MAGIC: &[u8; 16] = b"OCTRA-WALLET-V1\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const DEFAULT_PBKDF2_ITERS: u32 = 200_000;

/// Encrypt a 32-byte wallet secret under `passphrase`.
pub fn encrypt_secret(secret: &[u8; 32], passphrase: &str) -> Vec<u8> {
    encrypt_secret_with_iters(secret, passphrase, DEFAULT_PBKDF2_ITERS)
}

pub fn encrypt_secret_with_iters(secret: &[u8; 32], passphrase: &str, iters: u32) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // `kek` is `Zeroizing<[u8; 32]>` — it wipes on drop.
    let kek = derive_kek(passphrase, &salt, iters);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_slice())
        .expect("ChaCha20-Poly1305 encryption with valid key + nonce");

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + 4 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&iters.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a wallet secret using `passphrase`.
pub fn decrypt_secret(envelope: &[u8], passphrase: &str) -> CoreResult<[u8; 32]> {
    if envelope.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 4 + TAG_LEN {
        return Err(CoreError::InvalidEncoding(
            "wallet envelope too short".into(),
        ));
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        return Err(CoreError::InvalidEncoding(
            "wallet envelope: bad magic".into(),
        ));
    }
    let mut cursor = MAGIC.len();
    let salt = &envelope[cursor..cursor + SALT_LEN];
    cursor += SALT_LEN;
    let nonce = &envelope[cursor..cursor + NONCE_LEN];
    cursor += NONCE_LEN;
    let mut iters_arr = [0u8; 4];
    iters_arr.copy_from_slice(&envelope[cursor..cursor + 4]);
    let iters = u32::from_be_bytes(iters_arr);
    cursor += 4;
    let ciphertext = &envelope[cursor..];

    let kek = derive_kek(passphrase, salt, iters);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let mut plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            CoreError::Crypto("wallet decryption failed (wrong passphrase or corrupt file)".into())
        })?;
    let result = if plain.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        Ok(out)
    } else {
        Err(CoreError::InvalidLength {
            expected: 32,
            actual: plain.len(),
        })
    };
    // Always wipe the intermediate AEAD plaintext buffer before we
    // return — it briefly contained the wallet secret.
    use zeroize::Zeroize;
    plain.zeroize();
    result
}

/// Detect whether a file is a v1-encrypted envelope (vs a plain
/// hex/raw secret).
pub fn looks_like_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Derive the wallet KEK. Return type is `Zeroizing<[u8; 32]>` so the
/// caller's stack copy is wiped when it goes out of scope; AES key
/// material must never linger after the cipher object is built.
fn derive_kek(passphrase: &str, salt: &[u8], iters: u32) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut *out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let secret = [7u8; 32];
        let enc = encrypt_secret_with_iters(&secret, "correct horse", 100);
        assert!(looks_like_envelope(&enc));
        let got = decrypt_secret(&enc, "correct horse").unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let secret = [7u8; 32];
        let enc = encrypt_secret_with_iters(&secret, "right", 100);
        let r = decrypt_secret(&enc, "wrong");
        assert!(r.is_err());
    }

    #[test]
    fn truncated_envelope_fails() {
        let secret = [7u8; 32];
        let mut enc = encrypt_secret_with_iters(&secret, "x", 100);
        enc.truncate(20);
        assert!(decrypt_secret(&enc, "x").is_err());
    }

    #[test]
    fn looks_like_envelope_detects_plain_hex() {
        let plain = b"deadbeef...";
        assert!(!looks_like_envelope(plain));
        let raw = [7u8; 32];
        assert!(!looks_like_envelope(&raw));
    }

    // ====================================================================
    // Property-based harness (would-be Kani: see verify.rs)
    // ====================================================================
    use proptest::prelude::*;

    proptest! {
        // PBKDF2 at 100 iterations (test-only) so we can do many cases
        // cheaply. The production iter count is 200_000; we're testing
        // the *envelope* invariants, not the work factor.
        #![proptest_config(ProptestConfig {
            cases: 128,
            max_global_rejects: 200_000,
            .. ProptestConfig::default()
        })]

        /// `wallet_enc::encrypt_secret` then `decrypt_secret` is
        /// identity.
        #[test]
        fn prop_wallet_seal_unseal_identity(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase in "[ -~]{1,64}",
        ) {
            let enc = encrypt_secret_with_iters(&secret, &passphrase, 100);
            let got = decrypt_secret(&enc, &passphrase).unwrap();
            prop_assert_eq!(got, secret);
        }

        /// Wrong passphrase MUST fail — no false-positive decrypts.
        #[test]
        fn prop_wallet_wrong_passphrase_fails(
            secret in prop::array::uniform32(any::<u8>()),
            correct in "[ -~]{1,32}",
            wrong in "[ -~]{1,32}",
        ) {
            prop_assume!(correct != wrong);
            let enc = encrypt_secret_with_iters(&secret, &correct, 100);
            prop_assert!(decrypt_secret(&enc, &wrong).is_err());
        }

        /// **Tamper rejection.** Flipping any single bit in the
        /// ciphertext portion of the envelope MUST cause decryption
        /// to fail (ChaCha20-Poly1305 AEAD authenticity).
        #[test]
        fn prop_wallet_rejects_bit_flip(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase in "[ -~]{1,32}",
            flip_idx in 0usize..200,
        ) {
            let mut enc = encrypt_secret_with_iters(&secret, &passphrase, 100);
            // Skip the 16-byte magic; flip somewhere in salt/nonce/
            // iters/ciphertext.
            let lo = MAGIC.len();
            if enc.len() <= lo + 1 { return Ok(()); }
            let idx = lo + (flip_idx % (enc.len() - lo));
            enc[idx] ^= 0x01;
            prop_assert!(decrypt_secret(&enc, &passphrase).is_err());
        }

        /// `encrypt_secret` output always starts with the magic.
        #[test]
        fn prop_wallet_envelope_starts_with_magic(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase in "[ -~]{1,32}",
        ) {
            let enc = encrypt_secret_with_iters(&secret, &passphrase, 100);
            prop_assert_eq!(&enc[..MAGIC.len()], &MAGIC[..]);
            prop_assert!(looks_like_envelope(&enc));
        }

        /// Truncating the envelope below the minimum size MUST fail
        /// cleanly (no panic, no false-positive decrypt).
        #[test]
        fn prop_wallet_truncated_envelope_fails(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase in "[ -~]{1,32}",
            cut_at in 0usize..(MAGIC.len() + SALT_LEN + NONCE_LEN + 4 + TAG_LEN),
        ) {
            let mut enc = encrypt_secret_with_iters(&secret, &passphrase, 100);
            enc.truncate(cut_at);
            prop_assert!(decrypt_secret(&enc, &passphrase).is_err());
        }
    }
}

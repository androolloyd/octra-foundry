//! Ed25519 signing for ephemeral session keys and node receipt keys.
//!
//! These are *not* the user's main wallet key — that one stays untouched.
//! For each session we generate a fresh ephemeral keypair so the chain
//! never sees the wallet pubkey alongside session activity.

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zeroize::Zeroizing;

use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde_as(as = "Bytes")] pub [u8; 64]);

/// Wrapper that zeroizes secret material on drop.
pub struct KeyPair {
    secret: SigningKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SigningKey::generate(&mut OsRng);
        let public = PublicKey(secret.verifying_key().to_bytes());
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(bytes);
        let public = PublicKey(secret.verifying_key().to_bytes());
        Self { secret, public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.secret.sign(msg).to_bytes())
    }

    /// Export the 32-byte ed25519 secret.
    ///
    /// The return type is `Zeroizing<[u8; 32]>` (from the `zeroize`
    /// crate): the buffer is wiped to zero when the wrapper drops, so
    /// the caller's stack frame doesn't retain the secret after the
    /// expression ends. Callers can `*kp.secret_bytes()` to copy out
    /// into another `Zeroizing` wrapper, but copying into a plain
    /// `[u8; 32]` is the pattern this return type discourages.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // `SigningKey` already zeroizes on drop in `ed25519-dalek` 2.x
        // (it derives `ZeroizeOnDrop`). We keep this empty `Drop` impl
        // around purely as a tripwire: if a future migration swaps the
        // crypto backend for one that doesn't zeroize on drop, this
        // explicit `impl Drop` is the conspicuous place to notice. The
        // body intentionally does NOT call `zeroize` on a stack copy —
        // that would only zero the *copy*, not the original, and the
        // misleading optics were a v1.1 audit finding.
    }
}

/// Verify an ed25519 signature.
pub fn verify(pubkey: &PublicKey, msg: &[u8], sig: &Signature) -> CoreResult<()> {
    let vk = VerifyingKey::from_bytes(&pubkey.0)
        .map_err(|e| CoreError::Crypto(format!("bad pubkey: {e}")))?;
    let s = DalekSig::from_bytes(&sig.0);
    vk.verify(msg, &s)
        .map_err(|e| CoreError::Crypto(format!("verify: {e}")))
}

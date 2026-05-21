//! Thin Octra primitives shared by both the OctraVPN stack
//! (`octravpn-core`) and the Octra Foundry tooling.
//!
//! This crate intentionally stays *very* small: only the bits that have
//! no OctraVPN-specific dependency surface live here. Today that's:
//!
//!   - [`address`]    — Octra `oct…` address codec (SHA-256 of an Ed25519
//!                      pubkey, base58-encoded with `1`-padding).
//!   - [`sig`]        — Ed25519 keypair / sign / verify primitives.
//!   - [`coverage`]   — A `Mutex<Option<Recorder>>` global the mock chain
//!                      and the AML coverage report wire together.
//!   - [`tx`]         — Canonical Octra transaction signing / verification.
//!   - [`util`]       — Tracing init, HKDF subkey derivation, secret-file
//!                      loading.
//!   - [`wallet_enc`] — Passphrase-protected wallet secret envelope.
//!
//! Everything OctraVPN-specific (sessions, receipts, onion routing,
//! validator oracle, RPC, …) stays in `octravpn-core`.

pub mod address;
pub mod circle;
pub mod coverage;
pub mod sig;
pub mod tx;
pub mod util;
pub mod wallet_enc;

// Formal-verification harness module. Today's content is Kani-only
// (`#[cfg(kani)]`); see the module-level doc for the proptest fallback
// story and `scripts/verify.sh` for the runner.
pub mod verify;

pub use address::{Address, ADDRESS_LEN};
pub use sig::{KeyPair, PublicKey, Signature};

/// Library-wide error type. Crates downstream return their own errors;
/// this is just for shared utilities that don't already use `anyhow`.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    /// The on-disk secret at `path` is plaintext (raw bytes or hex). The
    /// operator-side strict loader refuses to use it as-is. `suggested_cmd`
    /// is the exact CLI invocation that wraps it under the passphrase
    /// envelope; tooling that surfaces this error should print
    /// `suggested_cmd` so the operator has a one-line copy-paste to fix.
    /// Threat-model ref: docs/v2-threat-model.md P1-6.
    #[error("plaintext key on disk at {path}; re-seal via: {suggested_cmd}")]
    PlaintextKeyOnDisk { path: String, suggested_cmd: String },
}

pub type CoreResult<T> = std::result::Result<T, CoreError>;

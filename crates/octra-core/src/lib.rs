//! Thin Octra primitives shared by both the OctraVPN stack
//! (`octravpn-core`) and the Octra Foundry tooling.
//!
//! This crate intentionally stays *very* small: only the bits that have
//! no OctraVPN-specific dependency surface live here. Today that's:
//!
//!   - [`address`] — Octra `oct…` address codec (SHA-256 of an Ed25519
//!     pubkey, base58-encoded with `1`-padding).
//!   - [`sig`]     — Ed25519 keypair / sign / verify primitives.
//!   - [`coverage`] — A `Mutex<Option<Recorder>>` global the mock chain
//!     and the AML coverage report wire together.
//!
//! Everything OctraVPN-specific (sessions, receipts, onion routing,
//! validator oracle, RPC, …) stays in `octravpn-core`.

pub mod address;
pub mod coverage;
pub mod sig;

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
}

pub type CoreResult<T> = std::result::Result<T, CoreError>;

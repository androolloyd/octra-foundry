//! Errors every tier reports in one vocabulary.
//!
//! The JSON-RPC codes carried here are the node's own
//! (`lib/core/rpc.ml:20-40`, `node_rpc_server.ml:440-444`); the mock
//! emits `-32000` for everything, which is itself a documented divergence
//! rather than something this crate papers over.

use thiserror::Error;

use crate::tier::Tier;

/// Node JSON-RPC codes this crate reasons about by number rather than by
/// string-matching a message. String heuristics are how the old clients
/// missed `-32012` entirely.
pub mod codes {
    /// Method does not exist. The real node answers this for
    /// `octra_isValidator` and all seven `octra_fhe*` methods — which the
    /// mock happily implements. Verified live against
    /// `octra-foundry/octra-node`: `{"code":-32601,"message":"method not
    /// found: octra_isValidator"}`.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid params.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Single-flight busy (`node_rpc_server.ml`). Retryable.
    pub const BUSY: i64 = -32005;
    /// Committed state changed during a stable read — the node itself is
    /// telling the client to retry (`node_rpc_server.ml:440-444`).
    /// Retryable.
    pub const COMMITTED_STATE_CHANGED: i64 = -32012;

    /// Invalid signature. Almost always one byte of preimage drift.
    pub const INVALID_SIGNATURE: i64 = 101;
    /// Invalid nonce (`lib/core/rpc.ml:29-30`).
    pub const INVALID_NONCE: i64 = 102;
    /// Nonce too far ahead.
    pub const NONCE_TOO_FAR_AHEAD: i64 = 103;
    /// Timestamp outside the ±300s window.
    pub const BAD_TIMESTAMP: i64 = 105;
    /// Receipt / record not found. Not an error for non-call ops, which
    /// legitimately have no execution receipt.
    pub const NOT_FOUND: i64 = 112;
}

/// Everything a backend can go wrong with.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BackendError {
    /// The node answered with a JSON-RPC error object.
    #[error("rpc {method} error {code}: {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
    },

    /// Never reached the node (DNS, connect, TLS, read timeout).
    #[error("transport: {0}")]
    Transport(String),

    /// A response parsed as JSON but not into the shape we needed. Kept
    /// distinct from `Rpc` because this is *our* bug or a node upgrade,
    /// never the caller's input.
    #[error("decoding {what}: {detail}")]
    Decode { what: String, detail: String },

    /// Signing failed — bad call shape, or a `chain_id` smuggled into the
    /// preimage.
    #[error("sign: {0}")]
    Sign(String),

    /// A confirmed tx whose VM execution reverted. `confirmed` only means
    /// the epoch applied it; the receipt is authoritative for success
    /// (`contract_rpc.ml:765-780`). The nonce is consumed either way.
    #[error("tx {hash} confirmed but reverted: {error}")]
    Reverted { hash: String, error: String },

    /// The staging validator refused the tx at epoch apply. The nonce was
    /// NOT consumed (`tx_view.ml:107-122`).
    #[error("tx {hash} rejected at epoch apply ({error_type}): {reason}")]
    Rejected {
        hash: String,
        error_type: String,
        reason: String,
    },

    /// Evicted from staging without ever applying (`tx_view.ml:124-136`).
    #[error("tx {hash} dropped before apply: {reason} ({detail})")]
    Dropped {
        hash: String,
        reason: String,
        detail: String,
    },

    /// Still `pending` after the confirmation budget elapsed. NOT a
    /// failure verdict — the tx is staged and holds a nonce, and may yet
    /// apply. Callers must not resubmit on this.
    #[error(
        "tx {hash} still pending after {polls} polls / {elapsed_secs}s (staged, may yet apply)"
    )]
    ConfirmTimeout {
        hash: String,
        polls: u32,
        elapsed_secs: u64,
    },

    /// A tier-1-only cheat was requested from a tier that has no such
    /// lever. This is the loud runtime half of the `as_mock` split; the
    /// quiet compile-time half is taking `&MockBackend` instead of
    /// `&Chain`.
    #[error(
        "`{cheat}` is a MOCK-ONLY cheat and the active tier is {tier}. \
         Real nodes have no faucet, no instant mint and no test namespace \
         (there is no `octra_test_*` in rpc_dispatch.ml). Either fund the \
         address from a devkeys account with a real transfer, or take \
         `&MockBackend` in this test's signature so tier {tier} cannot \
         even be selected for it."
    )]
    MockOnly { cheat: String, tier: Tier },
}

impl BackendError {
    /// Retry the same request unchanged? Codes, not string matching.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Rpc { code, .. } => {
                *code == codes::COMMITTED_STATE_CHANGED || *code == codes::BUSY
            }
            Self::Transport(_) => true,
            _ => false,
        }
    }

    /// Resign at a freshly-reconciled nonce and retry? The staging
    /// validator has exactly two nonce errors.
    #[must_use]
    pub fn is_nonce_error(&self) -> bool {
        matches!(
            self,
            Self::Rpc { code, .. }
                if *code == codes::INVALID_NONCE || *code == codes::NONCE_TOO_FAR_AHEAD
        )
    }

    /// The node has no such method. Worth its own predicate: it is the
    /// signature of a test that has been passing against mock fiction
    /// (`octra_isValidator`, `octra_fhe*`, `octra_test_*`).
    #[must_use]
    pub fn is_method_not_found(&self) -> bool {
        matches!(self, Self::Rpc { code, .. } if *code == codes::METHOD_NOT_FOUND)
    }

    #[must_use]
    pub fn rpc_code(&self) -> Option<i64> {
        match self {
            Self::Rpc { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Result alias for backend operations.
pub type BackendResult<T> = Result<T, BackendError>;

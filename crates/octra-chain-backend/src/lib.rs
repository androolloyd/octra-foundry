//! Tiered chain backends for octra-foundry.
//!
//! The premise, learned the hard way: our in-process mock implements 13 of
//! ~108 real RPC handlers with response-shape drift on all 13, and executes
//! no AML at all — so a green Tier-1 test proves our reimplementation agrees
//! with itself, not that the chain agrees with us. Four money-path bugs
//! already passed every mock test and were caught only by real daemons on
//! devnet.
//!
//! The answer is not "delete the mock": the real node's epoch interval is a
//! hardcoded 10s (upstream `epoch_time.ml:10-11`), so it can never be the
//! sub-second tier. It is to make tier membership explicit, with one rule:
//!
//! > **Nothing money-shaped may have the mock tier as its only coverage.**
//!
//! Tiers:
//!   * **mock** — fast, hermetic, unit/property tests.
//!   * **node** — a real containerized lite node (see `docker/octra-node/`),
//!     Single mode, 10s epochs, deterministic genesis from `octra-devkeys`.
//!   * **fork** — a node booted on real devnet state via state sync.
//!
//! ## Status
//!
//! **Scaffolding.** [`canonical_tx`] and [`error`] are complete and tested;
//! the `ChainBackend` trait itself and the Mock/Node backends are not written
//! yet. This crate is committed in this state deliberately — the signer port
//! is the load-bearing piece and is worth having under test now — but nothing
//! here drives a test suite yet.
//!
//! ## Why the signer is duplicated
//!
//! [`canonical_tx`] mirrors `octravpn-core`'s `tx_signer.rs`. It cannot
//! simply depend on it: octravpn depends on octra-foundry, not the reverse.
//! Both are ports of the same upstream source of truth
//! (`transaction.ml:309-326`, verified against the node's own verifier at
//! `tx_view.ml:1135-1148`), and both pin golden preimage bytes, so drift
//! shows up as a failing golden rather than as a silent code 101. If a third
//! copy is ever needed, extract a shared crate instead.

pub mod canonical_tx;
pub mod error;
pub mod tier;

pub use canonical_tx::{
    canonical_tx_from_call, sign_call_canonical, yojson_float, CanonicalTx, OP_CALL,
    OP_CIRCLE_CALL, OP_CIRCLE_INGRESS_COMMIT, OP_CIRCLE_OUTBOX_OPEN, OP_CIRCLE_RELAY_CANCEL,
    OP_CIRCLE_RELAY_CLAIM, OP_DEPLOY_CIRCLE, OP_STANDARD,
};
pub use error::{BackendError, BackendResult};
pub use tier::{Tier, TIER_ENV};

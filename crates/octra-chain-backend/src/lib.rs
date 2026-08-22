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
//! ## The shape
//!
//! One trait, [`ChainBackend`], with three things bolted down:
//!
//!   1. **Submit stages; it does not confirm.** [`backend::Staged`] has a
//!      hash and no status field, so no backend can hand back a value
//!      meaning "confirmed". Confirmation lives in
//!      [`ConfirmExt::await_confirmation`], supplied by a *blanket* impl
//!      over every `T: ChainBackend` — coherence forbids a backend from
//!      substituting its own. This is the enforcement behind "a backend
//!      must not be able to pretend a submit confirmed".
//!   2. **Waiting is advancing epochs.** `await_confirmation` waits by
//!      calling [`ChainBackend::advance_epochs`], because on the real
//!      chain that is literally what waiting is. The mock implements it
//!      by draining its own staging queue, so one test body means the
//!      same thing on both tiers.
//!   3. **Cheats are off the trait.** Faucets, forced owners and epoch
//!      warps are inherent methods on [`MockBackend`]. A test that wants
//!      one names `&MockBackend` and then cannot be handed a node — a
//!      compile error, not a runtime surprise. [`ChainBackend::as_mock`]
//!      is the runtime fallback for tier-parameterised suites, and it
//!      fails with [`BackendError::MockOnly`] naming the cheat and tier.
//!
//! ## Choosing a backend in a test
//!
//! ```ignore
//! use octra_chain_backend::{harness, skip_unless_backend, ConfirmExt};
//!
//! #[tokio::test]
//! async fn settles() {
//!     let chain = skip_unless_backend!(
//!         harness::money_path_backend_from_env().await.unwrap(),
//!         "settles"
//!     );
//!     // …
//! }
//! ```
//!
//! An absent node SKIPS with the compose command to fix it, so `cargo
//! test` works on a laptop with no docker; `OCTRA_TEST_STRICT=1` turns
//! every skip into a failure for CI.
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

pub mod backend;
pub mod canonical_tx;
pub mod error;
pub mod harness;
pub mod mock;
pub mod node;
pub mod tier;

pub use backend::{
    wall_clock_secs, Account, ChainBackend, ConfirmBudget, ConfirmExt, Confirmed, Receipt, Staged,
    TxStatus, ViewResult,
};
pub use canonical_tx::{
    canonical_tx_from_call, sign_call_canonical, yojson_float, CanonicalTx, OP_CALL,
    OP_CIRCLE_CALL, OP_CIRCLE_INGRESS_COMMIT, OP_CIRCLE_OUTBOX_OPEN, OP_CIRCLE_RELAY_CANCEL,
    OP_CIRCLE_RELAY_CLAIM, OP_DEPLOY_CIRCLE, OP_STANDARD,
};
pub use error::{BackendError, BackendResult};
pub use harness::{backend_for_tier, backend_from_env, money_path_backend_from_env, Harness};
pub use mock::MockBackend;
pub use node::{NodeBackend, DEFAULT_NODE_RPC, EPOCH_INTERVAL};
pub use tier::{Tier, TIER_ENV};

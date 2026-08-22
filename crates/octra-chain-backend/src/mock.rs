//! Tier 1 — the in-process mock.
//!
//! # What this tier can and cannot prove
//!
//! `octra-mock-rpc` **executes no AML**. It is hand-written Rust that
//! reimplements our program's per-method semantics, so a green tier-1 run
//! proves our reimplementation agrees with itself and nothing more. That
//! is why the money-path policy exists
//! ([`Tier::satisfies_money_path_policy`]) and why this backend cannot be
//! a money-shaped test's only coverage.
//!
//! # This is an adapter, not a second model
//!
//! Everything below delegates to `octra-mock-rpc`'s own primitives:
//!
//!   * [`octra_mock_rpc::stage_tx`] for submission — which is
//!     `octra_submit`, and therefore **only stages**;
//!   * [`octra_mock_rpc::advance_epoch`] for application;
//!   * the mock's `staged` / `txs` / `receipts` / `rejected_txs` /
//!     `dropped_txs` tables for status and receipts, read in the node's
//!     own lookup order (`history_read_rpc.ml:134-161`): staging,
//!     confirmed, rejected, dropped.
//!
//! Deliberately NOT used: [`octra_mock_rpc::submit_tx`], which composes a
//! stage with an epoch close. That composition is convenient for a test
//! about program semantics and wrong for anything about the submission
//! lifecycle — collapsing the two steps is the conflation that let four
//! money-path bugs through. This backend keeps them apart, so a test that
//! reads state right after submitting sees the *old* state on tier 1,
//! exactly as it would on tier 2.
//!
//! Modelling the lifecycle a second time here would just be a third
//! opinion to keep in sync, so the only places this file adds behaviour
//! of its own are the two below.
//!
//! # What this adapter adds
//!
//!   * **`contract_call` respects the contract address.** The mock
//!     answers for any address; the node does not. Verified live:
//!     `{"code":-32000,"message":"bytecode not found"}`. A view that
//!     "works" against an address that was never deployed is a test that
//!     dies on tier 2.
//!   * **Events never reach [`ChainBackend::transaction`].** The chain
//!     emits none there (`tx_view.ml:93-136`); they exist only on the
//!     [`Receipt`], and even there they are the mock's own invention.
//!     State reads remain the only assertions worth trusting on this
//!     tier.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use octra_mock_rpc::{AppState, ChainState, RpcError};

use crate::{
    backend::{Account, ChainBackend, Receipt, Staged, TxStatus, ViewResult},
    error::{codes, BackendError, BackendResult},
    tier::Tier,
};

/// Tier 1: fast, hermetic, executes no AML.
pub struct MockBackend {
    app: AppState,
}

impl MockBackend {
    /// A fresh mock chain with `program_addr` as the one deployed
    /// contract.
    #[must_use]
    pub fn new(program_addr: impl Into<String>) -> Self {
        Self {
            app: AppState {
                state: Arc::new(parking_lot::RwLock::new(ChainState {
                    epoch: 1,
                    ..Default::default()
                })),
                program_addr: program_addr.into(),
                // The real tx envelope has NO chain_id field
                // (transaction.ml:273-325), so the mock's chain_id gate
                // is tier-1-only fiction and is never armed from here.
                // `canonical_tx_from_call` rejects a chain_id outright.
                expected_chain_id: None,
            },
        }
    }

    /// Wrap an existing mock chain — for migrating a suite that already
    /// holds an [`AppState`] (an `octraforge::ForgeCtx`, say).
    #[must_use]
    pub const fn from_app(app: AppState) -> Self {
        Self { app }
    }

    /// The underlying mock chain, for state assertions the trait does
    /// not model.
    #[must_use]
    pub const fn app(&self) -> &AppState {
        &self.app
    }

    /// The one contract address this mock will answer views for.
    #[must_use]
    pub fn program_addr(&self) -> &str {
        &self.app.program_addr
    }

    // ===================================================================
    // CHEATS — mock-only, and inherent on purpose.
    //
    // None of these are on `ChainBackend`. That is the compile-time half
    // of the `as_mock` split: a test that wants one must name
    // `&MockBackend` in its signature, and then a node backend cannot be
    // passed to it at all. There is no faucet, no instant mint and no
    // `octra_test_*` namespace on a real node — the wire namespace is
    // gone from the mock too — so on tier 2 the right answer is a real
    // transfer from a devkeys account, and the type system should say so
    // before the test runs rather than after.
    // ===================================================================

    /// Credit an account from nothing, optionally registering its
    /// base64 ed25519 public key. Foundry's `deal`.
    ///
    /// Note the mock's own semantics: the first `fund` flips
    /// `ledger_enforced`, after which admission evaluates 100
    /// sender-not-found, 104 insufficient-balance and the 101 signature
    /// check for real. Funding one account therefore tightens the whole
    /// chain — which is the direction we want.
    pub fn deal(&self, addr: impl Into<String>, amount: u64) {
        self.app.fund(addr, amount, None);
    }

    /// [`MockBackend::deal`] with a registered public key, for tests
    /// that need the 101 signature check armed.
    pub fn deal_with_pubkey(&self, addr: impl Into<String>, amount: u64, public_key_b64: String) {
        self.app.fund(addr, amount, Some(public_key_b64));
    }

    /// Force the program owner without a governance tx.
    pub fn set_owner(&self, addr: impl Into<String>) {
        self.app.set_owner(addr);
    }

    /// Seed operator stake without routing through `bond_endpoint`.
    pub fn seed_endpoint_stake(&self, addr: impl Into<String>, amount: u64) {
        self.app.seed_endpoint_stake(addr, amount);
    }

    /// Seed a program storage key. The mock runs no VM, so this is the
    /// only way a view's `storage` envelope gets anything to return.
    pub fn insert_contract_storage(
        &self,
        contract: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.app.insert_contract_storage(contract, key, value);
    }

    /// Jump the epoch counter without applying anything. Foundry's
    /// `warp`. This does NOT drain staging — use
    /// [`ChainBackend::advance_epochs`] for that.
    pub fn warp_epoch(&self, epoch: u64) {
        self.app.state.write().epoch = epoch;
    }

    /// How many transactions are staged and unapplied.
    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.app.state.read().staged.len()
    }

    // ===================================================================

    fn epoch_now(&self) -> u64 {
        self.app.state.read().epoch
    }
}

/// The mock now speaks the node's numbered error table, so codes carry
/// straight across instead of being flattened to a string.
fn from_rpc_error(method: &str, e: &RpcError) -> BackendError {
    let mut message = e.message.clone();
    if let Some(data) = e.data.as_ref().and_then(Value::as_str) {
        message.push_str(" [");
        message.push_str(data);
        message.push(']');
    }
    BackendError::Rpc {
        method: method.to_string(),
        code: e.code,
        message,
    }
}

#[async_trait]
impl ChainBackend for MockBackend {
    fn tier(&self) -> Tier {
        Tier::Mock
    }

    fn describe(&self) -> String {
        format!("mock (in-process, program {})", self.app.program_addr)
    }

    async fn epoch(&self) -> BackendResult<u64> {
        Ok(self.epoch_now())
    }

    async fn account(&self, address: &str) -> BackendResult<Account> {
        let s = self.app.state.read();
        let nonce = s.accounts.get(address).map_or(0, |a| a.nonce);
        Ok(Account {
            address: address.to_string(),
            balance_raw: s.accounts.get(address).map_or(0, |a| a.balance),
            nonce,
            // Staging holds a nonce whether or not the epoch ultimately
            // accepts the tx, so `pending_nonce` is the high-water mark
            // across everything this account has in flight.
            pending_nonce: s
                .staged
                .iter()
                .filter(|t| t.from == address)
                .map(|t| t.nonce)
                .max()
                .unwrap_or(nonce)
                .max(nonce),
        })
    }

    async fn recommended_fee(&self) -> BackendResult<u64> {
        // The local node answers `recommended: "1000"`; the mock's HTTP
        // handler still answers `10`. Report the node's value so fee
        // arithmetic in a test does not change meaning when the suite
        // moves to tier 2.
        Ok(1000)
    }

    async fn submit(&self, signed_tx: &Value) -> BackendResult<Staged> {
        // `stage_tx` IS `octra_submit`: admission checks, then the tx
        // sits in staging. Nothing is applied. `submit_tx` — which
        // closes an epoch too — is deliberately not used here.
        let accepted = octra_mock_rpc::stage_tx(&self.app, signed_tx)
            .map_err(|e| from_rpc_error("octra_submit", &e))?;
        let hash = accepted
            .get("tx_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Decode {
                what: "octra_submit".into(),
                detail: format!("no tx_hash in {accepted}"),
            })?
            .to_string();
        // `status: "accepted"` is read and discarded: it is a statement
        // about staging, not application.
        Ok(Staged::new(
            hash,
            accepted.get("nonce").and_then(Value::as_u64),
        ))
    }

    async fn transaction(&self, hash: &str) -> BackendResult<TxStatus> {
        let s = self.app.state.read();
        // The node's lookup order (`history_read_rpc.ml:134-161`).
        if s.staged.iter().any(|t| t.hash == hash) {
            return Ok(TxStatus::Pending);
        }
        if let Some(row) = s.txs.get(hash) {
            if row.status == "confirmed" {
                return Ok(TxStatus::Confirmed {
                    epoch: Some(row.epoch),
                });
            }
        }
        // The mock stores these as the node's own documents, so they
        // parse through the same code path a real response does.
        if let Some(doc) = s.rejected_txs.get(hash).or_else(|| s.dropped_txs.get(hash)) {
            return Ok(TxStatus::from_json(doc));
        }
        Err(BackendError::Rpc {
            method: "octra_transaction".into(),
            code: codes::NOT_FOUND,
            message: format!("transaction {hash} not found"),
        })
    }

    async fn contract_receipt(&self, hash: &str) -> BackendResult<Option<Receipt>> {
        Ok(self
            .app
            .state
            .read()
            .receipts
            .get(hash)
            .cloned()
            .map(Receipt::from_json))
    }

    async fn contract_call(
        &self,
        contract: &str,
        method: &str,
        params: &[Value],
    ) -> BackendResult<ViewResult> {
        // The mock's in-process `read_call` always targets its one
        // program. Refuse a different address instead of quietly
        // answering: on the node an undeployed address is
        // `{"code":-32000,"message":"bytecode not found"}` (verified
        // live), and a view that succeeds against a nonexistent contract
        // on tier 1 is a test that will die on tier 2.
        if contract != self.app.program_addr {
            return Err(BackendError::Rpc {
                method: "contract_call".into(),
                code: -32000,
                message: "bytecode not found".into(),
            });
        }
        octra_mock_rpc::read_call(&self.app, method, params)
            .map(ViewResult::from_json)
            .map_err(|message| BackendError::Rpc {
                method: "contract_call".into(),
                code: -32000,
                message,
            })
    }

    async fn advance_epochs(&self, n: u64) -> BackendResult<u64> {
        for _ in 0..n {
            octra_mock_rpc::advance_epoch(&self.app);
        }
        Ok(self.epoch_now())
    }

    /// The one backend for which this succeeds.
    fn as_mock(&self, _cheat: &str) -> BackendResult<&Self> {
        Ok(self)
    }
}

/// Hand-written because `octra_mock_rpc::AppState` is not `Debug`.
impl std::fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.app.state.read();
        f.debug_struct("MockBackend")
            .field(
                "app",
                &format_args!(
                    "{}@epoch{} ({} staged, {} applied)",
                    self.app.program_addr,
                    s.epoch,
                    s.staged.len(),
                    s.txs.len()
                ),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{wall_clock_secs, ConfirmBudget, ConfirmExt};
    use crate::canonical_tx::{CanonicalTx, OP_CALL};
    use octra_core::KeyPair;
    use serde_json::json;

    /// A funded, key-registered sender.
    ///
    /// Funding is not decoration: the mock keeps a ledger row only for
    /// funded accounts, and the first `fund` arms admission (100 sender
    /// not found, 101 signature, 104 balance). An unfunded sender has no
    /// nonce to burn — which is the honest answer, and the same one the
    /// node gives.
    fn funded_sender(b: &MockBackend, seed: u8) -> (String, KeyPair) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let kp = KeyPair::from_secret_bytes(&[seed; 32]);
        let from = octra_core::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        b.deal_with_pubkey(from.clone(), 10_000_000, B64.encode(kp.public.0));
        (from, kp)
    }

    /// A signed call envelope, timestamped now — the mock validates
    /// ±300s drift exactly as the node does, so a frozen fixture
    /// timestamp is rejected (code 105).
    fn signed_call(kp: &KeyPair, from: &str, nonce: u64, method: &str, params: &Value) -> Value {
        CanonicalTx {
            from: from.to_string(),
            to: "octPROG".into(),
            amount: 0,
            nonce,
            ou: 1000,
            timestamp: wall_clock_secs(),
            op_type: OP_CALL.into(),
            encrypted_data: Some(method.to_string()),
            message: Some(params.to_string()),
        }
        .signed_envelope(kp)
    }

    /// The headline property: a submit does not apply.
    #[tokio::test]
    async fn submit_only_stages() {
        let b = MockBackend::new("octPROG");
        let (from, kp) = funded_sender(&b, 1);
        let env = signed_call(&kp, &from, 1, "register_device", &json!(["octDEV"]));
        let staged = b.submit(&env).await.unwrap();
        assert_eq!(b.staged_len(), 1);
        assert_eq!(
            b.transaction(staged.hash()).await.unwrap(),
            TxStatus::Pending
        );
        // Nothing applied, so no receipt exists yet.
        assert!(b.contract_receipt(staged.hash()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn advance_epochs_applies_staged_work() {
        let b = MockBackend::new("octPROG");
        let (from, kp) = funded_sender(&b, 1);
        let env = signed_call(&kp, &from, 1, "register_device", &json!(["octDEV"]));
        let staged = b.submit(&env).await.unwrap();
        let epoch = b.advance_epochs(1).await.unwrap();
        assert_eq!(b.staged_len(), 0);
        assert_eq!(
            b.transaction(staged.hash()).await.unwrap(),
            TxStatus::Confirmed { epoch: Some(epoch) }
        );
        // The nonce is consumed only now.
        assert_eq!(b.account(&from).await.unwrap().nonce, 1);
    }

    /// One call to `advance_epochs(n)` must mean exactly n epochs, or an
    /// epoch-count assertion changes meaning when the suite moves to a
    /// real chain.
    #[tokio::test]
    async fn advance_epochs_advances_exactly_n() {
        let b = MockBackend::new("octPROG");
        let start = b.epoch().await.unwrap();
        assert_eq!(b.advance_epochs(3).await.unwrap(), start + 3);
    }

    #[tokio::test]
    async fn await_confirmation_drives_the_epoch_itself() {
        let b = MockBackend::new("octPROG");
        let (from, kp) = funded_sender(&b, 1);
        let env = signed_call(&kp, &from, 1, "register_device", &json!(["octDEV"]));
        let staged = b.submit(&env).await.unwrap();
        let c = b
            .await_confirmation(&staged, ConfirmBudget::for_tier(Tier::Mock))
            .await
            .unwrap();
        assert_eq!(c.hash, staged.hash());
        assert!(c.receipt.is_some_and(|r| r.success));
    }

    #[tokio::test]
    async fn a_refused_tx_surfaces_as_a_terminal_failure_not_a_success() {
        let b = MockBackend::new("octPROG");
        // `register_endpoint` without a bond is refused
        // ("must bond_endpoint first").
        let (from, kp) = funded_sender(&b, 2);
        let env = signed_call(
            &kp,
            &from,
            1,
            "register_endpoint",
            &json!(["ep", "wg", "hfhe", "zero", "eu", 10]),
        );
        let staged = b.submit(&env).await.unwrap();
        let err = b
            .await_confirmation(&staged, ConfirmBudget::for_tier(Tier::Mock))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                BackendError::Rejected { .. } | BackendError::Reverted { .. }
            ),
            "a refused tx must be an Err, got {err}"
        );
    }

    /// The mock now runs the node's admission checks, so its nonce
    /// errors carry the node's codes rather than a flattened string.
    #[tokio::test]
    async fn nonce_errors_use_the_chain_codes() {
        let b = MockBackend::new("octPROG");
        let (from, kp) = funded_sender(&b, 3);
        // Nonce 0 when the account is at 0: the next acceptable nonce is
        // 1 (ledger.ml:241).
        let stale_env = signed_call(&kp, &from, 0, "register_device", &json!(["octDEV"]));
        let stale = b.submit(&stale_env).await.unwrap_err();
        assert!(
            stale.is_nonce_error(),
            "expected a nonce error, got {stale} (code {:?})",
            stale.rpc_code()
        );
    }

    #[tokio::test]
    async fn views_respect_the_contract_address() {
        let b = MockBackend::new("octPROG");
        b.contract_call("octPROG", "get_endpoint_stake", &[json!("octA")])
            .await
            .expect("the deployed program answers");
        let err = b
            .contract_call("octNOPE", "get_endpoint_stake", &[json!("octA")])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("bytecode not found"),
            "an undeployed address must fail like the node: {err}"
        );
    }

    #[tokio::test]
    async fn unknown_accounts_are_not_secretly_rich() {
        let b = MockBackend::new("octPROG");
        assert_eq!(b.account("octNOBODY").await.unwrap().balance_raw, 0);
        b.deal("octNOBODY", 500);
        assert_eq!(b.account("octNOBODY").await.unwrap().balance_raw, 500);
    }

    #[tokio::test]
    async fn as_mock_succeeds_on_the_mock() {
        let b = MockBackend::new("octPROG");
        b.as_mock("deal").expect("mock backend yields itself");
    }

    /// The hash a signed envelope gets is the chain's own hash
    /// (`transaction.ml:482-497`), so a tier-1 capture can be compared
    /// with a tier-2 one.
    #[tokio::test]
    async fn signed_envelopes_get_the_chain_tx_hash() {
        let kp = KeyPair::from_secret_bytes(&[9u8; 32]);
        let canon = CanonicalTx {
            from: octra_core::Address::from_pubkey(&kp.public.0)
                .display()
                .to_string(),
            to: "octPROG".into(),
            amount: 0,
            nonce: 1,
            ou: 1000,
            timestamp: wall_clock_secs(),
            op_type: OP_CALL.into(),
            encrypted_data: Some("register_device".into()),
            message: Some("[\"octDEV\"]".into()),
        };
        let env = canon.signed_envelope(&kp);
        let expected = canon.tx_hash(
            env["signature"].as_str().unwrap(),
            env["public_key"].as_str(),
        );
        let b = MockBackend::new("octPROG");
        let staged = b.submit(&env).await.unwrap();
        assert_eq!(staged.hash(), expected);
    }
}

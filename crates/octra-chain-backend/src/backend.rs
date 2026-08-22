//! The `ChainBackend` trait: one interface over all three tiers.
//!
//! # The design constraint that shaped this file
//!
//! Our mock's `octra_submit` returned `{"hash", "status":"confirmed"}` —
//! it applied the transaction inline and told the caller it was done. The
//! real chain does not do that. `octra_submit` **stages** and answers
//! `{"tx_hash", "status":"accepted", …}` (`rpc_view.ml:706-712`);
//! application happens at the next epoch apply, and the epoch interval is
//! a hardcoded 10s (`epoch_time.ml:10-11`). Every client written against
//! the mock's answer had a latent premature-read bug, and we shipped four
//! of them into the money path before real daemons on devnet caught them.
//!
//! So this trait makes that lie unrepresentable rather than merely
//! discouraged:
//!
//!   * [`ChainBackend::submit`] returns a [`Staged`] — a value with a
//!     hash and **no status field at all**. There is no variant of it
//!     that says "confirmed", so no backend can return one.
//!   * Confirmation lives in [`ConfirmExt::await_confirmation`], which is
//!     supplied by a **blanket impl over every `T: ChainBackend`**. A
//!     backend cannot override it: coherence forbids a competing impl.
//!     The only way to learn a tx confirmed is to go through the
//!     [`ChainBackend::transaction`] / [`ChainBackend::contract_receipt`]
//!     pair, which is exactly how the chain reports it.
//!   * That waiting loop is written in terms of
//!     [`ChainBackend::advance_epochs`], because on the real chain
//!     "waiting for a tx" *is* "waiting for epochs". The mock implements
//!     `advance_epochs` by draining its own staging queue, so the same
//!     test body has the same meaning on both tiers — instantly on tier 1,
//!     in real 10s ticks on tier 2.
//!
//! # Two-document confirmation
//!
//! `octra_transaction` reports the staging lifecycle — pending / confirmed
//! / rejected / dropped (`history_read_rpc.ml:131-175`) — and **never
//! carries events**; the chain emits none (`tx_view.ml:93-136`). Whether
//! a confirmed contract call actually succeeded lives in a second
//! document, `contract_receipt`: `{contract, effort, epoch, error, events,
//! method, program, success, ts}` (`contract_rpc.ml:765-780`, key set
//! confirmed live on devnet by `upstream-reality-probe.sh` item 4).
//!
//! `confirmed` therefore means only "an epoch applied it, and the nonce is
//! spent". [`ConfirmExt::await_confirmation`] refines it with the receipt
//! and raises [`BackendError::Reverted`] when the VM reverted.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    error::{codes, BackendError, BackendResult},
    mock::MockBackend,
    tier::Tier,
};

// ===========================================================================
// Value types
// ===========================================================================

/// An account as the chain reports it (`octra_balance`).
///
/// The real node answers `{address, balance, balance_raw, nonce,
/// pending_nonce, has_public_key}`; the mock's HTTP handler answers
/// `{formatted, raw, nonce, pending_nonce, public_key}` **and invents a
/// balance of 1e9 for accounts it has never heard of**. This struct is
/// the normalised form; [`crate::mock::MockBackend`] does not reproduce
/// the invented balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub address: String,
    /// Balance in OU (the integer unit); the node sends it as a decimal
    /// string under `balance_raw`.
    pub balance_raw: u64,
    /// Last nonce the ledger has **applied** for this account.
    pub nonce: u64,
    /// Highest nonce currently spoken for, staged included. Equals
    /// `nonce` when staging is empty for this account.
    pub pending_nonce: u64,
}

impl Account {
    /// The nonce the next transaction from this account must carry.
    ///
    /// Two rules, both learned the hard way:
    ///
    /// 1. It is `nonce + 1`, not `nonce` (`ledger.ml:241`). Getting this
    ///    wrong is a code 102, and it broke every naive client we wrote.
    /// 2. It counts from `pending_nonce`, not `nonce`, whenever the
    ///    account has something in staging. `nonce` is the last
    ///    **applied** nonce, so a client that has already staged a tx and
    ///    computes `nonce + 1` produces the nonce it just used.
    ///
    /// Rule 2 is why the node reports both numbers, and it is not
    /// theoretical — observed live against the local node when a test
    /// re-ran inside one epoch:
    ///
    /// ```text
    /// {"code":105,"message":"malformed transaction",
    ///  "data":"duplicate nonce (fee rate bump < 10%)"}
    /// ```
    ///
    /// Note the code: 105 malformed, from the replace-by-fee rule — NOT
    /// 102/103, so [`BackendError::is_nonce_error`] does not catch it and
    /// no nonce-reconcile retry will save a client that got this wrong.
    ///
    /// With empty staging `pending_nonce == nonce` and this is plain
    /// `nonce + 1`.
    #[must_use]
    pub const fn next_nonce(&self) -> u64 {
        let base = if self.pending_nonce > self.nonce {
            self.pending_nonce
        } else {
            self.nonce
        };
        base.saturating_add(1)
    }
}

/// A transaction that has been **staged**, and nothing more.
///
/// Deliberately has no status: the chain's own `"accepted"` is a
/// statement about staging, not about application, and carrying it here
/// invites exactly the misreading this crate exists to prevent. To learn
/// the outcome, call [`ConfirmExt::await_confirmation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    hash: String,
    nonce: Option<u64>,
}

impl Staged {
    #[must_use]
    pub fn new(hash: impl Into<String>, nonce: Option<u64>) -> Self {
        Self {
            hash: hash.into(),
            nonce,
        }
    }

    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The nonce the chain says this staged tx consumed, when it told us.
    ///
    /// Staging holds the nonce even if the epoch later rejects the tx —
    /// which is why a rejection must reconcile the next nonce from chain
    /// rather than assume `+1`.
    #[must_use]
    pub const fn nonce(&self) -> Option<u64> {
        self.nonce
    }
}

/// Staging lifecycle status from `octra_transaction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// Staged, not yet applied by an epoch.
    Pending,
    /// An epoch applied it. Says nothing about VM success — see
    /// [`ChainBackend::contract_receipt`].
    Confirmed { epoch: Option<u64> },
    /// Refused at epoch apply. The nonce was NOT consumed
    /// (`tx_view.ml:107-122`); `reason` carries our own `require()`
    /// string verbatim.
    Rejected { error_type: String, reason: String },
    /// Evicted from staging without ever applying
    /// (`tx_view.ml:124-136`). Nonce not consumed.
    Dropped { reason: String, detail: String },
    /// A status string a newer node introduced. Treated as non-terminal
    /// by the confirm loop — an unknown status must never be read as
    /// success.
    Unknown(String),
}

impl TxStatus {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Confirmed { .. } | Self::Rejected { .. } | Self::Dropped { .. }
        )
    }

    /// Parse the `octra_transaction` document.
    #[must_use]
    pub fn from_json(v: &Value) -> Self {
        match v.get("status").and_then(Value::as_str) {
            Some("confirmed") => Self::Confirmed {
                epoch: v.get("epoch").and_then(Value::as_u64),
            },
            Some("rejected") => Self::Rejected {
                error_type: v
                    .pointer("/error/type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                reason: v
                    .pointer("/error/reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified")
                    .to_string(),
            },
            Some("dropped") => Self::Dropped {
                reason: v
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified")
                    .to_string(),
                detail: v
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            Some("pending") | None => Self::Pending,
            Some(other) => Self::Unknown(other.to_string()),
        }
    }
}

/// A contract execution receipt (`contract_receipt`).
///
/// `events` is the ONE place events legitimately appear. The chain emits
/// none from `octra_transaction`, so any assertion phrased as "the tx
/// emitted X" must read this document or, better, read state.
#[derive(Clone, Debug)]
pub struct Receipt {
    pub success: bool,
    pub error: Option<String>,
    pub effort: Option<u64>,
    pub epoch: Option<u64>,
    pub events: Vec<Value>,
    /// The untouched document, for assertions on keys this struct does
    /// not model.
    pub raw: Value,
}

impl Receipt {
    #[must_use]
    pub fn from_json(v: Value) -> Self {
        Self {
            // A receipt with no `success` key is not evidence of success.
            success: v.get("success").and_then(Value::as_bool).unwrap_or(false),
            error: v
                .get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            effort: v.get("effort").and_then(Value::as_u64),
            epoch: v.get("epoch").and_then(Value::as_u64),
            events: v
                .get("events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            raw: v,
        }
    }
}

/// The result of a `contract_call` view.
///
/// The real node answers `{"result": …, "storage": {…}}`; the mock
/// answers a bare value. Normalising here is what lets a view assertion
/// mean the same thing on both tiers.
#[derive(Clone, Debug, Default)]
pub struct ViewResult {
    pub result: Value,
    pub storage: BTreeMap<String, Value>,
}

impl ViewResult {
    #[must_use]
    pub fn from_json(v: Value) -> Self {
        // Only treat `{result: …}` as the wrapped form. A program that
        // legitimately returns an object with a `result` key would be
        // misread, which is why the node also always sends `storage`.
        if v.get("result").is_some() && v.get("storage").is_some() {
            let storage = v
                .get("storage")
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, x)| (k.clone(), x.clone())).collect())
                .unwrap_or_default();
            Self {
                result: v.get("result").cloned().unwrap_or(Value::Null),
                storage,
            }
        } else {
            Self {
                result: v,
                storage: BTreeMap::new(),
            }
        }
    }

    /// The `result` field as an integer. AML returns integers as decimal
    /// **strings** through the RPC (`{"result":"0"}` on the live node),
    /// so accept both.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match &self.result {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// A storage slot, which the node also renders as decimal strings.
    #[must_use]
    pub fn storage_u64(&self, key: &str) -> Option<u64> {
        match self.storage.get(key)? {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }
}

/// A transaction that an epoch applied, with its receipt when it had one.
#[derive(Clone, Debug)]
pub struct Confirmed {
    pub hash: String,
    pub epoch: Option<u64>,
    /// `None` for ops with no execution receipt — plain transfers have
    /// none, and the node answers code 112 for them.
    pub receipt: Option<Receipt>,
}

// ===========================================================================
// The trait
// ===========================================================================

/// One chain, whichever tier it is.
///
/// Everything here is a real chain operation. Cheats — funding an account
/// from nothing, forcing an owner, jumping the epoch counter — are NOT on
/// this trait; see [`ChainBackend::as_mock`].
#[async_trait]
pub trait ChainBackend: Send + Sync {
    /// Which tier this is. Used by the money-path policy and by the
    /// confirm loop to size its budget.
    fn tier(&self) -> Tier;

    /// Human-readable identity for skip/failure messages — an endpoint
    /// URL for the real tiers, a program address for the mock.
    fn describe(&self) -> String;

    /// Current epoch.
    async fn epoch(&self) -> BackendResult<u64>;

    /// Balance and nonces for `address`.
    async fn account(&self, address: &str) -> BackendResult<Account>;

    /// Recommended fee in OU for an ordinary call.
    async fn recommended_fee(&self) -> BackendResult<u64>;

    /// **Stage** a signed transaction.
    ///
    /// Returns as soon as the node has taken it into staging. This is
    /// NOT confirmation: use [`ConfirmExt::await_confirmation`].
    async fn submit(&self, signed_tx: &Value) -> BackendResult<Staged>;

    /// Staging lifecycle status of `hash`.
    async fn transaction(&self, hash: &str) -> BackendResult<TxStatus>;

    /// Execution receipt for `hash`, or `None` when the op has none.
    async fn contract_receipt(&self, hash: &str) -> BackendResult<Option<Receipt>>;

    /// Read-only contract call.
    async fn contract_call(
        &self,
        contract: &str,
        method: &str,
        params: &[Value],
    ) -> BackendResult<ViewResult>;

    /// Move the chain forward by `n` epochs and return the new epoch.
    ///
    /// On a real node this **waits** — the interval is a hardcoded 10s
    /// and no RPC can hurry it (there is no `octra_test_*` namespace and
    /// no mining call anywhere in `rpc_dispatch.ml`). On the mock it
    /// applies the staged queue and returns immediately. Both meanings
    /// are "the chain advanced by n epochs, and anything staged for them
    /// has now been applied or refused".
    async fn advance_epochs(&self, n: u64) -> BackendResult<u64>;

    /// The mock-only escape hatch.
    ///
    /// # Prefer the compile-time split
    ///
    /// This is the *runtime* half. The cheats themselves are inherent
    /// methods on [`MockBackend`], not trait methods, so a test that
    /// wants them can simply take `&MockBackend` in its signature — and
    /// then no node backend can ever be handed to it, because it does
    /// not typecheck. That is the preferred shape, and it is the shape
    /// `octra-circle-sim` already uses (`MemoryChain::upsert_session` /
    /// `fail_next_submit` are inherent on the memory impl, absent from
    /// the `MockChain` trait).
    ///
    /// This method exists for the other case: a suite written once
    /// against `dyn ChainBackend` and run at several tiers, which needs
    /// a cheat during setup only. There it fails loudly — with the cheat
    /// named and the tier named — instead of silently doing nothing.
    ///
    /// The default implementation is the only one a real backend can
    /// have: it must produce a `&MockBackend`, and a node has none.
    fn as_mock(&self, cheat: &str) -> BackendResult<&MockBackend> {
        Err(BackendError::MockOnly {
            cheat: cheat.to_string(),
            tier: self.tier(),
        })
    }
}

// ===========================================================================
// Confirmation — blanket, therefore not overridable
// ===========================================================================

/// How long to wait for a staged tx.
#[derive(Clone, Copy, Debug)]
pub struct ConfirmBudget {
    /// How many epochs to wait through before giving up.
    pub max_epochs: u64,
    /// Wall-clock backstop, independent of the epoch count: each poll is
    /// an RPC that can burn its own timeout.
    pub max_wall: Duration,
}

impl ConfirmBudget {
    /// Three epochs — enough to ride out one late tick without pinning a
    /// test forever. On a real node that is ~30s of chain time, so the
    /// wall backstop is generous; on the mock it is instant.
    #[must_use]
    pub const fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Mock => Self {
                max_epochs: 3,
                max_wall: Duration::from_secs(5),
            },
            Tier::Node | Tier::Fork => Self {
                max_epochs: 3,
                max_wall: Duration::from_secs(90),
            },
        }
    }
}

/// Confirmation, supplied to every backend and overridable by none.
///
/// This is a blanket impl over `T: ChainBackend + ?Sized`. Coherence
/// forbids a second impl for any concrete backend, so a backend author
/// physically cannot substitute a version that reports success without
/// consulting the chain. That is the enforcement behind "a backend must
/// not be able to pretend a submit confirmed".
#[async_trait]
pub trait ConfirmExt: ChainBackend {
    /// Wait for a staged tx to reach a terminal status.
    ///
    /// Waiting is done by [`ChainBackend::advance_epochs`], because on
    /// the real chain that is literally what waiting is.
    ///
    /// # Errors
    ///
    /// * [`BackendError::Rejected`] / [`BackendError::Dropped`] — the
    ///   epoch refused it. The nonce was NOT consumed; reconcile before
    ///   signing anything else.
    /// * [`BackendError::Reverted`] — applied, then the VM reverted. The
    ///   nonce WAS consumed.
    /// * [`BackendError::ConfirmTimeout`] — still pending. This is not a
    ///   verdict: the tx is staged, holds a nonce, and may yet apply. Do
    ///   not resubmit on it.
    async fn await_confirmation(
        &self,
        staged: &Staged,
        budget: ConfirmBudget,
    ) -> BackendResult<Confirmed> {
        let started = Instant::now();
        let hash = staged.hash().to_string();
        let mut polls = 0u32;

        for _ in 0..budget.max_epochs {
            // Wait BEFORE looking: `octra_submit` only stages
            // (rpc_view.ml:706-712) and nothing terminal can happen
            // before the next epoch apply, so an immediate read always
            // says "pending".
            self.advance_epochs(1).await?;
            polls += 1;

            // Lookup failures here are poll-transient — a -32012 stable
            // read, or the brief staging->chaindata indexing gap at
            // epoch apply (healed lazily, history_read_rpc.ml:100-126).
            // Keep polling inside the budget rather than failing the tx.
            let status = match self.transaction(&hash).await {
                Ok(s) => s,
                Err(e) if e.is_transient() || e.rpc_code() == Some(codes::NOT_FOUND) => {
                    if started.elapsed() >= budget.max_wall {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };

            match status {
                TxStatus::Confirmed { epoch } => {
                    // "confirmed" is about the epoch, not the VM. A
                    // missing receipt is not a failure: non-call ops have
                    // none (code 112).
                    let receipt = self.contract_receipt(&hash).await.unwrap_or(None);
                    if let Some(r) = &receipt {
                        if !r.success {
                            return Err(BackendError::Reverted {
                                hash,
                                error: r.error.clone().unwrap_or_else(|| "unspecified".into()),
                            });
                        }
                    }
                    return Ok(Confirmed {
                        hash,
                        epoch,
                        receipt,
                    });
                }
                TxStatus::Rejected { error_type, reason } => {
                    return Err(BackendError::Rejected {
                        hash,
                        error_type,
                        reason,
                    })
                }
                TxStatus::Dropped { reason, detail } => {
                    return Err(BackendError::Dropped {
                        hash,
                        reason,
                        detail,
                    })
                }
                // Pending, or a status a newer node invented. Neither is
                // success; keep waiting.
                TxStatus::Pending | TxStatus::Unknown(_) => {}
            }

            if started.elapsed() >= budget.max_wall {
                break;
            }
        }

        Err(BackendError::ConfirmTimeout {
            hash,
            polls,
            elapsed_secs: started.elapsed().as_secs(),
        })
    }

    /// Submit and wait, with the tier's default budget. The common case.
    async fn submit_and_confirm(&self, signed_tx: &Value) -> BackendResult<Confirmed> {
        let staged = self.submit(signed_tx).await?;
        self.await_confirmation(&staged, ConfirmBudget::for_tier(self.tier()))
            .await
    }

    /// Build, sign and stage a contract call from `kp`, reconciling the
    /// nonce and fee from chain first.
    ///
    /// Signing goes through [`crate::canonical_tx::CanonicalTx`] — the
    /// byte-exact port of `serialize_for_signing`
    /// (`transaction.ml:309-326`). Nothing in this crate constructs
    /// signing bytes any other way; every code-101 we have ever had came
    /// from a second renderer.
    async fn submit_call(
        &self,
        kp: &octra_core::KeyPair,
        from: &str,
        contract: &str,
        method: &str,
        params: &[Value],
        value: u64,
    ) -> BackendResult<Staged> {
        let account = self.account(from).await?;
        let fee = self.recommended_fee().await?;
        let tx = crate::canonical_tx::CanonicalTx {
            from: from.to_string(),
            to: contract.to_string(),
            amount: value,
            nonce: account.next_nonce(),
            ou: fee,
            // Wall-clock, and it must be wall-clock: the node rejects a
            // timestamp more than ±300s from its own (code 105,
            // tx_view.ml:1121-1129). The chain's epoch counter is NOT a
            // clock and must never be substituted here.
            timestamp: wall_clock_secs(),
            op_type: crate::canonical_tx::OP_CALL.to_string(),
            encrypted_data: Some(method.to_string()),
            message: Some(Value::Array(params.to_vec()).to_string()),
        };
        self.submit(&tx.signed_envelope(kp)).await
    }
}

#[async_trait]
impl<T: ChainBackend + ?Sized> ConfirmExt for T {}

/// Seconds since the Unix epoch as a float, the shape the node's
/// `timestamp` field wants (`transaction.ml:292-296`).
#[must_use]
pub fn wall_clock_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn next_nonce_is_plus_one_not_the_reported_nonce() {
        let a = Account {
            address: "octA".into(),
            balance_raw: 10,
            nonce: 0,
            pending_nonce: 0,
        };
        // ledger.ml:241 — a fresh genesis account reports nonce 0 and
        // wants nonce 1 on its first tx. Using 0 is a code 102.
        assert_eq!(a.next_nonce(), 1);
    }

    /// With something in staging, `nonce + 1` is the nonce already
    /// spoken for. The node answers that with a 105 "duplicate nonce",
    /// which is not a nonce-error code and so cannot be retried away.
    #[test]
    fn next_nonce_counts_from_pending_when_staging_is_not_empty() {
        let a = Account {
            address: "octA".into(),
            balance_raw: 10,
            nonce: 4,
            pending_nonce: 6,
        };
        assert_eq!(a.next_nonce(), 7);
    }

    #[test]
    fn staged_has_no_way_to_claim_confirmation() {
        let s = Staged::new("abc", Some(4));
        assert_eq!(s.hash(), "abc");
        assert_eq!(s.nonce(), Some(4));
        // The type has exactly two accessors; there is no status to read
        // and none to set. This test exists to fail if someone adds one.
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("confirmed"), "{dbg}");
        assert!(!dbg.contains("accepted"), "{dbg}");
    }

    #[test]
    fn tx_status_parses_every_terminal_shape() {
        assert_eq!(
            TxStatus::from_json(&json!({"status":"pending"})),
            TxStatus::Pending
        );
        assert_eq!(
            TxStatus::from_json(&json!({"status":"confirmed","epoch":7})),
            TxStatus::Confirmed { epoch: Some(7) }
        );
        assert_eq!(
            TxStatus::from_json(
                &json!({"status":"rejected","error":{"type":"nonce","reason":"stale"}})
            ),
            TxStatus::Rejected {
                error_type: "nonce".into(),
                reason: "stale".into()
            }
        );
        assert_eq!(
            TxStatus::from_json(&json!({"status":"dropped","reason":"evicted","detail":"full"})),
            TxStatus::Dropped {
                reason: "evicted".into(),
                detail: "full".into()
            }
        );
    }

    /// A newer node inventing a status must never read as success.
    #[test]
    fn unknown_status_is_not_terminal() {
        let s = TxStatus::from_json(&json!({"status":"finalizing"}));
        assert_eq!(s, TxStatus::Unknown("finalizing".into()));
        assert!(!s.is_terminal());
    }

    /// A receipt without an explicit `success: true` is not a success.
    #[test]
    fn receipt_without_success_key_is_not_success() {
        assert!(!Receipt::from_json(json!({"events":[]})).success);
        assert!(Receipt::from_json(json!({"success":true})).success);
    }

    #[test]
    fn view_result_normalises_both_tier_shapes() {
        // Real node: {"result":"0","storage":{"pokes":"0"}}
        let real = ViewResult::from_json(json!({"result":"0","storage":{"pokes":"3"}}));
        assert_eq!(real.as_u64(), Some(0));
        assert_eq!(real.storage_u64("pokes"), Some(3));
        // Mock: a bare value.
        let mock = ViewResult::from_json(json!(5));
        assert_eq!(mock.as_u64(), Some(5));
        assert!(mock.storage.is_empty());
    }
}

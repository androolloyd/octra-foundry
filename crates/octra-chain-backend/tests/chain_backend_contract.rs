//! The trait's own contract, driven against [`MockBackend`].
//!
//! These are tests of `ChainBackend` itself — object safety, the
//! stage/confirm split, the tier policy, and the two halves of the
//! `as_mock` escape hatch — not of any program's semantics. They run
//! everywhere, with no docker and no network.
//!
//! The tier-2 twin of this file is `node_backend_live.rs`, which drives
//! the same sequence against a real node and skips when none is running.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use octra_chain_backend::{
    backend::{ConfirmBudget, ConfirmExt},
    canonical_tx::{CanonicalTx, OP_CALL},
    harness::{backend_for_tier, money_path_backend_from_env, Harness},
    wall_clock_secs, BackendError, ChainBackend, MockBackend, Tier, TxStatus,
};
use octra_core::{Address, KeyPair};
use serde_json::{json, Value};

/// A funded, key-registered sender on a mock chain.
///
/// The mock keeps a ledger row only for funded accounts and arms its
/// admission checks (100 sender-not-found, 101 signature, 104 balance)
/// on the first `fund`, so this is what a sender looks like at every
/// tier — there is no unfunded shortcut to write instead.
fn funded_sender(chain: &MockBackend, seed: u8) -> (String, KeyPair) {
    let kp = KeyPair::from_secret_bytes(&[seed; 32]);
    let from = Address::from_pubkey(&kp.public.0).display().to_string();
    chain.deal_with_pubkey(from.clone(), 10_000_000, B64.encode(kp.public.0));
    (from, kp)
}

/// A signed contract-call envelope, timestamped now: both tiers reject a
/// timestamp more than ±300s from their clock (code 105), so a frozen
/// fixture timestamp is not an option.
fn call_tx(kp: &KeyPair, from: &str, nonce: u64, method: &str, params: &Value) -> Value {
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

/// The trait must be usable behind a pointer: that is what lets one
/// suite body run at three tiers.
#[tokio::test]
async fn the_trait_is_object_safe_and_usable_dynamically() {
    let chain: Box<dyn ChainBackend> = Box::new(MockBackend::new("octPROG"));
    assert_eq!(chain.tier(), Tier::Mock);
    let epoch = chain.epoch().await.unwrap();
    assert_eq!(chain.advance_epochs(2).await.unwrap(), epoch + 2);
}

/// `ConfirmExt` is a blanket impl, so it reaches `dyn ChainBackend` too.
/// If this stops compiling, the confirm path has stopped being uniform
/// across tiers — which is the whole design.
#[tokio::test]
async fn confirmation_works_through_a_trait_object() {
    let mock = MockBackend::new("octPROG");
    let (from, kp) = funded_sender(&mock, 1);
    let chain: Box<dyn ChainBackend> = Box::new(mock);
    let staged = chain
        .submit(&call_tx(
            &kp,
            &from,
            1,
            "register_device",
            &json!(["octDEV"]),
        ))
        .await
        .unwrap();
    // Staged is not applied.
    assert_eq!(
        chain.transaction(staged.hash()).await.unwrap(),
        TxStatus::Pending
    );
    let confirmed = chain
        .await_confirmation(&staged, ConfirmBudget::for_tier(Tier::Mock))
        .await
        .unwrap();
    assert_eq!(confirmed.hash, staged.hash());
}

/// `submit_and_confirm` is the same two steps, and must still go through
/// the chain rather than short-circuiting.
#[tokio::test]
async fn submit_and_confirm_composes_the_two_steps() {
    let chain = MockBackend::new("octPROG");
    let (from, kp) = funded_sender(&chain, 1);
    let confirmed = chain
        .submit_and_confirm(&call_tx(
            &kp,
            &from,
            1,
            "register_device",
            &json!(["octDEV"]),
        ))
        .await
        .unwrap();
    assert!(confirmed.receipt.is_some_and(|r| r.success));
    assert_eq!(chain.account(&from).await.unwrap().nonce, 1);
}

/// A staged tx that no epoch ever runs must time out — NOT report
/// success, and not report failure either. `ConfirmTimeout` says "still
/// staged, holds a nonce, may yet apply"; a caller that resubmits on it
/// double-spends its own nonce.
#[tokio::test]
async fn a_tx_no_epoch_ever_applies_times_out_rather_than_lying() {
    /// A backend whose epochs never run. Legal: `advance_epochs` promises
    /// to try, not to succeed — a real node under a stalled consensus
    /// behaves this way too.
    struct FrozenChain(MockBackend);

    #[async_trait::async_trait]
    impl ChainBackend for FrozenChain {
        fn tier(&self) -> Tier {
            Tier::Mock
        }
        fn describe(&self) -> String {
            "frozen".into()
        }
        async fn epoch(&self) -> octra_chain_backend::BackendResult<u64> {
            self.0.epoch().await
        }
        async fn account(
            &self,
            a: &str,
        ) -> octra_chain_backend::BackendResult<octra_chain_backend::Account> {
            self.0.account(a).await
        }
        async fn recommended_fee(&self) -> octra_chain_backend::BackendResult<u64> {
            self.0.recommended_fee().await
        }
        async fn submit(
            &self,
            tx: &Value,
        ) -> octra_chain_backend::BackendResult<octra_chain_backend::Staged> {
            self.0.submit(tx).await
        }
        async fn transaction(&self, h: &str) -> octra_chain_backend::BackendResult<TxStatus> {
            self.0.transaction(h).await
        }
        async fn contract_receipt(
            &self,
            h: &str,
        ) -> octra_chain_backend::BackendResult<Option<octra_chain_backend::Receipt>> {
            self.0.contract_receipt(h).await
        }
        async fn contract_call(
            &self,
            c: &str,
            m: &str,
            p: &[Value],
        ) -> octra_chain_backend::BackendResult<octra_chain_backend::ViewResult> {
            self.0.contract_call(c, m, p).await
        }
        async fn advance_epochs(&self, _n: u64) -> octra_chain_backend::BackendResult<u64> {
            // The chain is stuck. Report the epoch honestly; apply nothing.
            self.0.epoch().await
        }
    }

    let inner = MockBackend::new("octPROG");
    let (from, kp) = funded_sender(&inner, 1);
    let chain = FrozenChain(inner);
    let staged = chain
        .submit(&call_tx(
            &kp,
            &from,
            1,
            "register_device",
            &json!(["octDEV"]),
        ))
        .await
        .unwrap();
    let err = chain
        .await_confirmation(&staged, ConfirmBudget::for_tier(Tier::Mock))
        .await
        .unwrap_err();
    match err {
        BackendError::ConfirmTimeout { hash, polls, .. } => {
            assert_eq!(hash, staged.hash());
            assert_eq!(polls, 3, "one poll per budgeted epoch");
        }
        other => panic!("expected ConfirmTimeout, got {other}"),
    }
}

/// The runtime half of the escape hatch, on a backend that has no cheats.
#[tokio::test]
async fn as_mock_names_the_cheat_and_the_tier_it_was_refused_on() {
    let chain: Box<dyn ChainBackend> =
        Box::new(octra_chain_backend::NodeBackend::node("http://127.0.0.1:1/rpc").unwrap());
    let err = chain.as_mock("deal").unwrap_err();
    assert!(matches!(err, BackendError::MockOnly { .. }));
    let msg = err.to_string();
    for expected in ["deal", "MOCK-ONLY", "node", "faucet", "devkeys"] {
        assert!(msg.contains(expected), "message lacks {expected:?}: {msg}");
    }
}

/// The compile-time half. This function can only ever be handed the
/// mock: a `&dyn ChainBackend` does not coerce to `&MockBackend`, so a
/// test that takes this shape cannot be pointed at a node by changing an
/// environment variable. That is the preferred way to write a cheat-using
/// test — see `ChainBackend::as_mock`'s docs.
async fn a_test_that_needs_a_faucet(chain: &MockBackend) -> u64 {
    chain.deal("octRICH", 42);
    chain.account("octRICH").await.unwrap().balance_raw
}

#[tokio::test]
async fn cheats_are_reachable_only_through_the_concrete_mock_type() {
    let chain = MockBackend::new("octPROG");
    assert_eq!(a_test_that_needs_a_faucet(&chain).await, 42);
    // a_test_that_needs_a_faucet(&NodeBackend::node(..)) does not
    // compile — which is the point, and is why it is not written here.
}

/// The policy, exercised through the harness a money-path suite uses.
#[tokio::test]
async fn the_money_path_harness_refuses_tier_one() {
    // Read whatever tier this run selected, then check the rule directly
    // rather than mutating the shared process environment.
    let tier = Tier::from_env().expect("valid OCTRA_TEST_TIER");
    let h = money_path_backend_from_env().await.expect("tier parses");
    match (tier, h) {
        (Tier::Mock, Harness::Skip(reason)) => {
            assert!(reason.contains("executes no AML"), "{reason}");
            assert!(reason.contains("OCTRA_TEST_TIER=node"), "{reason}");
        }
        (Tier::Mock, Harness::Ready(_)) => {
            panic!("tier 1 must never satisfy the money-path policy")
        }
        // On a real tier the harness either hands back a chain or skips
        // because none is running; both are correct.
        (_, _) => {}
    }
}

#[tokio::test]
async fn the_mock_tier_never_needs_a_service_to_be_running() {
    match backend_for_tier(Tier::Mock).await {
        Harness::Ready(b) => assert_eq!(b.tier(), Tier::Mock),
        Harness::Skip(r) => panic!("tier 1 must always be available: {r}"),
    }
}

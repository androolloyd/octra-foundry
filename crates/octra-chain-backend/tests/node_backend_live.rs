//! Tier 2 — [`NodeBackend`] against a REAL Octra lite node.
//!
//! A backend that has never spoken to a node is not a backend, so this
//! test drives the whole staged-then-applied lifecycle against the
//! containerized Single-mode chain in `docker/octra-node/`:
//!
//!   1. read an account (real `octra_balance` shape),
//!   2. sign a transfer with the canonical preimage,
//!   3. **stage** it — and assert it is NOT yet applied,
//!   4. wait a real epoch,
//!   5. read the money back.
//!
//! Step 3 is the one worth having. It is not assertable at all against
//! the old mock, whose `octra_submit` applied inline and answered
//! `status: "confirmed"`.
//!
//! No node? The test SKIPS with the compose command. `OCTRA_TEST_STRICT=1`
//! makes that skip a failure instead, for CI.
//!
//!     cd octra-foundry/docker/octra-node && \
//!       docker compose -p octra-local-node up -d
//!
//! These are the public `octra-devkeys` accounts, which genesis mints
//! 10,000,000 OCT each on a private chain. Never point this at a network
//! holding real funds — the tier-3 guard below refuses devnet's chain id
//! for exactly that reason.

use octra_chain_backend::{
    backend::{ConfirmBudget, ConfirmExt},
    canonical_tx::{CanonicalTx, OP_STANDARD},
    node::NodeBackend,
    wall_clock_secs, ChainBackend, Tier,
};
use octra_core::KeyPair;
use octra_devkeys::DevAccount;
use serde_json::json;

/// The chain id devnet uses. If a tier-2/3 run ever sees this, the test
/// is about to spend real devnet funds with published keys.
const DEVNET_CHAIN_ID: &str = "octra-devnet-9871-cluster";

async fn node_or_skip(test: &str) -> Option<NodeBackend> {
    let endpoint = NodeBackend::endpoint_from_env(Tier::Node);
    let backend = NodeBackend::node(endpoint.clone()).expect("http client builds");
    if backend.is_reachable().await {
        return Some(backend);
    }
    let reason = format!(
        "no octra node answering at {endpoint}. Start one with:\n  \
         cd octra-foundry/docker/octra-node && docker compose -p octra-local-node up -d"
    );
    assert!(
        !matches!(
            std::env::var("OCTRA_TEST_STRICT").as_deref(),
            Ok("1" | "true" | "TRUE" | "yes")
        ),
        "{test}: {reason} (OCTRA_TEST_STRICT is set, so this skip is a failure)"
    );
    eprintln!("SKIP {test}: {reason}");
    None
}

fn keypair(acct: &DevAccount) -> KeyPair {
    KeyPair::from_secret_bytes(&acct.seed)
}

#[tokio::test]
async fn a_transfer_stages_then_applies_at_an_epoch() {
    let Some(chain) = node_or_skip("a_transfer_stages_then_applies_at_an_epoch").await else {
        return;
    };

    // Guard first: these keys are published in octra-devkeys' source.
    let chain_id = chain.chain_id().await.expect("octra_runtimeVersion");
    assert_ne!(
        chain_id, DEVNET_CHAIN_ID,
        "refusing to sign with PUBLIC devkeys against devnet"
    );

    let sender = DevAccount::get(5).expect("devkey 5");
    let recipient = DevAccount::get(6).expect("devkey 6");
    let from = sender.address().display().to_string();
    let to = recipient.address().display().to_string();

    // Drain first. This chain is persistent and this test is re-runnable,
    // so a previous run's transfer may still be sitting in staging — and
    // then the "before" balances would be read before an apply that is
    // not ours, and two transfers would land inside the measured window.
    // Costs one epoch; buys a deterministic test.
    chain.advance_epochs(1).await.expect("drain staging");

    let before_sender = chain.account(&from).await.expect("octra_balance sender");
    let before_recipient = chain.account(&to).await.expect("octra_balance recipient");
    let start_epoch = chain.epoch().await.expect("node_status");
    let fee = chain.recommended_fee().await.expect("octra_recommendedFee");
    const AMOUNT: u64 = 1_000_000; // 1 OCT, in OU.

    let tx = CanonicalTx {
        from: from.clone(),
        to: to.clone(),
        amount: AMOUNT,
        // nonce+1, not nonce (ledger.ml:241). Using the reported nonce
        // is a code 102.
        nonce: before_sender.next_nonce(),
        ou: fee,
        // Wall-clock: outside ±300s of the node's clock is a code 105.
        timestamp: wall_clock_secs(),
        op_type: OP_STANDARD.to_string(),
        encrypted_data: None,
        message: None,
    };
    let envelope = tx.signed_envelope(&keypair(&sender));

    let staged = chain.submit(&envelope).await.expect("octra_submit");
    eprintln!("staged {} at epoch {start_epoch}", staged.hash());

    // The point of the whole crate: submit STAGED it. Nothing has moved.
    let mid = chain.account(&to).await.expect("recipient mid-flight");
    assert_eq!(
        mid.balance_raw, before_recipient.balance_raw,
        "a staged tx must not have moved money yet"
    );

    let confirmed = chain
        .await_confirmation(&staged, ConfirmBudget::for_tier(Tier::Node))
        .await
        .expect("the epoch applies the transfer");
    eprintln!(
        "confirmed {} at epoch {:?}, receipt {:?}",
        confirmed.hash,
        confirmed.epoch,
        confirmed.receipt.as_ref().map(|r| r.success)
    );

    let after_sender = chain.account(&from).await.expect("sender after");
    let after_recipient = chain.account(&to).await.expect("recipient after");

    // Bounds, not equalities — and that is a finding, not a hedge. A
    // real chain credits the validator set at epoch boundaries, so a
    // balance moves for reasons that have nothing to do with the tx
    // under test. Observed on this very node: a +30 OU credit landed on
    // ALL TEN genesis accounts between the `before` read and the apply,
    // which made `before + AMOUNT` off by exactly that.
    //
    // Any suite that asserts an exact post-balance is asserting that
    // nothing else on the chain moved — true on the mock, false here,
    // and false on devnet. Assert deltas the tx is responsible for.
    let credited = after_recipient.balance_raw - before_recipient.balance_raw;
    assert!(
        credited >= AMOUNT,
        "recipient credited {credited}, expected at least {AMOUNT}"
    );
    let debited = before_sender.balance_raw - after_sender.balance_raw;
    assert!(
        (AMOUNT..=AMOUNT + fee).contains(&debited),
        "sender debited {debited}, expected {AMOUNT}..={} (amount plus fee, less any \
         epoch credit that landed in the same window)",
        AMOUNT + fee
    );
    // The nonce IS exact: nothing but this account's own transactions
    // moves it.
    assert_eq!(
        after_sender.nonce,
        before_sender.nonce + 1,
        "the applied nonce advances by exactly one"
    );
    assert!(
        chain.epoch().await.expect("epoch") > start_epoch,
        "confirmation implies at least one epoch passed"
    );
}

/// The node has no faucet and no test namespace, so the runtime half of
/// the `as_mock` split must fire here — loudly, naming the cheat.
#[tokio::test]
async fn mock_only_cheats_fail_against_a_real_node() {
    let Some(chain) = node_or_skip("mock_only_cheats_fail_against_a_real_node").await else {
        return;
    };
    let err = chain.as_mock("deal").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("deal"), "{msg}");
    assert!(msg.contains("MOCK-ONLY"), "{msg}");

    // And the fiction the mock implements really is absent upstream.
    for fiction in [
        "octra_isValidator",
        "octra_test_grantValidator",
        "octra_fheLoadPk",
    ] {
        let err = chain
            .call(fiction, json!([]))
            .await
            .expect_err("the node has no such method");
        assert!(
            err.is_method_not_found(),
            "{fiction} should be -32601, got {err}"
        );
    }
}

/// The mock discards the contract address; the node does not. Tier 1 was
/// taught to fail the same way, so this pins the shape both sides answer.
#[tokio::test]
async fn views_against_an_undeployed_address_fail_on_the_node_too() {
    let Some(chain) =
        node_or_skip("views_against_an_undeployed_address_fail_on_the_node_too").await
    else {
        return;
    };
    let not_a_contract = DevAccount::get(7).expect("devkey 7").address();
    let err = chain
        .contract_call(not_a_contract.display(), "get_pokes", &[])
        .await
        .expect_err("a plain account has no bytecode");
    assert!(
        err.to_string().contains("bytecode not found"),
        "unexpected error shape: {err}"
    );
}

/// `advance_epochs` on a real node is a wait, not a cheat: the interval
/// is a hardcoded 10s (`epoch_time.ml:10-11`) and no RPC can hurry it.
#[tokio::test]
async fn advance_epochs_really_waits_for_the_chain() {
    let Some(chain) = node_or_skip("advance_epochs_really_waits_for_the_chain").await else {
        return;
    };
    let before = chain.epoch().await.expect("epoch");
    let started = std::time::Instant::now();
    let after = chain.advance_epochs(1).await.expect("one epoch");
    assert!(after > before, "{before} -> {after}");
    eprintln!(
        "epoch {before} -> {after} in {:?} (hardcoded 10s interval)",
        started.elapsed()
    );
}

//! Mock-rpc tx-envelope chain_id binding (P1-5b).
//!
//! Mirrors the Lean axiom
//! `WireProtocol.RpcEnvelope.chain_id_binding_rejects_replay`:
//! when the mock is configured with an `expected_chain_id`, every
//! incoming `octra_submit` whose `chain_id` doesn't match is rejected.
//! This pins the runtime gate the Lean axiom claims is enforced.

use std::sync::Arc;

use octra_mock_rpc::{submit_tx, AppState, ChainState};
use parking_lot::RwLock;
use serde_json::json;

const PROGRAM_ADDR: &str = "octPROGRAM";
const OWNER: &str = "octOWNER";
const CHAIN_MAINNET: &str = "octra-mainnet";
const CHAIN_DEVNET: &str = "octra-devnet";

fn make_app(expected_chain_id: Option<&str>) -> AppState {
    AppState {
        state: Arc::new(RwLock::new(ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr: PROGRAM_ADDR.to_string(),
        expected_chain_id: expected_chain_id.map(str::to_string),
    }
}

/// Baseline: with no chain_id gate, every well-formed tx flows.
#[test]
fn no_gate_accepts_any_chain_id() {
    let app = make_app(None);
    let tx = json!({
        "method": "bond_endpoint",
        "from": OWNER,
        "params": [],
        "value": 1_000_000_000u64,
        "chain_id": CHAIN_MAINNET,
    });
    let (hash, _events) = submit_tx(&app, &tx).expect("no-gate must accept");
    assert!(!hash.is_empty());

    // Same tx without chain_id — also accepted by an un-gated mock.
    let tx = json!({
        "method": "bond_endpoint",
        "from": OWNER,
        "params": [],
        "value": 1_000_000_000u64,
    });
    let (hash2, _events2) = submit_tx(&app, &tx).expect("no-gate must accept v1 tx");
    assert!(!hash2.is_empty());
}

/// **Cross-chain replay rejection (mock layer).** A mock configured
/// for mainnet rejects a tx carrying a devnet chain_id.
#[test]
fn cross_chain_replay_rejected_by_mock() {
    let app = make_app(Some(CHAIN_MAINNET));
    let tx = json!({
        "method": "bond_endpoint",
        "from": OWNER,
        "params": [],
        "value": 1_000_000_000u64,
        "chain_id": CHAIN_DEVNET,
    });
    let err = submit_tx(&app, &tx).expect_err("must reject cross-chain");
    assert!(
        err.contains("chain_id mismatch")
            && err.contains(CHAIN_DEVNET)
            && err.contains(CHAIN_MAINNET),
        "unexpected error: {err}"
    );
}

/// **Missing chain_id on a gated mock is also rejected.** A v1 tx
/// (no chain_id field) submitted to a v2-gated chain fails.
#[test]
fn missing_chain_id_rejected_by_gated_mock() {
    let app = make_app(Some(CHAIN_MAINNET));
    let tx = json!({
        "method": "bond_endpoint",
        "from": OWNER,
        "params": [],
        "value": 1_000_000_000u64,
    });
    let err = submit_tx(&app, &tx).expect_err("must reject missing");
    assert!(
        err.contains("chain_id mismatch") && err.contains("missing chain_id"),
        "unexpected error: {err}"
    );
}

/// **Matching chain_id flows through.** Pin the happy-path so a
/// future regression in the gate logic that always rejects is caught.
#[test]
fn matching_chain_id_accepted_by_gated_mock() {
    let app = make_app(Some(CHAIN_MAINNET));
    let tx = json!({
        "method": "bond_endpoint",
        "from": OWNER,
        "params": [],
        "value": 1_000_000_000u64,
        "chain_id": CHAIN_MAINNET,
    });
    let (hash, _events) = submit_tx(&app, &tx).expect("matching chain_id must accept");
    assert!(!hash.is_empty(), "expected a tx hash on accept");
}

/// **Gate runs BEFORE handler dispatch.** A tx with a chain_id
/// mismatch must be rejected even if the rest of the envelope is
/// malformed (no method, bad op_type), so an attacker can't probe
/// handler-specific behaviour by sending mismatched-chain txs.
#[test]
fn chain_id_gate_precedes_handler_dispatch() {
    let app = make_app(Some(CHAIN_MAINNET));
    let tx = json!({
        // intentionally no `method` and no `op_type` — handler
        // dispatch would normally error with "missing method or
        // op_type". The chain_id gate must fire FIRST.
        "from": OWNER,
        "chain_id": CHAIN_DEVNET,
    });
    let err = submit_tx(&app, &tx).expect_err("must reject");
    assert!(
        err.contains("chain_id mismatch"),
        "gate must run first: {err}"
    );
    // Anti-leak check: the handler-dispatch error string must NOT
    // appear in the response (otherwise the gate wasn't first).
    assert!(!err.contains("missing method or op_type"), "leak: {err}");
}

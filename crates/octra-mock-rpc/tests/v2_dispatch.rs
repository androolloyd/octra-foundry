//! v2 (Circle-native) lifecycle tests for the mock RPC.
//!
//! Exercises the v2 dispatch surface end-to-end without touching
//! v1 state: `authorize_proxy`, `proxy_register_keys`,
//! `open_session_v2`, `settle_claim_v2`, `settle_confirm_v2`. The
//! per-method bodies live in `crates/octra-mock-rpc/src/lib.rs`;
//! these tests are the consumer-facing contract.

use std::sync::Arc;

use octra_mock_rpc::{submit_tx, AppState, ChainState, PROTOCOL_FEE_BPS};
use parking_lot::RwLock;
use serde_json::{json, Value};

const PROGRAM_ADDR: &str = "octPROGRAM";
const OWNER: &str = "octOWNER";
const CLIENT: &str = "octCLIENT";
const PROXY: &str = "octPROXY";

fn make_app() -> AppState {
    AppState {
        state: Arc::new(RwLock::new(ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr: PROGRAM_ADDR.to_string(),
        expected_chain_id: None,
    }
}

/// `submit_tx` returns an error string on the err arm; this helper
/// unwraps the events vec and panics with a useful message on err.
#[allow(clippy::needless_pass_by_value)]
fn submit(app: &AppState, from: &str, method: &str, params: Value, value: u64) -> Vec<Value> {
    let tx = json!({
        "method": method,
        "from": from,
        "params": params,
        "value": value,
    });
    let (_hash, events) = submit_tx(app, &tx).unwrap_or_else(|e| {
        panic!("submit {method} from {from} failed: {e}");
    });
    events
}

#[allow(clippy::needless_pass_by_value)]
fn submit_expect_err(
    app: &AppState,
    from: &str,
    method: &str,
    params: Value,
    value: u64,
) -> String {
    let tx = json!({
        "method": method,
        "from": from,
        "params": params,
        "value": value,
    });
    submit_tx(app, &tx).map(|_| String::new()).unwrap_err()
}

fn event_name(e: &Value) -> &str {
    e.get("name").and_then(|v| v.as_str()).unwrap_or("")
}

fn find_event<'a>(events: &'a [Value], name: &str) -> &'a Value {
    events
        .iter()
        .find(|e| event_name(e) == name)
        .unwrap_or_else(|| panic!("no event named {name} in {events:?}"))
}

/// Bootstrap a tailnet (owner, deposit ≥ min), add `CLIENT` as a
/// member, authorize the proxy, register HFHE keys for the proxy.
fn bootstrap(app: &AppState) -> u64 {
    submit(
        app,
        OWNER,
        "create_tailnet",
        json!(["acl_doc_v1"]),
        1_000_000,
    );
    // create_tailnet's mock counter starts at 0 (matches v1 behavior).
    let tid = 0u64;
    submit(app, OWNER, "add_member", json!([tid, CLIENT]), 0);
    submit(app, OWNER, "authorize_proxy", json!([tid, PROXY]), 0);
    submit(
        app,
        PROXY,
        "proxy_register_keys",
        json!(["hfhe_pubkey_hex", "enc_zero_hex"]),
        0,
    );
    tid
}

#[test]
fn authorize_and_revoke_proxy_emit_events_and_gate_state() {
    let app = make_app();
    submit(&app, OWNER, "create_tailnet", json!(["acl"]), 1_000);
    let tid = 0u64;

    let events = submit(&app, OWNER, "authorize_proxy", json!([tid, PROXY]), 0);
    let ev = find_event(&events, "ProxyAuthorized");
    assert_eq!(ev["tailnet_id"], json!(tid));
    assert_eq!(ev["proxy"], json!(PROXY));

    // Re-authorize is idempotent (set insert is fine).
    submit(&app, OWNER, "authorize_proxy", json!([tid, PROXY]), 0);

    // Non-owner cannot authorize.
    let err = submit_expect_err(
        &app,
        "octNOT_OWNER",
        "authorize_proxy",
        json!([tid, "octOTHER_PROXY"]),
        0,
    );
    assert!(err.contains("not tailnet owner"), "{err}");

    let events = submit(&app, OWNER, "revoke_proxy", json!([tid, PROXY]), 0);
    let ev = find_event(&events, "ProxyRevoked");
    assert_eq!(ev["proxy"], json!(PROXY));
}

#[test]
fn set_charge_internal_traffic_owner_only() {
    let app = make_app();
    submit(&app, OWNER, "create_tailnet", json!(["acl"]), 1_000);
    let tid = 0u64;

    // Non-owner rejected.
    let err = submit_expect_err(
        &app,
        CLIENT,
        "set_charge_internal_traffic",
        json!([tid, 1]),
        0,
    );
    assert!(err.contains("not tailnet owner"));

    // Out-of-range value rejected.
    let err = submit_expect_err(
        &app,
        OWNER,
        "set_charge_internal_traffic",
        json!([tid, 2]),
        0,
    );
    assert!(err.contains("charge must be 0 or 1"));

    let events = submit(
        &app,
        OWNER,
        "set_charge_internal_traffic",
        json!([tid, 1]),
        0,
    );
    let ev = find_event(&events, "TailnetChargeInternalSet");
    assert_eq!(ev["charge"], json!(1));
}

#[test]
fn full_v2_lifecycle_shared_class() {
    let app = make_app();
    let tid = bootstrap(&app);

    // Open: 1_000_000 max_pay, class=0 (shared), price=100 OU/MB.
    let max_pay = 1_000u64;
    let price_per_mb = 100u64;
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, price_per_mb, max_pay]),
        0,
    );
    let ev = find_event(&events, "SessionOpened");
    let sid = ev["session_id"].as_u64().unwrap();
    assert_eq!(ev["proxy"], json!(PROXY));
    assert_eq!(ev["class"], json!(0));
    assert_eq!(ev["price_per_mb"], json!(price_per_mb));
    assert_eq!(ev["deposit"], json!(max_pay));

    // Proxy claims 5 MB.
    let bytes_used = 5u64;
    let events = submit(&app, PROXY, "settle_claim_v2", json!([sid, bytes_used]), 0);
    let ev = find_event(&events, "SettleClaimed");
    assert_eq!(ev["bytes_used"], json!(bytes_used));
    assert_eq!(ev["proxy"], json!(PROXY));

    // Idempotent re-claim with same bytes_used emits nothing.
    let events = submit(&app, PROXY, "settle_claim_v2", json!([sid, bytes_used]), 0);
    assert!(events.is_empty(), "idempotent re-claim should be a no-op");

    // Client confirms with matching bytes.
    let events = submit(
        &app,
        CLIENT,
        "settle_confirm_v2",
        json!([sid, bytes_used]),
        0,
    );
    let confirmed = find_event(&events, "SettleConfirmed");
    assert_eq!(confirmed["bytes_used"], json!(bytes_used));
    let settled = find_event(&events, "SessionSettled");
    let total_paid = settled["total_paid"].as_u64().unwrap();
    let refund = settled["refund"].as_u64().unwrap();
    assert_eq!(total_paid, bytes_used * price_per_mb);
    assert_eq!(refund, max_pay - total_paid);
    assert_eq!(settled["class"], json!(0));

    // Encrypted earnings: net_pay = total - protocol_fee.
    let fee = total_paid * PROTOCOL_FEE_BPS / 10_000;
    let net_pay = total_paid - fee;
    let s = app.state.read();
    assert_eq!(s.enc_earnings_v2.get(PROXY).copied().unwrap(), net_pay);
    // Program treasury captured the fee.
    assert_eq!(s.program_treasury, fee);
    // Tailnet treasury restored by refund.
    let tail = s.tailnets.get(&tid).unwrap();
    assert_eq!(tail.treasury, 1_000_000 - max_pay + refund);
    // Session row reflects status=1.
    let sess = s.sessions_v2.get(&sid).unwrap();
    assert_eq!(sess.status, 1);
    drop(s);

    // Re-confirming a settled session fails.
    let err = submit_expect_err(
        &app,
        CLIENT,
        "settle_confirm_v2",
        json!([sid, bytes_used]),
        0,
    );
    assert!(err.contains("session not open"), "{err}");
}

#[test]
fn internal_class_with_charge_zero_settles_to_zero() {
    let app = make_app();
    let tid = bootstrap(&app);
    // charge_internal_traffic defaults to 0 — explicitly leave it.

    let max_pay = 5_000u64;
    let price_per_mb = 100u64;
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 1, price_per_mb, max_pay]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();

    let bytes_used = 42u64;
    submit(&app, PROXY, "settle_claim_v2", json!([sid, bytes_used]), 0);
    let events = submit(
        &app,
        CLIENT,
        "settle_confirm_v2",
        json!([sid, bytes_used]),
        0,
    );
    let settled = find_event(&events, "SessionSettled");
    assert_eq!(settled["total_paid"], json!(0));
    assert_eq!(settled["refund"], json!(max_pay));
    assert_eq!(settled["class"], json!(1));

    // Encrypted earnings untouched (still 0 from registration).
    let s = app.state.read();
    assert_eq!(s.enc_earnings_v2.get(PROXY).copied().unwrap(), 0);
    // Tailnet treasury fully restored.
    let tail = s.tailnets.get(&tid).unwrap();
    assert_eq!(tail.treasury, 1_000_000);
}

#[test]
fn internal_class_with_charge_one_bills_normally() {
    let app = make_app();
    let tid = bootstrap(&app);
    submit(
        &app,
        OWNER,
        "set_charge_internal_traffic",
        json!([tid, 1]),
        0,
    );

    let max_pay = 5_000u64;
    let price = 100u64;
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 1, price, max_pay]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();

    let bytes_used = 3u64;
    submit(&app, PROXY, "settle_claim_v2", json!([sid, bytes_used]), 0);
    let events = submit(
        &app,
        CLIENT,
        "settle_confirm_v2",
        json!([sid, bytes_used]),
        0,
    );
    let settled = find_event(&events, "SessionSettled");
    assert_eq!(settled["total_paid"], json!(bytes_used * price));
}

#[test]
fn open_session_fails_without_proxy_authorization() {
    let app = make_app();
    submit(&app, OWNER, "create_tailnet", json!(["acl"]), 1_000_000);
    let tid = 0u64;
    submit(&app, OWNER, "add_member", json!([tid, CLIENT]), 0);
    // Skip authorize_proxy.
    let err = submit_expect_err(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    assert!(err.contains("proxy not authorized"), "{err}");
}

#[test]
fn open_session_fails_for_non_member() {
    let app = make_app();
    submit(&app, OWNER, "create_tailnet", json!(["acl"]), 1_000_000);
    let tid = 0u64;
    submit(&app, OWNER, "authorize_proxy", json!([tid, PROXY]), 0);
    let err = submit_expect_err(
        &app,
        "octGHOST",
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    assert!(err.contains("not a tailnet member"), "{err}");
}

#[test]
fn equivocation_refunds_session_and_emits_proxy_bond_slashed() {
    let app = make_app();
    let tid = bootstrap(&app);
    let max_pay = 1_000u64;
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, max_pay]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();

    // First claim: 5.
    submit(&app, PROXY, "settle_claim_v2", json!([sid, 5]), 0);
    // Equivocating second claim: 7.
    let events = submit(&app, PROXY, "settle_claim_v2", json!([sid, 7]), 0);
    let slashed = find_event(&events, "ProxyBondSlashed");
    assert_eq!(slashed["proxy"], json!(PROXY));
    assert_eq!(slashed["amount"], json!(0));
    assert_eq!(slashed["reason"], json!("equivocation"));
    let refunded = find_event(&events, "SessionRefunded");
    assert_eq!(refunded["session_id"], json!(sid));

    // Session marked refunded; tailnet treasury restored.
    let s = app.state.read();
    let sess = s.sessions_v2.get(&sid).unwrap();
    assert_eq!(sess.status, 2);
    let tail = s.tailnets.get(&tid).unwrap();
    assert_eq!(tail.treasury, 1_000_000);
}

#[test]
fn settle_confirm_mismatch_records_dispute() {
    let app = make_app();
    let tid = bootstrap(&app);
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();

    submit(&app, PROXY, "settle_claim_v2", json!([sid, 5]), 0);
    let events = submit(&app, CLIENT, "settle_confirm_v2", json!([sid, 9]), 0);
    let dispute = find_event(&events, "SettleDispute");
    assert_eq!(dispute["operator_bytes"], json!(5));
    assert_eq!(dispute["client_bytes"], json!(9));

    // Session remains open for governance.
    let s = app.state.read();
    let sess = s.sessions_v2.get(&sid).unwrap();
    assert_eq!(sess.status, 0);
}

#[test]
fn settle_confirm_only_by_opener() {
    let app = make_app();
    let tid = bootstrap(&app);
    submit(&app, OWNER, "add_member", json!([tid, "octINTRUDER"]), 0);
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();
    submit(&app, PROXY, "settle_claim_v2", json!([sid, 5]), 0);

    let err = submit_expect_err(&app, "octINTRUDER", "settle_confirm_v2", json!([sid, 5]), 0);
    assert!(err.contains("not session opener"), "{err}");
}

#[test]
fn settle_claim_only_by_proxy() {
    let app = make_app();
    let tid = bootstrap(&app);
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();
    let err = submit_expect_err(&app, "octIMPOSTOR", "settle_claim_v2", json!([sid, 5]), 0);
    assert!(err.contains("not the session proxy"), "{err}");
}

#[test]
fn proxy_register_keys_idempotency_and_required_fields() {
    let app = make_app();
    submit(&app, OWNER, "create_tailnet", json!(["acl"]), 1_000);

    // Missing fields rejected.
    let err = submit_expect_err(&app, PROXY, "proxy_register_keys", json!(["", "z"]), 0);
    assert!(err.contains("required"), "{err}");

    submit(
        &app,
        PROXY,
        "proxy_register_keys",
        json!(["pk_hex", "z_hex"]),
        0,
    );
    // Re-registration rejected.
    let err = submit_expect_err(
        &app,
        PROXY,
        "proxy_register_keys",
        json!(["pk_hex2", "z_hex2"]),
        0,
    );
    assert!(err.contains("already registered"), "{err}");
}

#[test]
fn revoking_proxy_blocks_subsequent_claim() {
    let app = make_app();
    let tid = bootstrap(&app);
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();
    submit(&app, OWNER, "revoke_proxy", json!([tid, PROXY]), 0);
    let err = submit_expect_err(&app, PROXY, "settle_claim_v2", json!([sid, 5]), 0);
    assert!(err.contains("proxy not authorized"), "{err}");
}

#[test]
fn claim_earnings_v2_clears_balance_and_credits_payout() {
    let app = make_app();
    let tid = bootstrap(&app);
    let events = submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let sid = find_event(&events, "SessionOpened")["session_id"]
        .as_u64()
        .unwrap();
    submit(&app, PROXY, "settle_claim_v2", json!([sid, 5]), 0);
    submit(&app, CLIENT, "settle_confirm_v2", json!([sid, 5]), 0);

    let balance = app
        .state
        .read()
        .enc_earnings_v2
        .get(PROXY)
        .copied()
        .unwrap();
    assert!(balance > 0);

    // Wrong amount rejected.
    let err = submit_expect_err(
        &app,
        PROXY,
        "claim_earnings_v2",
        json!([balance + 1, "proof"]),
        0,
    );
    assert!(err.contains("bad opening"), "{err}");

    let events = submit(
        &app,
        PROXY,
        "claim_earnings_v2",
        json!([balance, "proof"]),
        0,
    );
    let claimed = find_event(&events, "EarningsClaimed");
    assert_eq!(claimed["amount"], json!(balance));
    let s = app.state.read();
    assert_eq!(s.enc_earnings_v2.get(PROXY).copied().unwrap(), 0);
    assert_eq!(s.balances.get(PROXY).copied().unwrap(), balance);
}

#[test]
fn v1_and_v2_session_counters_are_independent() {
    // Confirms the v1/v2 coexistence story: opening v1 sessions
    // doesn't bump v2 counters and vice versa.
    let app = make_app();
    let tid = bootstrap(&app);
    submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    submit(
        &app,
        CLIENT,
        "open_session_v2",
        json!([tid, PROXY, 0, 100, 1_000]),
        0,
    );
    let s = app.state.read();
    assert_eq!(s.session_count_v2, 2);
    // v1 counter untouched.
    assert_eq!(s.session_count, 0);
    assert!(s.sessions.is_empty());
}

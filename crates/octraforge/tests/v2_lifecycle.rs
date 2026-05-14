//! End-to-end coverage of the OctraVPN v2 lifecycle: proxy
//! authorization, key registration, the multi-class session model
//! (shared vs internal), and the two-tx settle path.
//!
//! v2 splits the "operator runs an endpoint" role of v1 into a
//! tailnet-scoped "proxy" role. Proxies are authorized per-tailnet by
//! the tailnet owner. Sessions carry a `class` (`0` = shared traffic,
//! billed at `price_per_mb`; `1` = internal traffic, subject to a
//! per-tailnet `charge_internal_traffic` toggle that defaults to off).
//!
//! NOTE: this test exercises method names with `_v2` / proxy suffixes
//! the mock-rpc dispatches once the v2 handlers land. If those
//! handlers are not yet implemented, the test will fail at the first
//! v2 call site — the helper envelopes themselves compile
//! independently of the mock surface.

use octraforge::{octra_test, ForgeCtx};
use serde_json::json;

const OWNER: &str = "octOWNER000000000000000000000000000000001";
const CLIENT: &str = "octCLIENT00000000000000000000000000000001";
const PROXY: &str = "octPROXY000000000000000000000000000000001";

const MOCK_HFHE: &str = "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
const MOCK_ENC_ZERO: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

/// Walk the full v2 happy path: deploy, create tailnet, add member,
/// authorize a proxy, register proxy keys, then run two sessions —
/// one `shared` (must bill at the per-MB rate), one `internal` (must
/// be free because the toggle defaults off).
fn build_v2_tailnet(forge: &mut ForgeCtx) -> u64 {
    // 1. Deploy v2 program (no-op on the mock; returns program addr).
    forge.deploy_octravpn_v2(100, 10);

    // 2. Owner creates the tailnet with a 5_000 OU treasury — enough
    //    headroom for both sessions' max_pay.
    forge.prank(OWNER);
    let created = forge
        .call_create_tailnet(&"ac".repeat(32), 5_000)
        .expect("create tailnet");
    let tid = created
        .event_u64("TailnetCreated", "tailnet_id")
        .expect("tailnet id");

    // 3. Owner adds CLIENT as a member.
    forge.prank(OWNER);
    forge.call_add_member(tid, CLIENT).expect("add member");

    // 4. Owner authorizes PROXY to serve this tailnet.
    forge.prank(OWNER);
    forge
        .call_authorize_proxy(tid, PROXY)
        .expect("authorize proxy");

    tid
}

octra_test!(v2_full_lifecycle_shared_then_internal, |forge| {
    let tid = build_v2_tailnet(&mut forge);

    // 5. charge_internal_traffic defaults to 0 (off). Explicitly
    //    re-affirm the default via the setter so the path is exercised,
    //    and verify it via a view.
    forge.prank(OWNER);
    forge
        .call_set_charge_internal_traffic(tid, 0)
        .expect("set toggle");
    let tnet = forge
        .view("get_tailnet", vec![json!(tid)])
        .expect("get tailnet");
    assert_eq!(
        tnet.get("charge_internal_traffic")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "charge_internal_traffic should default to 0 (off)"
    );

    // 6. Proxy publishes its HFHE pubkey + zero ciphertext so the
    //    program can route encrypted earnings.
    forge.prank(PROXY);
    forge
        .call_proxy_register_keys(MOCK_HFHE, MOCK_ENC_ZERO)
        .expect("proxy register keys");

    // 7. CLIENT opens a `shared` session (class=0) at 100 OU/MB with a
    //    1_000 OU cap.
    forge.prank(CLIENT);
    let opened_shared = forge
        .call_open_session_v2(tid, PROXY, 0, 100, 1_000)
        .expect("open shared session");
    let sid_shared = opened_shared
        .event_u64("SessionOpened", "session_id")
        .expect("shared session id");

    // 8. Proxy claims 5 bytes used.
    forge.prank(PROXY);
    let claimed = forge
        .call_settle_claim_v2(sid_shared, 5)
        .expect("proxy settle_claim_v2");
    assert!(claimed.find_event("SettleClaimed").is_some());
    assert!(
        claimed.find_event("SessionSettled").is_none(),
        "settlement must not apply until client confirms"
    );

    // 9. CLIENT confirms with the same bytes. 5 * 100 = 500 OU paid.
    forge.prank(CLIENT);
    let settled_shared = forge
        .call_settle_confirm_v2(sid_shared, 5)
        .expect("client settle_confirm_v2");
    assert_eq!(
        settled_shared.event_u64("SessionSettled", "total_paid"),
        Some(500),
        "shared traffic must bill at price_per_mb * bytes"
    );

    // 10. CLIENT opens a second session, this one `internal`
    //     (class=1), same price, max_pay=1_000.
    forge.prank(CLIENT);
    let opened_internal = forge
        .call_open_session_v2(tid, PROXY, 1, 100, 1_000)
        .expect("open internal session");
    let sid_internal = opened_internal
        .event_u64("SessionOpened", "session_id")
        .expect("internal session id");

    // 11. Proxy + client both settle the internal session at 5 bytes.
    forge.prank(PROXY);
    forge
        .call_settle_claim_v2(sid_internal, 5)
        .expect("proxy settle_claim_v2 internal");
    forge.prank(CLIENT);
    let settled_internal = forge
        .call_settle_confirm_v2(sid_internal, 5)
        .expect("client settle_confirm_v2 internal");

    // 12. Because `charge_internal_traffic = 0`, the internal session
    //     must settle for `total_paid = 0` regardless of price/bytes.
    assert_eq!(
        settled_internal.event_u64("SessionSettled", "total_paid"),
        Some(0),
        "internal traffic must be free when toggle is off"
    );
});

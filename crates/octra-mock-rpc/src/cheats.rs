// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mock's **fiction**, quarantined and named.
//!
//! # Why this module exists
//!
//! `octra-mock-rpc` used to serve three different kinds of thing from one
//! `match` arm list, with nothing telling them apart:
//!
//! 1. **Real methods** the node dispatches (`octra_submit`, `contract_call`, …).
//! 2. **Deliberate test backdoors** that no chain has or should have
//!    (`octra_test_*`) — legitimate, but only as long as they are *labelled*.
//! 3. **Invented methods** that exist nowhere in the node
//!    (`octra_isValidator`, the seven `octra_fhe*` wrappers). These were the
//!    dangerous ones: a test could call them, pass, and prove nothing, because
//!    on a real node the same call returns `-32601 method not found`.
//!
//! Category 1 now comes from [`crate::methods`], which is *generated* from the
//! node's OCaml dispatch tables (`tools/rpc-scrape`). Category 2 lives here,
//! under a name that cannot be mistaken for chain behaviour. Category 3 is
//! gone, with a tombstone in [`REMOVED_FICTION`] so it cannot quietly return.
//!
//! # The one rule
//!
//! A method the mock answers is EITHER in [`crate::methods::NODE_METHODS`] OR
//! in [`MOCK_CHEATS`]. Never both, never neither. [`classify`] is the whole
//! decision, and [`Surface::Unknown`] must produce [`method_not_found`] —
//! byte-identical to what the node itself would say.
//!
//! # Wiring (owner of `lib.rs`, this is the whole change)
//!
//! Declare the modules — `pub mod`, not `mod`, or the workspace's
//! `unreachable_pub` lint fires on every item here:
//!
//! ```ignore
//! pub mod cheats;
//! pub mod methods;
//! ```
//!
//! Then gate `rpc_handler` on [`classify`] *before* the existing match:
//!
//! ```ignore
//! async fn rpc_handler(State(app): State<AppState>, Json(req): Json<RpcReq>) -> impl IntoResponse {
//!     let _ = req.jsonrpc;
//!
//!     // A method the chain does not have can never be answered here, and a
//!     // cheat can never be answered outside tier 1.
//!     match cheats::classify(&req.method) {
//!         cheats::Surface::Node => {}
//!         cheats::Surface::Cheat(_) if cheats::cheats_enabled() => {}
//!         cheats::Surface::Cheat(_) => return Json(cheats::cheat_disabled(&req.id, &req.method)),
//!         cheats::Surface::Unknown => return Json(cheats::method_not_found(&req.id, &req.method)),
//!     }
//!
//!     let result = match req.method.as_str() { /* … existing arms … */ };
//!     match result {
//!         Ok(r) => Json(json!({"jsonrpc": "2.0", "id": req.id, "result": r})),
//!         // handler failures keep the generic -32000 they have today; use
//!         // `cheats::error_response` with a `methods::codes::*` constant when
//!         // porting an arm to the node's real code.
//!         Err(e) => Json(cheats::error_response(&req.id, -32000, &e, None)),
//!     }
//! }
//! ```
//!
//! The trailing `_ => Err(format!("unknown method: {}", req.method))` arm
//! becomes `_ => unreachable!("classify() admitted {}", req.method)` — an arm
//! that is now genuinely unreachable, because the gate above already rejected
//! everything the mock does not implement. Note that a *real* method the mock
//! has not implemented yet still lands there, so prefer
//! `_ => Err(format!("{} is a real node method the mock has not implemented", req.method))`.

use serde_json::{json, Value};

use crate::methods;

// ---------------------------------------------------------------------------
// The cheat registry
// ---------------------------------------------------------------------------

/// A mock-only backdoor: state manipulation no real chain exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cheat {
    /// JSON-RPC method name, as callers spell it.
    pub method: &'static str,
    /// What it does to mock state, and what the Tier-2/Tier-3 equivalent is.
    pub what: &'static str,
    /// How a caller must achieve the same effect against a real node.
    pub real_chain_equivalent: &'static str,
}

/// Every mock-only cheat, sorted by method name.
///
/// These are ours by design and honest *as cheats*. They exist nowhere in
/// `lite_node` — verified by zero grep hits at
/// [`methods::SOURCE_COMMIT`] — which is exactly why they must be
/// declared here rather than blended in with real routes.
pub const MOCK_CHEATS: &[Cheat] = &[
    Cheat {
        method: "octra_test_bondEndpoint",
        what: "forces an endpoint into the bonded set without a bond tx or its stake",
        real_chain_equivalent: "submit a real `bond_endpoint` contract call and wait an epoch",
    },
    Cheat {
        method: "octra_test_grantValidator",
        what: "adds an address to the mock's validator set",
        real_chain_equivalent:
            "seed OCTRA_VALIDATORS at genesis (Tier 2), or fork devnet state (Tier 3)",
    },
    Cheat {
        method: "octra_test_revokeValidator",
        what: "removes an address from the mock's validator set",
        real_chain_equivalent: "no equivalent; the node's validator set is consensus-owned",
    },
    Cheat {
        method: "octra_test_setOwner",
        what: "rewrites program-owner state directly, skipping the ownership transfer path",
        real_chain_equivalent:
            "submit the program's own owner-transfer method as the current owner",
    },
];

/// Methods the mock used to serve that **the node does not have**.
///
/// Kept as a tombstone: [`fiction_stays_dead`] asserts none of these has crept
/// back into either [`methods::NODE_METHODS`] or [`MOCK_CHEATS`]. Re-adding one
/// as a *cheat* would at least be honest; re-adding one as a *node method*
/// would be a lie, and the generated table makes that impossible anyway.
///
/// The reason each was wrong is recorded so the next person does not have to
/// re-derive it.
pub const REMOVED_FICTION: &[(&str, &str)] = &[
    (
        "octra_fheAdd",
        "no `fhe` RPC namespace exists in lite_node; HFHE work happens inside the VM \
         and via circle hfhe policy reads (octra_circleHfhePolicy*), not over JSON-RPC",
    ),
    ("octra_fheAddConst", "same as octra_fheAdd"),
    ("octra_fheDecrypt", "same as octra_fheAdd"),
    ("octra_fheEncrypt", "same as octra_fheAdd"),
    (
        "octra_fheLoadPk",
        "the real gate is an ed25519-signed PVAC pubkey registration via the REAL \
         methods octra_registerPvacPubkey / octra_pvacPubkey, both of which exist",
    ),
    ("octra_fheMakeZeroProof", "same as octra_fheAdd"),
    ("octra_fheVerifyZero", "same as octra_fheAdd"),
    (
        "octra_isValidator",
        "the node exposes no validator-membership predicate; the closest real reads are \
         octra_consensusPeerStates and octra_validatorSetProof, which have different shapes",
    ),
];

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Which surface a method name belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// A method the real node dispatches. Safe to implement, and the mock's
    /// answer is judged against the node's.
    Node,
    /// A mock-only backdoor. Answering this is only legitimate in Tier 1.
    Cheat(&'static Cheat),
    /// Neither. The mock must answer exactly as the node would: `-32601`.
    Unknown,
}

/// Classify a JSON-RPC method name.
///
/// This is the single decision the mock dispatcher should make before it does
/// anything else, so that "the mock invented a method" becomes unrepresentable.
#[must_use]
pub fn classify(method: &str) -> Surface {
    if methods::is_node_method(method) {
        return Surface::Node;
    }
    if let Some(cheat) = MOCK_CHEATS.iter().find(|c| c.method == method) {
        return Surface::Cheat(cheat);
    }
    Surface::Unknown
}

/// Is `method` a mock-only cheat?
#[must_use]
pub fn is_cheat(method: &str) -> bool {
    matches!(classify(method), Surface::Cheat(_))
}

// ---------------------------------------------------------------------------
// Tier gate
// ---------------------------------------------------------------------------

/// Env var that selects the test tier. Mirrors `octra_chain_backend::tier`.
pub const TIER_ENV: &str = "OCTRA_TEST_TIER";

/// Are mock-only cheats permitted in this process?
///
/// Cheats are Tier-1-only. The gate is deliberately **deny-by-default for
/// anything that is not explicitly `mock`**, including unset-but-suspicious and
/// unrecognised values: a Tier-2 run that still reaches for a cheat should hit
/// the node's own `-32601`, not get a courtesy answer from the mock.
///
/// Unset is treated as Tier 1, because that is what a bare `cargo test` is —
/// the mock binary itself only ever runs as Tier 1. What this gate actually
/// catches is a harness that set `OCTRA_TEST_TIER=node` and then pointed at the
/// mock by mistake.
///
/// Kept dependency-free on purpose: `octra-mock-rpc` does not depend on
/// `octra-chain-backend`, and adding that edge would invert the layering. The
/// value vocabulary must stay in sync with `crates/octra-chain-backend/src/tier.rs`.
#[must_use]
pub fn cheats_enabled() -> bool {
    match std::env::var(TIER_ENV) {
        Err(_) => true,
        Ok(v) => v.trim().eq_ignore_ascii_case("mock"),
    }
}

// ---------------------------------------------------------------------------
// The node's error envelope
// ---------------------------------------------------------------------------

/// The node's `method not found` response, byte-for-byte.
///
/// `lib/core/rpc.ml:23`
/// ```ocaml
/// let method_not_found m =
///   { code = -32601; message = Printf.sprintf "method not found: %s" m; data = None }
/// ```
///
/// `lib/core/rpc.ml:45-51` serialises `Error_` as
/// `{"jsonrpc":"2.0","error":{"code":..,"message":..},"id":..}`, and **omits
/// `data` entirely** when it is `None` — so there is no `"data":null` member.
///
/// The mock previously answered `{"code":-32000,"message":"unknown method: X"}`,
/// which is neither the right code nor the right text; any client that
/// branched on it was branching on the mock's imagination.
#[must_use]
pub fn method_not_found(id: &Value, method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": methods::METHOD_NOT_FOUND_CODE,
            "message": methods::method_not_found_message(method),
        },
        "id": id,
    })
}

/// Response for a cheat invoked outside Tier 1.
///
/// Deliberately identical to [`method_not_found`]: on a real node the cheat
/// *is* an unknown method, so the mock refusing it must be indistinguishable
/// from the node refusing it. A harness that "works on the mock but 404s on the
/// node" is the exact failure mode this whole module exists to prevent.
#[must_use]
pub fn cheat_disabled(id: &Value, method: &str) -> Value {
    method_not_found(id, method)
}

/// A generic node-shaped error envelope, for handlers that need one.
///
/// Codes live in [`methods::codes`]; do not invent new ones.
#[must_use]
pub fn error_response(id: &Value, code: i32, message: &str, data: Option<Value>) -> Value {
    let mut err = serde_json::Map::new();
    err.insert("code".into(), json!(code));
    err.insert("message".into(), json!(message));
    if let Some(d) = data {
        err.insert("data".into(), d);
    }
    json!({ "jsonrpc": "2.0", "error": Value::Object(err), "id": id })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cheats_are_sorted_and_unique() {
        for pair in MOCK_CHEATS.windows(2) {
            assert!(
                pair[0].method < pair[1].method,
                "MOCK_CHEATS unsorted at {:?}",
                (pair[0].method, pair[1].method)
            );
        }
    }

    #[test]
    fn cheats_are_not_node_methods() {
        // If this ever fires, upstream grew a method with our test-backdoor
        // name and the collision must be resolved in favour of the node.
        for c in MOCK_CHEATS {
            assert!(
                !methods::is_node_method(c.method),
                "{} is a REAL node method; it cannot also be a cheat",
                c.method
            );
        }
    }

    #[test]
    fn only_the_test_namespace_may_cheat() {
        // A cheat that does not announce itself as one is how the fiction got
        // in last time. `octra_test_` is the reserved, obviously-fake prefix.
        for c in MOCK_CHEATS {
            assert!(
                c.method.starts_with("octra_test_"),
                "cheat {} must live under the octra_test_ prefix",
                c.method
            );
        }
    }

    #[test]
    fn fiction_stays_dead() {
        for (name, why) in REMOVED_FICTION {
            assert!(
                !methods::is_node_method(name),
                "{name} is not a node method ({why})"
            );
            assert!(!is_cheat(name), "{name} came back as a cheat ({why})");
            assert_eq!(classify(name), Surface::Unknown);
        }
    }

    #[test]
    fn removed_fiction_is_sorted_and_unique() {
        for pair in REMOVED_FICTION.windows(2) {
            assert!(pair[0].0 < pair[1].0, "REMOVED_FICTION unsorted");
        }
    }

    #[test]
    fn the_pvac_methods_are_real_and_must_not_be_confused_with_the_fhe_fiction() {
        // These two survived the cull because the node genuinely has them:
        //   octra_registerPvacPubkey -> rpc_effect_dispatch.ml mutation group
        //   octra_pvacPubkey         -> account_read_rpc.ml pvac_dispatch
        assert_eq!(classify("octra_registerPvacPubkey"), Surface::Node);
        assert_eq!(classify("octra_pvacPubkey"), Surface::Node);
    }

    #[test]
    fn classify_covers_the_three_cases() {
        assert_eq!(classify("octra_submit"), Surface::Node);
        assert!(matches!(
            classify("octra_test_setOwner"),
            Surface::Cheat(c) if c.method == "octra_test_setOwner"
        ));
        assert_eq!(classify("octra_definitelyNotAThing"), Surface::Unknown);
    }

    #[test]
    fn aliases_classify_as_node_methods() {
        // Upstream registers both spellings against one handler
        // (rpc_dispatch.ml `route_aliases`); a mock that only knew one of them
        // would 404 on traffic the node happily serves.
        assert_eq!(classify("contract_call"), Surface::Node);
        assert_eq!(classify("octra_programCall"), Surface::Node);
        assert_eq!(classify("vm_contract"), Surface::Node);
        assert_eq!(classify("octra_programInfo"), Surface::Node);
        assert_eq!(methods::primary_name("octra_programCall"), "contract_call");
    }

    #[test]
    fn method_not_found_matches_the_node_envelope() {
        let v = method_not_found(&json!(7), "octra_isValidator");
        assert_eq!(
            v,
            json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32601,
                    "message": "method not found: octra_isValidator"
                },
                "id": 7
            })
        );
        // The node omits `data` when it is None — assert the absence, because
        // a stray "data": null is exactly the kind of drift that trains
        // clients on mock-only behaviour.
        assert!(v["error"].get("data").is_none());
    }

    #[test]
    fn cheat_disabled_is_indistinguishable_from_method_not_found() {
        let id = json!("abc");
        assert_eq!(
            cheat_disabled(&id, "octra_test_setOwner"),
            method_not_found(&id, "octra_test_setOwner")
        );
    }

    #[test]
    fn error_response_omits_absent_data() {
        let a = error_response(
            &json!(1),
            methods::codes::INVALID_NONCE,
            "invalid nonce",
            None,
        );
        assert!(a["error"].get("data").is_none());
        let b = error_response(
            &json!(1),
            methods::codes::MALFORMED_TX,
            "malformed transaction",
            Some(json!("timestamp missing")),
        );
        assert_eq!(b["error"]["data"], json!("timestamp missing"));
        assert_eq!(b["error"]["code"], json!(105));
    }

    #[test]
    fn tier_gate_denies_non_mock_tiers() {
        // `cheats_enabled` reads process env, so exercise the decision function
        // rather than mutating global state under a parallel test runner.
        let decide = |v: Option<&str>| match v {
            None => true,
            Some(s) => s.trim().eq_ignore_ascii_case("mock"),
        };
        assert!(decide(None));
        assert!(decide(Some("mock")));
        assert!(decide(Some("MOCK")));
        assert!(!decide(Some("node")));
        assert!(!decide(Some("fork")));
        assert!(!decide(Some("")));
        assert!(!decide(Some("mocking")));
    }
}

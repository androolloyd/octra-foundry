//! AML executor surface for the mock RPC.
//!
//! Today the mock dispatches RPC methods directly in `lib.rs` — it does
//! **not** interpret AML bytecode. The honest `host_fhe` module here
//! exposes the six HFHE host calls (`fhe_load_pk`, `fhe_deser`,
//! `fhe_add`, `fhe_add_const`, `fhe_verify_zero`, `fhe_ser`) that an
//! AML executor *would* dispatch to once one exists. Those six calls
//! are **not** JSON-RPC methods — the node answers `-32601` for every
//! `octra_fhe*` name — so this crate exposes them as in-process
//! helpers, plus the `apply_claim_earnings_v2` path when the
//! `OCTRAVPN_E2E_USE_HFHE_MOCK` env switch is on.

pub mod host_fhe;

//! AML executor surface for the mock RPC.
//!
//! Today the mock dispatches RPC methods directly in `lib.rs` — it does
//! **not** interpret AML bytecode. The honest `host_fhe` module here
//! exposes the six HFHE host calls (`fhe_load_pk`, `fhe_deser`,
//! `fhe_add`, `fhe_add_const`, `fhe_verify_zero`, `fhe_ser`) that an
//! AML executor *would* dispatch to once one exists. Today the same
//! surface is reached through the `octra_fhe*` RPC methods (see
//! `lib.rs::rpc_handler`) and through the `apply_claim_earnings_v2`
//! path when the `OCTRAVPN_E2E_USE_HFHE_MOCK` env switch is on. That
//! lets the v3 smoke test exercise the full ciphertext+proof flow
//! against the mock today, ahead of the chain-side `fhe_*` bridge.

pub mod host_fhe;

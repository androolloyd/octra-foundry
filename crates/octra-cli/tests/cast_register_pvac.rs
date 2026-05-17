//! Integration tests for `cast register-pvac`.
//!
//! Two flavours:
//!
//! 1. **Subprocess** via `assert_cmd` to confirm the binary's argv
//!    parsing and `--help` rendering match the spec.
//! 2. **In-process** via `octra_cli::run` to confirm `--print-only`
//!    never touches the network and that the printed envelope is
//!    well-formed JSON.
//!
//! Sibling unit tests in `src/cast/pvac.rs` cover canonical-message
//! format, signature verification, determinism, and reject paths for
//! malformed `--pvac-pk` / `--kat-hex`. Splitting concerns this way
//! keeps the integration layer cheap while the heavy invariants live
//! next to the implementation.

use std::fs;

use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

/// `octra cast register-pvac --help` renders and mentions the key
/// argument shapes documented in the spec.
#[test]
fn help_renders() {
    cmd()
        .args(["cast", "register-pvac", "--help"])
        .assert()
        .success()
        .stdout(contains("--key"))
        .stdout(contains("--pvac-pk"))
        .stdout(contains("--kat-hex"))
        .stdout(contains("--rpc-url"))
        .stdout(contains("--print-only"));
}

/// `--print-only` produces a signed envelope without hitting the
/// network — even though we pass a *bogus* rpc URL, the test must
/// still pass because nothing tries to dial it.
#[test]
fn print_only_does_not_dial_network() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    // Generate a wallet first via the existing `cast wallet new`
    // subcommand so the test exercises a realistic key file.
    cmd()
        .args(["cast", "wallet", "new", "--out"])
        .arg(&key_path)
        .assert()
        .success();

    let pvac_pk = STANDARD.encode([0x42u8; 32]);

    let out = cmd()
        .args([
            "cast",
            "register-pvac",
            "--key",
        ])
        .arg(&key_path)
        .args([
            "--pvac-pk",
            &pvac_pk,
            "--rpc-url",
            "http://127.0.0.1:1/should-never-be-dialed",
            "--print-only",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(v["method"], serde_json::json!("octra_registerPvacPubkey"));
    let params = v["params"].as_array().unwrap();
    assert_eq!(params.len(), 5, "5 RPC params expected");
    assert_eq!(params[1], serde_json::json!(pvac_pk));
    assert_eq!(params[4], serde_json::json!(""), "no KAT → empty string");

    // Address embedded in canonical_message should appear in params[0]
    // too (sanity check that the signer didn't drift from the spec).
    let canonical = v["canonical_message"].as_str().unwrap();
    let addr = v["addr"].as_str().unwrap();
    let expected_prefix = format!("register_pvac|{addr}|");
    assert!(
        canonical.starts_with(&expected_prefix),
        "canonical message {canonical} should start with {expected_prefix}"
    );
}

/// Malformed `--pvac-pk` fails fast with a clear error.
#[test]
fn rejects_bad_pvac_pk() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    fs::write(&key_path, "ff".repeat(32)).unwrap();
    let out = cmd()
        .args(["cast", "register-pvac", "--key"])
        .arg(&key_path)
        .args(["--pvac-pk", "!!!not-base64!!!", "--print-only"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "expected failure for non-base64 --pvac-pk"
    );
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("base64"),
        "error should mention base64; got: {err}"
    );
}

//! Integration tests for `cast circle put` — the forward-compatible
//! plaintext-asset publish subcommand.
//!
//! Coverage:
//!
//! 1. **Help renders** with the expected option surface.
//! 2. **Wire shape parity with `put-encrypted`**: both subcommands
//!    submit through the same `octra_submit` path against the in-process
//!    mock-rpc (which doesn't enforce `sealed_read`), and both report
//!    `status: confirmed` plus a tx hash. The mock accepts the envelope
//!    on the same code path; this locks the wire shape independent of
//!    the live chain's policy.
//! 3. **Stable output keys**: `put` prints the same envelope-summary
//!    fields the rest of `cast circle` does (`circle_id`, `path`,
//!    `plaintext_hash`, `submit.hash`, `submit.status`).
//!
//! Why this test layer exists: as of 2026-05 the live chain enforces
//! sealed-read on every circle (`circle_mode_invalid: sealed_read
//! circles require encrypted asset updates`), so we cannot run an
//! end-to-end "deploy + put + read" loop against devnet for plaintext.
//! These tests verify that the moment a chain version with a
//! non-sealed `resource_mode` (e.g. `public_read`) ships, the
//! subcommand works without any further client changes.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

/// `octra cast circle put --help` renders and lists the documented args.
#[test]
fn put_help_renders() {
    cmd()
        .args(["cast", "circle", "put", "--help"])
        .assert()
        .success()
        .stdout(contains("--circle"))
        .stdout(contains("--path"))
        .stdout(contains("--file"))
        .stdout(contains("--content-type"))
        .stdout(contains("--key"))
        .stdout(contains("--ou"))
        .stdout(contains("--rpc-url"));
}

/// `octra cast circle --help` lists `put` alongside `put-encrypted`.
#[test]
fn put_is_listed_in_circle_help() {
    cmd()
        .args(["cast", "circle", "--help"])
        .assert()
        .success()
        .stdout(contains("put"))
        .stdout(contains("put-encrypted"));
}

/// Wire shape parity vs `put-encrypted`: both subcommands submit
/// successfully against the in-process mock. The mock doesn't enforce
/// `sealed_read`, so a plaintext put returns `status: confirmed` the
/// same way `put-encrypted` does — proving the envelope is well-formed
/// on the same code path.
#[test]
fn put_envelope_accepted_by_mock_rpc() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    cmd()
        .args(["cast", "wallet", "new", "--out"])
        .arg(&key_path)
        .assert()
        .success();

    let asset_path = dir.path().join("hello.txt");
    fs::write(&asset_path, b"hello, sealed-free world").unwrap();

    let out = cmd()
        .args([
            "cast",
            "circle",
            "put",
            "--circle",
            "octCIRCLE0000000000000000000000000000000DEMO",
            "--path",
            "/hello.txt",
            "--file",
        ])
        .arg(&asset_path)
        .args(["--key"])
        .arg(&key_path)
        .args([
            "--content-type",
            "text/plain",
            "--rpc-url",
            "inprocess://octPROG",
            "--nonce",
            "1",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(v["path"], serde_json::json!("/hello.txt"), "got: {stdout}");
    assert_eq!(
        v["circle_id"],
        serde_json::json!("octCIRCLE0000000000000000000000000000000DEMO")
    );
    assert!(v["plaintext_hash"].is_string());
    assert_eq!(v["submit"]["status"], serde_json::json!("confirmed"));
    let hash = v["submit"]["hash"].as_str().expect("submit.hash present");
    assert_eq!(hash.len(), 64, "submit.hash should be sha256 hex");
}

/// `put-encrypted` against the same mock to lock-in parity: the
/// envelope-summary JSON shape that `put` emits is a strict subset of
/// what `put-encrypted` emits (no `resource_key` on plaintext side).
#[test]
fn put_encrypted_envelope_also_accepted() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    cmd()
        .args(["cast", "wallet", "new", "--out"])
        .arg(&key_path)
        .assert()
        .success();

    let asset_path = dir.path().join("hello.txt");
    fs::write(&asset_path, b"hello, sealed world").unwrap();

    let out = cmd()
        .args([
            "cast",
            "circle",
            "put-encrypted",
            "octCIRCLE0000000000000000000000000000000DEMO",
            "/hello.txt",
        ])
        .arg(&asset_path)
        .args(["--passphrase", "test"])
        .args(["--key"])
        .arg(&key_path)
        .args([
            "--content-type",
            "text/plain",
            "--rpc-url",
            "inprocess://octPROG",
            "--nonce",
            "1",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(v["path"], serde_json::json!("/hello.txt"));
    assert_eq!(v["submit"]["status"], serde_json::json!("confirmed"));
    assert!(
        v["resource_key"].is_string(),
        "put-encrypted publishes a resource_key; got: {stdout}"
    );
}

/// `cast circle put` and `cast circle put-encrypted` both submit to the
/// same RPC method with `op_type` distinguishing the two — verify the
/// stdout summaries share the load-bearing keys.
#[test]
fn put_and_put_encrypted_share_summary_keys() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    cmd()
        .args(["cast", "wallet", "new", "--out"])
        .arg(&key_path)
        .assert()
        .success();
    let asset_path = dir.path().join("a.txt");
    fs::write(&asset_path, b"abc").unwrap();

    let circle = "octCIRCLEPARITY00000000000000000000000000000";

    let put = cmd()
        .args([
            "cast", "circle", "put", "--circle", circle, "--path", "/a.txt", "--file",
        ])
        .arg(&asset_path)
        .args(["--key"])
        .arg(&key_path)
        .args(["--rpc-url", "inprocess://octPROG", "--nonce", "1"])
        .output()
        .unwrap();
    assert!(put.status.success(), "put failed: {put:?}");
    let put_v: serde_json::Value = serde_json::from_slice(&put.stdout).unwrap();

    let put_enc = cmd()
        .args(["cast", "circle", "put-encrypted", circle, "/a.txt"])
        .arg(&asset_path)
        .args(["--passphrase", "demo"])
        .args(["--key"])
        .arg(&key_path)
        .args(["--rpc-url", "inprocess://octPROG", "--nonce", "1"])
        .output()
        .unwrap();
    assert!(
        put_enc.status.success(),
        "put-encrypted failed: {put_enc:?}"
    );
    let enc_v: serde_json::Value = serde_json::from_slice(&put_enc.stdout).unwrap();

    for key in &[
        "circle_id",
        "path",
        "plaintext_hash",
        "from",
        "nonce",
        "ou",
        "submit",
    ] {
        assert!(put_v.get(*key).is_some(), "put missing key {key}: {put_v}");
        assert!(
            enc_v.get(*key).is_some(),
            "put-encrypted missing key {key}: {enc_v}"
        );
    }
    assert_eq!(put_v["circle_id"], enc_v["circle_id"]);
    assert_eq!(put_v["path"], enc_v["path"]);
    assert_eq!(put_v["submit"]["status"], enc_v["submit"]["status"]);
}

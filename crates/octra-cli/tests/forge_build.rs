//! `forge build` integration tests.
//!
//! Both happy-paths run with `--offline` to skip the RPC compile call;
//! we still smoke-test the in-process route via the mock when present.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

/// A self-contained AML program shaped like OctraVPN: lets the test
/// assert that the `OctraVPN.*` artifact set lands in `--out` and that
/// the ABI carries `register_endpoint`. We don't depend on a sibling
/// workspace's `program/` tree so the foundry repo stays standalone.
const OCTRAVPN_LIKE_AML: &str = r#"
// Self-contained AML fixture for the forge-build integration test.
contract OctraVPN {
    fn register_endpoint(addr: addr, region: str) {
        emit Registered(addr, region);
    }

    view fn get_endpoint(addr: addr): str {
        return "stub";
    }

    event Registered(addr, str);
}
"#;

#[test]
fn build_offline_against_program_dir() {
    // Self-contained: lay down a synthetic `program/` tree, build it
    // offline, and assert the artifact set.
    let prog_dir = tempdir().unwrap();
    fs::write(prog_dir.path().join("main.aml"), OCTRAVPN_LIKE_AML).unwrap();
    let dir = tempdir().unwrap();
    cmd()
        .args(["forge", "build", "--offline", "--root"])
        .arg(prog_dir.path())
        .arg("--out")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(contains("compiled"));
    let octravpn_json = dir.path().join("OctraVPN.json");
    assert!(
        octravpn_json.exists(),
        "expected {} to exist",
        octravpn_json.display()
    );
    let body = fs::read_to_string(&octravpn_json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["name"].as_str(), Some("OctraVPN"));
    assert!(v["abi"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == "register_endpoint"));
    // Companion files exist too.
    assert!(dir.path().join("OctraVPN.abi").exists());
    assert!(dir.path().join("OctraVPN.bin").exists());
    assert!(dir.path().join("OctraVPN.asm").exists());
}

#[test]
fn build_offline_synthetic_aml_file() {
    let src_dir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let path = src_dir.path().join("MyProg.aml");
    fs::write(
        &path,
        "program MyProg {\n  fn foo(x: int): bool { return true }\n}\n",
    )
    .unwrap();
    cmd()
        .args(["forge", "build", "--offline", "--root"])
        .arg(src_dir.path())
        .arg("--out")
        .arg(out_dir.path())
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out_dir.path().join("MyProg.json")).unwrap())
            .unwrap();
    assert_eq!(v["name"].as_str(), Some("MyProg"));
    assert!(v["abi"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == "foo"));
}

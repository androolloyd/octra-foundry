//! `forge inspect` — show ABI / bytecode / asm against an AML file.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

const FIXTURE_AML: &str = r#"
// Self-contained AML fixture for forge-inspect integration tests.
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
fn inspect_aml_file_dumps_abi() {
    let dir = tempdir().unwrap();
    let aml = dir.path().join("main.aml");
    fs::write(&aml, FIXTURE_AML).unwrap();
    cmd()
        .args(["forge", "inspect"])
        .arg(&aml)
        .arg("--field")
        .arg("abi")
        .assert()
        .success()
        .stdout(contains("register_endpoint"));
}

#[test]
fn inspect_aml_file_dumps_bytecode() {
    let dir = tempdir().unwrap();
    let aml = dir.path().join("main.aml");
    fs::write(&aml, FIXTURE_AML).unwrap();
    cmd()
        .args(["forge", "inspect"])
        .arg(&aml)
        .arg("--field")
        .arg("bytecode")
        .assert()
        .success()
        .stdout(contains("0x"));
}

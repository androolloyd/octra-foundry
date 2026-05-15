//! `forge bind` — ensure the generated Rust file compiles standalone.
//!
//! The test builds a tiny synthetic AML program (so the test is
//! self-contained and doesn't depend on a real `program/main.aml`
//! sitting in a sibling workspace), runs `forge build` against it to
//! produce an ABI, then runs `forge bind` and `cargo check`-compiles
//! the generated file against `octra-core`.

use std::fs;
use std::process::Command as PCommand;

use assert_cmd::Command;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

/// A self-contained AML program exposing one call method and one view.
/// `forge build --offline` parses the `fn` declarations to synthesize
/// an ABI; the names `call_register_endpoint` / `view_get_endpoint` are
/// what the spot-check below looks for.
const FIXTURE_AML: &str = r#"
// Self-contained AML fixture for the `forge bind` integration test.

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
fn bind_generates_compileable_file() {
    let out_dir = tempdir().unwrap();
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&manifest).ancestors().nth(2).unwrap();

    // 1. Lay down a tiny `program/` tree and build it offline to get
    //    the ABI. We stay self-contained so the test doesn't break if
    //    sibling workspaces (e.g. octra/program/) change shape.
    let prog_root = tempdir().unwrap();
    fs::write(prog_root.path().join("main.aml"), FIXTURE_AML).unwrap();
    let build_out = tempdir().unwrap();
    cmd()
        .args(["forge", "build", "--offline", "--root"])
        .arg(prog_root.path())
        .arg("--out")
        .arg(build_out.path())
        .assert()
        .success();
    let abi_path = build_out.path().join("OctraVPN.abi");
    assert!(abi_path.exists(), "expected {}", abi_path.display());

    // 2. Bind.
    cmd()
        .args(["forge", "bind"])
        .arg(&abi_path)
        .arg("--out")
        .arg(out_dir.path())
        .arg("--module")
        .arg("octravpn")
        .assert()
        .success();
    let rs_path = out_dir.path().join("octravpn.rs");
    assert!(rs_path.exists());
    let body = fs::read_to_string(&rs_path).unwrap();
    // Spot-check: register_endpoint and a view method are wired up.
    assert!(
        body.contains("pub fn call_register_endpoint"),
        "got: {body}"
    );
    assert!(body.contains("pub fn view_get_endpoint"), "got: {body}");

    // 3. Compile the generated file against a synthetic Cargo project
    //    to prove it parses + type-checks. The generated bindings only
    //    import `serde_json::{json, Value}`, so that's all we depend on
    //    here. We point `octra-core` at the workspace copy too so the
    //    test stays a meaningful smoke check if `bind` ever grows
    //    address-codec usage in its output.
    let proj = tempdir().unwrap();
    fs::create_dir_all(proj.path().join("src")).unwrap();
    fs::write(
        proj.path().join("Cargo.toml"),
        r#"[package]
name = "bind_smoke"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
serde_json = "1"
octra-core = { path = "OCTRA_CORE_PATH" }
"#
        .replace(
            "OCTRA_CORE_PATH",
            workspace_root
                .join("crates")
                .join("octra-core")
                .to_str()
                .unwrap(),
        ),
    )
    .unwrap();
    let lib_rs = "pub mod gen;\n#[allow(unused_imports)]\nuse gen::Octravpn;\n";
    fs::write(proj.path().join("src").join("lib.rs"), lib_rs).unwrap();
    fs::copy(&rs_path, proj.path().join("src").join("gen.rs")).unwrap();
    let target_dir = tempdir().unwrap();
    let status = PCommand::new(option_env!("CARGO").unwrap_or("cargo"))
        .current_dir(proj.path())
        .arg("check")
        .arg("--target-dir")
        .arg(target_dir.path())
        .arg("--quiet")
        .status()
        .unwrap();
    assert!(status.success(), "generated binding failed to compile");
}

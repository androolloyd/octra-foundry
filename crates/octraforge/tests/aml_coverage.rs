//! AML branch coverage smoke test — drives a representative flow and
//! confirms the recorder captured the expected branches.
//!
//! NOTE: the coverage recorder is a process-wide global. We run all
//! coverage assertions inside one test so concurrent `cargo test`
//! workers don't race on it.

use octraforge::{aml_coverage, ForgeCtx};
use std::path::PathBuf;

/// Locate the AML source used by this branch-coverage test. Foundry
/// lives in its own repo now; the AML it covers lives in the sibling
/// `octra/` checkout (or wherever `OCTRAFORGE_TEST_AML` points). If
/// neither is present, return `None` and the test skips so foundry
/// can build standalone without an `octra` clone next door.
fn aml_source() -> Option<String> {
    if let Ok(p) = std::env::var("OCTRAFORGE_TEST_AML") {
        return std::fs::read_to_string(p).ok();
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let foundry_root = PathBuf::from(manifest).ancestors().nth(2)?.to_path_buf();
    // Sibling layout: <parent>/octra-foundry + <parent>/octra
    let parent = foundry_root.parent()?.to_path_buf();
    let p = parent.join("octra").join("program").join("main.aml");
    std::fs::read_to_string(p).ok()
}

#[test]
fn coverage_records_branches_during_happy_and_revert_paths() {
    let Some(aml) = aml_source() else {
        eprintln!(
            "skipping aml_coverage: no main.aml found (sibling ../octra checkout \
             missing and OCTRAFORGE_TEST_AML unset)"
        );
        return;
    };

    aml_coverage::enable();

    // ----- 1. Happy path: register, create tailnet, open session ------
    let mut ctx = ForgeCtx::new();
    ctx.become_octra_validator("octV");
    ctx.prank("octV");
    ctx.call_register_endpoint_simple("1.2.3.4:51820", &"de".repeat(32), "eu-west", 100)
        .unwrap();

    ctx.prank("octOWN");
    let tid = ctx
        .call_create_tailnet(&"ab".repeat(32), 2000)
        .unwrap()
        .event_u64("TailnetCreated", "tailnet_id")
        .unwrap();
    ctx.prank("octOWN");
    ctx.call_add_member(tid, "octCLI").unwrap();
    ctx.prank("octOWN");
    ctx.call_configure_tailnet_exit(tid, "octV").unwrap();
    ctx.prank("octCLI");
    ctx.call_open_session(tid, "octV", 1000).unwrap();

    // ----- 2. Revert path: unprivileged register_endpoint ------------
    let mut ctx2 = ForgeCtx::new();
    ctx2.prank("octR");
    let _ = ctx2.call_register_endpoint_simple("1.2.3.4:51820", &"de".repeat(32), "x", 100);

    let rec = aml_coverage::finish().unwrap();
    let report = aml_coverage::report(&rec, &aml);

    let reg = report
        .per_method
        .get("register_endpoint")
        .expect("register_endpoint in report");
    assert!(
        reg.branches_hit >= 3,
        "expected ≥3 register_endpoint branches hit, got {} / {}",
        reg.branches_hit,
        reg.branches_total
    );

    let open = report
        .per_method
        .get("open_session")
        .expect("open_session in report");
    assert!(
        open.branches_hit >= 4,
        "expected ≥4 open_session branches hit, got {} / {}",
        open.branches_hit,
        open.branches_total
    );

    assert!(
        report.percent() > 0.0,
        "0% coverage; recorder wired correctly?"
    );
}

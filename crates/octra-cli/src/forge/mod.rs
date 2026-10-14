//! `octra forge` — build / deploy / test / snapshot / bind.
//!
//! Local builds/tests execute the configured real `amlc`; RPC builds fail closed.
//! Synthetic artifacts are available only through explicit `--mock` builds.

pub mod amlc;
pub mod bind;
pub mod build;
pub mod compile;
pub mod coverage;
pub mod create;
pub mod inspect;
pub mod snapshot;
pub mod test_cmd;
pub mod trace;
pub mod verification;
pub mod verify;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ForgeCmd {
    /// Walk `program/` for `*.aml` and emit `out/<Name>.{json,abi,bin,asm}`.
    Build(build::BuildArgs),
    /// Compile + sign + deploy + return address.
    Create(create::CreateArgs),
    /// Dump ABI / assembly / bytecode for an address or file.
    Inspect(inspect::InspectArgs),
    /// Generate typed Rust stubs from a compiled ABI.
    Bind(bind::BindArgs),
    /// Execute AML `test_*` methods; use --package for Rust tests.
    Test(test_cmd::TestArgs),
    /// Capture per-test OU costs to `.gas-snapshot` and diff on rerun.
    Snapshot(snapshot::SnapshotArgs),
    /// Print AML branch coverage from a recorder dump.
    Coverage(coverage::CoverageArgs),
    /// Bind a deployed program address to its on-disk `.aml` source.
    /// Sends `contract_verify`; on success the explorer (`octrascan`)
    /// can show the source. Mirrors Foundry's `forge verify-contract`.
    Verify(verify::VerifyArgs),
}

pub fn dispatch(cmd: ForgeCmd) -> Result<()> {
    match cmd {
        ForgeCmd::Build(a) => build::run(&a),
        ForgeCmd::Create(a) => create::run(&a),
        ForgeCmd::Inspect(a) => inspect::run(&a),
        ForgeCmd::Bind(a) => bind::run(&a),
        ForgeCmd::Test(a) => test_cmd::run(&a),
        ForgeCmd::Snapshot(a) => snapshot::run(&a),
        ForgeCmd::Coverage(a) => coverage::run(&a),
        ForgeCmd::Verify(a) => verify::run(&a),
    }
}

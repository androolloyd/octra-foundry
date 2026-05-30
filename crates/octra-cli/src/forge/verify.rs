//! `octra forge verify` — Foundry-style source verification with an
//! FV-ready report.
//!
//! Pairs a deployed program address with an on-disk `.aml` source. The
//! node recompiles the source server-side, compares the resulting
//! code_hash against the deployed bytecode, and — with the upcoming
//! compiler release — attaches a formal-verification audit. We parse the
//! `contract_verify` response into a typed [`verification::VerifyReport`]
//! so the same structure flows to the operator, to CI (`--json`), and to
//! `octrascan`'s verification tab.

use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;

use super::verification::{self, FvAudit};
use crate::rpc_client;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Source `.aml` file to verify against.
    pub file: PathBuf,
    /// On-chain program address to verify.
    pub address: String,
    /// RPC URL.
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: String,
    /// Emit the structured report as JSON (for octrascan / CI) instead
    /// of the human-readable table.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &VerifyArgs) -> Result<()> {
    let source = std::fs::read_to_string(&args.file)?;
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let raw = rpc_client::call(&endpoint, "contract_verify", json!([args.address, source]))
        .map_err(|e| anyhow!("contract_verify: {e}"))?;

    let report = verification::parse_verify(&args.address, &raw);

    let ok = if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        report.verified
            && !report
                .formal_verification
                .as_ref()
                .is_some_and(FvAudit::has_failures)
    } else {
        verification::render_verify(&report)
    };

    if !ok {
        return Err(anyhow!("verification failed"));
    }
    Ok(())
}

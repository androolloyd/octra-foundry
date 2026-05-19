//! `octra forge verify` — Foundry-style source verification.
//!
//! Pairs a deployed program address with an on-disk `.aml` source.
//! The node recompiles the source server-side and compares the
//! resulting code_hash against the deployed bytecode; on match,
//! `contract_source` starts returning the verified source so
//! explorers like octrascan can render it.

use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;

use crate::{io::dump_json, rpc_client};

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Source `.aml` file to verify against.
    pub file: PathBuf,
    /// On-chain program address to verify.
    pub address: String,
    /// RPC URL.
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: String,
}

pub fn run(args: &VerifyArgs) -> Result<()> {
    let source = std::fs::read_to_string(&args.file)?;
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let v = rpc_client::call(&endpoint, "contract_verify", json!([args.address, source]))
        .map_err(|e| anyhow!("contract_verify: {e}"))?;
    dump_json(&v);
    if v.get("verified").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(anyhow!("verification failed"));
    }
    Ok(())
}

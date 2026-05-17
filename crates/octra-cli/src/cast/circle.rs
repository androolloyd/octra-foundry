//! `cast circle …` — Octra Circles (Isolated Execution Environment)
//! operations. Wire format mirrors the reference webcli
//! (octra-labs/webcli `f9c73e1`, 2026-05-15).
//!
//! Subcommands:
//!   * `predict`  — compute the deterministic `oct…` circle id from
//!                  `(deployer, nonce)` and the deploy payload without
//!                  touching the chain. Useful for predeclaring `to_`.
//!   * `deploy`   — submit a `deploy_circle` tx and print the
//!                  resulting circle id + chain response.
//!   * `info`     — `circle_info` RPC.
//!   * `asset`    — `circle_asset` RPC (plaintext asset by path).
//!   * `asset-key` — `circle_asset_ciphertext_by_resource_key` RPC
//!                   (path-private encrypted asset).

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use octra_core::circle::{
    canonical_payload_json, circle_id_of_deploy, default_deploy_payload, resource_key,
    CircleDeployPayload,
};
use serde_json::{json, Value};

use crate::{io as cio, rpc_client};

#[derive(Subcommand, Debug)]
pub enum CircleCmd {
    /// Predict the circle id from (deployer, nonce) — no chain hit.
    Predict(PredictArgs),
    /// Submit a `deploy_circle` tx and print the resulting id.
    Deploy(DeployArgs),
    /// Call `circle_info` for an existing circle.
    Info(InfoArgs),
    /// Fetch a plaintext asset by path.
    Asset(AssetArgs),
    /// Fetch an encrypted asset by resource key (path stays private).
    AssetKey(AssetKeyArgs),
    /// Compute the resource_key for `(circle_id, canonical_path)`.
    Key(KeyArgs),
}

#[derive(Args, Debug)]
pub struct PredictArgs {
    /// Deployer wallet address (`oct…`).
    #[arg(long)]
    pub deployer: String,
    /// Nonce that the deploy tx will use (current_nonce + 1).
    #[arg(long)]
    pub nonce: u64,
    /// Path to a JSON file with overrides for the deploy payload.
    /// When omitted, the webcli defaults are used (sealed/octb).
    #[arg(long)]
    pub payload: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Wallet key file.
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: std::path::PathBuf,
    /// Explicit nonce. Omit to auto-fetch.
    #[arg(long)]
    pub nonce: Option<u64>,
    /// Fee in OU (default mirrors webcli: 200_000).
    #[arg(long, default_value_t = 200_000u64)]
    pub ou: u64,
    /// Path to a JSON file with overrides for the deploy payload.
    #[arg(long)]
    pub payload: Option<std::path::PathBuf>,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    pub circle_id: String,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct AssetArgs {
    pub circle_id: String,
    /// Canonical path (e.g. `/index.html`).
    pub path: String,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct AssetKeyArgs {
    pub circle_id: String,
    /// Hex resource_key returned by `cast circle key`.
    pub resource_key: String,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct KeyArgs {
    pub circle_id: String,
    pub canonical_path: String,
}

pub fn dispatch(cmd: CircleCmd) -> Result<()> {
    match cmd {
        CircleCmd::Predict(a) => predict(&a),
        CircleCmd::Deploy(a) => deploy(&a),
        CircleCmd::Info(a) => info(&a),
        CircleCmd::Asset(a) => asset(&a),
        CircleCmd::AssetKey(a) => asset_key(&a),
        CircleCmd::Key(a) => {
            println!("{}", resource_key(&a.circle_id, &a.canonical_path));
            Ok(())
        }
    }
}

fn load_payload(path: Option<&std::path::Path>) -> Result<CircleDeployPayload> {
    if let Some(p) = path {
        let raw = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let parsed: CircleDeployPayload =
            serde_json::from_str(&raw).context("parse payload JSON")?;
        Ok(parsed)
    } else {
        Ok(default_deploy_payload())
    }
}

fn predict(args: &PredictArgs) -> Result<()> {
    let payload = load_payload(args.payload.as_deref())?;
    let id = circle_id_of_deploy(&args.deployer, args.nonce, &payload);
    cio::dump_json(&json!({
        "circle_id": id,
        "deployer": &args.deployer,
        "nonce": args.nonce,
        "payload": payload,
        "canonical_payload_json": canonical_payload_json(&payload),
    }));
    Ok(())
}

fn deploy(args: &DeployArgs) -> Result<()> {
    let payload = load_payload(args.payload.as_deref())?;
    let bytes = cio::read_secret_hex(&args.key)?;
    let kp = octra_core::sig::KeyPair::from_secret_bytes(&bytes);
    let from = octra_core::address::Address::from_pubkey(&kp.public.0)
        .display()
        .to_string();
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);

    let resolved_nonce = match args.nonce {
        Some(n) => n,
        None => {
            let bal = rpc_client::call(&endpoint, "octra_balance", json!([&from]))
                .context("fetch balance for nonce")?;
            bal.get("nonce").and_then(Value::as_u64).unwrap_or(0) + 1
        }
    };

    let circle_id = circle_id_of_deploy(&from, resolved_nonce, &payload);
    let message = canonical_payload_json(&payload);

    let tx = json!({
        "from": &from,
        "to_": &circle_id,
        "amount": "0",
        "nonce": resolved_nonce,
        "ou": args.ou.to_string(),
        "timestamp": cio::current_timestamp(),
        "op_type": "deploy_circle",
        "message": message,
    });
    let signed = octra_core::tx::sign_call(&kp, tx).map_err(|e| anyhow!("sign_call: {e}"))?;
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))
        .context("submit deploy_circle")?;

    cio::dump_json(&json!({
        "circle_id": circle_id,
        "from": from,
        "nonce": resolved_nonce,
        "ou": args.ou,
        "submit": result,
    }));
    Ok(())
}

fn info(args: &InfoArgs) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let v = rpc_client::call(&endpoint, "circle_info", json!([&args.circle_id]))
        .context("circle_info")?;
    cio::dump_json(&v);
    Ok(())
}

fn asset(args: &AssetArgs) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let v = rpc_client::call(
        &endpoint,
        "circle_asset",
        json!([&args.circle_id, &args.path]),
    )
    .context("circle_asset")?;
    cio::dump_json(&v);
    Ok(())
}

fn asset_key(args: &AssetKeyArgs) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let v = rpc_client::call(
        &endpoint,
        "circle_asset_ciphertext_by_resource_key",
        json!([&args.circle_id, &args.resource_key]),
    )
    .context("circle_asset_ciphertext_by_resource_key")?;
    cio::dump_json(&v);
    Ok(())
}

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
    canonical_payload_json, circle_id_of_deploy, default_deploy_payload, decrypt_sealed_bytes,
    encrypt_sealed_bytes, resource_key, CircleDeployPayload, PaddingClass,
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
    /// Encrypt + upload a sealed asset to a circle (PUT-style).
    PutEncrypted(PutEncryptedArgs),
    /// Encrypt-only (no upload) — prints the envelope you'd submit.
    EncryptOnly(EncryptOnlyArgs),
    /// Fetch + decrypt a sealed asset by `resource_key`.
    GetEncrypted(GetEncryptedArgs),
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

#[derive(Args, Debug)]
pub struct PutEncryptedArgs {
    /// Circle to upload into.
    pub circle_id: String,
    /// Canonical path inside the circle (e.g. `/policy.json`).
    pub path: String,
    /// Source file to encrypt + upload.
    pub file: std::path::PathBuf,
    /// Content type to register with the asset.
    #[arg(long, default_value = "application/octet-stream")]
    pub content_type: String,
    /// Symmetric key id (logical name, e.g. "default"). Pairs with
    /// `--passphrase` to derive the AES-GCM key.
    #[arg(long, default_value = "default")]
    pub key_id: String,
    /// Passphrase for PBKDF2-derived sealed-read key.
    #[arg(long, env = "OCTRA_SEALED_PASSPHRASE")]
    pub passphrase: String,
    /// Padding class: none, 4k, 16k, 32k, 128k. Empty = none.
    #[arg(long, default_value = "")]
    pub padding_class: String,
    /// Optional plain "encoding" hint stored alongside the asset.
    #[arg(long)]
    pub encoding: Option<String>,
    /// Wallet key file for signing the tx.
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: std::path::PathBuf,
    /// OU fee (default mirrors webcli: 5000).
    #[arg(long, default_value_t = 5_000u64)]
    pub ou: u64,
    /// Explicit nonce; auto-fetched if omitted.
    #[arg(long)]
    pub nonce: Option<u64>,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct EncryptOnlyArgs {
    pub circle_id: String,
    pub file: std::path::PathBuf,
    #[arg(long, default_value = "default")]
    pub key_id: String,
    #[arg(long, env = "OCTRA_SEALED_PASSPHRASE")]
    pub passphrase: String,
    #[arg(long, default_value = "")]
    pub padding_class: String,
}

#[derive(Args, Debug)]
pub struct GetEncryptedArgs {
    pub circle_id: String,
    /// Resource key (hex) — fetch with `cast circle key`.
    pub resource_key: String,
    /// Passphrase to derive the AES-GCM read key.
    #[arg(long, env = "OCTRA_SEALED_PASSPHRASE")]
    pub passphrase: String,
    /// Optional override of the key_id used at encrypt time.
    #[arg(long, default_value = "default")]
    pub key_id: String,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
    /// Destination file for the decrypted plaintext. If omitted,
    /// prints to stdout (assumes UTF-8 — text only).
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
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
        CircleCmd::PutEncrypted(a) => put_encrypted(&a),
        CircleCmd::EncryptOnly(a) => encrypt_only(&a),
        CircleCmd::GetEncrypted(a) => get_encrypted(&a),
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

    let resolved_nonce = if let Some(n) = args.nonce { n } else {
        let bal = rpc_client::call(&endpoint, "octra_balance", json!([&from]))
            .context("fetch balance for nonce")?;
        bal.get("nonce").and_then(Value::as_u64).unwrap_or(0) + 1
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

fn parse_padding(s: &str) -> Result<PaddingClass> {
    PaddingClass::from_str_opt(s)
        .ok_or_else(|| anyhow!("unknown padding class: {s} (expected: none, 4k, 16k, 32k, 128k)"))
}

fn put_encrypted(args: &PutEncryptedArgs) -> Result<()> {
    let plaintext = std::fs::read(&args.file)
        .with_context(|| format!("read {}", args.file.display()))?;
    let padding = parse_padding(&args.padding_class)?;
    let (ciphertext_b64, plaintext_hash) = encrypt_sealed_bytes(
        &args.circle_id,
        &args.key_id,
        &args.passphrase,
        &plaintext,
        padding,
    )?;

    let bytes = cio::read_secret_hex(&args.key)?;
    let kp = octra_core::sig::KeyPair::from_secret_bytes(&bytes);
    let from = octra_core::address::Address::from_pubkey(&kp.public.0)
        .display()
        .to_string();
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);

    let resolved_nonce = if let Some(n) = args.nonce { n } else {
        let bal = rpc_client::call(&endpoint, "octra_balance", json!([&from]))
            .context("fetch balance for nonce")?;
        bal.get("nonce").and_then(Value::as_u64).unwrap_or(0) + 1
    };

    let mut payload = json!({
        "path": &args.path,
        "content_type": &args.content_type,
        "key_id": &args.key_id,
        "plaintext_hash": &plaintext_hash,
    });
    if let Some(enc) = &args.encoding {
        payload
            .as_object_mut()
            .unwrap()
            .insert("encoding".into(), json!(enc));
    }
    if !args.padding_class.is_empty() {
        payload
            .as_object_mut()
            .unwrap()
            .insert("padding_class".into(), json!(args.padding_class));
    }

    let tx = json!({
        "from": &from,
        "to_": &args.circle_id,
        "amount": "0",
        "nonce": resolved_nonce,
        "ou": args.ou.to_string(),
        "timestamp": cio::current_timestamp(),
        "op_type": "circle_asset_put_encrypted",
        "encrypted_data": ciphertext_b64,
        "message": payload.to_string(),
    });
    let signed = octra_core::tx::sign_call(&kp, tx).map_err(|e| anyhow!("sign_call: {e}"))?;
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))
        .context("submit circle_asset_put_encrypted")?;

    cio::dump_json(&json!({
        "circle_id": &args.circle_id,
        "path": &args.path,
        "resource_key": resource_key(&args.circle_id, &args.path),
        "plaintext_hash": plaintext_hash,
        "from": from,
        "nonce": resolved_nonce,
        "ou": args.ou,
        "submit": result,
    }));
    Ok(())
}

fn encrypt_only(args: &EncryptOnlyArgs) -> Result<()> {
    let plaintext = std::fs::read(&args.file)
        .with_context(|| format!("read {}", args.file.display()))?;
    let padding = parse_padding(&args.padding_class)?;
    let (ciphertext_b64, plaintext_hash) = encrypt_sealed_bytes(
        &args.circle_id,
        &args.key_id,
        &args.passphrase,
        &plaintext,
        padding,
    )?;
    cio::dump_json(&json!({
        "circle_id": &args.circle_id,
        "key_id": &args.key_id,
        "padding_class": &args.padding_class,
        "plaintext_size": plaintext.len(),
        "plaintext_hash": plaintext_hash,
        "ciphertext_b64": ciphertext_b64,
    }));
    Ok(())
}

fn get_encrypted(args: &GetEncryptedArgs) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let v = rpc_client::call(
        &endpoint,
        "circle_asset_ciphertext_by_resource_key",
        json!([&args.circle_id, &args.resource_key]),
    )
    .context("circle_asset_ciphertext_by_resource_key")?;
    let ciphertext_b64 = v
        .get("ciphertext_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response missing ciphertext_b64: {v}"))?;
    let plaintext_hash = v
        .get("plaintext_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response missing plaintext_hash: {v}"))?;
    let key_id_on_chain = v.get("key_id").and_then(Value::as_str).unwrap_or(&args.key_id);

    let plaintext = decrypt_sealed_bytes(
        &args.circle_id,
        key_id_on_chain,
        &args.passphrase,
        ciphertext_b64,
        plaintext_hash,
    )?;

    if let Some(out) = &args.out {
        std::fs::write(out, &plaintext)
            .with_context(|| format!("write {}", out.display()))?;
        eprintln!("wrote {} bytes -> {}", plaintext.len(), out.display());
    } else {
        let s = std::str::from_utf8(&plaintext)
            .context("decrypted plaintext is not UTF-8 — pass --out for binary")?;
        print!("{s}");
    }
    Ok(())
}

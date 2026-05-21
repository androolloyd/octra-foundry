//! `octra cast` — JSON-RPC and wallet operations.
//!
//! Modelled after `cast` (Foundry). All subcommands route through
//! [`crate::rpc_client`] so they work identically against a real Octra
//! node, a locally-spawned `anvil`, or an in-process mock spawned by
//! integration tests.

pub mod abi;
pub mod circle;
pub mod hash;
pub mod pvac;
pub mod tx;
pub mod wallet;

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::{io as cio, rpc_client};

/// Default RPC endpoint used when `--rpc-url` is not supplied.
pub const DEFAULT_RPC_URL: &str = "https://octra.network/rpc";

#[derive(Subcommand, Debug)]
pub enum CastCmd {
    /// Read-only program call. Output is JSON.
    Call {
        /// Program (contract) address.
        addr: String,
        /// Method name.
        method: String,
        /// Positional method args (JSON literal or plain string).
        args: Vec<String>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long)]
        caller: Option<String>,
    },
    /// Build, sign, and submit a state-changing tx.
    Send {
        addr: String,
        method: String,
        args: Vec<String>,
        #[arg(long, default_value_t = 0u64)]
        value: u64,
        #[arg(long, default_value_t = 10u64)]
        fee: u64,
        /// Explicit nonce. Omit to auto-fetch via `octra_balance`.
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: Option<std::path::PathBuf>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        /// v2 chain-id binding (P1-5b). When set, the tx envelope's
        /// canonical bytes include `chain_id`, binding the signature
        /// to a specific network. Omit (or leave empty) for v1
        /// (wallet-compat) signing. Mainnet operators should pass
        /// `octra-mainnet`; devnet, `octra-devnet`.
        #[arg(long, env = "OCTRA_CHAIN_ID")]
        chain_id: Option<String>,
    },
    /// Fetch a tx by hash.
    Tx {
        hash: String,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Fetch an epoch by id (== block).
    Block {
        epoch: u64,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Wallet operations.
    #[command(subcommand)]
    Wallet(wallet::WalletCmd),
    /// sha256 helper. Octra uses sha256 for hashes; `keccak` is an alias
    /// so `cast keccak <hex>` keeps muscle memory from Ethereum tooling.
    Sha256 { hex: String },
    /// Alias of `sha256`. Octra uses sha256 for hashing; this name only
    /// exists for muscle memory with Foundry's `cast keccak`.
    Keccak { hex: String },
    /// Decode a hex-encoded params blob against a compiled ABI.
    #[command(name = "abi-decode")]
    AbiDecode {
        abi_file: std::path::PathBuf,
        method: String,
        hex: String,
    },
    /// Plain OCT transfer (op_type=standard). Sender's nonce is read
    /// from the chain unless `--nonce` is supplied.
    Transfer {
        /// Recipient address.
        to: String,
        /// Amount in OU (1 OCT = 1_000_000 OU).
        amount: u64,
        #[arg(long, default_value_t = 1000u64)]
        ou: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: std::path::PathBuf,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        /// Optional message attached to the tx.
        #[arg(long)]
        message: Option<String>,
        /// v2 chain-id binding (P1-5b). See `Send::chain_id`.
        #[arg(long, env = "OCTRA_CHAIN_ID")]
        chain_id: Option<String>,
    },
    /// Raw JSON-RPC pass-through.
    Rpc {
        method: String,
        args: Vec<String>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Octra Circles (Isolated Execution Environment) ops:
    /// predict / deploy / info / asset / asset-key / key.
    #[command(subcommand)]
    Circle(circle::CircleCmd),
    /// Register a PVAC (HFHE) pubkey for the wallet behind `--key`
    /// via the per-wallet `octra_registerPvacPubkey` JSON-RPC.
    ///
    /// The signed message is exactly
    /// `"register_pvac|" + addr + "|" + sha256_hex(pvac_pk_blob)` —
    /// see `cast::pvac` for the canonical-format rationale.
    #[command(name = "register-pvac")]
    RegisterPvac(pvac::RegisterPvacArgs),
}

pub fn dispatch(cmd: CastCmd) -> Result<()> {
    match cmd {
        CastCmd::Call {
            addr,
            method,
            args,
            rpc_url,
            caller,
        } => cast_call(&addr, &method, &args, &rpc_url, caller.as_deref()),
        CastCmd::Send {
            addr,
            method,
            args,
            value,
            fee,
            nonce,
            from,
            key,
            rpc_url,
            chain_id,
        } => cast_send(
            &addr,
            &method,
            &args,
            value,
            fee,
            nonce,
            from.as_deref(),
            key.as_deref(),
            &rpc_url,
            chain_id.as_deref(),
        ),
        CastCmd::Tx { hash, rpc_url } => tx::print_tx(&hash, &rpc_url),
        CastCmd::Block { epoch, rpc_url } => tx::print_block(epoch, &rpc_url),
        CastCmd::Wallet(c) => wallet::dispatch(c),
        CastCmd::Sha256 { hex } | CastCmd::Keccak { hex } => hash::sha256_cmd(&hex),
        CastCmd::AbiDecode {
            abi_file,
            method,
            hex,
        } => abi::abi_decode_cmd(&abi_file, &method, &hex),
        CastCmd::Transfer {
            to,
            amount,
            ou,
            nonce,
            key,
            rpc_url,
            message,
            chain_id,
        } => cast_transfer(
            &to,
            amount,
            ou,
            nonce,
            &key,
            &rpc_url,
            message.as_deref(),
            chain_id.as_deref(),
        ),
        CastCmd::Rpc {
            method,
            args,
            rpc_url,
        } => cast_rpc(&method, &args, &rpc_url),
        CastCmd::Circle(c) => circle::dispatch(c),
        CastCmd::RegisterPvac(a) => pvac::dispatch(&a),
    }
}

#[allow(clippy::too_many_arguments)]
fn cast_transfer(
    to: &str,
    amount: u64,
    ou: u64,
    nonce: Option<u64>,
    key: &std::path::Path,
    rpc_url: &str,
    message: Option<&str>,
    chain_id: Option<&str>,
) -> Result<()> {
    let bytes = cio::read_secret_hex(key)?;
    let kp = octra_core::sig::KeyPair::from_secret_bytes(&bytes);
    let from = octra_core::address::Address::from_pubkey(&kp.public.0)
        .display()
        .to_string();
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let actual_nonce = if let Some(n) = nonce {
        n
    } else {
        let bal = rpc_client::call(&endpoint, "octra_balance", json!([&from]))
            .context("fetch balance for nonce")?;
        bal.get("nonce")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            + 1
    };
    let mut tx = json!({
        "from": from,
        "to_": to,
        "amount": amount.to_string(),
        "nonce": actual_nonce,
        "ou": ou.to_string(),
        "timestamp": cio::current_timestamp(),
        "op_type": "standard",
    });
    if let Some(m) = message {
        tx.as_object_mut()
            .unwrap()
            .insert("message".into(), json!(m));
    }
    // v2 chain-id binding (P1-5b). Adding the field promotes the
    // envelope to v2 — the signed canonical bytes include `chain_id`
    // so the chain checker can reject cross-chain replays. Default
    // (no flag) keeps the v1 wallet-compat encoding.
    if let Some(cid) = chain_id.filter(|s| !s.is_empty()) {
        tx.as_object_mut()
            .unwrap()
            .insert("chain_id".into(), json!(cid));
    }
    let signed = octra_core::tx::sign_call(&kp, tx).map_err(|e| anyhow!("sign_call: {e}"))?;
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;
    println!("transfer from: {from}");
    cio::dump_json(&result);
    Ok(())
}

fn cast_call(
    addr: &str,
    method: &str,
    args: &[String],
    rpc_url: &str,
    caller: Option<&str>,
) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    let mut params = vec![json!(addr), json!(method), json!(parsed)];
    if let Some(c) = caller {
        params.push(json!(c));
    }
    let result = rpc_client::call(&endpoint, "contract_call", json!(params))?;
    cio::dump_json(&result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cast_send(
    addr: &str,
    method: &str,
    args: &[String],
    value: u64,
    fee: u64,
    nonce: Option<u64>,
    from: Option<&str>,
    key: Option<&std::path::Path>,
    rpc_url: &str,
    chain_id: Option<&str>,
) -> Result<()> {
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    // Auto-fetch nonce if not supplied + we have a key (so we know
    // whose nonce to read). Falls back to 0 when neither key nor
    // explicit nonce is provided — useful for mock chains that
    // ignore nonce.
    let resolved_nonce = match nonce {
        Some(n) => n,
        None => {
            if let Some(k) = key {
                let bytes = cio::read_secret_hex(k)?;
                let kp = octra_core::sig::KeyPair::from_secret_bytes(&bytes);
                let addr = octra_core::address::Address::from_pubkey(&kp.public.0)
                    .display()
                    .to_string();
                rpc_client::call(&endpoint, "octra_balance", json!([&addr]))
                    .ok()
                    .and_then(|v| v.get("nonce").and_then(serde_json::Value::as_u64))
                    .map_or(1, |n| n + 1)
            } else {
                0
            }
        }
    };
    let (from_str, signed) = build_envelope(
        addr,
        method,
        &parsed,
        value,
        fee,
        resolved_nonce,
        from,
        key,
        chain_id,
    )?;
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;
    println!("submitted from: {from_str}");
    cio::dump_json(&result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    addr: &str,
    method: &str,
    params: &[Value],
    value: u64,
    fee: u64,
    nonce: u64,
    from: Option<&str>,
    key: Option<&std::path::Path>,
    chain_id: Option<&str>,
) -> Result<(String, Value)> {
    let mut call = json!({
        "kind": "contract_call",
        "from": from.unwrap_or(""),
        "to": addr,
        "method": method,
        "params": params,
        "value": value,
        "fee": fee,
        "nonce": nonce,
        "timestamp": cio::current_timestamp(),
    });
    if let Some(cid) = chain_id.filter(|s| !s.is_empty()) {
        call.as_object_mut()
            .unwrap()
            .insert("chain_id".into(), json!(cid));
    }
    if let Some(p) = key {
        let bytes = cio::read_secret_hex(p)?;
        let kp = octra_core::sig::KeyPair::from_secret_bytes(&bytes);
        let derived_addr = octra_core::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        // If --from was also supplied, prefer it, but warn via stderr.
        let from_value = from.map_or_else(|| derived_addr, str::to_string);
        if let Some(obj) = call.as_object_mut() {
            obj.insert("from".into(), json!(from_value));
        }
        let signed = octra_core::tx::sign_call(&kp, call).map_err(|e| anyhow!("sign_call: {e}"))?;
        Ok((from_value, signed))
    } else {
        let from_value = from
            .ok_or_else(|| anyhow!("either --from or --key is required"))?
            .to_string();
        Ok((from_value, call))
    }
}

fn cast_rpc(method: &str, args: &[String], rpc_url: &str) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    let v = rpc_client::call(&endpoint, method, json!(parsed))
        .with_context(|| format!("rpc {method}"))?;
    cio::dump_json(&v);
    Ok(())
}

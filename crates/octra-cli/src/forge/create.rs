//! `octra forge create` — compile + sign + deploy + return address.
//!
//! Real Octra exposes deploy as a regular `Transaction` with
//! `op_type="deploy"` and `encrypted_data` carrying the compiled
//! bytecode (base64). The deployed contract address is computed by the
//! chain from `(bytecode, deployer, nonce)` — see
//! `octra_computeContractAddress`. We:
//!
//!   1. compile the AML source (`octra_compileAml`),
//!   2. fetch the deployer's nonce (`octra_balance`),
//!   3. compute the would-be deploy address (`octra_computeContractAddress`)
//!      so callers learn it before broadcast,
//!   4. assemble the OctraTx (`op_type=deploy`, `encrypted_data=bytecode`)
//!      and sign it (`octra_core::tx::sign_call`),
//!   5. broadcast via `octra_submit`,
//!   6. emit `{ address, tx_hash, name, compiler }` as JSON.
//!
//! The in-process mock at `inprocess://<prog>` doesn't expose
//! `octra_computeContractAddress`; in that path we fall back to a
//! deterministic hash-derived address and let the mock's
//! `op_type=deploy` synthesizer return the same one.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use octra_core::{
    address::Address,
    sig::KeyPair,
    tx::{OctraTx, OP_DEPLOY},
};
use serde_json::{json, Value};

use crate::{
    forge::compile,
    io::{current_timestamp, dump_json, parse_arg_token, read_secret_hex},
    rpc_client,
};

/// Default deploy fee in OU per the reference web client
/// (`octra-labs/webcli`). The user can override with `--ou`.
const DEFAULT_DEPLOY_OU: u64 = 50_000_000;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Source `.aml` file.
    pub file: PathBuf,
    /// Constructor args (parsed as JSON if possible). When supplied,
    /// rendered as a JSON-encoded `message` on the tx envelope.
    #[arg(long = "constructor-args", num_args = 0.., allow_hyphen_values = true)]
    pub constructor_args: Vec<String>,
    /// Key file (32-byte hex) to sign the deploy tx.
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: PathBuf,
    /// RPC URL (HTTP or `inprocess://...`).
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: String,
    /// Fee in OU (defaults to 50_000_000, the webcli default).
    #[arg(long)]
    pub ou: Option<u64>,
    /// Do not wait for the epoch apply; print the staged tx_hash and the
    /// PREDICTED address only. The prediction can be wrong (see the
    /// receipt logic in `run`), so prefer the default unless you poll.
    #[arg(long, default_value_t = false)]
    pub no_wait: bool,
    /// How long to wait for the execution receipt. Epochs apply every 10s
    /// (epoch_time.ml:10-11); three epochs covers one late tick.
    #[arg(long, default_value_t = 45)]
    pub wait_secs: u64,
}

pub fn run(args: &CreateArgs) -> Result<()> {
    let source = std::fs::read_to_string(&args.file)?;
    let name = compile::infer_program_name(
        args.file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("Program"),
        &source,
    );
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let is_mock = matches!(endpoint, rpc_client::Endpoint::InProcess(_));

    // (1) Compile the AML source. Real Octra accepts the RPC; the
    //     in-process mock provides the same shape via a stub.
    // Params are `[source]` with an OPTIONAL second BOOLEAN (`program`),
    // not `[source, name]` — contract_rpc.ml:342-357 rejects a string
    // second param with "program must be boolean", and `true` demands
    // program facts a plain contract compile does not carry. Passing the
    // name here silently failed against every real node.
    let compiled = rpc_client::call(&endpoint, "octra_compileAml", json!([source]));
    // Only the in-process mock may synthesize an artifact. Against a real
    // node a compile failure is fatal: the old blanket fallback produced a
    // fake non-base64 bytecode that surfaced much later and far away, as
    // `octra_computeContractAddress -> Invalid_argument("Wrong padding")`.
    let artifact = match compiled {
        Ok(a) => a,
        Err(e) if is_mock => {
            let _ = e;
            compile::synthesize_artifact(&name, &source)
        }
        Err(e) => return Err(anyhow!("octra_compileAml failed: {e}")),
    };
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("missing bytecode in compile result"))?;

    // (2) Sender + key. The signer derives the from-address.
    let secret = read_secret_hex(&args.key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let from_addr = Address::from_pubkey(&kp.public.0).display().to_string();

    // (3) Fetch nonce. Real Octra: `octra_balance` returns
    //     `pending_nonce` + `nonce`. The next available nonce is
    //     `max(pending_nonce, nonce) + 1`. The mock always returns 0;
    //     we still treat that as a starting point.
    let bal = rpc_client::call(&endpoint, "octra_balance", json!([from_addr]))
        .unwrap_or_else(|_| json!({"nonce": 0u64, "pending_nonce": 0u64}));
    let cur_nonce = bal
        .get("nonce")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let pending = bal
        .get("pending_nonce")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let nonce = cur_nonce.max(pending) + 1;

    // (4) Predict the deploy address. Real Octra exposes
    //     `octra_computeContractAddress(bytecode_b64, deployer, nonce)`;
    //     against the mock we deterministically derive an `oct…`
    //     address from `(deployer, bytecode, nonce)` — the same scheme
    //     the mock's `op_type=deploy` handler synthesizes, so the
    //     submitted tx's returned `address` matches.
    let address = if is_mock {
        synth_deploy_addr(&from_addr, bytecode, nonce)
    } else {
        let resp = rpc_client::call(
            &endpoint,
            "octra_computeContractAddress",
            json!([bytecode, from_addr, nonce]),
        )?;
        resp.get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("octra_computeContractAddress missing `address`: {resp}"))?
            .to_string()
    };

    // (5) Build the OctraTx envelope. Optional constructor-args go
    //     into `message` as a JSON-encoded array — that matches webcli
    //     which puts a plain string there.
    let message = if args.constructor_args.is_empty() {
        None
    } else {
        let args_values: Vec<Value> = args
            .constructor_args
            .iter()
            .map(|s| parse_arg_token(s))
            .collect();
        Some(Value::Array(args_values).to_string())
    };

    let tx = OctraTx {
        from: from_addr,
        to: address.clone(),
        amount: 0,
        nonce,
        ou: args.ou.unwrap_or(DEFAULT_DEPLOY_OU),
        timestamp: current_timestamp(),
        op_type: OP_DEPLOY.to_string(),
        // v1 envelope — `forge create` produces wallet-compat bytecode
        // deploys that match the webcli encoding byte-for-byte. Chain-id
        // binding (v2) is opt-in via `cast send --chain-id`.
        chain_id: None,
        encrypted_data: Some(bytecode.to_string()),
        message,
    };

    // (6) Sign and submit.
    let envelope = serde_json::to_value(&tx).map_err(|e| anyhow!("serialize tx: {e}"))?;
    let signed = octra_core::tx::sign_call(&kp, envelope).map_err(|e| anyhow!("sign_call: {e}"))?;
    let res = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;

    // octra_submit only STAGES (rpc_view.ml:706-712) and answers
    // {tx_hash, status:"accepted", nonce, ou_cost} — there is no `hash`
    // and no `address` in that response, which is why this used to print
    // an empty tx_hash and could only ever echo back its own prediction.
    let tx_hash = res
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let staged_status = res.get("status").and_then(|v| v.as_str()).unwrap_or("");

    // The predicted address is a guess made before the epoch applied.
    // Since the Rehovot compiler the node derives the program address at
    // apply time from the deploy PACKAGE it actually executes
    // (consensus_epoch_vm_shell.ml:759, `addr_from_code package.envelope
    // tx.from tx.nonce`), and on devnet that has diverged from what
    // `octra_computeContractAddress` returns for the bare bytecode. The
    // execution receipt is the only authoritative source, so wait for the
    // epoch and read the address off it. `--no-wait` keeps the old
    // fire-and-forget behaviour for callers that poll themselves.
    let mut resolved_address: Option<String> = None;
    let mut receipt_note = String::new();
    if !is_mock && !args.no_wait && !tx_hash.is_empty() {
        match wait_for_receipt(&endpoint, &tx_hash, args.wait_secs) {
            Ok(receipt) => {
                let ok = receipt.get("success").and_then(Value::as_bool).unwrap_or(false);
                let err = receipt.get("error").and_then(Value::as_str).unwrap_or("");
                if !ok {
                    return Err(anyhow!(
                        "deploy tx {tx_hash} applied but execution failed: {err}"
                    ));
                }
                resolved_address = receipt
                    .get("program")
                    .or_else(|| receipt.get("contract"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if let Some(actual) = &resolved_address {
                    if actual != &address {
                        receipt_note = format!(
                            "predicted {address} but the chain deployed at {actual} \
                             (address taken from the execution receipt)"
                        );
                    }
                }
            }
            Err(e) => {
                receipt_note = format!("could not confirm via receipt: {e}");
            }
        }
    }

    dump_json(&json!({
        "address": resolved_address.as_deref().unwrap_or(&address),
        "predicted_address": address,
        "tx_hash": tx_hash,
        "staged_status": staged_status,
        "confirmed": resolved_address.is_some(),
        "note": receipt_note,
        "name": name,
        "compiler": artifact.get("compiler").cloned().unwrap_or(Value::Null),
    }));
    Ok(())
}

/// Poll `octra_transaction` until the tx reaches a terminal status, then
/// fetch its `contract_receipt`. `rejected`/`dropped` carry the node's
/// reason verbatim (history_read_rpc.ml:131-175) and surface as errors.
fn wait_for_receipt(
    endpoint: &crate::rpc_client::Endpoint,
    tx_hash: &str,
    wait_secs: u64,
) -> Result<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        let st = rpc_client::call(endpoint, "octra_transaction", json!([tx_hash]))?;
        match st.get("status").and_then(Value::as_str) {
            Some("confirmed") => {
                return rpc_client::call(endpoint, "contract_receipt", json!([tx_hash]));
            }
            Some(s @ ("rejected" | "dropped")) => {
                let reason = st.get("reason").and_then(Value::as_str).unwrap_or("unspecified");
                return Err(anyhow!("deploy tx {tx_hash} {s}: {reason}"));
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "deploy tx {tx_hash} still not terminal after {wait_secs}s (last status: {})",
                st.get("status").and_then(Value::as_str).unwrap_or("?")
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

/// Mock-path deploy-address synthesis. Mirrors the mock's
/// `synthesize_deploy_address` in `octra-mock-rpc` so the address
/// predicted client-side matches the one the mock returns. Real Octra
/// uses `octra_computeContractAddress` instead.
fn synth_deploy_addr(from: &str, bytecode: &str, nonce: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(from.as_bytes());
    h.update(b"::deploy::");
    h.update(bytecode.as_bytes());
    h.update(nonce.to_le_bytes());
    let digest = h.finalize();
    let body = hex::encode(digest);
    let padded = if body.len() >= 44 {
        body[..44].to_string()
    } else {
        let mut s = String::with_capacity(44);
        for _ in body.len()..44 {
            s.push('1');
        }
        s.push_str(&body);
        s
    };
    format!("oct{padded}")
}

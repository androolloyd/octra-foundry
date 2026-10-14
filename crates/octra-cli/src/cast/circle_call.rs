//! Invoke Circle applications with the native envelope and view RPC.
use crate::{io as cio, rpc_client};
use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};

#[derive(Args, Debug)]
pub struct CallArgs {
    pub circle_id: String,
    pub method: String,
    pub args: Vec<String>,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

#[derive(Args, Debug)]
pub struct SendArgs {
    pub circle_id: String,
    pub method: String,
    pub args: Vec<String>,
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: std::path::PathBuf,
    #[arg(long)]
    pub nonce: Option<u64>,
    #[arg(long, default_value_t = 1000)]
    pub ou: u64,
    #[arg(long, default_value_t = 0)]
    pub value: u64,
    #[arg(long, env = "OCTRA_RPC_URL", default_value = super::DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

fn validate(circle: &str, method: &str) -> Result<()> {
    anyhow::ensure!(
        octra_core::circle::valid_circle_id(circle),
        "invalid Circle id"
    );
    anyhow::ensure!(
        !method.is_empty()
            && method.len() <= 128
            && method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid Circle method"
    );
    Ok(())
}

pub(super) fn nonce(
    endpoint: &rpc_client::Endpoint,
    from: &str,
    explicit: Option<u64>,
) -> Result<u64> {
    if let Some(value) = explicit {
        return Ok(value);
    }
    let balance = rpc_client::call(endpoint, "octra_balance", json!([from]))
        .context("fetch Circle sender nonce")?;
    let committed = balance
        .get("nonce")
        .and_then(Value::as_u64)
        .context("balance response missing nonce")?;
    let pending = balance
        .get("pending_nonce")
        .and_then(Value::as_u64)
        .unwrap_or(committed);
    committed
        .max(pending)
        .checked_add(1)
        .context("nonce exhausted")
}

pub(super) fn call(args: &CallArgs) -> Result<()> {
    validate(&args.circle_id, &args.method)?;
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let params: Vec<Value> = args
        .args
        .iter()
        .map(|arg| cio::parse_arg_token(arg))
        .collect();
    let result = rpc_client::call(
        &endpoint,
        "circle_view",
        json!([args.circle_id, args.method, params]),
    )?;
    cio::dump_json(&result);
    Ok(())
}

fn envelope(from: &str, args: &SendArgs, nonce: u64, timestamp: f64) -> Value {
    let params: Vec<Value> = args
        .args
        .iter()
        .map(|arg| cio::parse_arg_token(arg))
        .collect();
    json!({"from":from,"to_":args.circle_id,"amount":args.value.to_string(),"ou":args.ou.to_string(),
        "nonce":nonce,"timestamp":timestamp,"op_type":"circle_call","encrypted_data":args.method,"message":Value::Array(params).to_string()})
}

pub(super) fn send(args: &SendArgs) -> Result<()> {
    validate(&args.circle_id, &args.method)?;
    let key = cio::read_secret_hex(&args.key)?;
    let kp = octra_core::sig::KeyPair::from_secret_bytes(&key);
    let from = octra_core::address::Address::from_pubkey(&kp.public.0)
        .display()
        .to_owned();
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let next = nonce(&endpoint, &from, args.nonce)?;
    let signed = crate::io::sign_call(&kp, envelope(&from, args, next, cio::current_timestamp()))
        .map_err(|e| anyhow::anyhow!("sign Circle call: {e}"))?;
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;
    cio::dump_json(&result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    #[test]
    fn native_circle_envelope_binds_operation_method_and_params() {
        let key = octra_core::sig::KeyPair::from_secret_bytes(&[17; 32]);
        let from = octra_core::address::Address::from_pubkey(&key.public.0)
            .display()
            .to_owned();
        let args = SendArgs {
            circle_id: from.clone(),
            method: "publish".into(),
            args: vec!["\"record-json\"".into()],
            key: "unused.key".into(),
            nonce: None,
            ou: 1000,
            value: 0,
            rpc_url: "unused".into(),
        };
        let tx = envelope(&from, &args, 7, 1.0);
        let signed = crate::io::sign_call(&key, tx).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(signed["signature"].as_str().unwrap())
            .unwrap();
        let signature = octra_core::sig::Signature(bytes.try_into().unwrap());
        let check = |value: &Value| {
            let native = octra_core::native_tx::canonical_tx_from_call(value).unwrap();
            octra_core::sig::verify(
                &key.public,
                native.signing_preimage().as_bytes(),
                &signature,
            )
        };
        check(&signed).unwrap();
        assert_eq!(signed["op_type"], "circle_call");
        assert_eq!(signed["message"], "[\"record-json\"]");
        for (field, value) in [
            ("op_type", json!("call")),
            ("encrypted_data", json!("retire")),
            ("message", json!("[]")),
        ] {
            let mut altered = signed.clone();
            altered[field] = value;
            assert!(check(&altered).is_err());
        }
        assert!(validate(&from, "bad/method").is_err());
        validate(
            "octJfWXtvbohUBeXcvDAWJQ71Pog5ueFWDrzqgnn6x1yPeJ",
            "operator",
        )
        .unwrap();
        assert!(validate(&format!("oct{}", "0".repeat(44)), "operator").is_err());
    }
}

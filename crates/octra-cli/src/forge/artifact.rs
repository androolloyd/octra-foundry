//! Caller-reviewed compiled artifacts for deployment without a compiler RPC.
//!
//! The explicit file digest is the operator's immutable review boundary. Compiler
//! metadata and an unsigned native safety certificate are not attestations of
//! network authority; the ceremony separately compares the complete native result.
use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_ARTIFACT: u64 = 4 * 1024 * 1024;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_hash(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(super) fn load(
    path: &Path,
    expected_hash: &str,
    source: &[u8],
    endpoint: &str,
) -> Result<Value> {
    ensure!(
        is_hash(&Value::String(expected_hash.into())),
        "artifact SHA256 must be canonical lowercase hex"
    );
    ensure!(
        !path.is_symlink(),
        "compiled artifact must be a regular file"
    );
    let file = File::open(path).context("open compiled artifact")?;
    ensure!(
        file.metadata()?.is_file(),
        "compiled artifact must be a regular file"
    );
    let mut raw = Vec::new();
    file.take(MAX_ARTIFACT + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= MAX_ARTIFACT,
        "compiled artifact exceeds size bound"
    );
    ensure!(
        hash(&raw) == expected_hash,
        "compiled artifact SHA256 mismatch"
    );
    validate(&serde_json::from_slice(&raw)?, source, endpoint)
}

fn validate(document: &Value, source: &[u8], endpoint: &str) -> Result<Value> {
    ensure!(
        document["schema"] == "octra-compiled-artifact-v1",
        "unknown compiled artifact schema"
    );
    ensure!(
        document["rpc_url"].as_str() == Some(endpoint),
        "compiled artifact execution target differs"
    );
    ensure!(
        is_hash(&document["target_binding_sha256"]),
        "compiled artifact target binding missing"
    );
    let compiler = &document["compiler"];
    ensure!(
        compiler["kind"] == "verified_local_rust_node",
        "compiled artifact requires reviewed local compiler provenance"
    );
    for key in [
        "binding_sha256",
        "binary_sha256",
        "source_manifest_sha256",
        "native_fixture_sha256",
    ] {
        ensure!(
            is_hash(&compiler[key]),
            "compiled artifact compiler binding missing: {key}"
        );
    }
    let profiles = compiler["native_profiles"]
        .as_array()
        .context("compiled artifact native profiles missing")?;
    ensure!(
        !profiles.is_empty()
            && profiles.iter().all(|value| {
                matches!(value["syntax"].as_str(), Some("source" | "forms"))
                    && value["loops"].is_boolean()
            }),
        "compiled artifact native profiles invalid"
    );
    let before = &compiler["before"];
    let after = &compiler["after"];
    ensure!(
        before["runtime"].is_object() && before["runtime"] == after["runtime"],
        "compiled artifact runtime profile changed"
    );
    let runtime = &before["runtime"];
    ensure!(
        runtime["schema"] == "octra-runtime-release-v1"
            && runtime["chain_id"].as_str().is_some_and(|s| !s.is_empty()),
        "compiled artifact runtime identity missing"
    );
    for key in [
        "consensus_standard_hash",
        "activation_graph_hash",
        "runtime_profile_hash",
        "config_hash",
    ] {
        ensure!(
            is_hash(&runtime[key]),
            "compiled artifact runtime binding missing: {key}"
        );
    }
    ensure!(
        runtime["consensus_profile"].as_u64().is_some()
            && runtime["consensus_rules_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "compiled artifact execution profile missing"
    );
    ensure!(
        before["head_epoch"]
            .as_u64()
            .zip(after["head_epoch"].as_u64())
            .is_some_and(|(before, after)| after >= before),
        "compiled artifact head window invalid"
    );
    ensure!(
        is_hash(&before["state_root"]) && is_hash(&after["state_root"]),
        "compiled artifact head root missing"
    );
    let artifact = &document["result"];
    let bytecode = artifact["bytecode"]
        .as_str()
        .context("compiled artifact bytecode missing")?;
    let code = STANDARD
        .decode(bytecode)
        .context("compiled artifact bytecode base64")?;
    ensure!(
        code.starts_with(b"OCTB") && STANDARD.encode(&code) == bytecode,
        "compiled artifact requires canonical OCTB"
    );
    let certificate = &artifact["certificate"];
    ensure!(
        certificate["schema"] == "aml_bytecode_certificate_v1",
        "unsupported native bytecode certificate"
    );
    ensure!(
        certificate["source_hash"].as_str() == Some(hash(source).as_str()),
        "compiled artifact source hash mismatch"
    );
    ensure!(
        certificate["bytecode_hash"].as_str() == Some(hash(&code).as_str()),
        "compiled artifact code hash mismatch"
    );
    let verification_raw = STANDARD.decode(
        document["verification_json_b64"]
            .as_str()
            .context("compiled artifact native verification bytes missing")?,
    )?;
    let verification: Value = serde_json::from_slice(&verification_raw)?;
    ensure!(
        certificate["verification_hash"].as_str() == Some(hash(&verification_raw).as_str())
            && verification == artifact["verification"],
        "compiled artifact verification hash mismatch"
    );
    let report = super::verification::parse_compile("deployment", artifact);
    let audit = report
        .formal_verification
        .context("compiled artifact native safety report missing")?;
    ensure!(
        audit.schema == "aml_safety_report_v1" && !audit.has_failures(),
        "compiled artifact native safety verification failed"
    );
    let mut labels = BTreeSet::new();
    for line in artifact["disasm"]
        .as_str()
        .context("compiled artifact disassembly missing")?
        .lines()
    {
        if let Some(label) = line.strip_prefix("JDEST ") {
            if label.is_empty()
                || !label.bytes().all(|byte| byte.is_ascii_digit())
                || !labels.insert(label)
            {
                bail!("compiled artifact duplicate or invalid jump label");
            }
        }
    }
    Ok(artifact.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        let verification =
            json!({"schema":"aml_safety_report_v1", "verified":true, "safety":"ok", "errors":0});
        let raw = serde_json::to_vec(&verification).unwrap();
        let runtime = json!({"schema":"octra-runtime-release-v1", "chain_id":"fixture", "consensus_standard_hash":"a".repeat(64), "activation_graph_hash":"b".repeat(64), "runtime_profile_hash":"c".repeat(64), "config_hash":"d".repeat(64), "consensus_profile":16,"consensus_rules_id":"fixture"});
        let head = json!({"runtime":runtime, "head_epoch":10,"state_root":"f".repeat(64)});
        json!({"schema":"octra-compiled-artifact-v1", "rpc_url":"inprocess://fixture", "target_binding_sha256":"a".repeat(64),
            "compiler":{"kind":"verified_local_rust_node", "binding_sha256":"b".repeat(64),"binary_sha256":"c".repeat(64),"source_manifest_sha256":"d".repeat(64),"native_fixture_sha256":"e".repeat(64),"native_profiles":[{"syntax":"source","loops":true}],"before":head,"after":head},
            "verification_json_b64":STANDARD.encode(&raw),
            "result":{"bytecode":STANDARD.encode(b"OCTBfixture"),"disasm":"JDEST 1\n", "verification":verification,
                "certificate":{"schema":"aml_bytecode_certificate_v1","source_hash":hash(b"source"),"bytecode_hash":hash(b"OCTBfixture"),"verification_hash":hash(&raw)}}})
    }

    #[test]
    fn pinned_artifact_rejects_each_binding_before_deployment() {
        let original = fixture();
        assert!(validate(&original, b"source", "inprocess://fixture").is_ok());
        for (pointer, replacement) in [
            ("/schema", json!("other")),
            ("/rpc_url", json!("other")),
            ("/target_binding_sha256", json!(null)),
            ("/compiler/kind", json!("unbound")),
            ("/compiler/binary_sha256", json!("")),
            ("/compiler/native_profiles", json!([])),
            ("/compiler/after/runtime/consensus_profile", json!(17)),
            ("/compiler/after/head_epoch", json!(9)),
            ("/compiler/before/state_root", json!("bad")),
            ("/result/bytecode", json!("bad")),
            ("/result/certificate/source_hash", json!("0".repeat(64))),
            ("/result/certificate/bytecode_hash", json!("0".repeat(64))),
            (
                "/result/certificate/verification_hash",
                json!("0".repeat(64)),
            ),
            ("/result/verification/errors", json!(1)),
            ("/result/disasm", json!("JDEST 1\nJDEST 1\n")),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate(&changed, b"source", "inprocess://fixture").is_err(),
                "{pointer}"
            );
        }
        assert!(validate(&original, b"wrong source", "inprocess://fixture").is_err());
    }

    #[test]
    fn raw_file_hash_is_required_and_checked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact.json");
        let raw = serde_json::to_vec(&fixture()).unwrap();
        std::fs::write(&path, &raw).unwrap();
        assert!(load(&path, &hash(&raw), b"source", "inprocess://fixture").is_ok());
        assert!(load(&path, &"0".repeat(64), b"source", "inprocess://fixture").is_err());
        assert!(load(&path, "bad", b"source", "inprocess://fixture").is_err());
    }
}

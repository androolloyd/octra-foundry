//! Adapter for the real, explicitly selected standalone AML compiler and VM.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub fn execute(binary: &Path, command: &str, source: &Path, extra: &[String]) -> Result<Output> {
    Command::new(binary)
        .arg(command)
        .arg(source)
        .args(extra)
        .output()
        .with_context(|| {
            format!(
                "run {} {command}; install the pinned amlc or set AMLC",
                binary.display()
            )
        })
}

pub fn checked(binary: &Path, command: &str, source: &Path, extra: &[String]) -> Result<String> {
    let output = execute(binary, command, source, extra)?;
    if !output.status.success() {
        bail!(
            "amlc {command} failed for {}: {}{}",
            source.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("amlc output is not UTF-8")
}

pub fn compile(binary: &Path, source: &Path) -> Result<Value> {
    let temp = tempfile::tempdir()?;
    let octb = temp.path().join("artifact.octb");
    let report = checked(
        binary,
        "compile",
        source,
        &["--out".into(), octb.display().to_string()],
    )?;
    if !report.starts_with("status = pass ") {
        bail!("amlc did not confirm successful compilation");
    }
    let bytes = std::fs::read(&octb).context("compiler did not produce OCTB")?;
    if !bytes.starts_with(b"OCTB") {
        bail!("compiler output is not OCTB");
    }
    let abi: Value = serde_json::from_str(&checked(binary, "abi", source, &[])?)?;
    functions(&abi)?;
    let name = report
        .split("program = ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .context("compiler report lacks program name")?;
    validate_name(name)?;
    let version = Command::new(binary)
        .arg("version")
        .output()
        .context("query amlc version")?;
    if !version.status.success() {
        bail!("amlc version query failed");
    }
    let source_bytes = std::fs::read(source)?;
    Ok(
        json!({"name": name, "abi": abi, "bytecode": STANDARD.encode(&bytes),
            "bytecode_sha256": hex::encode(Sha256::digest(&bytes)),
            "source_hash": hex::encode(Sha256::digest(source_bytes)),
            "compiler": String::from_utf8_lossy(&version.stdout).trim(),
            "compiler_backend": "local-amlc", "compiler_report": report.trim(),
            "deployable": false, "deployment_requirement": "recompile under the target chain's epoch/profile and compare",
            "assembly": checked(binary, "dump", &octb, &[])?
        }),
    )
}

/// Normalize the current object ABI and the legacy list ABI at one boundary.
pub fn functions(abi: &Value) -> Result<Vec<Value>> {
    if let Some(raw) = abi.as_str() {
        let decoded: Value = serde_json::from_str(raw).context("ABI string is not JSON")?;
        return functions(&decoded);
    }
    let value = abi.get("abi").unwrap_or(abi);
    if let Some(list) = value.as_array() {
        return Ok(list.clone());
    }
    let list = value
        .get("functions")
        .and_then(Value::as_array)
        .context("ABI lacks functions")?;
    list.iter()
        .map(|function| {
            let mut item = function
                .as_object()
                .context("ABI function is not an object")?
                .clone();
            let types = item
                .get("inputs")
                .and_then(Value::as_array)
                .context("ABI inputs absent")?;
            let names = item
                .get("input_names")
                .and_then(Value::as_array)
                .context("ABI input_names absent")?;
            if types.len() != names.len() {
                bail!("ABI input names and types differ in length");
            }
            let inputs = types
                .iter()
                .zip(names)
                .map(|(ty, name)| {
                    Ok(
                        json!({"name": name.as_str().context("ABI input name is not text")?,
                "type": ty.as_str().context("ABI input type is not text")?}),
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let kind = if item.get("view").and_then(Value::as_bool).unwrap_or(false) {
                "view"
            } else {
                "call"
            };
            item.insert("kind".into(), json!(kind));
            item.insert("inputs".into(), json!(inputs));
            Ok(Value::Object(item))
        })
        .collect()
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("unsafe artifact name: {name}");
    }
    Ok(())
}

pub fn discover(root: &Path, tests: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!(
                "source symlink must be resolved explicitly: {}",
                entry.path().display()
            );
        }
        if kind.is_dir() {
            files.extend(discover(&entry.path(), tests)?);
        } else if kind.is_file() && entry.path().extension().is_some_and(|ext| ext == "aml") {
            let is_test = entry.file_name().to_string_lossy().ends_with(".t.aml");
            if is_test == tests {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

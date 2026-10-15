//! Execute `test_*` AML methods in the real VM. Rust tests are an explicit mode.
use super::{amlc, trace};
use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, process::Command};

#[derive(Args, Debug)]
pub struct TestArgs {
    #[arg(long)]
    pub filter: Option<String>,
    /// Run Rust libtest for this package instead of AML tests.
    #[arg(long)]
    pub package: Option<String>,
    #[arg(long)]
    pub release: bool,
    #[arg(long)]
    pub raw: bool,
    /// Directory containing `.t.aml` test contracts or method fragments.
    #[arg(long, default_value = "test")]
    pub root: PathBuf,
    /// Append test method fragments to this exact production contract.
    /// The production method bodies are never rewritten.
    #[arg(long)]
    pub contract: Option<PathBuf>,
    #[arg(long, env = "AMLC", default_value = "amlc")]
    pub amlc: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub epoch: u64,
}

pub fn run(args: &TestArgs) -> Result<()> {
    if let Some(package) = &args.package {
        return run_rust(args, package);
    }
    if args.release {
        bail!("--release applies only to --package Rust tests");
    }
    let files = amlc::discover(&args.root, true)?;
    if files.is_empty() {
        bail!("no .t.aml tests found in {}", args.root.display());
    }
    let production = args
        .contract
        .as_ref()
        .map(std::fs::read_to_string)
        .transpose()?;
    let mut passed = 0;
    let mut failed = 0;
    for file in files {
        let fragment = std::fs::read_to_string(&file)?;
        let expectations = revert_expectations(&fragment)?;
        let source = if let Some(production) = &production {
            let prefix = production
                .trim_end()
                .strip_suffix('}')
                .context("contract must end with a closing brace")?;
            format!("{prefix}\n{fragment}\n}}\n")
        } else {
            fragment
        };
        // Keep imported paths rooted exactly as the production contract/compiler expects.
        let parent = args
            .contract
            .as_ref()
            .unwrap_or(&file)
            .parent()
            .context("source parent absent")?;
        let temp = tempfile::Builder::new()
            .prefix(".forge-test-")
            .suffix(".aml")
            .tempfile_in(parent)?;
        std::fs::write(temp.path(), source)?;
        let abi: Value =
            serde_json::from_str(&amlc::checked(&args.amlc, "abi", temp.path(), &[])?)?;
        amlc::checked(&args.amlc, "check", temp.path(), &[])?;
        let methods = amlc::functions(&abi)?;
        for name in expectations.keys() {
            if !methods.iter().any(|m| m["name"].as_str() == Some(name)) {
                bail!("expected-revert annotation references missing method {name}");
            }
        }
        for method in methods {
            let name = method["name"].as_str().context("ABI method name absent")?;
            if !name.starts_with("test_") || args.filter.as_ref().is_some_and(|f| !name.contains(f))
            {
                continue;
            }
            if method["inputs"].as_array().is_none_or(|a| !a.is_empty()) {
                bail!("{name} must have zero arguments");
            }
            let output = amlc::execute(
                &args.amlc,
                "run",
                temp.path(),
                &[
                    "--method".into(),
                    name.into(),
                    "--epoch".into(),
                    args.epoch.to_string(),
                ],
            )?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let success = if let Some(reason) = expectations.get(name) {
                let escaped = serde_json::to_string(reason)?;
                let needle = format!(
                    "error = Require message = text:{} effort =",
                    &escaped[1..escaped.len() - 1]
                );
                !output.status.success()
                    && stderr.contains("stop = reverted")
                    && stderr.contains(&needle)
            } else {
                output.status.success()
                    && stdout.starts_with("status = pass ")
                    && (method["output"] != "bool" || stdout.contains(" result = bool:true "))
            };
            if success {
                passed += 1;
                println!("[PASS] {}::{name}", file.display());
            } else {
                failed += 1;
                println!("[FAIL] {}::{name}\n{stdout}{stderr}", file.display());
            }
        }
    }
    println!(
        "AML result: {passed} passed; {failed} failed (real amlc VM, isolated state per method)"
    );
    if passed + failed == 0 {
        bail!("no AML test methods matched");
    }
    if failed > 0 {
        bail!("AML tests failed");
    }
    Ok(())
}

fn revert_expectations(source: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for line in source.lines() {
        if let Some(raw) = line.trim().strip_prefix("// expect-revert ") {
            let (name, reason) = raw
                .split_once(' ')
                .context("expected-revert needs method and JSON string reason")?;
            let decoded: String = serde_json::from_str(reason)?;
            if decoded.len() > 96 || !decoded.bytes().all(|b| (32..=126).contains(&b)) {
                bail!("expected-revert reason must be printable ASCII up to 96 bytes");
            }
            if !name.starts_with("test_")
                || out
                    .insert(name.into(), serde_json::from_str::<String>(reason)?)
                    .is_some()
            {
                bail!("invalid or duplicate expected-revert annotation: {name}");
            }
        }
    }
    Ok(out)
}

fn run_rust(args: &TestArgs, package: &str) -> Result<()> {
    let mut cmd = Command::new(option_env!("CARGO").unwrap_or("cargo"));
    cmd.arg("test").arg("-p").arg(package);
    if args.release {
        cmd.arg("--release");
    }
    cmd.arg("--").arg("--nocapture");
    if let Some(filter) = &args.filter {
        cmd.arg(filter);
    }
    if args.raw {
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("cargo test failed: {status}"));
        }
    } else {
        let output = cmd.output()?;
        trace::render_test_output(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        );
        if !output.status.success() {
            bail!("cargo test failed: {}", output.status);
        }
    }
    Ok(())
}

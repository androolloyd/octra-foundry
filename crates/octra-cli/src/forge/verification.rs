//! Surface the Octra compiler's formal-verification audit in `octra forge`.
//!
//! Every `octra_compileAml` / `octra_compileAmlMulti` / `contract_verify`
//! response from the live compiler ("1.0 Rehovot") carries a
//! `verification` object — schema `aml_safety_report_v1`, produced by the
//! `aml_ast_verifier` engine backed by a Coq proof model
//! (`formal/coq/aml_value_safety_model.v`) — plus a `certificate` binding
//! `source_hash` ↔ `bytecode_hash` ↔ `verification_hash`. That audit is
//! exactly what `octrascan`'s verification tab renders.
//!
//! This module parses that payload into typed reports so the same audit
//! flows to the operator (`forge build`/`verify`), to CI (`--json`), and
//! on to octrascan. The verifier checks value-safety properties (signed
//! ints in value-like storage, unchecked transfers, supply conservation,
//! …) — see [`FvAudit`]. Parsing is tolerant of unknown fields (the raw
//! payload is retained) so schema growth doesn't break the pipeline.

use serde::Serialize;
use serde_json::Value;

/// Severity of a verifier finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "error" | "err" | "fail" | "failed" => Severity::Error,
        "info" | "note" | "hint" => Severity::Info,
        _ => Severity::Warning,
    }
}

/// One safety check from the verifier's `trace`. `status` is `error`
/// (a real violation), `warning`, or `pass`; `findings` counts the
/// offending sites.
#[derive(Debug, Clone, Serialize)]
pub struct FvCheck {
    pub code: String,
    pub title: String,
    pub status: String,
    pub severity: Severity,
    pub findings: u64,
}

impl FvCheck {
    /// A check that actually flagged something (not `pass`).
    #[must_use]
    pub fn is_finding(&self) -> bool {
        !self.status.eq_ignore_ascii_case("pass") && self.findings > 0
            || self.status.eq_ignore_ascii_case("error")
            || self.status.eq_ignore_ascii_case("warning")
    }
}

/// Per-function data-flow summary from the verifier. `signed_params`
/// and `value_writes` are what make the value-safety checks actionable:
/// they pinpoint the exact function (and field/param) behind each
/// finding, so `signed_value_parameter` / `signed_value_storage` errors
/// map to a concrete fix site.
#[derive(Debug, Clone, Serialize)]
pub struct FvFunction {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signed_params: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value_writes: Vec<String>,
}

impl FvFunction {
    /// A function the value-safety checks flagged (signed param or
    /// signed write into a value-like field).
    #[must_use]
    pub fn is_flagged(&self) -> bool {
        !self.signed_params.is_empty() || !self.value_writes.is_empty()
    }
}

/// The `aml_safety_report_v1` formal-verification audit. This is the
/// structure octrascan renders; `raw` keeps the full payload
/// (invariants, proof_model, …).
#[derive(Debug, Clone, Serialize)]
pub struct FvAudit {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<String>,
    pub verified: bool,
    pub safety: String,
    pub errors: u64,
    pub warnings: u64,
    pub checks: Vec<FvCheck>,
    pub functions: Vec<FvFunction>,
    pub raw: Value,
}

impl FvAudit {
    /// True when the contract failed formal verification.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        !self.verified || self.errors > 0 || self.safety.eq_ignore_ascii_case("error")
    }
}

/// Result of compiling a program through the live compiler.
#[derive(Debug, Clone, Serialize)]
pub struct CompileReport {
    pub program: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<u64>,
    /// Tamper-evident binding of source ↔ bytecode ↔ verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_verification: Option<FvAudit>,
}

/// Result of `contract_verify` for a deployed address.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub address: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_verification: Option<FvAudit>,
}

#[must_use]
pub fn parse_compile(program: &str, v: &Value) -> CompileReport {
    CompileReport {
        program: program.to_string(),
        compiler_version: str_field(v, "version"),
        size: v.get("size").and_then(Value::as_u64),
        instructions: v.get("instructions").and_then(Value::as_u64),
        certificate: v.get("certificate").cloned(),
        formal_verification: parse_fv(v),
    }
}

#[must_use]
pub fn parse_verify(address: &str, v: &Value) -> VerifyReport {
    VerifyReport {
        address: address.to_string(),
        verified: v.get("verified").and_then(Value::as_bool).unwrap_or(false),
        code_hash: str_field(v, "code_hash"),
        certificate: v.get("certificate").cloned(),
        formal_verification: parse_fv(v),
    }
}

/// Pull the `verification` audit. Accepts the canonical key plus a few
/// aliases for forward-compat; retains the raw payload either way.
fn parse_fv(v: &Value) -> Option<FvAudit> {
    let fv = ["verification", "formal_verification", "fv"]
        .iter()
        .find_map(|k| v.get(*k))
        .filter(|x| x.is_object())?;

    let checks = fv
        .get("trace")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_check).collect())
        .unwrap_or_default();
    let functions = fv
        .get("function_summaries")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_function).collect())
        .unwrap_or_default();

    Some(FvAudit {
        schema: str_field(fv, "schema").unwrap_or_else(|| "unknown".into()),
        engine: str_field(fv, "engine"),
        program_name: str_field(fv, "program_name"),
        verified: fv.get("verified").and_then(Value::as_bool).unwrap_or(false),
        safety: str_field(fv, "safety").unwrap_or_else(|| "unknown".into()),
        errors: fv.get("errors").and_then(Value::as_u64).unwrap_or(0),
        warnings: fv.get("warnings").and_then(Value::as_u64).unwrap_or(0),
        checks,
        functions,
        raw: fv.clone(),
    })
}

fn parse_function(f: &Value) -> FvFunction {
    let strs = |key: &str| {
        f.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    FvFunction {
        name: str_field(f, "name").unwrap_or_default(),
        signed_params: strs("signed_params"),
        value_writes: strs("value_writes"),
    }
}

fn parse_check(c: &Value) -> FvCheck {
    FvCheck {
        code: str_field(c, "code").unwrap_or_default(),
        title: str_field(c, "title").unwrap_or_default(),
        status: str_field(c, "status").unwrap_or_else(|| "unknown".into()),
        severity: c
            .get("severity")
            .and_then(Value::as_str)
            .map_or(Severity::Warning, parse_severity),
        findings: c.get("findings").and_then(Value::as_u64).unwrap_or(0),
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Render a compile report Foundry-style. Returns `false` if formal
/// verification failed.
#[must_use]
pub fn render_compile(r: &CompileReport) -> bool {
    let v = r.compiler_version.as_deref().unwrap_or("compiler");
    match (r.size, r.instructions) {
        (Some(s), Some(i)) => println!("  ✓ {} compiled ({v}, {i} instrs, {s} bytes)", r.program),
        _ => println!("  ✓ {} compiled ({v})", r.program),
    }
    r.formal_verification.as_ref().map_or(true, render_fv)
}

/// Render a verify report. Returns `false` on failed verification or FV
/// failure.
#[must_use]
pub fn render_verify(r: &VerifyReport) -> bool {
    if r.verified {
        println!(
            "  ✓ {} source verified  code_hash={}",
            r.address,
            r.code_hash.as_deref().unwrap_or("")
        );
    } else {
        println!("  ✗ {} source NOT verified", r.address);
    }
    let fv_ok = r.formal_verification.as_ref().map_or(true, render_fv);
    r.verified && fv_ok
}

/// Render the formal-verification audit. Returns `false` if it failed.
fn render_fv(fv: &FvAudit) -> bool {
    let engine = fv.engine.as_deref().unwrap_or("aml verifier");
    if fv.verified {
        println!("    ✓ formally verified — {engine} ({})", fv.schema);
    } else {
        println!(
            "    ✗ formal verification FAILED — {} error(s), {} warning(s) [{engine}]",
            fv.errors, fv.warnings
        );
    }
    // List the checks that flagged something, errors first.
    let mut findings: Vec<&FvCheck> = fv.checks.iter().filter(|c| c.is_finding()).collect();
    findings.sort_by_key(|c| c.severity != Severity::Error);
    for c in findings {
        let mark = if c.severity == Severity::Error {
            "error"
        } else {
            "warn "
        };
        println!(
            "      {mark}  {} ({}, {} finding(s))",
            c.title, c.code, c.findings
        );
    }
    // Pinpoint the fix sites: functions whose signed params / value
    // writes drive the value-safety findings above.
    let flagged: Vec<&FvFunction> = fv.functions.iter().filter(|f| f.is_flagged()).collect();
    if !flagged.is_empty() {
        println!("      at:");
        for f in flagged {
            let mut bits = Vec::new();
            if !f.signed_params.is_empty() {
                bits.push(format!("signed params [{}]", f.signed_params.join(", ")));
            }
            if !f.value_writes.is_empty() {
                bits.push(format!("value writes [{}]", f.value_writes.join(", ")));
            }
            println!("        {}: {}", f.name, bits.join("; "));
        }
    }
    !fv.has_failures()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The exact `aml_safety_report_v1` shape the live devnet compiler
    /// returns for the `vault` example (4 errors, 1 warning).
    fn vault_response() -> Value {
        json!({
            "version": "1.0 Rehovot", "size": 765, "instructions": 146,
            "certificate": {"source_hash": "abc", "bytecode_hash": "def", "verification_hash": "123"},
            "verification": {
                "schema": "aml_safety_report_v1", "engine": "aml_ast_verifier",
                "program_name": "Vault", "verified": false, "safety": "error",
                "errors": 4, "warnings": 1,
                "trace": [
                    {"code": "signed_value_storage", "title": "value-like storage must not use signed int",
                     "status": "error", "severity": "error", "findings": 1},
                    {"code": "unchecked_transfer_result", "title": "native transfer result should be checked",
                     "status": "warning", "severity": "warning", "findings": 1},
                    {"code": "supply_invariant_unproven", "title": "conservation", "status": "pass",
                     "severity": "warning", "findings": 0}
                ],
                "function_summaries": [{"name": "deposit", "value_writes": ["deposits"]}]
            }
        })
    }

    #[test]
    fn parses_live_aml_safety_report() {
        let r = parse_compile("Vault", &vault_response());
        assert_eq!(r.compiler_version.as_deref(), Some("1.0 Rehovot"));
        assert!(r.certificate.is_some(), "proof certificate carried");
        let fv = r.formal_verification.expect("verification parsed");
        assert_eq!(fv.schema, "aml_safety_report_v1");
        assert_eq!(fv.engine.as_deref(), Some("aml_ast_verifier"));
        assert!(!fv.verified);
        assert_eq!(fv.errors, 4);
        assert!(fv.has_failures());
        // 2 of the 3 trace entries are findings (the `pass` one is not).
        let findings = fv.checks.iter().filter(|c| c.is_finding()).count();
        assert_eq!(findings, 2);
    }

    #[test]
    fn render_fails_on_verification_errors() {
        let r = parse_compile("Vault", &vault_response());
        assert!(!render_compile(&r), "errors → compile gate fails");
    }

    #[test]
    fn clean_contract_passes() {
        let v = json!({
            "version": "1.0 Rehovot", "size": 100, "instructions": 20,
            "verification": {"schema": "aml_safety_report_v1", "verified": true,
                             "safety": "ok", "errors": 0, "warnings": 0, "trace": []}
        });
        let r = parse_compile("Clean", &v);
        assert!(render_compile(&r));
        assert!(!r.formal_verification.unwrap().has_failures());
    }
}

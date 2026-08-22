#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
rpc-scrape — derive the REAL Octra node JSON-RPC method registry from upstream
OCaml source, and emit a committed Rust module (`methods.rs`) that the mock
dispatcher checks itself against.

Why this exists
---------------
`octra-mock-rpc` used to invent RPC methods the chain does not have
(`octra_isValidator`, the seven `octra_fhe*` wrappers). Tests then passed
against a chain that cannot exist. This tool makes the mock's surface a
DERIVED artifact of upstream source rather than an opinion.

Design rule: **a scraper that silently emits an empty list is worse than no
scraper.** Every extractor below declares what it expects to find, and the
tool exits non-zero with a loud diagnostic when the upstream shape changes:

  * missing file                              -> hard error
  * missing `let <binding> ... =` declaration -> hard error
  * a line inside a route body that *looks*
    like a route but does not parse           -> hard error
  * a list entry that does not start with a
    string-literal method name                -> hard error
  * fewer routes than the declared floor       -> hard error
  * total method count != the pinned
    EXPECTED_TOTAL_NAMES                       -> hard error
    (override deliberately with
     --accept-count-change, which reprints the
     new number to paste back into this file)

Usage
-----
    python3 tools/rpc-scrape/rpc_scrape.py \
        --upstream /path/to/lite_node \
        --out crates/octra-mock-rpc/src/methods.rs

    # report only, no write
    python3 tools/rpc-scrape/rpc_scrape.py --upstream ... --print

The generated file is COMMITTED. This tool is not needed at build time; it is
run when upstream's pinned SOURCE_COMMIT moves.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Upstream source map. Line numbers are documentation only (they drift); the
# extractors locate bindings by name. Every entry was hand-verified against
# lite_node @ dd342e754c91df55a41b515c510369d637af2385.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """One upstream route table."""

    group: str
    relpath: str
    binding: str  # the `let <binding>` whose body holds the routes
    mode: str  # "route_dsl" | "assoc_list"
    min_routes: int  # loud floor; below this we assume a parse regression
    note: str = ""


SOURCES: tuple[Source, ...] = (
    # --- rpc_dispatch.ml: the `route` / `route_aliases` DSL (~L109-202) ------
    Source(
        "circle",
        "node_runtime/rpc_dispatch.ml",
        "circle_routes",
        "route_dsl",
        60,
        "circle_read_rpc.ml:1522 feeds these handlers",
    ),
    Source(
        "program",
        "node_runtime/rpc_dispatch.ml",
        "program_routes",
        "route_dsl",
        14,
        "program_read_rpc.ml:64 feeds these handlers",
    ),
    # --- rpc_effect_dispatch.ml: submission / staging / mutation (~L24-34) ---
    Source(
        "effect",
        "node_runtime/rpc_effect_dispatch.ml",
        "dispatch",
        "route_dsl",
        6,
        "the only write-side methods on the node",
    ),
    # --- plain OCaml assoc lists ------------------------------------------
    Source("status_core", "node_runtime/status_read_rpc.ml", "core_dispatch", "assoc_list", 5),
    Source("status_proof", "node_runtime/status_read_rpc.ml", "proof_dispatch", "assoc_list", 9),
    Source("account_public", "node_runtime/account_read_rpc.ml", "public_dispatch", "assoc_list", 7),
    Source("account_pvac", "node_runtime/account_read_rpc.ml", "pvac_dispatch", "assoc_list", 9),
    Source("history", "node_runtime/history_read_rpc.ml", "dispatch", "assoc_list", 7),
    Source("rest", "node_runtime/rest_read_rpc.ml", "dispatch", "assoc_list", 9),
    Source(
        "compute",
        "node_runtime/node_rpc_server.ml",
        "compute_dispatch",
        "assoc_list",
        3,
        "node_rpc_server.ml:431-438",
    ),
)

# node_rpc_server.ml `dispatch` (~L461-480) composes exactly these groups.
# If upstream adds a group there and not here, we would silently miss it, so
# we cross-check the composition text against this list.
EXPECTED_COMPOSITION = (
    "Status_read_rpc.core_dispatch",
    "Account_read_rpc.public_dispatch",
    "history_dispatch",
    "rest_dispatch",
    "circle_dispatch",
    "program_dispatch",
    "Account_read_rpc.pvac_dispatch",
    "Status_read_rpc.proof_dispatch",
    "effect_dispatch.submission",
    "effect_dispatch.staging",
    "effect_dispatch.mutation",
    "compute_dispatch",
)

ERROR_SOURCE = "lib/core/rpc.ml"  # constants at ~L21-43
MIN_ERROR_CONSTANTS = 18

# Pinned totals. A change here is a real upstream API change and must be
# reviewed, not rubber-stamped. Bump only with --accept-count-change.
EXPECTED_TOTAL_NAMES = 212
EXPECTED_TOTAL_PRIMARIES = 136


class ScrapeError(RuntimeError):
    """Loud failure: the upstream shape is not what this tool was written for."""


def die(msg: str) -> "ScrapeError":
    return ScrapeError(msg)


# ---------------------------------------------------------------------------
# OCaml surgery helpers
# ---------------------------------------------------------------------------

COMMENT_RE = re.compile(r"\(\*.*?\*\)", re.DOTALL)


def strip_comments(text: str) -> str:
    """Remove (* ... *) comments. Non-nesting, which is all upstream uses."""
    return COMMENT_RE.sub(" ", text)


def binding_body(text: str, binding: str, *, where: str) -> str:
    """
    Return the source of `let <binding> ... = <body>`, ending at the next
    top-level `let`/`and`/`type`/`module` at column 0, or EOF.
    """
    start_re = re.compile(rf"^let\s+{re.escape(binding)}\b", re.MULTILINE)
    m = start_re.search(text)
    if not m:
        raise die(
            f"{where}: no top-level `let {binding}` found. Upstream renamed or "
            f"moved this route table — re-read the file and update SOURCES."
        )
    rest = text[m.end() :]
    end_re = re.compile(r"^(let|and|type|module)\b", re.MULTILINE)
    e = end_re.search(rest)
    body = rest[: e.start()] if e else rest
    if not body.strip():
        raise die(f"{where}: `let {binding}` body is empty after comment strip.")
    return body


def split_top_level(text: str, sep: str) -> list[str]:
    """Split on `sep` at bracket-depth 0, ignoring string literals."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf))
    return out


def outer_list(text: str, *, where: str) -> str:
    """Return the contents of the first bracket-balanced `[ ... ]`."""
    in_str = False
    esc = False
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "[":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise die(f"{where}: could not find a balanced `[ ... ]` list body.")


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


@dataclass
class Route:
    primary: str
    aliases: list[str] = field(default_factory=list)
    group: str = ""

    @property
    def names(self) -> list[str]:
        return [self.primary, *self.aliases]


ROUTE_ALIASES_RE = re.compile(r'\broute_aliases\s+"([^"]+)"\s+"([^"]+)"\s+\S')
ROUTE_RE = re.compile(r'\broute\s+"([^"]+)"\s+\S')
METHOD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def extract_route_dsl(body: str, group: str, where: str) -> list[Route]:
    """
    Parse the `route` / `route_aliases` DSL. Any line mentioning either
    combinator MUST parse; an unparseable one is a hard error, because that is
    exactly the drift this tool exists to catch.
    """
    routes: list[Route] = []
    for lineno, raw in enumerate(body.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if "route_aliases" in line:
            m = ROUTE_ALIASES_RE.search(line)
            if not m:
                raise die(
                    f"{where}:+{lineno}: line mentions `route_aliases` but does "
                    f"not parse as `route_aliases \"primary\" \"alias\" handler`:\n"
                    f"    {line}"
                )
            routes.append(Route(m.group(1), [m.group(2)], group))
            continue
        if re.search(r"\broute\b", line):
            m = ROUTE_RE.search(line)
            if not m:
                raise die(
                    f"{where}:+{lineno}: line mentions `route` but does not parse "
                    f'as `route "name" handler`:\n    {line}'
                )
            routes.append(Route(m.group(1), [], group))
    return routes


ASSOC_HEAD_RE = re.compile(r'^\s*"([^"]+)"\s*,')


def extract_assoc_list(body: str, group: str, where: str) -> list[Route]:
    """
    Parse `[ "name", handler; "name", handler; ... ]`. Every non-empty entry
    must start with a string-literal method name.
    """
    inner = outer_list(body, where=where)
    routes: list[Route] = []
    for idx, entry in enumerate(split_top_level(inner, ";")):
        if not entry.strip():
            continue
        m = ASSOC_HEAD_RE.match(entry)
        if not m:
            raise die(
                f"{where}: assoc-list entry #{idx} does not start with a "
                f'"method_name", head:\n    {entry.strip()[:160]}'
            )
        routes.append(Route(m.group(1), [], group))
    return routes


def scrape_routes(upstream: Path) -> list[Route]:
    all_routes: list[Route] = []
    for src in SOURCES:
        path = upstream / src.relpath
        if not path.is_file():
            raise die(f"missing upstream file: {path}")
        text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        where = f"{src.relpath}::{src.binding}"
        body = binding_body(text, src.binding, where=where)
        if src.mode == "route_dsl":
            routes = extract_route_dsl(body, src.group, where)
        elif src.mode == "assoc_list":
            routes = extract_assoc_list(body, src.group, where)
        else:  # pragma: no cover - programmer error
            raise die(f"unknown extractor mode {src.mode!r}")
        if len(routes) < src.min_routes:
            raise die(
                f"{where}: extracted {len(routes)} routes but expected at least "
                f"{src.min_routes}. Either upstream shrank this table (verify by "
                f"hand!) or the extractor regressed."
            )
        for r in routes:
            for n in r.names:
                if not METHOD_NAME_RE.match(n):
                    raise die(f"{where}: implausible method name {n!r}")
        all_routes.extend(routes)
    return all_routes


def check_composition(upstream: Path) -> None:
    """
    node_rpc_server.ml `dispatch` is the single place that concatenates every
    route group. If it grows a group we do not scrape, we would silently ship
    an incomplete registry — so assert the composition we were written for.
    """
    path = upstream / "node_runtime/node_rpc_server.ml"
    text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    body = binding_body(text, "dispatch", where="node_rpc_server.ml::dispatch")
    missing = [g for g in EXPECTED_COMPOSITION if g not in body]
    if missing:
        raise die(
            "node_rpc_server.ml::dispatch no longer mentions: "
            + ", ".join(missing)
            + " — the route composition changed; re-read it before trusting this tool."
        )
    # Catch NEW groups: every `X_dispatch` / `Module.y_dispatch` token in the
    # composition must be one we know about.
    # NB: the trailing lookahead keeps `status_dispatch_adapters` (an adapter
    # record, not a route group) from being mistaken for a table.
    seen = set(
        re.findall(
            r"[A-Za-z_][A-Za-z0-9_.]*_dispatch(?:\.[a-z_]+)?(?![A-Za-z0-9_])", body
        )
    )
    seen.discard("dispatch")
    unknown = sorted(t for t in seen if t not in EXPECTED_COMPOSITION)
    if unknown:
        raise die(
            "node_rpc_server.ml::dispatch composes route groups this tool does "
            "not scrape: " + ", ".join(unknown) + ". Add them to SOURCES."
        )


# ---------------------------------------------------------------------------
# Error constants
# ---------------------------------------------------------------------------


@dataclass
class RpcErr:
    ident: str
    code: int
    message: str
    templated: bool  # message is a format string taking the method name
    has_data: bool


ERR_PATTERNS = (
    # let method_not_found m = { code = -32601; message = Printf.sprintf "..." m; ... }
    re.compile(
        r'^let\s+(?P<id>\w+)\s+\w+\s*=\s*\{\s*code\s*=\s*(?P<code>-?\d+);\s*'
        r'message\s*=\s*Printf\.sprintf\s*"(?P<msg>[^"]*)"'
    ),
    # let parse_error = { code = -32700; message = "parse error"; data = None }
    re.compile(
        r'^let\s+(?P<id>\w+)\s*=\s*\{\s*code\s*=\s*(?P<code>-?\d+);\s*'
        r'message\s*=\s*"(?P<msg>[^"]*)"'
    ),
    # let invalid_params msg = { code = -32602; message = "invalid params"; ... }
    # (covered by the pattern above once the arg is allowed)
    re.compile(
        r'^let\s+(?P<id>\w+)\s+\w+\s*=\s*\{\s*code\s*=\s*(?P<code>-?\d+);\s*'
        r'message\s*=\s*"(?P<msg>[^"]*)"'
    ),
    # let sender_not_found = err 100 "sender not found" None
    # let malformed_tx msg  = err 105 "malformed transaction" (Some ...)
    re.compile(r'^let\s+(?P<id>\w+)(?:\s+\w+)?\s*=\s*err\s+\(?(?P<code>-?\d+)\)?\s+"(?P<msg>[^"]*)"'),
)


def scrape_errors(upstream: Path) -> list[RpcErr]:
    path = upstream / ERROR_SOURCE
    if not path.is_file():
        raise die(f"missing upstream file: {path}")
    text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    # Region: from `let parse_error` to `let response_json`.
    start = text.find("let parse_error")
    end = text.find("let response_json")
    if start < 0 or end < 0 or end <= start:
        raise die(
            f"{ERROR_SOURCE}: could not delimit the error-constant region "
            f"(`let parse_error` .. `let response_json`)."
        )
    region = text[start:end]

    out: list[RpcErr] = []
    for lineno, raw in enumerate(region.splitlines(), 1):
        line = raw.strip()
        if not line.startswith("let "):
            continue
        if re.match(r"^let\s+err\s+code\s+message\s+data\s*=", line):
            continue  # the constructor itself, not a constant
        hit = None
        for pat in ERR_PATTERNS:
            hit = pat.match(line)
            if hit:
                break
        if not hit:
            raise die(
                f"{ERROR_SOURCE}:+{lineno}: `let` inside the error-constant region "
                f"does not parse as an rpc_error:\n    {line}"
            )
        msg = hit.group("msg")
        out.append(
            RpcErr(
                ident=hit.group("id"),
                code=int(hit.group("code")),
                message=msg,
                templated="%s" in msg,
                has_data="data = Some" in line or "(Some" in line,
            )
        )
    if len(out) < MIN_ERROR_CONSTANTS:
        raise die(
            f"{ERROR_SOURCE}: parsed {len(out)} error constants, expected at "
            f"least {MIN_ERROR_CONSTANTS}."
        )
    if not any(e.ident == "method_not_found" and e.code == -32601 for e in out):
        raise die(
            f"{ERROR_SOURCE}: `method_not_found` with code -32601 not found — "
            f"that is the single constant the mock dispatcher depends on."
        )
    return out


# ---------------------------------------------------------------------------
# Rust emission
# ---------------------------------------------------------------------------


def rs_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def const_ident(ident: str) -> str:
    return ident.upper()


def emit_rust(routes: list[Route], errors: list[RpcErr], commit: str, upstream_desc: str) -> str:
    by_group: dict[str, list[Route]] = {}
    for r in routes:
        by_group.setdefault(r.group, []).append(r)

    names: list[str] = []
    for r in routes:
        names.extend(r.names)
    unique_names = sorted(set(names))
    aliases = sorted(
        (a, r.primary) for r in routes for a in r.aliases
    )

    mnf = next(e for e in errors if e.ident == "method_not_found")
    mnf_fmt = mnf.message.replace("%s", "{method}")

    L: list[str] = []
    w = L.append
    w("// SPDX-License-Identifier: MIT OR Apache-2.0")
    w("//")
    w("// @generated by tools/rpc-scrape/rpc_scrape.py — DO NOT EDIT BY HAND.")
    w("//")
    w(f"// Upstream: {upstream_desc}")
    w(f"// SOURCE_COMMIT: {commit}")
    w("//")
    w("// This is the REAL JSON-RPC surface of the Octra lite node, derived from")
    w("// its OCaml dispatch tables. The mock uses it to guarantee it can never")
    w("// answer a method the chain does not have, and never invent an error")
    w("// shape the chain does not emit.")
    w("//")
    w("// Regenerate with:")
    w("//   python3 tools/rpc-scrape/rpc_scrape.py \\")
    w("//       --upstream <lite_node checkout> \\")
    w("//       --out crates/octra-mock-rpc/src/methods.rs")
    w("")
    w("/// The upstream commit these tables were scraped from. Must match")
    w("/// `docker/octra-node/Dockerfile`'s `SOURCE_COMMIT`.")
    w(f"pub const SOURCE_COMMIT: &str = {rs_str(commit)};")
    w("")

    # ---- error constants -------------------------------------------------
    w("/// JSON-RPC / chain error codes, scraped from `lib/core/rpc.ml`.")
    w("///")
    w("/// Codes are the node's, verbatim. Where the node's message is a")
    w("/// template, the Rust side gets a formatter below instead of a const.")
    w("pub mod codes {")
    for e in sorted(errors, key=lambda e: (e.code >= 0, e.code)):
        w(f"    /// node: `{e.ident}` -> {e.message}")
        w(f"    pub const {const_ident(e.ident)}: i32 = {e.code};")
    w("}")
    w("")
    w("/// Message text the node pairs with each code (template markers intact).")
    w("pub const ERROR_MESSAGES: &[(i32, &str)] = &[")
    seen_codes: set[int] = set()
    for e in sorted(errors, key=lambda e: (e.code >= 0, e.code)):
        if e.code in seen_codes:
            continue
        seen_codes.add(e.code)
        w(f"    ({e.code}, {rs_str(e.message)}),")
    w("];")
    w("")
    w("/// The node's method-not-found error, byte-for-byte.")
    w("///")
    w("/// `lib/core/rpc.ml`: `method_not_found m = { code = -32601; message =")
    w('/// Printf.sprintf "method not found: %s" m; data = None }` — note there is')
    w("/// NO `data` member, so the serialized error object is exactly")
    w("/// `{\"code\":-32601,\"message\":\"method not found: <m>\"}`.")
    w(f"pub const METHOD_NOT_FOUND_CODE: i32 = {mnf.code};")
    w("")
    w("#[must_use]")
    w("pub fn method_not_found_message(method: &str) -> String {")
    w(f"    format!({rs_str(mnf_fmt)})")
    w("}")
    w("")

    # ---- method tables ---------------------------------------------------
    total_names = len(names)
    w(f"/// Every dispatchable method name on the node ({len(unique_names)} unique,")
    w(f"/// {total_names} route entries including aliases), sorted.")
    w("///")
    w("/// Sourced from `node_rpc_server.ml::dispatch`, which concatenates:")
    for g in EXPECTED_COMPOSITION:
        w(f"///   - {g}")
    w("pub const NODE_METHODS: &[&str] = &[")
    for n in unique_names:
        w(f"    {rs_str(n)},")
    w("];")
    w("")
    w("/// `(alias, primary)` pairs — upstream `route_aliases` registers BOTH")
    w("/// names against the same handler, so both are live.")
    w("pub const NODE_METHOD_ALIASES: &[(&str, &str)] = &[")
    for a, p in aliases:
        w(f"    ({rs_str(a)}, {rs_str(p)}),")
    w("];")
    w("")
    w("/// Methods grouped by the upstream route table they come from.")
    w("pub const NODE_METHOD_GROUPS: &[(&str, &[&str])] = &[")
    for src in SOURCES:
        grp = by_group.get(src.group, [])
        gnames = sorted({n for r in grp for n in r.names})
        w(f"    // {src.relpath}::{src.binding}")
        w(f"    ({rs_str(src.group)}, &[")
        for n in gnames:
            w(f"        {rs_str(n)},")
        w("    ]),")
    w("];")
    w("")

    # ---- helpers ---------------------------------------------------------
    w("/// Is `method` a method the real node dispatches?")
    w("///")
    w("/// The mock MUST consult this before answering anything, so that a method")
    w("/// the chain lacks can never be silently invented in a test.")
    w("#[must_use]")
    w("pub fn is_node_method(method: &str) -> bool {")
    w("    NODE_METHODS.binary_search(&method).is_ok()")
    w("}")
    w("")
    w("/// Resolve an alias to its primary name (identity for primaries).")
    w("#[must_use]")
    w("pub fn primary_name(method: &str) -> &str {")
    w("    NODE_METHOD_ALIASES")
    w("        .iter()")
    w("        .find(|(alias, _)| *alias == method)")
    w("        .map_or(method, |(_, primary)| *primary)")
    w("}")
    w("")
    w("#[cfg(test)]")
    w("mod generated_tests {")
    w("    use super::*;")
    w("")
    w("    #[test]")
    w("    fn methods_are_sorted_and_unique() {")
    w("        // `is_node_method` binary-searches; a regeneration that broke the")
    w("        // ordering would make lookups silently wrong.")
    w("        for pair in NODE_METHODS.windows(2) {")
    w("            assert!(pair[0] < pair[1], \"NODE_METHODS unsorted at {pair:?}\");")
    w("        }")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn plausible_method_count() {")
    w(f"        assert_eq!(NODE_METHODS.len(), {len(unique_names)});")
    w(f"        assert_eq!(NODE_METHOD_ALIASES.len(), {len(aliases)});")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn aliases_and_primaries_are_both_live() {")
    w("        for (alias, primary) in NODE_METHOD_ALIASES {")
    w("            assert!(is_node_method(alias), \"alias {alias} missing\");")
    w("            assert!(is_node_method(primary), \"primary {primary} missing\");")
    w("            assert_eq!(primary_name(alias), *primary);")
    w("        }")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn fiction_is_absent() {")
    w("        // These were in octra-mock-rpc and exist NOWHERE in the node.")
    w("        // Zero grep hits in lite_node @ SOURCE_COMMIT.")
    w("        for fake in [")
    w("            \"octra_isValidator\",")
    w("            \"octra_fheLoadPk\",")
    w("            \"octra_fheEncrypt\",")
    w("            \"octra_fheAdd\",")
    w("            \"octra_fheAddConst\",")
    w("            \"octra_fheVerifyZero\",")
    w("            \"octra_fheDecrypt\",")
    w("            \"octra_fheMakeZeroProof\",")
    w("        ] {")
    w("            assert!(!is_node_method(fake), \"{fake} is not a real node method\");")
    w("        }")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn method_not_found_matches_the_node() {")
    w("        assert_eq!(METHOD_NOT_FOUND_CODE, -32601);")
    w("        assert_eq!(")
    w("            method_not_found_message(\"octra_isValidator\"),")
    w("            \"method not found: octra_isValidator\"")
    w("        );")
    w("    }")
    w("}")
    w("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def upstream_commit(upstream: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(upstream), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise die(
            f"cannot read upstream git HEAD at {upstream}: {exc}. Pass "
            f"--source-commit explicitly if scraping a non-git checkout."
        ) from exc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--upstream", required=True, type=Path, help="lite_node checkout")
    ap.add_argument("--out", type=Path, help="path to write methods.rs")
    ap.add_argument("--source-commit", help="override the scraped git HEAD")
    ap.add_argument("--print", dest="do_print", action="store_true")
    ap.add_argument(
        "--accept-count-change",
        action="store_true",
        help="allow the total method count to differ from the pinned expectation",
    )
    ap.add_argument("--json", action="store_true", help="dump the scraped registry as JSON")
    args = ap.parse_args(argv)

    upstream: Path = args.upstream.expanduser().resolve()
    if not upstream.is_dir():
        print(f"rpc-scrape: not a directory: {upstream}", file=sys.stderr)
        return 2

    try:
        check_composition(upstream)
        routes = scrape_routes(upstream)
        errors = scrape_errors(upstream)
        commit = args.source_commit or upstream_commit(upstream)

        names = [n for r in routes for n in r.names]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise die(
                "duplicate method names across route groups (List.assoc_opt would "
                "shadow the later one): " + ", ".join(dupes)
            )
        primaries = {r.primary for r in routes}

        drift = []
        if len(names) != EXPECTED_TOTAL_NAMES:
            drift.append(f"total names {len(names)} != pinned {EXPECTED_TOTAL_NAMES}")
        if len(primaries) != EXPECTED_TOTAL_PRIMARIES:
            drift.append(
                f"primaries {len(primaries)} != pinned {EXPECTED_TOTAL_PRIMARIES}"
            )
        if drift and not args.accept_count_change:
            raise die(
                "UPSTREAM RPC SURFACE CHANGED: "
                + "; ".join(drift)
                + ".\nThis is a real API change, not a parse glitch (per-table floors "
                "all passed). Review the diff, then rerun with "
                "--accept-count-change and update EXPECTED_TOTAL_NAMES="
                f"{len(names)} / EXPECTED_TOTAL_PRIMARIES={len(primaries)} in this file."
            )
    except ScrapeError as exc:
        print(f"rpc-scrape: FAIL\n  {exc}", file=sys.stderr)
        return 1

    if args.json:
        import json

        print(
            json.dumps(
                {
                    "source_commit": commit,
                    "methods": sorted(set(names)),
                    "aliases": {a: r.primary for r in routes for a in r.aliases},
                    "groups": {
                        g: sorted({n for r in routes if r.group == g for n in r.names})
                        for g in {r.group for r in routes}
                    },
                    "errors": [
                        {"ident": e.ident, "code": e.code, "message": e.message}
                        for e in errors
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    desc = "octra-labs/lite_node (BSD-3-Clause)"
    rust = emit_rust(routes, errors, commit, desc)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rust, encoding="utf-8")
        print(
            f"rpc-scrape: wrote {args.out} — {len(set(names))} unique methods, "
            f"{len(names)} route entries, {len(errors)} error constants, "
            f"SOURCE_COMMIT={commit[:12]}",
            file=sys.stderr,
        )
    if args.do_print or not args.out:
        print(rust)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

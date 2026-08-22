# `rpc-scrape`

Derives the **real** Octra node JSON-RPC method registry from upstream OCaml
source and emits a committed Rust module,
`crates/octra-mock-rpc/src/methods.rs`.

## Why

`octra-mock-rpc` used to serve methods the chain does not have. Three of them
were pure invention (`octra_isValidator`, the seven `octra_fhe*` wrappers), and
a test that called them passed while proving nothing — against a real node the
same call returns:

```json
{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found: octra_isValidator"},"id":1}
```

(That is a real devnet response, captured in
`octra/docker/devnet/.generated/upstream-reality-probe/06-is-validator.json`.)

This tool makes the mock's method surface a **derived artifact** instead of an
opinion. A method the mock can answer is now either in the generated
`NODE_METHODS` table or explicitly declared a cheat in
`crates/octra-mock-rpc/src/cheats.rs`. There is no third option.

## Upstream sources

Everything is reachable from `node_rpc_server.ml::dispatch`, which concatenates
exactly twelve route groups. The tool asserts that composition, so a *new*
upstream group cannot slip past unnoticed.

| Group | File | Binding | Shape |
| --- | --- | --- | --- |
| `status_core` | `node_runtime/status_read_rpc.ml` | `core_dispatch` | assoc list |
| `account_public` | `node_runtime/account_read_rpc.ml` | `public_dispatch` | assoc list |
| `history` | `node_runtime/history_read_rpc.ml` | `dispatch` | assoc list |
| `rest` | `node_runtime/rest_read_rpc.ml` | `dispatch` | assoc list |
| `circle` | `node_runtime/rpc_dispatch.ml` | `circle_routes` | `route` / `route_aliases` DSL |
| `program` | `node_runtime/rpc_dispatch.ml` | `program_routes` | `route` / `route_aliases` DSL |
| `account_pvac` | `node_runtime/account_read_rpc.ml` | `pvac_dispatch` | assoc list |
| `status_proof` | `node_runtime/status_read_rpc.ml` | `proof_dispatch` | assoc list |
| `effect` | `node_runtime/rpc_effect_dispatch.ml` | `dispatch` | `route` DSL |
| `compute` | `node_runtime/node_rpc_server.ml` | `compute_dispatch` | assoc list |

Error constants come from `lib/core/rpc.ml`, region `let parse_error` ..
`let response_json`.

`route_aliases "primary" "alias" handler` registers **both** names against one
handler, so both are live methods. Hence 136 primaries but 212 dispatchable
names.

## The loud-failure contract

Regex-parsing OCaml is only acceptable if the parser cannot fail quietly. Every
one of these exits non-zero with a diagnostic naming the file and the offending
line — verified by mutating a scratch copy of upstream:

| Mutation | Result |
| --- | --- |
| a `route_aliases` line loses its alias string | `rpc_dispatch.ml::circle_routes:+3: line mentions route_aliases but does not parse` |
| an assoc entry loses its `"name",` head | `status_read_rpc.ml::core_dispatch: assoc-list entry #0 does not start with a "method_name"` |
| a whole table becomes `[]` | `rest_read_rpc.ml::dispatch: extracted 0 routes but expected at least 9` |
| a binding is renamed upstream | `no top-level 'let core_dispatch' found` |
| a new group appears in the composition | `composes route groups this tool does not scrape: shiny_new_dispatch` |
| the node gains/loses a method | `UPSTREAM RPC SURFACE CHANGED: total names 213 != pinned 212` |
| an error constant stops parsing | `rpc.ml:+10: 'let' inside the error-constant region does not parse as an rpc_error` |
| a source file disappears | `missing upstream file: .../history_read_rpc.ml` |

The count pin is the important one. Per-table floors catch parser regressions;
the pinned total catches *real* upstream API drift, which is a thing a human
should look at rather than silently absorb. Re-run with
`--accept-count-change` once you have reviewed the diff, then update
`EXPECTED_TOTAL_NAMES` / `EXPECTED_TOTAL_PRIMARIES` in `rpc_scrape.py`.

## Usage

The generated file is **committed**. This tool is not part of the build; run it
when `docker/octra-node/Dockerfile`'s `SOURCE_COMMIT` moves.

```sh
# regenerate
python3 tools/rpc-scrape/rpc_scrape.py \
    --upstream /path/to/lite_node \
    --out crates/octra-mock-rpc/src/methods.rs

# inspect without writing
python3 tools/rpc-scrape/rpc_scrape.py --upstream /path/to/lite_node --json

# after a reviewed upstream API change
python3 tools/rpc-scrape/rpc_scrape.py --upstream ... --out ... --accept-count-change
```

No dependencies beyond CPython 3.9+. `--source-commit` overrides the scraped
git HEAD for non-git checkouts.

## Keeping the pin honest

`methods::SOURCE_COMMIT` must equal the `SOURCE_COMMIT` arg in
`docker/octra-node/Dockerfile`. Upstream ships mandatory epoch-gated releases
weekly, so this pin is perishable by design — bumping the node image and
forgetting to re-scrape is exactly the drift this tool exists to surface.

Current pin: `dd342e754c91df55a41b515c510369d637af2385`
(212 dispatchable names, 136 primaries, 76 aliases, 20 error constants).

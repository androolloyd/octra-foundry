# octra-foundry

Foundry-style testing toolkit for Octra dApps.

## Crates

- **`octraforge`** — the Forge equivalent. Cheatcodes (`prank`, `deal`,
  `roll`, `warp`), expectations, snapshot harnesses, AML coverage,
  invariant checking, and a proptest-backed fuzz runner. The
  `octraforge::octravpn` module is a reference dApp-helpers template:
  consumers should mirror its shape for their own dApps rather than
  treat it as boilerplate to strip.
- **`octra-mock-rpc`** — the Anvil equivalent. An in-process mock of
  the Octra JSON-RPC surface: tx submission, contract state, events,
  and view-method dispatch. Driven directly from tests through
  `octraforge`, or run as a standalone HTTP server for client-side
  integration tests.

- **`octra-devkeys`** — ten fixed, deterministic ed25519 dev accounts,
  anvil-style. The seeds are published in the source: these keys are
  PUBLIC and must never hold real funds. Emits `wallets.toml`, the
  node's `OCTRA_VALIDATORS` string, and per-account `wallet.json`
  bodies via `cargo run -p octra-devkeys -- <wallets-toml |
  validators-env | wallet-json <i>>`.

## Local node

`docker/octra-node/` builds the real `octra-labs/lite_node` from
source (pinned by `SOURCE_COMMIT`; upstream ships no binaries) and
runs a single node in Single mode: no peers, an epoch every 10s, and
a genesis that mints 10M OCT to each of the ten `octra-devkeys`
accounts. This is the foundation for `octra anvil` fronting a real
node instead of the mock RPC (CLI wiring is not hooked up yet).

```sh
docker compose -f docker/octra-node/docker-compose.yml up --build -d
# RPC (JSON-RPC POST) once healthy:
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"octra_runtimeVersion","params":[]}' \
  http://127.0.0.1:18080/rpc
```

The first build compiles OCaml 4.14.2 plus the 115 locked opam deps —
roughly 15 minutes on an M-series laptop, up to an hour on slower
machines; config-only changes reuse those layers. The chain id is
`octra-foundry-local` and the RPC binds loopback only — the dev keys
are public, so this stack must never be pointed at a real network.

## Usage

```sh
cargo build --workspace
cargo test  --workspace
```

## Status

Pre-1.0. The cheatcode and assertion surface is still evolving in
lockstep with the reference OctraVPN dApp tests.

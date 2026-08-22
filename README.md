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
  the Octra JSON-RPC surface. `octra_submit` **stages**; application
  happens at an epoch boundary (in-process via `advance_epoch`, over
  HTTP on a 10s timer / `OCTRA_MOCK_EPOCH_MS`). Method names are a
  derived artifact of `octra-labs/lite_node` (`tools/rpc-scrape`);
  methods the node does not have (`octra_isValidator`, `octra_fhe*`)
  return `-32601`. Mock-only backdoors live under `octra_test_*` and
  are labelled cheats.

- **`octra-chain-backend`** — one `ChainBackend` trait over three
  test tiers: in-process mock, a real containerized lite node, and a
  node booted on forked devnet state. Submit returns a staged hash
  with no status field; confirmation is a blanket `ConfirmExt` that
  waits by advancing epochs. Money-path suites must not have the mock
  as their only coverage (`OCTRA_TEST_TIER=node` / `OCTRA_TEST_STRICT=1`).

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

The image is pinned to lite_node `dd342e754c91df55a41b515c510369d637af2385`
(devnet release sequence 2). Sequence 4 (`f3b6d58`, 2026-08-22) did not
change the RPC surface (still 212 names), the signing preimage, or
`runtime_profile_hash`, so this pin is still a valid Single-mode VM.
Bump `SOURCE_COMMIT` in the Dockerfile and re-run `tools/rpc-scrape`
when a release actually moves the RPC or the runtime profile.

## Usage

```sh
cargo build --workspace
cargo test  --workspace
```

## Status

Pre-1.0. The cheatcode and assertion surface is still evolving in
lockstep with the reference OctraVPN dApp tests.

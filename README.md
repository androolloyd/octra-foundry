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
`octra-local-foundry` and the RPC binds loopback only — the dev keys
are public, so this stack must never be pointed at a real network.

The image and generated RPC registry pin lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50` (214 names, 138 primaries and
76 aliases). The private startup opt-in and canonical staging-order regression
are documented in [`LOCAL_TEST_MODE.md`](docker/octra-node/LOCAL_TEST_MODE.md).
This local fixture does not qualify a public chain's activated execution profile.
When updating the node pin, regenerate the registry with `tools/rpc-scrape`
and rerun the native startup, staging and backend tests.

## Usage

```sh
cargo build --workspace
cargo test  --workspace
```

## AML and native signing

Set `AMLC` to the pinned real compiler. `octra forge test --root test`
executes zero-argument `test_*` AML methods in isolated VM state; add
`--contract program.aml` to append test fragments to the production source.
`// expect-revert test_name "reason"` requires that exact VM revert.
False boolean results, compiler failures, and empty selections fail the run.
Rust tests remain available through `forge test --package <crate>`.

Local builds use the real compiler; `--mock` is required for synthetic artifacts.
RPC compilation fails closed. Deployment waits require a successful receipt and
an actual program address; `--no-wait` reports an unconfirmed prediction.
Wallet commands use `octra_core::native_tx`, also re-exported by the chain adapter.
The older `tx` signing domain remains available for explicit model fixtures.
Traffic settlement in the VPN mock pays the operator in full with zero commission.

## Status

Pre-1.0. The cheatcode and assertion surface is still evolving in
lockstep with the reference OctraVPN dApp tests.

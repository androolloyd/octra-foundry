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

## Usage

```sh
cargo build --workspace
cargo test  --workspace
```

## Status

Pre-1.0. The cheatcode and assertion surface is still evolving in
lockstep with the reference OctraVPN dApp tests.

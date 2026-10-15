# Isolated native test mode

The image pins upstream `7f9be4489870645cfcc95439638cde40f5da9f50`.
`patches/local-test-mode.py` changes only node startup and the P2P service
launcher. It does not edit the consensus engine, rule graph, VM or epoch rules.

Opt in with `OCTRA_LOCAL_TEST_MODE=1`, an `octra-local-*` chain ID, Single mode,
consensus port zero, no `OCTRA_PEERS`, and an empty `nodes.config`. Observer and
publisher flags (`--state-sync-publisher`, plus defensive `--publisher`) are refused.
The final resolved role must have consensus disabled, including recovery-role
promotion from a persisted sync marker.
The legacy P2P listener is disabled. Leave the HTTP port bound to host loopback,
as the compose file does. These genesis keys are public and must never hold
external funds. The mode is disabled by default; live-chain startup gates remain.

A private chain uses upstream's unchanged prior execution profile. Tests here do
not certify a public chain's activated profile. Record the runtime profile and
rerun the candidate under the selected target rules before any real signing.

Build with `docker compose build` from this directory. A test maturity method is
appended only by the VPN money harness, never by this node patch. It exercises
the real finalization body after seeding elapsed grace, without changing time or
consensus. The harness contract must never be treated as a deployment artifact.

## Reproduced upstream staging-order bug

Single-mode selection passed staging insertion order into the outcome validator,
which requires canonical transaction order. Two independent senders submitted
in reverse canonical order caused `outcome_order_invalid`, terminated the epoch
loop and discarded staged work on restart. `patches/staging-order.py` sorts this
one input with upstream's existing `Transaction.consensus_order` before strict
validation. It changes neither the comparator nor BFT/override validation.

The image build executes `test_local_staging_order.ml` before the patch and
requires that the reversed-sender assertion fail, then applies the patch and
requires the same test to pass. The test also checks that unsorted overrides,
missing BFT finalization and duplicate outcomes remain rejected. This is the
consensus-adjacent bug exception authorized for this test setup; no new consensus
features or activation rules were introduced.

The image build also runs `patches/test_local_startup.py` with its network
disabled and an explicit `--isolated-network-namespace` test opt-in. The test
refuses an external IPv4 default route; it supports BuildKit, which omits the
`/.dockerenv` marker. It checks eleven real startup refusals, including the actual
`--state-sync-publisher` flag and recovery-role promotion, before wallet or HEAD
creation, then requires a fresh private node to answer its local RPC.

#!/bin/sh
# Entrypoint for the local octra-node container.
#
# Two jobs before exec'ing the node, both about determinism:
#
#  1. Make sure the data dir exists. Without it the node fatals unless
#     run with --init, and --init gates nothing else (upstream
#     startup_process_shell.ml:107-116, octra_node.ml:98,121), so a
#     mkdir here replaces the flag entirely and stays idempotent
#     across restarts of a compose named volume.
#
#  2. The node auto-generates a RANDOM wallet.json on first boot
#     (Wallet.ensure, lib/core/crypto.ml). For a throwaway dev chain we
#     want the node's own identity to be a well-known devkey instead,
#     so if OCTRA_DEV_WALLET_JSON is set we write it first. The value
#     comes from `cargo run -p octra-devkeys -- wallet-json 0` and is
#     public by design — never reuse this container setup outside a
#     private chain.
set -eu

DATA_DIR=${OCTRA_DATA_DIR:-data}

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ -n "${OCTRA_DEV_WALLET_JSON:-}" ] && [ ! -f "$DATA_DIR/wallet.json" ]; then
  umask 077
  printf '%s\n' "$OCTRA_DEV_WALLET_JSON" > "$DATA_DIR/wallet.json"
fi

exec /usr/local/bin/octra_node.exe "$@"

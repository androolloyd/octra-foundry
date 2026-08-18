# syntax=docker/dockerfile:1
#
# A real Octra lite node (octra-labs/lite_node) as a container image,
# for `octra anvil`'s local-chain mode. Upstream publishes no release
# binaries (every GitHub release has an empty asset list), so this is
# a source build, pinned to SOURCE_COMMIT for reproducibility.
#
# We deliberately do NOT run upstream's controls/install.sh here: it
# assumes sudo, systemd/pm2, an "octra" operator user, and absolute
# paths under /opt/octra + /var/lib/octra. The node binary itself is
# 12-factor (env-configured, relative data dir — see upstream
# startup_process_shell.ml), so all we take from install.sh is its
# package lists (line ~151 runtime, ~154 source-build).
#
# Layering: the opam dependency solve/build is the 35-55 minute layer.
# It depends only on the two opam metadata files, so iterating on the
# entrypoint, compose config, or even bumping SOURCE_COMMIT without a
# lockfile change reuses it from cache.

# NOTE: this is a GIT sha of octra-labs/lite_node. It is NOT the value
# of the in-tree SOURCE_COMMIT file — that file is upstream's release
# marker and does not resolve as a git ref.
ARG SOURCE_COMMIT=dd342e754c91df55a41b515c510369d637af2385

# --- source: pin the upstream tree ------------------------------------
# A separate minimal stage so the (cheap) clone re-runs on commit bumps
# while the builder's COPY steps stay content-addressed: the expensive
# opam layer below only invalidates if the opam files actually changed.
FROM debian:bookworm-slim AS source
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
ARG SOURCE_COMMIT
RUN git clone https://github.com/octra-labs/lite_node.git /src \
 && git -C /src checkout --detach "$SOURCE_COMMIT" \
 && git -C /src log -1 --format='pinned %H %cI %s'

# --- builder: OCaml 4.14.2 + Rust 1.80.1 + vendored mcl ---------------
# ocaml/opam's debian-12 image gives us opam 2.x, but its prebuilt
# "4.14" switch is 4.14.4 — upstream pins 4.14.2 exactly and its
# install.sh refuses a mismatch (controls/install.sh:9,129-135), so we
# build the exact compiler in its own cached layer. The guard below
# mirrors that refusal.
FROM ocaml/opam:debian-12-ocaml-4.14 AS builder

# Source-build system deps, from controls/install.sh:154 (minus opam,
# which the base image provides, and minus the pm2/systemd half).
# python3 is from the base list at :151 — mcl's Makefile shells out to
# it for src/gen_bint_header.py.
RUN sudo apt-get update \
 && sudo apt-get install -y --no-install-recommends \
      build-essential clang curl libev-dev libgmp-dev liblmdb-dev \
      libsqlite3-dev m4 pkg-config python3 \
 && sudo rm -rf /var/lib/apt/lists/*

RUN opam update \
 && opam switch create 4.14.2 --yes
# Pin the switch by env so every later RUN uses it regardless of what
# the base image's shell profile selects.
ENV OPAMSWITCH=4.14.2
RUN test "$(opam exec -- ocamlc -version)" = "4.14.2"

# Rust toolchain pinned to upstream's tested version
# (controls/install.sh:10). dune drives cargo itself for the
# liboctra_circle_wasm_host staticlib (lib/core/dune), so cargo just
# has to be on PATH.
ENV RUSTUP_HOME=/home/opam/.rustup \
    CARGO_HOME=/home/opam/.cargo
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.80.1
ENV PATH=/home/opam/.cargo/bin:$PATH

WORKDIR /home/opam/build

# The long layer: solve + build the 115 locked opam deps against the
# lockfile only. Nothing else from the tree is visible here, so config
# iterations never re-run this.
COPY --from=source --chown=opam:opam /src/octra_node.opam /src/octra_node.opam.locked ./
RUN opam update \
 && opam install . --deps-only --locked --require-checksums --yes

# Full pinned tree, then the vendored mcl staticlib (256-bit curve
# profile, exactly as the README's manual-update path builds it) and
# the two binaries the runtime needs. octra_pvac_worker.exe is not
# optional: the node refuses to start without it as a sibling
# (bin/octra_node.ml:87-95, lib/core/pvac_verify_worker.ml:85-93).
COPY --from=source --chown=opam:opam /src/ ./
# mcl's Makefile assumes obj/ and lib/ already exist; upstream's config
# tooling pre-creates them (controls/lib/validator_config.py:426-427),
# so mirror that here.
RUN mkdir -p mcl/obj mcl/lib \
 && make -C mcl MCL_FP_BIT=256 MCL_FR_BIT=256 -j"$(nproc)" lib/libmcl.a
RUN opam exec -- dune build --profile release \
      bin/octra_node.exe \
      bin/octra_pvac_worker.exe

# --- runtime: debian-slim + the four shared libs ----------------------
# Runtime lib list from controls/install.sh:151 (ca-certificates for
# outbound TLS, curl for the compose healthcheck; nodejs/npm/pm2 and
# python3 are host-orchestration tools we replace with compose).
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl libev4 libgmp10 liblmdb0 libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*

# Both binaries in one directory: the node resolves the pvac worker as
# a sibling of Sys.executable_name.
COPY --from=builder /home/opam/build/_build/default/bin/octra_node.exe /usr/local/bin/octra_node.exe
COPY --from=builder /home/opam/build/_build/default/bin/octra_pvac_worker.exe /usr/local/bin/octra_pvac_worker.exe
COPY entrypoint.sh /usr/local/bin/octra-node-entrypoint

# Pre-create the data dir owned by the node user: a compose named
# volume copies ownership from the image on first mount, so without
# this it appears root-owned and the (non-root) node cannot write it.
RUN useradd --system --create-home --home-dir /octra --shell /usr/sbin/nologin octra \
 && install -d -m 0700 -o octra -g octra /octra/data \
 && chmod 0755 /usr/local/bin/octra-node-entrypoint
# The node unconditionally reads ./nodes.config from its cwd mid-boot
# (bin/octra_node.ml:515) and dies without it — worse, dying there is
# AFTER the store root is written, which wedges the data volume with
# "HEAD.json is missing". Ship the upstream default: an empty peer list.
RUN printf '[]\n' > /octra/nodes.config && chown octra:octra /octra/nodes.config
USER octra
WORKDIR /octra

# Leave OCTRA_CONSENSUS_MODE unset: that selects the Single role
# (lib/consensus/c_role.ml:12-22) — no peers, no quorum, an epoch
# applied from staged txs every 10s. Everything else is compose-level.
ENV OCTRA_DATA_DIR=/octra/data
EXPOSE 8080 9000 19000

# Run under an init process (`docker run --init` / compose `init: true`).
# The pvac worker self-SIGKILLs when its parent is PID 1 (orphan guard
# in pvac_ffi/pvac_stubs.cpp), so the node itself must never be PID 1.
ENTRYPOINT ["octra-node-entrypoint"]

//! Tier 2/3 — a real Octra lite node over JSON-RPC.
//!
//! One HTTP client, pointed at a node's `/rpc` (the only route,
//! `rpc_http.ml:90-95`). Tier 2 points it at
//! `docker/octra-node/docker-compose.yml`'s local Single-mode chain;
//! tier 3 points it at a node booted on imported devnet state. The wire
//! protocol is identical, so there is one implementation.
//!
//! # What "real" costs, and why it is worth it
//!
//! The node's epoch interval is a hardcoded `interval_ms = 10_000L`
//! (`epoch_time.ml:10-11`). There is no faucet, no instant-mine, and no
//! `octra_test_*` namespace anywhere in `rpc_dispatch.ml` — verified
//! live: `octra_test_grantValidator` →
//! `{"code":-32601,"message":"method not found: octra_test_grantValidator"}`.
//! So [`ChainBackend::advance_epochs`] here really does wait. In exchange
//! this tier runs the actual VM on the actual AML, which the mock cannot
//! do at any speed.
//!
//! # Signing
//!
//! Through [`crate::canonical_tx`], the byte-exact port of
//! `serialize_for_signing` (`transaction.ml:309-326`). That module is a
//! deliberate mirror of `octravpn-core/src/tx_signer.rs` rather than a
//! dependency on it — `octravpn-core` already depends on this workspace
//! by path, so the reverse edge would make the two repositories mutually
//! dependent; see the header of `canonical_tx.rs` for the full argument
//! and for the anti-drift test that pins the mirror.
//!
//! # Transient errors
//!
//! `-32012` (committed state changed during a stable read,
//! `node_rpc_server.ml:440-444`) and `-32005` (single-flight busy) are
//! the node telling the client to retry. Every call here retries them
//! with backoff. Clients that had never seen `-32012` are one of the
//! documented ways our tests were passing against fiction.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::{
    backend::{Account, ChainBackend, Receipt, Staged, TxStatus, ViewResult},
    error::{codes, BackendError, BackendResult},
    tier::Tier,
};

/// Where tier 2 lives by default — the host port
/// `docker/octra-node/docker-compose.yml` publishes.
pub const DEFAULT_NODE_RPC: &str = "http://127.0.0.1:18080/rpc";

/// Environment override for the tier-2 endpoint.
pub const NODE_RPC_ENV: &str = "OCTRA_NODE_RPC";

/// Environment override for the tier-3 (fork) endpoint. A fork is a
/// second node process on its own port, so it never shares a data dir
/// with the tier-2 chain.
pub const FORK_RPC_ENV: &str = "OCTRA_FORK_RPC";

/// Where a forked node lives by default.
pub const DEFAULT_FORK_RPC: &str = "http://127.0.0.1:18081/rpc";

/// The epoch interval, hardcoded upstream (`epoch_time.ml:10-11`).
/// Not configurable — this is why the node can never be the fast tier.
pub const EPOCH_INTERVAL: Duration = Duration::from_secs(10);

const MAX_TRANSIENT_RETRIES: usize = 4;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const EPOCH_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// A real node, at a URL.
pub struct NodeBackend {
    endpoint: String,
    tier: Tier,
    http: reqwest::Client,
}

impl NodeBackend {
    /// Tier 2: the local containerized node.
    pub fn node(endpoint: impl Into<String>) -> BackendResult<Self> {
        Self::with_tier(endpoint, Tier::Node)
    }

    /// Tier 3: a node booted on imported devnet state. Same wire
    /// protocol; the difference is what is in the ledger.
    pub fn fork(endpoint: impl Into<String>) -> BackendResult<Self> {
        Self::with_tier(endpoint, Tier::Fork)
    }

    fn with_tier(endpoint: impl Into<String>, tier: Tier) -> BackendResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        Ok(Self {
            endpoint: endpoint.into(),
            tier,
            http,
        })
    }

    /// Tier-2 endpoint from `OCTRA_NODE_RPC`, else [`DEFAULT_NODE_RPC`].
    #[must_use]
    pub fn endpoint_from_env(tier: Tier) -> String {
        let (var, default) = match tier {
            Tier::Fork => (FORK_RPC_ENV, DEFAULT_FORK_RPC),
            Tier::Mock | Tier::Node => (NODE_RPC_ENV, DEFAULT_NODE_RPC),
        };
        std::env::var(var)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| default.to_string())
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// One JSON-RPC round trip, retrying the node's own "retry me" codes.
    pub async fn call(&self, method: &str, params: Value) -> BackendResult<Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let mut attempt = 0usize;
        loop {
            let err = match self.call_once(method, &body).await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            attempt += 1;
            if !err.is_transient() || attempt > MAX_TRANSIENT_RETRIES {
                return Err(err);
            }
            // 100ms, 200ms, 400ms, 800ms.
            tokio::time::sleep(Duration::from_millis(100 << (attempt - 1))).await;
        }
    }

    async fn call_once(&self, method: &str, body: &Value) -> BackendResult<Value> {
        let resp = self
            .http
            .post(&self.endpoint)
            .json(body)
            .send()
            .await
            .map_err(|e| BackendError::Transport(format!("{method}: {e}")))?;
        let doc: Value = resp
            .json()
            .await
            .map_err(|e| BackendError::Transport(format!("{method}: reading body: {e}")))?;
        if let Some(err) = doc.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let mut message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            // The node puts the useful part in `data` — "invalid hash
            // format for hash", "Malformed JSON: missing or invalid
            // fields". Dropping it is how a debugging session becomes an
            // afternoon.
            if let Some(data) = err.get("data").and_then(Value::as_str) {
                message.push_str(" [");
                message.push_str(data);
                message.push(']');
            }
            return Err(BackendError::Rpc {
                method: method.to_string(),
                code,
                message,
            });
        }
        doc.get("result")
            .cloned()
            .ok_or_else(|| BackendError::Decode {
                what: method.to_string(),
                detail: "response carried neither `result` nor `error`".into(),
            })
    }

    /// Cheap liveness probe. Used by the harness to decide whether to
    /// skip rather than fail.
    pub async fn is_reachable(&self) -> bool {
        self.call("octra_runtimeVersion", json!([])).await.is_ok()
    }

    /// The node's `chain_id` (`octra_runtimeVersion`). Worth asserting in
    /// tier 3: the whole point of a fork is that it carries devnet's
    /// chain id, not the local private one.
    pub async fn chain_id(&self) -> BackendResult<String> {
        let v = self.call("octra_runtimeVersion", json!([])).await?;
        v.get("chain_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| BackendError::Decode {
                what: "octra_runtimeVersion".into(),
                detail: "no chain_id".into(),
            })
    }
}

/// The node renders integers as decimal strings on the wire
/// (`balance_raw`, `recommended`, …). Accept a bare number too, so a
/// future node that stops quoting them does not break the client.
fn wire_u64(v: Option<&Value>, what: &str) -> BackendResult<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| BackendError::Decode {
            what: what.to_string(),
            detail: format!("not a u64: {n}"),
        }),
        Some(Value::String(s)) => s.parse().map_err(|e| BackendError::Decode {
            what: what.to_string(),
            detail: format!("{s:?}: {e}"),
        }),
        other => Err(BackendError::Decode {
            what: what.to_string(),
            detail: format!("missing or wrong type: {other:?}"),
        }),
    }
}

#[async_trait]
impl ChainBackend for NodeBackend {
    fn tier(&self) -> Tier {
        self.tier
    }

    fn describe(&self) -> String {
        format!("{} node at {}", self.tier, self.endpoint)
    }

    async fn epoch(&self) -> BackendResult<u64> {
        let v = self.call("node_status", json!([])).await?;
        // Live shape: {"epoch":2569,"current_epoch":2569,"head_epoch":2568,
        //  "validator":…,"state_root":…,"network_version":"v3.0.0-irmin",…}
        v.get("epoch")
            .or_else(|| v.get("current_epoch"))
            .and_then(Value::as_u64)
            .ok_or_else(|| BackendError::Decode {
                what: "node_status".into(),
                detail: "no epoch".into(),
            })
    }

    async fn account(&self, address: &str) -> BackendResult<Account> {
        let v = self.call("octra_balance", json!([address])).await?;
        // Live shape: {"address","balance","balance_raw","nonce",
        //  "pending_nonce","has_public_key"}. Note `balance_raw`, not the
        //  mock's `raw`, and no invented balance for unknown accounts —
        //  a malformed address is code 109, not a default.
        let nonce = wire_u64(v.get("nonce"), "octra_balance.nonce")?;
        Ok(Account {
            address: address.to_string(),
            balance_raw: wire_u64(v.get("balance_raw"), "octra_balance.balance_raw")?,
            nonce,
            pending_nonce: wire_u64(v.get("pending_nonce"), "octra_balance.pending_nonce")
                .unwrap_or(nonce),
        })
    }

    async fn recommended_fee(&self) -> BackendResult<u64> {
        let v = self.call("octra_recommendedFee", json!(["call"])).await?;
        // Live shape: {"minimum":"1000","base_fee":"1000",
        //  "recommended":"1000","fast":"2000",…}
        wire_u64(v.get("recommended"), "octra_recommendedFee.recommended")
    }

    async fn submit(&self, signed_tx: &Value) -> BackendResult<Staged> {
        let v = self.call("octra_submit", json!([signed_tx])).await?;
        // The node answers {tx_hash, status:"accepted", nonce, ou_cost}
        // (rpc_view.ml:706-712). `status` is READ AND DISCARDED on
        // purpose: "accepted" is a statement about staging, and letting
        // it reach the caller is how the mock's "confirmed" taught a
        // generation of our clients to read state too early.
        let hash = v
            .get("tx_hash")
            .or_else(|| v.get("hash"))
            .and_then(Value::as_str)
            .ok_or_else(|| BackendError::Decode {
                what: "octra_submit".into(),
                detail: format!("no tx_hash in {v}"),
            })?
            .to_string();
        Ok(Staged::new(hash, wire_u64(v.get("nonce"), "nonce").ok()))
    }

    async fn transaction(&self, hash: &str) -> BackendResult<TxStatus> {
        self.call("octra_transaction", json!([hash]))
            .await
            .map(|v| TxStatus::from_json(&v))
    }

    async fn contract_receipt(&self, hash: &str) -> BackendResult<Option<Receipt>> {
        match self.call("contract_receipt", json!([hash])).await {
            Ok(v) if v.is_null() => Ok(None),
            Ok(v) => Ok(Some(Receipt::from_json(v))),
            // Ops with no execution receipt legitimately answer "not
            // found" — a plain transfer has none. That is an absence,
            // not a failure.
            Err(e) if e.rpc_code() == Some(codes::NOT_FOUND) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn contract_call(
        &self,
        contract: &str,
        method: &str,
        params: &[Value],
    ) -> BackendResult<ViewResult> {
        let v = self
            .call("contract_call", json!([contract, method, params, null]))
            .await?;
        // Live shape: {"result":"0","storage":{"blob":"0","pokes":"0"}}.
        Ok(ViewResult::from_json(v))
    }

    async fn advance_epochs(&self, n: u64) -> BackendResult<u64> {
        if n == 0 {
            return self.epoch().await;
        }
        let start = self.epoch().await?;
        let target = start.saturating_add(n);
        // No RPC can hurry a real node, so this is a wait. Budget three
        // intervals per epoch plus a floor: a Single-mode node applies on
        // a 10s tick, but a first-boot or a busy store can be late.
        let budget = EPOCH_INTERVAL
            .saturating_mul(u32::try_from(n).unwrap_or(u32::MAX))
            .saturating_mul(3)
            + Duration::from_secs(15);
        let started = Instant::now();
        loop {
            tokio::time::sleep(EPOCH_POLL_INTERVAL).await;
            match self.epoch().await {
                Ok(now) if now >= target => return Ok(now),
                // Transient read failures must not abort a wait; the
                // deadline below is the real bound.
                Ok(_) | Err(_) => {}
            }
            if started.elapsed() >= budget {
                return Err(BackendError::Transport(format!(
                    "{} did not reach epoch {target} (started at {start}) within {}s; \
                     the node's epoch interval is a hardcoded 10s — is the container running?",
                    self.endpoint,
                    budget.as_secs()
                )));
            }
        }
    }

    // `as_mock` is deliberately NOT overridden: the default
    // implementation raises `BackendError::MockOnly`, naming the cheat
    // and this tier. It could not be overridden usefully anyway — it
    // must produce a `&MockBackend`, and a node has none to give.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_defaults_are_per_tier() {
        // Read without mutating the process environment: these tests run
        // in parallel with everything else in the crate.
        if std::env::var(NODE_RPC_ENV).is_err() {
            assert_eq!(NodeBackend::endpoint_from_env(Tier::Node), DEFAULT_NODE_RPC);
        }
        if std::env::var(FORK_RPC_ENV).is_err() {
            assert_eq!(NodeBackend::endpoint_from_env(Tier::Fork), DEFAULT_FORK_RPC);
        }
    }

    #[test]
    fn wire_u64_accepts_the_node_string_encoding_and_bare_ints() {
        assert_eq!(
            wire_u64(Some(&json!("10000001500000")), "x").unwrap(),
            10_000_001_500_000
        );
        assert_eq!(wire_u64(Some(&json!(7)), "x").unwrap(), 7);
        assert!(wire_u64(None, "x").is_err());
        assert!(wire_u64(Some(&json!("abc")), "x").is_err());
    }

    /// The runtime half of the split, on the tier it is meant to fire on.
    #[tokio::test]
    async fn as_mock_is_a_loud_failure_on_a_node() {
        let b = NodeBackend::node("http://127.0.0.1:1/rpc").unwrap();
        let err = b.as_mock("deal").unwrap_err();
        assert!(matches!(err, BackendError::MockOnly { .. }));
        let msg = err.to_string();
        assert!(msg.contains("deal"), "{msg}");
        assert!(msg.contains("node"), "{msg}");
        // It must also say what to do instead.
        assert!(msg.contains("devkeys"), "{msg}");
    }

    #[tokio::test]
    async fn an_absent_node_is_a_transport_error_not_a_hang() {
        let b = NodeBackend::node("http://127.0.0.1:1/rpc").unwrap();
        assert!(!b.is_reachable().await);
        let err = b.epoch().await.unwrap_err();
        assert!(matches!(err, BackendError::Transport(_)), "{err}");
    }
}

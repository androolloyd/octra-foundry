//! Picking a backend for a test — and skipping, loudly, when the tier's
//! chain is not there.
//!
//! Two failure modes to avoid, pulling in opposite directions:
//!
//!   * `cargo test` on a laptop with no docker must still run. A tier-2
//!     suite that hard-fails because nothing is listening on 18080 makes
//!     the whole workspace un-testable and teaches people to ignore red.
//!   * A skip that nobody reads is worse than a failure. Silently
//!     skipping the only real-chain coverage of the money path is exactly
//!     how four money-path bugs reached devnet.
//!
//! So: a skip always prints what was missing and how to fix it, and
//! `OCTRA_TEST_STRICT=1` turns every skip into a failure. CI sets that;
//! a laptop does not.
//!
//! Tier selection itself is [`Tier::from_env`] — `OCTRA_TEST_TIER`, with
//! an unknown value a hard error rather than a quiet downgrade to the
//! mock.

use crate::{
    backend::ChainBackend,
    mock::MockBackend,
    node::{NodeBackend, DEFAULT_NODE_RPC},
    tier::{Tier, TIER_ENV},
};

/// Set to `1`/`true` to make every skip a failure. For CI, where an
/// unreachable node is a broken job rather than a missing laptop.
pub const STRICT_ENV: &str = "OCTRA_TEST_STRICT";

/// Default program address for a tier-1 chain, matching the octraforge
/// convention.
pub const DEFAULT_PROGRAM_ADDR: &str = "octPROG";

/// The outcome of asking for a backend.
pub enum Harness {
    /// A live backend at the requested tier.
    Ready(Box<dyn ChainBackend>),
    /// No backend. `reason` is written for a human reading test output.
    Skip(String),
}

impl Harness {
    /// Unwrap for a test that has already decided a skip is acceptable.
    ///
    /// Returns `None` after printing the reason. Under [`STRICT_ENV`] it
    /// panics instead, so CI cannot go green on an absent chain.
    #[must_use]
    pub fn or_skip(self, test_name: &str) -> Option<Box<dyn ChainBackend>> {
        match self {
            Self::Ready(b) => Some(b),
            Self::Skip(reason) => {
                assert!(
                    !strict(),
                    "{test_name}: {reason}\n\
                     ({STRICT_ENV} is set, so this skip is a failure.)"
                );
                eprintln!("SKIP {test_name}: {reason}");
                None
            }
        }
    }
}

fn strict() -> bool {
    matches!(
        std::env::var(STRICT_ENV).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes")
    )
}

/// A backend for the tier `OCTRA_TEST_TIER` names.
///
/// # Errors
///
/// Only for a malformed `OCTRA_TEST_TIER`. An unreachable node is a
/// [`Harness::Skip`], not an error — that distinction is the whole point.
pub async fn backend_from_env() -> Result<Harness, String> {
    Ok(backend_for_tier(Tier::from_env()?).await)
}

/// A backend for an explicitly chosen tier.
pub async fn backend_for_tier(tier: Tier) -> Harness {
    match tier {
        Tier::Mock => Harness::Ready(Box::new(MockBackend::new(DEFAULT_PROGRAM_ADDR))),
        Tier::Node | Tier::Fork => {
            let endpoint = NodeBackend::endpoint_from_env(tier);
            let built = if tier == Tier::Fork {
                NodeBackend::fork(endpoint.clone())
            } else {
                NodeBackend::node(endpoint.clone())
            };
            let backend = match built {
                Ok(b) => b,
                Err(e) => return Harness::Skip(format!("could not build an HTTP client: {e}")),
            };
            if backend.is_reachable().await {
                Harness::Ready(Box::new(backend))
            } else {
                Harness::Skip(unreachable_advice(tier, &endpoint))
            }
        }
    }
}

fn unreachable_advice(tier: Tier, endpoint: &str) -> String {
    if tier == Tier::Fork {
        format!(
            "no forked node answering at {endpoint} ({TIER_ENV}=fork). A fork is a node \
             booted on an imported devnet state dump; bring one up and point OCTRA_FORK_RPC \
             at it, or run with {TIER_ENV}=node."
        )
    } else {
        format!(
            "no octra node answering at {endpoint} ({TIER_ENV}={tier}). Start one with:\n  \
             cd octra-foundry/docker/octra-node && docker compose -p octra-local-node up -d\n  \
             (RPC lands on {DEFAULT_NODE_RPC}; first boot replays genesis, allow ~30s.)\n  \
             Override the endpoint with OCTRA_NODE_RPC."
        )
    }
}

/// Assert that the active tier may serve as a money-shaped test's only
/// coverage, and skip loudly if it may not.
///
/// **The policy: nothing money-shaped may have tier 1 as its only
/// coverage.** Escrow, receipts, earnings, claims, refunds, slashing and
/// bonds must be exercised against a real VM somewhere. A money-path
/// suite calls this instead of [`backend_from_env`], so running it on
/// tier 1 produces a visible "this proved nothing" line rather than a
/// green tick.
///
/// # Errors
///
/// Only for a malformed `OCTRA_TEST_TIER`.
pub async fn money_path_backend_from_env() -> Result<Harness, String> {
    let tier = Tier::from_env()?;
    if !tier.satisfies_money_path_policy() {
        return Ok(Harness::Skip(format!(
            "tier {tier} cannot be a money-path test's only coverage: it executes no AML, so \
             a pass here proves our reimplementation agrees with itself and nothing more. \
             Re-run with {TIER_ENV}=node (or fork) against a real chain."
        )));
    }
    Ok(backend_for_tier(tier).await)
}

/// Get a backend or return from the test, printing why.
///
/// ```ignore
/// #[tokio::test]
/// async fn my_test() {
///     let chain = skip_unless_backend!(backend_from_env().await.unwrap(), "my_test");
///     // …
/// }
/// ```
#[macro_export]
macro_rules! skip_unless_backend {
    ($harness:expr, $name:expr) => {
        match $harness.or_skip($name) {
            Some(b) => b,
            None => return,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_tier_is_always_available() {
        let h = backend_for_tier(Tier::Mock).await;
        let b = h.or_skip("mock_tier_is_always_available").expect("no skip");
        assert_eq!(b.tier(), Tier::Mock);
        assert!(b.describe().contains("mock"));
    }

    /// A dead endpoint must produce a skip carrying the compose command,
    /// not a panic and not a bare "connection refused".
    #[tokio::test]
    async fn an_absent_node_skips_with_instructions() {
        // Port 1 is never a node.
        let backend = NodeBackend::node("http://127.0.0.1:1/rpc").unwrap();
        assert!(!backend.is_reachable().await);
        let advice = unreachable_advice(Tier::Node, "http://127.0.0.1:1/rpc");
        assert!(advice.contains("docker compose"), "{advice}");
        assert!(advice.contains("OCTRA_NODE_RPC"), "{advice}");
    }

    #[tokio::test]
    async fn money_path_policy_excludes_tier_one() {
        // Exercised directly rather than through the environment so this
        // test does not race others in the same process.
        assert!(!Tier::Mock.satisfies_money_path_policy());
        assert!(Tier::Node.satisfies_money_path_policy());
    }
}

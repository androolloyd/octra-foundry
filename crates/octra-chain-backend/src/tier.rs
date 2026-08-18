//! Which chain a test runs against.
//!
//! Selected by the `OCTRA_TEST_TIER` environment variable so a suite can be
//! moved between tiers as configuration rather than a rewrite. The default is
//! [`Tier::Mock`], because an unconfigured `cargo test` on a laptop with no
//! docker must still run.
//!
//! The tiers exist because two facts are both true and pull in opposite
//! directions: the real node's epoch interval is a hardcoded 10s (upstream
//! `epoch_time.ml:10-11`), so it can never serve sub-second feedback; and the
//! mock executes no AML and has shape drift on every method it implements, so
//! it can never be trusted alone. Hence: fast tier for logic, real tier for
//! anything that moves value.

use std::{fmt, str::FromStr};

/// The environment variable that selects the tier.
pub const TIER_ENV: &str = "OCTRA_TEST_TIER";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Tier {
    /// In-process mock. Fast and hermetic; executes no AML, so it can only
    /// ever confirm that our reimplementation agrees with itself.
    #[default]
    Mock,
    /// A real lite node in Single mode (`docker/octra-node/`): genuine VM,
    /// genuine staging lifecycle, 10s epochs, deterministic genesis.
    Node,
    /// A real node booted on imported devnet state via state sync — real
    /// contracts, real balances, local epochs.
    Fork,
}

impl Tier {
    /// Read the tier from `OCTRA_TEST_TIER`, defaulting to [`Tier::Mock`].
    ///
    /// An unrecognised value is a hard error rather than a silent fallback:
    /// a typo that quietly downgrades a money-path suite to the mock is
    /// precisely the failure this crate exists to prevent.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(TIER_ENV) {
            Err(_) => Ok(Self::default()),
            Ok(raw) if raw.trim().is_empty() => Ok(Self::default()),
            Ok(raw) => raw.trim().parse(),
        }
    }

    /// True when this tier runs against a real node, and therefore has no
    /// faucet, no instant mint, and no `octra_test_*` namespace.
    #[must_use]
    pub const fn is_real_chain(self) -> bool {
        matches!(self, Self::Node | Self::Fork)
    }

    /// May a money-shaped suite treat this tier as its only coverage?
    ///
    /// The policy: no. Escrow, receipts, earnings, claims, refunds, slashing
    /// and bonds must all be exercised against a real VM somewhere.
    #[must_use]
    pub const fn satisfies_money_path_policy(self) -> bool {
        self.is_real_chain()
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Node => "node",
            Self::Fork => "fork",
        }
    }
}

impl FromStr for Tier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "node" => Ok(Self::Node),
            "fork" => Ok(Self::Fork),
            other => Err(format!(
                "unknown {TIER_ENV} value {other:?}: expected one of mock, node, fork"
            )),
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_tier_and_is_case_insensitive() {
        assert_eq!("mock".parse::<Tier>().unwrap(), Tier::Mock);
        assert_eq!("NODE".parse::<Tier>().unwrap(), Tier::Node);
        assert_eq!("  Fork ".parse::<Tier>().unwrap(), Tier::Fork);
    }

    /// A typo must not silently downgrade a suite to the mock.
    #[test]
    fn unknown_tier_is_an_error_not_a_default() {
        let err = "noed".parse::<Tier>().unwrap_err();
        assert!(err.contains("noed"), "{err}");
        assert!(err.contains("mock, node, fork"), "{err}");
    }

    #[test]
    fn money_path_policy_rejects_mock_only() {
        assert!(!Tier::Mock.satisfies_money_path_policy());
        assert!(Tier::Node.satisfies_money_path_policy());
        assert!(Tier::Fork.satisfies_money_path_policy());
    }

    #[test]
    fn round_trips_through_display() {
        for t in [Tier::Mock, Tier::Node, Tier::Fork] {
            assert_eq!(t.to_string().parse::<Tier>().unwrap(), t);
        }
    }
}

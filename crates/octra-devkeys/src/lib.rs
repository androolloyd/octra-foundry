//! Well-known deterministic dev accounts for the local `octra-node`.
//!
//! This is the Octra analogue of anvil's ten famous accounts: a fixed
//! set of ed25519 seeds that every checkout derives identically, so
//! tests, docs, and the `docker/octra-node` compose file can all refer
//! to the same addresses without any key-generation step. The compose
//! file seeds `OCTRA_VALIDATORS` from these keys, which is what makes
//! the node's genesis mint them the whole 100M OCT circulating supply
//! (upstream `startup_account_shell.ml` splits it evenly across the
//! validator set on an empty ledger).
//!
//! # These keys are PUBLIC
//!
//! The seeds below are published in this source file, exactly like
//! anvil's mnemonic. Anyone on the internet can sign for these
//! accounts. **Never fund them on devnet or any real network** — they
//! exist solely so a throwaway local chain has money in known places.
//!
//! Derivation, verified against the upstream node
//! (`controls/lib/validator_common.py:184-189` and the OCaml twin in
//! `lib/core/crypto.ml`):
//!
//! ```text
//! address = "oct" + base58(sha256(ed25519_pubkey)).rjust(44, '1')
//! ```
//!
//! which is exactly [`octra_core::Address::from_pubkey`]; the golden
//! test below pins all ten derived addresses so silent drift in either
//! crate fails loudly.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use octra_core::Address;

/// How many well-known accounts exist. Fixed forever; append-only
/// changes would still reshuffle the genesis split (supply divides by
/// validator count), so treat the set as frozen.
pub const ACCOUNT_COUNT: usize = 10;

/// The fixed ed25519 seeds, as hex. Each seed is
/// `sha256("octra-foundry/devkey/<index>")` — the label rule is only
/// provenance documentation; the hex strings here are the source of
/// truth and must never change.
pub const SEED_HEX: [&str; ACCOUNT_COUNT] = [
    "057100ceb1241633e746ab70365d98e2e4306cd62aee781cf39ae5b506d2cc6a",
    "90bba675aebc5cbd0903d504799e4044f846c66643030a51475de169df3c2a33",
    "2e108de58f0886c39c540ba8864ed8ab429add95cfe061846eca4c7f444e822a",
    "b47be8004cb701dd5f35e4f8b057ec09c5a4e2d60302871a850115e43b4d78d3",
    "cae9366d97aa516b0a1e7235d8563dafe11710217660eb69687409a29c308be4",
    "230ec6f877b545b1f44658631415016a184972d0bc0f742a678bf5e12c754f75",
    "05e9edc076be71f76c4661825a7857fb2366ed33e9957850ef6b1dd9b705f729",
    "a7ba63c9bf7078e11399016cdf323e6a7a1e428b956a315d149cca2bc32176b7",
    "c7d436f3029a1dd833e27e8880f50b35d4387ddfad75a0f7d013d708c707b91a",
    "7f9319376962e562b2a997f71c1287391fb3f55afc50fc3932a737a05004475f",
];

/// One well-known account. Construct via [`DevAccount::get`] or
/// [`accounts`]; the struct is just the index plus its decoded seed.
#[derive(Clone, Copy, Debug)]
pub struct DevAccount {
    pub index: usize,
    pub seed: [u8; 32],
}

impl DevAccount {
    /// Look up account `index` (0..[`ACCOUNT_COUNT`]).
    pub fn get(index: usize) -> Option<Self> {
        let hex_seed = SEED_HEX.get(index)?;
        let mut seed = [0u8; 32];
        // The constants above are 64 hex chars by construction; a
        // decode failure here is a corrupted source file, not input.
        hex::decode_to_slice(hex_seed, &mut seed).expect("SEED_HEX entries are 32-byte hex");
        Some(Self { index, seed })
    }

    /// The ed25519 signing key (the seed *is* the 32-byte secret, same
    /// as the node wallet's `priv` field).
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// The 32-byte ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// Public key in base64 — the encoding `OCTRA_VALIDATORS` and the
    /// node's `wallet.json` use (upstream `decode_public_key` insists
    /// on base64, not hex).
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key())
    }

    /// Secret seed in base64, matching `wallet.json`'s `priv` field.
    pub fn secret_b64(&self) -> String {
        B64.encode(self.seed)
    }

    /// The derived `oct…` address.
    pub fn address(&self) -> Address {
        Address::from_pubkey(&self.public_key())
    }

    /// The node's `wallet.json` body for this account, byte-compatible
    /// with what `Wallet.ensure` (upstream `lib/core/crypto.ml`) reads:
    /// `{"priv": b64, "pub": b64, "address": "oct…"}`. The compose
    /// entrypoint writes account 0's into the data dir so the node's
    /// own identity is deterministic too.
    pub fn node_wallet_json(&self) -> String {
        format!(
            "{{\"priv\":\"{}\",\"pub\":\"{}\",\"address\":\"{}\"}}",
            self.secret_b64(),
            self.public_key_b64(),
            self.address()
        )
    }
}

/// All ten accounts, in index order.
pub fn accounts() -> Vec<DevAccount> {
    (0..ACCOUNT_COUNT)
        .map(|i| DevAccount::get(i).expect("index in range"))
        .collect()
}

/// The `OCTRA_VALIDATORS` string the node's genesis wants:
/// `addr:pubkey_b64,addr:pubkey_b64,…` (same shape as upstream
/// `config/network.env`).
pub fn validators_env() -> String {
    accounts()
        .iter()
        .map(|a| format!("{}:{}", a.address(), a.public_key_b64()))
        .collect::<Vec<_>>()
        .join(",")
}

/// A `wallets.toml` rendering of the whole set, for tooling that wants
/// the accounts as a file rather than a library call.
pub fn wallets_toml() -> String {
    let mut out = String::from(
        "# octra-foundry dev accounts — deterministic, PUBLIC keys.\n\
         # Never fund these on devnet or any real network.\n\
         # Generated by `cargo run -p octra-devkeys -- wallets-toml`.\n",
    );
    use std::fmt::Write as _;
    for a in accounts() {
        write!(
            out,
            "\n[[wallet]]\nindex = {}\naddress = \"{}\"\npub = \"{}\"\npriv = \"{}\"\n",
            a.index,
            a.address(),
            a.public_key_b64(),
            a.secret_b64(),
        )
        .expect("write to String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden addresses. These are load-bearing: docker-compose.yml
    /// hardcodes the same values in its OCTRA_VALIDATORS line, so a
    /// derivation change here must fail this test rather than quietly
    /// producing a genesis that funds different addresses.
    const GOLDEN_ADDRESSES: [&str; ACCOUNT_COUNT] = [
        "oct1fKQS6gwqbVUFnzMSVsNRcY7aeJE5Kt84uq55mLAsH3r",
        "oct21vtY7jGprbS5gzL7Crxu22GJhXVQwCzfNmBCgGHvC72",
        "octEfyBH8nq6YbVspRYhCnWXsbM7UopJt1rk3DixJggb8GP",
        "octH4AFtmpTmezJKxKCZ4wUHjDVS78vEXpmkjLg1DzmQ8dq",
        "oct7TMi64mtRYXZ7jQPdTUbAc7774KsXykHTVuMsSSch1zJ",
        "oct78d9RxFufJHD6RonAT5JWY5zUogAhLh7xa9oHWJW9CkY",
        "octEgfmbNJoXnBqQ3KcL5JXMvjd77Nk1wsKPCnh1hBiaF5j",
        "octGn5wKZR1Wfh7A2nA7UC3znixUogy8TwcHMCX4erHzDBc",
        "octDsU65W5JygSZFhU8UGnkfAz9rQJXs5natsTC9VALteta",
        "octFDqPsZkAirxQ87fm3bkiZpA8fXASAMZnRe8dBbHrRjfJ",
    ];

    /// Golden pubkeys, base64 — the other half of each
    /// OCTRA_VALIDATORS pair.
    const GOLDEN_PUBKEYS_B64: [&str; ACCOUNT_COUNT] = [
        "DcVw9lEfzSxuM9V1ROmKJQq6Mybz0BG/9XImA4kfQDI=",
        "sp+3RZzqiSbuv2Gd2ptqPF8BGjaiEfF65apMtp3EtKs=",
        "5dL/EPzRpxS/Xr4aiRNZNN5i8KNa+F0GX3jje5ddoyI=",
        "k3FwmGXi3I5z3rU9m28QkZWkPuZLymdU2WnlS0rE4BY=",
        "2UKljDakccgg3togUKo9WXD6pjhTYbkXB5+iMo1m7iY=",
        "XSDVYtk2PHDnHZPt44LH1wf6BYxLjhsff/Zzi0Kdrwk=",
        "n5md3kYgSyNiqY2EVZg2WNO8nF5QWQ8h/7lBwFNunMQ=",
        "sCpf47ysXojA+5h0DBxLe4pej5JuvkXmdRvTt6RysA4=",
        "SFFVIRkROp5zGzDrvuW3mpc080Li+YhOitp6BSPh/kE=",
        "xJmAZYZA7zICQC4Xx3Q2qIHUjNTbUhRWTL5U0JkLvpk=",
    ];

    #[test]
    fn golden_addresses_are_stable() {
        for (i, a) in accounts().iter().enumerate() {
            assert_eq!(
                a.address().display(),
                GOLDEN_ADDRESSES[i],
                "devkey {i} address drifted — derivation or seed changed"
            );
            assert_eq!(
                a.public_key_b64(),
                GOLDEN_PUBKEYS_B64[i],
                "devkey {i} pubkey drifted — seed changed"
            );
        }
    }

    #[test]
    fn validators_env_matches_goldens() {
        let expected = GOLDEN_ADDRESSES
            .iter()
            .zip(GOLDEN_PUBKEYS_B64.iter())
            .map(|(a, p)| format!("{a}:{p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(validators_env(), expected);
    }

    #[test]
    fn addresses_are_well_formed() {
        // Mirror upstream valid_address (validator_common.py:188-189):
        // 47 chars, "oct" prefix, base58 body.
        const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for a in accounts() {
            let display = a.address().display().to_string();
            assert_eq!(display.len(), 47);
            assert!(display.starts_with("oct"));
            assert!(display[3..].chars().all(|c| BASE58.contains(c)));
        }
    }

    #[test]
    fn seeds_round_trip_through_signing_key() {
        // The seed is the wallet's 32-byte secret; deriving the
        // signing key and re-extracting it must be lossless, or the
        // wallet.json we emit would not reproduce the same account.
        for a in accounts() {
            assert_eq!(a.signing_key().to_bytes(), a.seed);
        }
    }

    #[test]
    fn wallet_json_parses_and_matches() {
        // Sanity on the exact field names Wallet.ensure reads.
        let j = DevAccount::get(0).unwrap().node_wallet_json();
        assert!(j.contains("\"priv\":"));
        assert!(j.contains("\"pub\":"));
        assert!(j.contains(&format!("\"address\":\"{}\"", GOLDEN_ADDRESSES[0])));
    }
}

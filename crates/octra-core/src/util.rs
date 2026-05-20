//! Small cross-crate utilities. Kept narrow on purpose — only things that
//! recur in three or more call sites belong here.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{wallet_enc, CoreError, CoreResult};

/// HKDF-Expand a 32-byte master secret into a domain-separated 32-byte
/// child secret. The master should already be high-entropy (we don't
/// salt because the master is the wallet's root secret).
pub fn derive_subkey(master: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(domain, &mut out)
        .expect("HKDF-Expand of 32 bytes always fits in one Sha256 block");
    out
}

pub const DOMAIN_RECEIPT_SIGN: &[u8] = b"octravpn-key-v1/receipt-sign-ed25519";
pub const DOMAIN_NOISE: &[u8] = b"octravpn-key-v1/noise-x25519";
pub const DOMAIN_VIEW: &[u8] = b"octravpn-key-v1/stealth-view";

/// Env var holding the passphrase for v1-encrypted wallet envelopes.
/// Honoured by `read_secret_32` when the file on disk has the v1 magic.
pub const WALLET_PASSPHRASE_ENV: &str = "OCTRAVPN_WALLET_PASSPHRASE";

/// Current wall-clock time as seconds since the Unix epoch.
/// Returns 0 if the system clock is before the epoch (impossible on a
/// correctly-configured machine, but we never want this to panic).
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Decode a hex string into a fixed-size byte array. The input must be
/// exactly `2 * N` hex digits.
///
/// The intermediate `Vec<u8>` produced by `hex::decode` is zeroized
/// before the function returns, so secret hex inputs don't leave a
/// plaintext copy in the heap's free list. Callers that decode public
/// data pay only the cost of one memset; callers that decode secret
/// data get the protection automatically.
pub fn hex_to_array<const N: usize>(s: &str, what: &str) -> CoreResult<[u8; N]> {
    let mut bytes =
        hex::decode(s).map_err(|e| CoreError::InvalidEncoding(format!("{what} hex: {e}")))?;
    let result = if bytes.len() == N {
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    } else {
        Err(CoreError::InvalidLength {
            expected: N,
            actual: bytes.len(),
        })
    };
    bytes.zeroize();
    result
}

/// Read a 32-byte secret from disk. Accepts:
///   - a v1 encrypted envelope (passphrase from `WALLET_PASSPHRASE_ENV`)
///   - raw 32 bytes
///   - 64 hex digits (with optional trailing whitespace)
///
/// All intermediate buffers that contain secret material (the raw file
/// bytes, the hex-decoded `Vec<u8>` inside `hex_to_array`, the env-var
/// passphrase string) are wiped before this function returns so the
/// allocator's free list doesn't retain a copy.
pub fn read_secret_32(path: &str) -> CoreResult<[u8; 32]> {
    let mut raw =
        std::fs::read(path).map_err(|e| CoreError::InvalidEncoding(format!("read {path}: {e}")))?;
    if wallet_enc::looks_like_envelope(&raw) {
        let mut pass = std::env::var(WALLET_PASSPHRASE_ENV).map_err(|_| {
            CoreError::InvalidEncoding(format!(
                "{path} is encrypted; set {WALLET_PASSPHRASE_ENV} to decrypt"
            ))
        })?;
        let r = wallet_enc::decrypt_secret(&raw, &pass);
        pass.zeroize();
        raw.zeroize();
        return r;
    }
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        raw.zeroize();
        return Ok(out);
    }
    // Hex-encoded file path: parse, then wipe.
    let r = (|| {
        let s = std::str::from_utf8(&raw)
            .map_err(|e| CoreError::InvalidEncoding(format!("non-utf8 secret: {e}")))?
            .trim();
        hex_to_array::<32>(s, "secret file")
    })();
    raw.zeroize();
    r
}

/// Strict variant of [`read_secret_32`] for operator-side daemons that
/// MUST refuse to start with plaintext keys on disk.
///
/// Behaviour:
///
///   - If the file at `path` carries the `OCTRA-WALLET-V1\0` envelope
///     magic, the passphrase is sourced from `passphrase_hint`
///     (interactive callers can pass an already-prompted secret),
///     falling back to the `OCTRAVPN_KEY_PASSPHRASE` env var, then to
///     `WALLET_PASSPHRASE_ENV`. The envelope is decrypted and returned.
///   - If the file is *not* sealed (raw 32 bytes or 64 hex digits), the
///     function refuses with [`CoreError::PlaintextKeyOnDisk`]. The
///     `suggested_cmd` field on the error names the exact CLI subcommand
///     an operator should run to wrap the file.
///
/// Threat-model reference: `docs/v2-threat-model.md` P1-6 (operator-host
/// key storage). Devnet and the v1.1 e2e harness continue to call the
/// permissive [`read_secret_32`] above so the existing flows are
/// preserved; v2 operator-side hardening uses this strict variant.
///
/// The returned `Zeroizing<[u8; 32]>` wipes the secret on drop. All
/// intermediate buffers (the on-disk envelope bytes, the passphrase
/// string) are also zeroized before the function returns.
pub fn read_secret_32_or_sealed(
    path: &str,
    passphrase_hint: Option<&str>,
) -> CoreResult<Zeroizing<[u8; 32]>> {
    let mut raw =
        std::fs::read(path).map_err(|e| CoreError::InvalidEncoding(format!("read {path}: {e}")))?;
    if !wallet_enc::looks_like_envelope(&raw) {
        raw.zeroize();
        return Err(CoreError::PlaintextKeyOnDisk {
            path: path.to_string(),
            suggested_cmd: suggest_seal_cmd(path),
        });
    }
    // Sealed path: resolve passphrase from caller hint, then env vars.
    // The hint is meant for one-shot CLI subcommands that have already
    // prompted the operator; the env-var path is the daemon's primary
    // boot mode (see docs/v2-operator-key-hygiene.md).
    let mut pass_storage = String::new();
    let pass: &str = if let Some(p) = passphrase_hint {
        p
    } else if let Ok(p) = std::env::var(KEY_PASSPHRASE_ENV) {
        pass_storage = p;
        &pass_storage
    } else if let Ok(p) = std::env::var(WALLET_PASSPHRASE_ENV) {
        pass_storage = p;
        &pass_storage
    } else {
        raw.zeroize();
        return Err(CoreError::InvalidEncoding(format!(
            "{path} is sealed; set {KEY_PASSPHRASE_ENV} (or pass --passphrase) to decrypt"
        )));
    };
    let decrypted = wallet_enc::decrypt_secret(&raw, pass);
    pass_storage.zeroize();
    raw.zeroize();
    decrypted.map(Zeroizing::new)
}

/// Env var holding the passphrase used by the operator daemon to unseal
/// wallet / wg / receipt-signing keys at boot. Honoured by
/// [`read_secret_32_or_sealed`]. Falls back to [`WALLET_PASSPHRASE_ENV`]
/// for back-compat with v1 deployments that already export the latter.
pub const KEY_PASSPHRASE_ENV: &str = "OCTRAVPN_KEY_PASSPHRASE";

/// Build the CLI suggestion an operator should run to wrap a plaintext
/// key under the passphrase envelope. Kept here so the same string
/// appears in error messages and in `octravpn-node seal-keys --help`.
fn suggest_seal_cmd(path: &str) -> String {
    format!(
        "octravpn-node seal-keys --in {path} --out {path}.sealed \
         (then export {KEY_PASSPHRASE_ENV}=... and re-point your TOML at the sealed file)"
    )
}

/// Env var: set to `json` to emit JSON-formatted logs.
pub const LOG_FORMAT_ENV: &str = "OCTRAVPN_LOG_FORMAT";

/// Initialise `tracing` for a daemon binary writing to stdout. Honours
/// `RUST_LOG` (via `EnvFilter`) and `OCTRAVPN_LOG_FORMAT=json` for
/// structured output. Safe to call exactly once from `main`.
pub fn init_tracing(default_filter: &str) {
    let filter = build_env_filter(default_filter);
    if json_logs() {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Same as `init_tracing` but writes to stderr — appropriate for CLI
/// tools where stdout is reserved for command output.
pub fn init_tracing_stderr(default_filter: &str) {
    let filter = build_env_filter(default_filter);
    if json_logs() {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    }
}

fn build_env_filter(default: &str) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default))
}

fn json_logs() -> bool {
    std::env::var(LOG_FORMAT_ENV).as_deref() == Ok("json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_array_round_trip() {
        let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let arr: [u8; 4] = hex_to_array(&hex::encode(bytes), "test").unwrap();
        assert_eq!(arr, bytes);
    }

    #[test]
    fn hex_to_array_rejects_wrong_length() {
        let ok: CoreResult<[u8; 2]> = hex_to_array("dead", "test");
        assert!(ok.is_ok());
        let too_short: CoreResult<[u8; 8]> = hex_to_array("dead", "test");
        assert!(too_short.is_err());
        let too_long: CoreResult<[u8; 1]> = hex_to_array("dead", "test");
        assert!(too_long.is_err());
    }

    // Run both env-var paths in one test so they don't race over the
    // shared `OCTRAVPN_WALLET_PASSPHRASE` global. Cargo runs tests in
    // parallel by default.
    #[test]
    fn read_secret_32_envelope_paths() {
        let secret = [42u8; 32];
        let enc = wallet_enc::encrypt_secret_with_iters(&secret, "pw", 100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.enc");
        std::fs::write(&path, &enc).unwrap();
        let path_str = path.to_str().unwrap();

        std::env::remove_var(WALLET_PASSPHRASE_ENV);
        assert!(read_secret_32(path_str).is_err());

        std::env::set_var(WALLET_PASSPHRASE_ENV, "pw");
        let got = read_secret_32(path_str).unwrap();
        std::env::remove_var(WALLET_PASSPHRASE_ENV);
        assert_eq!(got, secret);
    }

    /// P1-6: the strict loader MUST refuse a plaintext-hex key, and the
    /// resulting error MUST carry the suggested CLI for sealing it.
    #[test]
    fn read_secret_32_or_sealed_rejects_plaintext_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        // Plaintext hex on disk — the v1 / devnet shape.
        std::fs::write(&path, "11".repeat(32) + "\n").unwrap();

        let err = read_secret_32_or_sealed(path.to_str().unwrap(), None).unwrap_err();
        match err {
            CoreError::PlaintextKeyOnDisk {
                path: p,
                suggested_cmd,
            } => {
                assert_eq!(p, path.to_str().unwrap());
                assert!(
                    suggested_cmd.contains("octravpn-node seal-keys"),
                    "suggested_cmd should name the seal-keys CLI: {suggested_cmd}"
                );
                assert!(
                    suggested_cmd.contains(path.to_str().unwrap()),
                    "suggested_cmd should mention the offending path: {suggested_cmd}"
                );
            }
            other => panic!("expected PlaintextKeyOnDisk, got {other:?}"),
        }
    }

    /// P1-6: the strict loader MUST refuse a 32-raw-byte file too — the
    /// v1 `read_secret_32` accepts both shapes, so we test both here.
    #[test]
    fn read_secret_32_or_sealed_rejects_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        std::fs::write(&path, [7u8; 32]).unwrap();

        let err = read_secret_32_or_sealed(path.to_str().unwrap(), None).unwrap_err();
        assert!(matches!(err, CoreError::PlaintextKeyOnDisk { .. }));
    }

    /// P1-6: with the passphrase hint provided directly, the strict
    /// loader unseals a v1 envelope to the original secret. Verifies
    /// the round-trip surface the seal-keys CLI relies on.
    #[test]
    fn read_secret_32_or_sealed_hint_passphrase() {
        let secret = [0xA5u8; 32];
        let enc = wallet_enc::encrypt_secret_with_iters(&secret, "rosebud", 100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sealed");
        std::fs::write(&path, &enc).unwrap();

        let got = read_secret_32_or_sealed(path.to_str().unwrap(), Some("rosebud")).unwrap();
        assert_eq!(*got, secret);
    }

    /// P1-6: env-var fallback — the daemon's primary boot mode. Without
    /// a hint and without the env var, the call MUST fail cleanly.
    /// With the env var set, decrypt succeeds. Removed at end so we
    /// don't leak state across tests.
    #[test]
    fn read_secret_32_or_sealed_env_passphrase() {
        let secret = [0xC3u8; 32];
        let enc = wallet_enc::encrypt_secret_with_iters(&secret, "tarpit", 100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sealed");
        std::fs::write(&path, &enc).unwrap();
        let p = path.to_str().unwrap();

        // Both passphrase sources empty → InvalidEncoding error.
        std::env::remove_var(KEY_PASSPHRASE_ENV);
        std::env::remove_var(WALLET_PASSPHRASE_ENV);
        let err = read_secret_32_or_sealed(p, None).unwrap_err();
        assert!(matches!(err, CoreError::InvalidEncoding(_)));

        // KEY_PASSPHRASE_ENV is the v2 env var — preferred over the v1.
        std::env::set_var(KEY_PASSPHRASE_ENV, "tarpit");
        let got = read_secret_32_or_sealed(p, None).unwrap();
        assert_eq!(*got, secret);
        std::env::remove_var(KEY_PASSPHRASE_ENV);
    }
}

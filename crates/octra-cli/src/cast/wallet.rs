//! `cast wallet ...` — keygen, signing, address derivation.
//!
//! Wallet files are 64-char hex on a single line. This keeps tooling
//! interop with `octra_pre_client` and the C++ wallet trivial and stays
//! human-readable; it's *not* the production wallet format and shouldn't
//! be used to hold real funds.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Subcommand;
use octra_core::{address::Address, sig::KeyPair};
use serde_json::json;

use crate::io::{dump_json, read_secret_hex, write_to};

#[derive(Subcommand, Debug)]
pub enum WalletCmd {
    /// Generate a fresh ed25519 keypair.
    New {
        /// Output path for the 32-byte hex secret. If omitted, the
        /// command refuses unless `--show-secret` is also passed —
        /// emitting raw secret material to a terminal by default is
        /// a common shell-history / log-capture footgun.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the secret to stderr (used when `--out` is omitted).
        /// Off by default so a naive `cast wallet new` doesn't leak
        /// the secret into shell history or a `2>&1` capture.
        #[arg(long, default_value_t = false)]
        show_secret: bool,
    },
    /// Sign arbitrary bytes with a key file.
    Sign {
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: PathBuf,
        /// Message to sign. If it parses as hex (with or without `0x`),
        /// the decoded bytes are signed; otherwise the raw UTF-8 bytes.
        message: String,
    },
    /// Derive the `oct...` address from a key file.
    Addr {
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: PathBuf,
    },
    /// Print the raw 32-byte ed25519 verifying-key derived from a key
    /// file. Use `--format base64` (default) when feeding the result
    /// into `register_endpoint.receipt_pubkey` or `ed25519_ok` — AML
    /// expects base64. Use `--format hex` for tooling interop.
    Pubkey {
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: PathBuf,
        #[arg(long, value_enum, default_value_t = PubkeyFormat::Base64)]
        format: PubkeyFormat,
    },
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum PubkeyFormat {
    Hex,
    Base64,
}

pub fn dispatch(cmd: WalletCmd) -> Result<()> {
    match cmd {
        WalletCmd::New { out, show_secret } => new_wallet(out.as_deref(), show_secret),
        WalletCmd::Sign { key, message } => sign_message(&key, &message),
        WalletCmd::Addr { key } => print_address(&key),
        WalletCmd::Pubkey { key, format } => print_pubkey(&key, format),
    }
}

fn print_pubkey(p: &Path, format: PubkeyFormat) -> Result<()> {
    use zeroize::Zeroize;
    let mut bytes = read_secret_hex(p)?;
    let kp = KeyPair::from_secret_bytes(&bytes);
    bytes.zeroize();
    let out = match format {
        PubkeyFormat::Hex => hex::encode(kp.public.0),
        PubkeyFormat::Base64 => STANDARD.encode(kp.public.0),
    };
    println!("{out}");
    Ok(())
}

fn new_wallet(out: Option<&Path>, show_secret: bool) -> Result<()> {
    let kp = KeyPair::generate();
    let addr = Address::from_pubkey(&kp.public.0).display().to_string();
    let public = hex::encode(kp.public.0);
    if let Some(p) = out {
        // `secret_bytes()` returns `Zeroizing<[u8;32]>` so the buffer
        // is wiped when this scope exits; the hex-encoded `String`
        // also gets manually zeroized after writing.
        let mut secret = hex::encode(kp.secret_bytes());
        write_to(p, &secret).context("write wallet")?;
        use zeroize::Zeroize;
        secret.zeroize();
        // Mode bits aren't enforced on Windows, but on Unix the file
        // contains a private key, so tighten read perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
        // On disk we wrote only the secret; print summary as JSON for
        // pipeline-friendliness.
        dump_json(&json!({
            "path": p.display().to_string(),
            "address": addr,
            "public_key": public,
        }));
    } else {
        // No `--out`: refuse unless the caller opts into explicit
        // stderr emission. Default-refusing here is the v2 hardening:
        // `cast wallet new` used to drop the secret into stderr by
        // default, which is the wrong default for a tool that's
        // routinely run inside shell history.
        if !show_secret {
            return Err(anyhow!(
                "refusing to emit secret material on stderr by default.\n\
                 \n\
                 Either pass `--out <PATH>` to write the hex secret to a file\n\
                 (recommended; the file will be chmod 0600 on Unix), or pass\n\
                 `--show-secret` to print it to stderr regardless."
            ));
        }
        let mut secret = hex::encode(kp.secret_bytes());
        eprintln!("{secret}");
        use zeroize::Zeroize;
        secret.zeroize();
        dump_json(&json!({
            "address": addr,
            "public_key": public,
        }));
    }
    Ok(())
}

fn sign_message(key: &Path, msg: &str) -> Result<()> {
    use zeroize::Zeroize;
    let mut secret = read_secret_hex(key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    secret.zeroize();
    let bytes = decode_hex_or_utf8(msg);
    let sig = kp.sign(&bytes);
    println!("{}", STANDARD.encode(sig.0));
    Ok(())
}

fn print_address(key: &Path) -> Result<()> {
    use zeroize::Zeroize;
    let mut secret = read_secret_hex(key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    secret.zeroize();
    let addr = Address::from_pubkey(&kp.public.0).display().to_string();
    println!("{addr}");
    Ok(())
}

fn decode_hex_or_utf8(s: &str) -> Vec<u8> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.is_empty() {
        return Vec::new();
    }
    if stripped.len() % 2 == 0 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(stripped).unwrap_or_else(|_| s.as_bytes().to_vec());
    }
    s.as_bytes().to_vec()
}

/// Public re-export so tests can roundtrip without parsing CLI args.
pub fn derive_address(secret_hex: &str) -> Result<String> {
    use zeroize::Zeroize;
    let mut bytes = hex::decode(secret_hex.trim().trim_start_matches("0x"))?;
    let out = if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        let kp = KeyPair::from_secret_bytes(&k);
        k.zeroize();
        Ok(Address::from_pubkey(&kp.public.0).display().to_string())
    } else {
        Err(anyhow!("secret must be 32 bytes"))
    };
    bytes.zeroize();
    out
}

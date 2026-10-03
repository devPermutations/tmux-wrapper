//! Test-only RSA key generation and JWT minting. Keys are produced at test
//! runtime with `openssl genrsa` (no private key is committed) and cached.
//! Every helper returns `None` when the `openssl` binary is unavailable;
//! callers skip their test in that case.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use serde::Serialize;
use std::process::Command;
use std::sync::OnceLock;

fn gen_pem() -> Option<String> {
    let out = Command::new("openssl")
        .args(["genrsa", "2048"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Public key PEM (SPKI) for a private key PEM, via `openssl rsa -pubout`.
fn public_pem(private: &str) -> Option<String> {
    use std::io::Write;
    let mut child = Command::new("openssl")
        .args(["rsa", "-pubout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(private.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn pair(pem: &Option<(String, String)>) -> Option<(EncodingKey, DecodingKey)> {
    let (private, public) = pem.as_ref()?;
    Some((
        EncodingKey::from_rsa_pem(private.as_bytes()).ok()?,
        DecodingKey::from_rsa_pem(public.as_bytes()).ok()?,
    ))
}

fn generate() -> Option<(String, String)> {
    let private = gen_pem()?;
    let public = public_pem(&private)?;
    Some((private, public))
}

static PRIMARY: OnceLock<Option<(String, String)>> = OnceLock::new();
// `other_keys` is first used by later tasks.
#[allow(dead_code)]
static OTHER: OnceLock<Option<(String, String)>> = OnceLock::new();

/// The primary test key pair; `None` if `openssl` is unavailable.
pub fn keys() -> Option<(EncodingKey, DecodingKey)> {
    pair(PRIMARY.get_or_init(generate))
}

/// A second, different key pair, for "signed by the wrong key" tests.
#[allow(dead_code)]
pub fn other_keys() -> Option<(EncodingKey, DecodingKey)> {
    pair(OTHER.get_or_init(generate))
}

#[derive(Serialize)]
struct TestClaims<'a> {
    email: &'a str,
    sub: &'a str,
    aud: &'a str,
    iss: &'a str,
    exp: u64,
}

/// An RS256 JWT signed by [`keys`], with the given email/aud/iss/exp.
pub fn mint(email: &str, aud: &str, iss: &str, exp: u64) -> Option<String> {
    let (enc, _) = keys()?;
    let claims = TestClaims {
        email,
        sub: email,
        aud,
        iss,
        exp,
    };
    encode(&Header::new(Algorithm::RS256), &claims, &enc).ok()
}

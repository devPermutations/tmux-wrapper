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

/// A scratch tmux server on its own socket under a unique temp dir. Never
/// touches the user's real server; `Drop` kills it and removes the dir.
pub struct ScratchTmux {
    dir: std::path::PathBuf,
    sock: std::path::PathBuf,
}

/// Whether tmux-dependent tests can run; they skip when it is absent.
pub fn tmux_available() -> bool {
    std::path::Path::new("/usr/bin/tmux").exists()
}

impl ScratchTmux {
    /// `None` when `/usr/bin/tmux` is absent or the server won't start.
    pub fn start(first_session: &str) -> Option<Self> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        if !tmux_available() {
            return None;
        }
        let dir = std::env::temp_dir().join(format!(
            "tmuxwrapper-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let this = ScratchTmux {
            sock: dir.join("sock"),
            dir,
        };
        // Constructed first so Drop cleans up even if the start fails.
        this.new_detached(first_session).then_some(this)
    }

    pub fn socket(&self) -> &std::path::Path {
        &self.sock
    }

    pub fn new_detached(&self, name: &str) -> bool {
        Command::new("/usr/bin/tmux")
            .env_remove("TMUX")
            .arg("-S")
            .arg(&self.sock)
            .args(["new-session", "-d", "-s", name])
            .status()
            .is_ok_and(|s| s.success())
    }
}

impl Drop for ScratchTmux {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/tmux")
            .env_remove("TMUX")
            .arg("-S")
            .arg(&self.sock)
            .arg("kill-server")
            .status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

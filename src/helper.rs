//! The per-user helper: runs as the target unix user and is the security
//! boundary. Every request carries the original Cloudflare Access token, which
//! is re-verified against the helper's own JWKS before anything else happens,
//! so a compromised front cannot get a terminal without a valid token for this
//! user.

use crate::auth::{Claims, JwksCache, token_grants};
use crate::config::{CloudflareConfig, UserConfig};
use crate::proto::{AsyncSeqpacket, Request, Response};
use crate::pty::spawn_tmux_client;
use crate::tmux::{
    TmuxServer, is_valid_session_name, kill_session, list_sessions, query_server,
    refuses_new_session, start_server_unit,
};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

const KEYS_UNAVAILABLE: &str = "auth keys unavailable — try again shortly";
const NO_TMUX_SERVER: &str = "tmux server isn't running — start tmux-server.service";
const SESSION_LIMIT: &str = "session limit reached — kill an old session first";
const SPAWN_FAILED: &str = "could not start terminal";
const KILL_FAILED: &str = "could not kill session";

pub struct HelperCtx {
    pub user: UserConfig,
    pub home: PathBuf,
    pub jwks: JwksCache,
    pub max_sessions: usize,
    pub tmux_socket: Option<PathBuf>,
}

/// Verify `token` for this helper's user. `Err` is the reply to send.
async fn authorize(ctx: &HelperCtx, token: &str) -> Result<Claims, Response> {
    if !ctx.jwks.has_keys().await {
        warn!("request refused: no JWKS keys loaded yet");
        return Err(Response::Refused {
            reason: KEYS_UNAVAILABLE.into(),
        });
    }
    let claims = ctx.jwks.verify(token).await.map_err(|e| {
        warn!(error = %e, "token verification failed");
        Response::Unauthorized
    })?;
    if !token_grants(&ctx.user, &claims) {
        warn!("token is for a different user");
        return Err(Response::Unauthorized);
    }
    Ok(claims)
}

/// Session and kill names: the tmux charset, and not empty.
fn valid_name(name: &str) -> bool {
    !name.is_empty() && is_valid_session_name(name)
}

/// Handle one request. The token is always verified first, so an
/// unauthenticated caller learns nothing else. `Opened` always carries the
/// PTY master fd; every other reply carries none.
pub async fn handle(ctx: &HelperCtx, req: Request) -> (Response, Option<OwnedFd>) {
    let token = match &req {
        Request::Open { token, .. } | Request::List { token } | Request::Kill { token, .. } => {
            token
        }
    };
    let claims = match authorize(ctx, token).await {
        Ok(claims) => claims,
        Err(resp) => return (resp, None),
    };
    let socket = ctx.tmux_socket.as_deref();
    match req {
        Request::Open { session, .. } => open(ctx, &session, claims.exp).await,
        Request::List { .. } => (
            Response::Sessions {
                sessions: list_sessions(socket).await,
            },
            None,
        ),
        Request::Kill { name, .. } => {
            if !valid_name(&name) {
                return (Response::BadRequest, None);
            }
            let resp = match kill_session(&name, socket).await {
                Ok(true) => Response::Killed,
                Ok(false) => Response::NotFound,
                Err(e) => {
                    warn!(session = %name, error = %e, "kill-session failed");
                    Response::Refused {
                        reason: KILL_FAILED.into(),
                    }
                }
            };
            (resp, None)
        }
    }
}

async fn open(ctx: &HelperCtx, session: &str, expires_at: u64) -> (Response, Option<OwnedFd>) {
    let refused = |reason: &str| {
        (
            Response::Refused {
                reason: reason.into(),
            },
            None,
        )
    };
    if !valid_name(session) {
        return (Response::BadRequest, None);
    }
    let socket = ctx.tmux_socket.as_deref();
    // Never let `tmux new-session` start a server here: it would inherit this
    // service's sandbox — the D-012 failure. The unit serves the default
    // socket only, so it is not started for an explicit (test) socket.
    let mut server = query_server(socket).await;
    if server == TmuxServer::NotRunning && socket.is_none() {
        start_server_unit().await;
        server = query_server(socket).await;
    }
    let existing = match server {
        TmuxServer::Running(names) => names,
        TmuxServer::Unknown => {
            warn!("tmux list-sessions failed — session cap not enforced for this connection");
            Vec::new()
        }
        TmuxServer::NotRunning => {
            warn!("no tmux server and tmux-server.service didn't start one");
            return refused(NO_TMUX_SERVER);
        }
    };
    // Attaching to an existing session is always allowed; only a new name
    // past the cap is refused.
    if refuses_new_session(&existing, session, ctx.max_sessions) {
        warn!(
            session = %session,
            existing = existing.len(),
            "tmux session limit reached"
        );
        return refused(SESSION_LIMIT);
    }
    match spawn_tmux_client(session, &ctx.home, socket) {
        Ok((master, mut child)) => {
            // Reap the client once the front hangs it up.
            tokio::spawn(async move {
                match child.wait().await {
                    Ok(status) if !status.success() => debug!(%status, "tmux client exited"),
                    Ok(_) => {}
                    Err(e) => debug!(error = %e, "waiting for tmux client failed"),
                }
            });
            info!(session = %session, "opened terminal");
            (Response::Opened { expires_at }, Some(master))
        }
        Err(e) => {
            error!(session = %session, error = %e, "could not spawn tmux client");
            refused(SPAWN_FAILED)
        }
    }
}

/// Answer requests from the front until it goes away. A malformed message
/// gets `BadRequest` and the loop continues; EOF returns cleanly; any other
/// socket error is logged and returns.
pub async fn serve(ctx: HelperCtx, sock: AsyncSeqpacket) {
    loop {
        let (resp, fd) = match sock.recv::<Request>().await {
            // The protocol never sends the helper an fd; any received one
            // is closed by dropping it here.
            Ok((req, _fd)) => handle(&ctx, req).await,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                warn!(error = %e, "malformed request");
                (Response::BadRequest, None)
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                info!("front closed the helper socket");
                return;
            }
            Err(e) => {
                error!(error = %e, "helper socket receive failed");
                return;
            }
        };
        // `fd` (our copy of the PTY master) is dropped after sending, so the
        // front's copy is the only one and closing it hangs the client up.
        if let Err(e) = sock.send(&resp, fd.as_ref().map(|f| f.as_fd())).await {
            error!(error = %e, "helper socket send failed");
            return;
        }
    }
}

/// Process entrypoint for the helper after the privilege drop. Builds its
/// own current-thread runtime, fetches its own JWKS, serves the front over
/// `sock`, and exits 0 when the front goes away.
#[allow(dead_code)] // Called by main after the fork (Task 6).
pub fn run_helper(
    sock: OwnedFd,
    user: UserConfig,
    home: PathBuf,
    cloudflare: &CloudflareConfig,
    max_sessions: usize,
) -> ! {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "helper: failed to build tokio runtime");
            std::process::exit(1);
        }
    };
    let jwks = JwksCache::new(
        &cloudflare.resolved_jwks_url(),
        &cloudflare.resolved_issuer(),
        &cloudflare.audience,
    );
    let refresh_secs = cloudflare.jwks_refresh_secs;
    rt.block_on(async move {
        let sock = match AsyncSeqpacket::new(sock) {
            Ok(sock) => sock,
            Err(e) => {
                error!(error = %e, "helper: bad front socket");
                std::process::exit(1);
            }
        };
        if let Err(e) = jwks.refresh().await {
            warn!(error = %e, "helper: initial JWKS fetch failed (will retry in background)");
        }
        jwks.spawn_refresh_task(refresh_secs);
        let ctx = HelperCtx {
            user,
            home,
            jwks,
            max_sessions,
            tmux_socket: None,
        };
        serve(ctx, sock).await;
    });
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::seqpacket_pair;
    use crate::pty::PtyMaster;
    use crate::test_support::{self, ScratchTmux};
    use jsonwebtoken::{Algorithm, DecodingKey, Header};
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;

    const ISS: &str = "https://test.example";
    const AUD: &str = "aud-1";
    const EMAIL: &str = "alice@example.com";
    const KEYS_REASON: &str = "auth keys unavailable — try again shortly";
    const LIMIT_REASON: &str = "session limit reached — kill an old session first";
    const SERVER_REASON: &str = "tmux server isn't running — start tmux-server.service";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn ctx(keys: Vec<DecodingKey>, socket: &Path, max_sessions: usize) -> HelperCtx {
        HelperCtx {
            user: UserConfig {
                email: EMAIL.into(),
                unix_user: "alice".into(),
                tmux_session: "main".into(),
            },
            home: std::env::temp_dir(),
            jwks: JwksCache::with_static_keys(keys, ISS, AUD),
            max_sessions,
            tmux_socket: Some(socket.to_path_buf()),
        }
    }

    fn good_token() -> String {
        test_support::mint(EMAIL, AUD, ISS, now() + 300).unwrap()
    }

    /// Same claim shape as `test_support::mint`, signed by a different key.
    fn token_signed_by_other_key() -> Option<String> {
        #[derive(serde::Serialize)]
        struct C<'a> {
            email: &'a str,
            sub: &'a str,
            aud: &'a str,
            iss: &'a str,
            exp: u64,
        }
        let (enc, _) = test_support::other_keys()?;
        let c = C {
            email: EMAIL,
            sub: EMAIL,
            aud: AUD,
            iss: ISS,
            exp: now() + 300,
        };
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &c, &enc).ok()
    }

    /// Keys and a scratch tmux server, or `None` (test skips).
    fn setup(first_session: &str) -> Option<(DecodingKey, ScratchTmux)> {
        let Some((_, dec)) = test_support::keys() else {
            eprintln!("skipping: openssl unavailable");
            return None;
        };
        let Some(t) = ScratchTmux::start(first_session) else {
            eprintln!("skipping: /usr/bin/tmux not available");
            return None;
        };
        Some((dec, t))
    }

    fn requests(token: &str, name: &str) -> Vec<Request> {
        vec![
            Request::Open {
                token: token.into(),
                session: name.into(),
            },
            Request::List {
                token: token.into(),
            },
            Request::Kill {
                token: token.into(),
                name: name.into(),
            },
        ]
    }

    async fn session_names(socket: &Path) -> Vec<String> {
        crate::tmux::list_sessions(Some(socket))
            .await
            .into_iter()
            .map(|s| s.name)
            .collect()
    }

    /// Read from a PTY master until some output arrives.
    async fn read_some(fd: OwnedFd) -> usize {
        let mut pty = PtyMaster::from_fd(fd).unwrap();
        let mut buf = [0u8; 4096];
        tokio::time::timeout(Duration::from_secs(3), pty.read(&mut buf))
            .await
            .expect("no terminal output within 3s")
            .unwrap()
    }

    #[tokio::test]
    async fn forged_expired_wrong_audience_and_wrong_user_tokens_are_unauthorized() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![dec], t.socket(), 5);
        let bad_tokens = [
            ("other key", token_signed_by_other_key().unwrap()),
            (
                "expired",
                test_support::mint(EMAIL, AUD, ISS, now() - 3600).unwrap(),
            ),
            (
                "wrong audience",
                test_support::mint(EMAIL, "other-aud", ISS, now() + 300).unwrap(),
            ),
            (
                "wrong issuer",
                test_support::mint(EMAIL, AUD, "https://evil.example", now() + 300).unwrap(),
            ),
            (
                "other user",
                test_support::mint("mallory@example.com", AUD, ISS, now() + 300).unwrap(),
            ),
            ("garbage", "not-a-jwt".to_string()),
            ("empty", String::new()),
        ];
        for (what, tok) in &bad_tokens {
            // "base" exists: a Kill that got through would remove it; "fresh"
            // does not: an Open that got through would create it.
            for req in requests(tok, "fresh")
                .into_iter()
                .chain(requests(tok, "base"))
            {
                // Not `{req:?}`: keep tokens out of failure output.
                let desc = match &req {
                    Request::Open { session, .. } => format!("{what}: open {session}"),
                    Request::List { .. } => format!("{what}: list"),
                    Request::Kill { name, .. } => format!("{what}: kill {name}"),
                };
                let (resp, fd) = handle(&c, req).await;
                assert_eq!(resp, Response::Unauthorized, "{desc}");
                assert!(fd.is_none(), "{desc}: PTY fd returned");
            }
        }
        assert_eq!(session_names(t.socket()).await, vec!["base".to_string()]);
    }

    #[tokio::test]
    async fn bad_token_with_bad_name_is_unauthorized_not_bad_request() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![dec], t.socket(), 5);
        let tok = test_support::mint(EMAIL, AUD, ISS, now() - 3600).unwrap();
        for name in ["", "../etc", "a;b"] {
            for req in requests(&tok, name) {
                if matches!(req, Request::List { .. }) {
                    continue;
                }
                let (resp, fd) = handle(&c, req).await;
                assert_eq!(resp, Response::Unauthorized, "name {name:?}");
                assert!(fd.is_none());
            }
        }
    }

    #[tokio::test]
    async fn no_keys_loaded_is_refused_for_every_request() {
        let Some((_, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![], t.socket(), 5);
        for req in requests(&good_token(), "fresh") {
            let (resp, fd) = handle(&c, req).await;
            assert_eq!(
                resp,
                Response::Refused {
                    reason: KEYS_REASON.into()
                }
            );
            assert!(fd.is_none());
        }
        assert_eq!(session_names(t.socket()).await, vec!["base".to_string()]);
    }

    #[tokio::test]
    async fn valid_open_returns_a_live_pty() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![dec], t.socket(), 5);
        let exp = now() + 300;
        let tok = test_support::mint(EMAIL, AUD, ISS, exp).unwrap();
        let (resp, fd) = handle(
            &c,
            Request::Open {
                token: tok,
                session: "fresh".into(),
            },
        )
        .await;
        assert_eq!(resp, Response::Opened { expires_at: exp });
        assert!(read_some(fd.expect("Opened without an fd")).await > 0);
        assert!(session_names(t.socket()).await.contains(&"fresh".into()));
    }

    #[tokio::test]
    async fn invalid_or_empty_names_are_bad_requests() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![dec], t.socket(), 5);
        for name in ["", "../etc", "a;b", "a b"] {
            for req in requests(&good_token(), name) {
                if matches!(req, Request::List { .. }) {
                    continue;
                }
                let (resp, fd) = handle(&c, req).await;
                assert_eq!(resp, Response::BadRequest, "name {name:?}");
                assert!(fd.is_none());
            }
        }
        assert_eq!(session_names(t.socket()).await, vec!["base".to_string()]);
    }

    #[tokio::test]
    async fn list_and_kill_with_a_valid_token() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        assert!(t.new_detached("other"));
        let c = ctx(vec![dec], t.socket(), 5);
        let (resp, fd) = handle(
            &c,
            Request::List {
                token: good_token(),
            },
        )
        .await;
        assert!(fd.is_none());
        let Response::Sessions { sessions } = resp else {
            panic!("expected Sessions, got {resp:?}");
        };
        let mut names: Vec<_> = sessions.into_iter().map(|s| s.name).collect();
        names.sort();
        assert_eq!(names, vec!["base".to_string(), "other".to_string()]);

        let kill = |name: &str| Request::Kill {
            token: good_token(),
            name: name.into(),
        };
        assert_eq!(handle(&c, kill("other")).await.0, Response::Killed);
        assert_eq!(handle(&c, kill("other")).await.0, Response::NotFound);
        assert_eq!(session_names(t.socket()).await, vec!["base".to_string()]);
    }

    #[tokio::test]
    async fn session_cap_refuses_new_names_but_allows_existing_ones() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let c = ctx(vec![dec], t.socket(), 1);
        let open = |name: &str| Request::Open {
            token: good_token(),
            session: name.into(),
        };
        let (resp, fd) = handle(&c, open("fresh")).await;
        assert_eq!(
            resp,
            Response::Refused {
                reason: LIMIT_REASON.into()
            }
        );
        assert!(fd.is_none());

        let (resp, fd) = handle(&c, open("base")).await;
        assert!(matches!(resp, Response::Opened { .. }), "{resp:?}");
        assert!(read_some(fd.expect("Opened without an fd")).await > 0);
        assert_eq!(session_names(t.socket()).await, vec!["base".to_string()]);
    }

    #[tokio::test]
    async fn no_tmux_server_on_a_custom_socket_is_refused() {
        let Some((dec, _t)) = setup("base") else {
            return;
        };
        let missing = std::env::temp_dir().join("tmuxwrapper-test-helper-no-such-socket");
        let c = ctx(vec![dec], &missing, 5);
        let (resp, fd) = handle(
            &c,
            Request::Open {
                token: good_token(),
                session: "fresh".into(),
            },
        )
        .await;
        assert_eq!(
            resp,
            Response::Refused {
                reason: SERVER_REASON.into()
            }
        );
        assert!(fd.is_none());
    }

    #[tokio::test]
    async fn serve_survives_bad_json_and_releases_its_pty_copy() {
        let Some((dec, t)) = setup("base") else {
            return;
        };
        let (front, back) = seqpacket_pair().unwrap();
        // A malformed datagram, queued before serve starts.
        nix::unistd::write(&front, b"not json").unwrap();
        let front = AsyncSeqpacket::new(front).unwrap();
        let server = tokio::spawn(serve(
            ctx(vec![dec], t.socket(), 5),
            AsyncSeqpacket::new(back).unwrap(),
        ));

        let (resp, fd): (Response, _) = front.recv().await.unwrap();
        assert_eq!(resp, Response::BadRequest);
        assert!(fd.is_none());

        front
            .send(
                &Request::List {
                    token: good_token(),
                },
                None,
            )
            .await
            .unwrap();
        let (resp, _): (Response, _) = front.recv().await.unwrap();
        assert!(matches!(resp, Response::Sessions { .. }), "{resp:?}");

        front
            .send(
                &Request::Open {
                    token: good_token(),
                    session: "base".into(),
                },
                None,
            )
            .await
            .unwrap();
        let (resp, fd): (Response, _) = front.recv().await.unwrap();
        assert!(matches!(resp, Response::Opened { .. }), "{resp:?}");
        assert!(read_some(fd.expect("Opened without an fd")).await > 0);
        // read_some dropped our master. If the helper kept a copy, the tmux
        // client would never be hung up and "base" would stay attached.
        let detached = async {
            loop {
                let s = crate::tmux::list_sessions(Some(t.socket())).await;
                if s.iter().all(|s| !s.attached) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3), detached)
            .await
            .expect("tmux client still attached after the front closed its fd");

        drop(front);
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("serve did not return after the front closed")
            .unwrap();
    }
}

use crate::auth::{JwksCache, until_expiry};
use crate::config::{Config, UserConfig};
use crate::helper_client::{HelperClient, HelperDead};
use crate::proto::{Request, Response as HelperResponse};
use crate::pty::PtyMaster;
use crate::tmux::is_valid_session_name;
use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

/// Cap on simultaneous WebSocket connections per user (a browser tab each).
/// Distinct from the tmux-session cap, which is configurable via
/// `[terminal] max_sessions_per_user`.
const MAX_CONCURRENT_CONNECTIONS_PER_USER: usize = 5;

/// Close code sent when the Cloudflare Access session behind a live socket
/// lapses. The frontend reloads, which bounces through the Access login.
const CLOSE_CODE_SESSION_EXPIRED: u16 = 4001;

/// Close code used when the server refuses the socket (a connection or
/// session limit, or no tmux server to attach to). The reason text is
/// surfaced verbatim by the frontend.
const CLOSE_CODE_REFUSED: u16 = 4004;

/// Close reason sent with `CLOSE_CODE_SESSION_EXPIRED`.
const SESSION_EXPIRED: &str = "session expired";

/// Refusal reason when the helper could not hand over a usable terminal.
const OPEN_FAILED: &str = "could not start terminal";

/// Mask email for logging: "user@example.com" → "us***@example.com"
fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let visible = if local.len() <= 2 { local.len() } else { 2 };
            format!("{}***@{}", &local[..visible], domain)
        }
        None => "***".to_string(),
    }
}

pub struct AppState {
    pub config: Config,
    pub jwks: JwksCache,
    pub sessions: Mutex<HashMap<String, usize>>,
    /// One helper per configured user, keyed by `unix_user`.
    pub helpers: HashMap<String, HelperClient>,
}

#[derive(Debug, Deserialize)]
struct ControlMessage {
    #[serde(rename = "type")]
    msg_type: String,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub session: Option<String>,
}

/// Authenticated identity derived from a verified Cloudflare Access JWT.
struct AuthIdentity {
    /// Key used for session counting (the JWT email).
    key: String,
    /// Display string for logs.
    display_name: String,
    user_config: UserConfig,
    /// The verified Access JWT, forwarded to the helper (which re-verifies
    /// it). Never log it.
    token: String,
}

/// Extract and verify the Cloudflare Access JWT, return identity on success.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<AuthIdentity, StatusCode> {
    let token = headers
        .get("Cf-Access-Jwt-Assertion")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';').find_map(|c| {
                        let c = c.trim();
                        c.strip_prefix("CF_Authorization=").map(|t| t.to_string())
                    })
                })
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = state.jwks.verify(&token).await.map_err(|e| {
        warn!(error = %e, "JWT verification failed");
        StatusCode::UNAUTHORIZED
    })?;

    let user_config = state
        .config
        .find_user(&claims.email)
        .cloned()
        .ok_or_else(|| {
            warn!(email = %mask_email(&claims.email), "no user mapping found");
            StatusCode::FORBIDDEN
        })?;

    Ok(AuthIdentity {
        display_name: mask_email(&claims.email),
        key: claims.email,
        user_config,
        token,
    })
}

/// Send `req` to `unix_user`'s helper. `None` if no helper is configured for
/// the user (a startup bug). A dead helper ends the process — retrying on the
/// same socket could pair a late reply with the wrong request — and systemd
/// restarts the service.
async fn ask_helper(
    state: &AppState,
    unix_user: &str,
    req: &Request,
) -> Option<(HelperResponse, Option<OwnedFd>)> {
    let Some(helper) = state.helpers.get(unix_user) else {
        error!(unix_user = %unix_user, "no helper for this user");
        return None;
    };
    match helper.request(req).await {
        Ok(reply) => Some(reply),
        Err(HelperDead) => {
            error!(unix_user = %unix_user, "helper is dead or unresponsive — exiting");
            std::process::exit(1);
        }
    }
}

/// GET /api/sessions — list tmux sessions for the authenticated user
pub async fn sessions_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    let req = Request::List {
        token: identity.token,
    };
    let reply = ask_helper(&state, &identity.user_config.unix_user, &req).await;
    list_response(reply.map(|(resp, _fd)| resp))
}

fn list_response(resp: Option<HelperResponse>) -> Response {
    match resp {
        Some(HelperResponse::Sessions { sessions }) => Json(sessions).into_response(),
        Some(HelperResponse::Unauthorized) => StatusCode::UNAUTHORIZED.into_response(),
        Some(HelperResponse::Refused { .. }) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// DELETE /api/sessions/:name — kill a tmux session
pub async fn kill_session_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Validate session name
    if !is_valid_session_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let unix_user = identity.user_config.unix_user;
    let req = Request::Kill {
        token: identity.token,
        name: name.clone(),
    };
    let resp = ask_helper(&state, &unix_user, &req).await.map(|(r, _fd)| r);
    match &resp {
        Some(HelperResponse::Killed) => {
            info!(user = %unix_user, session = %name, "killed tmux session")
        }
        Some(HelperResponse::Refused { reason }) => {
            warn!(user = %unix_user, session = %name, reason = %reason, "kill-session refused")
        }
        _ => {}
    }
    kill_response(resp)
}

fn kill_response(resp: Option<HelperResponse>) -> Response {
    match resp {
        Some(HelperResponse::Killed) => StatusCode::OK,
        Some(HelperResponse::NotFound) => StatusCode::NOT_FOUND,
        Some(HelperResponse::BadRequest) => StatusCode::BAD_REQUEST,
        Some(HelperResponse::Unauthorized) => StatusCode::UNAUTHORIZED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
    .into_response()
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> Response {
    // Origin check (CF Access SameSite=None cookies need server-side CSRF protection).
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Extract hostname only (strip scheme and port) for exact comparison
        let origin_host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .unwrap_or(origin)
            .split(':')
            .next()
            .unwrap_or("");
        let host_name = host.split(':').next().unwrap_or("");
        if origin_host != host_name {
            warn!(origin = %origin, host = %host, "rejected WebSocket: origin mismatch");
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    let identity = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Validate requested session name if provided
    let session_name = query.session.clone();
    if let Some(ref name) = session_name
        && !is_valid_session_name(name)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let state_clone = Arc::clone(&state);
    ws.on_upgrade(move |socket| handle_socket(socket, state_clone, identity, session_name))
        .into_response()
}

async fn close_socket(mut socket: WebSocket, code: u16, reason: &str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

/// Refuse a freshly upgraded socket with a close frame the frontend surfaces.
async fn refuse_socket(socket: WebSocket, reason: &str) {
    close_socket(socket, CLOSE_CODE_REFUSED, reason).await;
}

async fn handle_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    identity: AuthIdentity,
    session_name: Option<String>,
) {
    let key = identity.key.clone();
    // Atomic check + increment of the per-user WebSocket connection count
    {
        let mut sessions = state.sessions.lock().await;
        let count = sessions.get(&key).copied().unwrap_or(0);
        if count >= MAX_CONCURRENT_CONNECTIONS_PER_USER {
            warn!(user = %identity.display_name, count, "connection limit reached");
            refuse_socket(
                socket,
                "connection limit reached — close another terminal tab first",
            )
            .await;
            return;
        }
        *sessions.entry(key.clone()).or_insert(0) += 1;
    }
    open_terminal(socket, &state, identity, session_name).await;
    decrement_session(&state, &key).await;
}

/// What to do with an upgraded socket, given the helper's reply to `Open`.
#[derive(Debug)]
enum OpenOutcome {
    Bridge { fd: OwnedFd, expires_in: Duration },
    Close { code: u16, reason: String },
}

impl OpenOutcome {
    fn refused(reason: &str) -> Self {
        OpenOutcome::Close {
            code: CLOSE_CODE_REFUSED,
            reason: reason.into(),
        }
    }

    fn expired() -> Self {
        OpenOutcome::Close {
            code: CLOSE_CODE_SESSION_EXPIRED,
            reason: SESSION_EXPIRED.into(),
        }
    }
}

/// Decide from the helper's reply (`None`: no helper for the user) and the
/// current time (unix seconds). A stray fd on a non-`Opened` reply is closed.
fn open_outcome(reply: Option<(HelperResponse, Option<OwnedFd>)>, now: u64) -> OpenOutcome {
    match reply {
        Some((HelperResponse::Opened { expires_at }, Some(fd))) => {
            let expires_in = until_expiry(expires_at, now);
            if expires_in.is_zero() {
                // Accepted within the verifier's leeway but already past `exp`.
                OpenOutcome::expired()
            } else {
                OpenOutcome::Bridge { fd, expires_in }
            }
        }
        Some((HelperResponse::Refused { reason }, _)) => OpenOutcome::refused(&reason),
        Some((HelperResponse::Unauthorized, _)) => OpenOutcome::expired(),
        // `Opened` without its fd is a protocol error; nothing else is a
        // valid answer to `Open`.
        Some(_) | None => OpenOutcome::refused(OPEN_FAILED),
    }
}

/// Ask the helper for a terminal and bridge it to the socket until either
/// side ends or the Access session lapses.
async fn open_terminal(
    socket: WebSocket,
    state: &AppState,
    identity: AuthIdentity,
    session_name: Option<String>,
) {
    let user = identity.display_name;
    let unix_user = identity.user_config.unix_user;
    let session = session_name.unwrap_or(identity.user_config.tmux_session);
    info!(user = %user, unix_user = %unix_user, session = %session, "opening terminal");

    let req = Request::Open {
        token: identity.token,
        session: session.clone(),
    };
    let reply = ask_helper(state, &unix_user, &req).await;
    if let Some((resp, fd)) = &reply
        && !matches!(resp, HelperResponse::Opened { .. } if fd.is_some())
    {
        warn!(user = %user, session = %session, reply = ?resp, has_fd = fd.is_some(), "terminal not opened");
    }
    // Authentication happens once, at upgrade; without a deadline a socket
    // would outlive the Access session indefinitely (pings keep it alive).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    let (fd, expires_in) = match open_outcome(reply, now) {
        OpenOutcome::Bridge { fd, expires_in } => (fd, expires_in),
        OpenOutcome::Close { code, reason } => {
            close_socket(socket, code, &reason).await;
            return;
        }
    };
    let pty = match PtyMaster::from_fd(fd) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "could not use the PTY from the helper");
            refuse_socket(socket, OPEN_FAILED).await;
            return;
        }
    };
    run_bridge(
        socket,
        pty,
        state.config.terminal.ping_interval_secs,
        expires_in,
        &user,
        &session,
    )
    .await;
    info!(user = %user, "session ended");
}

async fn decrement_session(state: &AppState, key: &str) {
    let mut sessions = state.sessions.lock().await;
    if let Some(count) = sessions.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            sessions.remove(key);
        }
    }
}

// Binary WebSocket protocol:
//   0x00 — raw terminal data (both directions)
//   0x01 — JSON control message, client → server (currently only resize)
enum WsInput {
    Data(Vec<u8>),
    Resize(u16, u16),
    Close,
}

async fn run_bridge(
    mut socket: WebSocket,
    pty: PtyMaster,
    ping_interval_secs: u64,
    expires_in: Duration,
    user: &str,
    session: &str,
) {
    let user = user.to_string();
    let session = session.to_string();
    // Shared by the reader and writer tasks; the master closes (hanging up the
    // tmux client) once both have been dropped.
    let pty = Arc::new(pty);
    let pty_reader = Arc::clone(&pty);
    let pty_writer = pty;
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(16);
    let (ws_in_tx, mut ws_in_rx) = mpsc::channel::<WsInput>(16);

    // Task 1: WebSocket I/O loop — owns the socket
    let user1 = user.clone();
    let session1 = session.clone();
    let mut ws_task = tokio::spawn(async move {
        let mut ping_ticker = interval(Duration::from_secs(ping_interval_secs));
        let expiry = tokio::time::sleep(expires_in);
        tokio::pin!(expiry);
        loop {
            tokio::select! {
                _ = &mut expiry => {
                    info!(user = %user1, session = %session1, "Access session expired — closing socket");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_CODE_SESSION_EXPIRED,
                            reason: SESSION_EXPIRED.into(),
                        })))
                        .await;
                    break;
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if data.is_empty() {
                                continue;
                            }
                            let input = match data[0] {
                                0x00 => WsInput::Data(data[1..].to_vec()),
                                0x01 => {
                                    if let Ok(ctrl) = serde_json::from_slice::<ControlMessage>(&data[1..]) {
                                        if ctrl.msg_type == "resize" {
                                            if let (Some(cols), Some(rows)) = (ctrl.cols, ctrl.rows) {
                                                WsInput::Resize(cols, rows)
                                            } else {
                                                continue;
                                            }
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        continue;
                                    }
                                }
                                _ => continue,
                            };
                            if ws_in_tx.send(input).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            let _ = ws_in_tx.send(WsInput::Close).await;
                            break;
                        }
                        Some(Err(e)) => {
                            warn!(user = %user1, session = %session1, error = %e, "WebSocket recv error");
                            break;
                        }
                        _ => {}
                    }
                }
                Some(msg) = ws_out_rx.recv() => {
                    if socket.send(msg).await.is_err() {
                        break;
                    }
                }
                _ = ping_ticker.tick() => {
                    if socket.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task 2: PTY → WebSocket
    let user2 = user.clone();
    let session2 = session.clone();
    let ws_out_tx_clone = ws_out_tx.clone();
    let mut pty_to_ws = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut pty_read = &*pty_reader;
        loop {
            match pty_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut frame = Vec::with_capacity(1 + n);
                    frame.push(0x00);
                    frame.extend_from_slice(&buf[..n]);
                    if ws_out_tx_clone
                        .send(Message::Binary(frame.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    warn!(user = %user2, session = %session2, error = %e, "PTY read error");
                    break;
                }
            }
        }
    });

    // Task 3: WebSocket → PTY
    let mut ws_to_pty = tokio::spawn(async move {
        let mut pty_write = &*pty_writer;
        while let Some(input) = ws_in_rx.recv().await {
            match input {
                WsInput::Data(data) => {
                    if let Err(e) = pty_write.write_all(&data).await {
                        warn!(user = %user, session = %session, error = %e, "PTY write error");
                        break;
                    }
                }
                WsInput::Resize(cols, rows) => pty_write.resize(cols, rows),
                WsInput::Close => break,
            }
        }
    });

    // Wait for any task to finish, then abort the others
    tokio::select! {
        _ = &mut ws_task => {}
        _ = &mut pty_to_ws => {}
        _ = &mut ws_to_pty => {}
    }

    ws_task.abort();
    pty_to_ws.abort();
    ws_to_pty.abort();
    drop(ws_out_tx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SessionInfo;

    #[test]
    fn mask_email_hides_local_part() {
        assert_eq!(mask_email("user@example.com"), "us***@example.com");
        assert_eq!(mask_email("ab@example.com"), "ab***@example.com");
        assert_eq!(mask_email("not-an-email"), "***");
    }

    fn some_fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    fn refused(reason: &str) -> HelperResponse {
        HelperResponse::Refused {
            reason: reason.into(),
        }
    }

    #[tokio::test]
    async fn sessions_reply_is_the_same_json_shape_as_before() {
        let resp = list_response(Some(HelperResponse::Sessions {
            sessions: vec![SessionInfo {
                name: "main".into(),
                windows: 2,
                attached: true,
            }],
        }));
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!([{"name": "main", "windows": 2, "attached": true}])
        );
    }

    #[test]
    fn list_statuses() {
        let status = |r| list_response(r).status();
        assert_eq!(
            status(Some(HelperResponse::Unauthorized)),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(Some(refused("auth keys unavailable — try again shortly"))),
            StatusCode::SERVICE_UNAVAILABLE
        );
        for other in [HelperResponse::Killed, HelperResponse::BadRequest] {
            assert_eq!(status(Some(other)), StatusCode::INTERNAL_SERVER_ERROR);
        }
        assert_eq!(status(None), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn kill_statuses() {
        let status = |r| kill_response(r).status();
        assert_eq!(status(Some(HelperResponse::Killed)), StatusCode::OK);
        assert_eq!(
            status(Some(HelperResponse::NotFound)),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(Some(HelperResponse::BadRequest)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(Some(HelperResponse::Unauthorized)),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(Some(refused("could not kill session"))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status(Some(HelperResponse::Sessions { sessions: vec![] })),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(status(None), StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn close_of(outcome: OpenOutcome) -> (u16, String) {
        match outcome {
            OpenOutcome::Close { code, reason } => (code, reason),
            OpenOutcome::Bridge { .. } => panic!("expected a close, got a bridge"),
        }
    }

    #[test]
    fn opened_with_fd_bridges_until_expiry() {
        let reply = (HelperResponse::Opened { expires_at: 1300 }, Some(some_fd()));
        match open_outcome(Some(reply), 1000) {
            OpenOutcome::Bridge { expires_in, .. } => {
                assert_eq!(expires_in, Duration::from_secs(300))
            }
            other => panic!("expected a bridge, got {other:?}"),
        }
    }

    #[test]
    fn opened_at_or_past_expiry_closes_as_expired() {
        for expires_at in [1000, 990] {
            let reply = (HelperResponse::Opened { expires_at }, Some(some_fd()));
            assert_eq!(
                close_of(open_outcome(Some(reply), 1000)),
                (4001, "session expired".to_string()),
                "expires_at {expires_at}"
            );
        }
    }

    #[test]
    fn helper_refusals_and_failures_close_the_socket() {
        let limit = "session limit reached — kill an old session first";
        let no_server = "tmux server isn't running — start tmux-server.service";
        let failed = (4004, "could not start terminal".to_string());
        let cases = [
            (Some((refused(limit), None)), (4004, limit.to_string())),
            (
                Some((refused(no_server), None)),
                (4004, no_server.to_string()),
            ),
            // A stray fd on a refusal is ignored (and closed).
            (
                Some((refused(limit), Some(some_fd()))),
                (4004, limit.to_string()),
            ),
            (
                Some((HelperResponse::Unauthorized, None)),
                (4001, "session expired".to_string()),
            ),
            (
                Some((
                    HelperResponse::Opened {
                        expires_at: u64::MAX,
                    },
                    None,
                )),
                failed.clone(),
            ),
            (Some((HelperResponse::BadRequest, None)), failed.clone()),
            (Some((HelperResponse::Killed, None)), failed.clone()),
            (None, failed.clone()),
        ];
        for (reply, want) in cases {
            let desc = format!("{:?}", reply.as_ref().map(|(r, fd)| (r, fd.is_some())));
            assert_eq!(close_of(open_outcome(reply, 1000)), want, "{desc}");
        }
    }

    /// Nothing in `src/` shells out to switch users any more (the helper
    /// already runs as the user), and `pty.rs` no longer forks or calls
    /// setuid itself.
    #[test]
    fn no_user_switching_command_in_src_and_no_fork_in_pty() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Built at runtime so this file doesn't match itself.
        let needle = ["su", "do"].concat();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains(&needle),
                "{} mentions {needle}",
                path.display()
            );
        }
        let pty = std::fs::read_to_string(src.join("pty.rs")).unwrap();
        for word in [["fo", "rk("].concat(), ["set", "uid"].concat()] {
            assert!(!pty.contains(&word), "pty.rs contains {word}");
        }
    }
}

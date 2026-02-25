use crate::auth::AuthProvider;
use crate::config::{AuthMode, Config, UserConfig};
use crate::password_auth::PasswordAuth;
use crate::pty::PtyMaster;
use crate::user::ResolvedUser;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use nix::libc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant, interval};
use tracing::{error, info, warn};

const MAX_SESSIONS_PER_USER: usize = 5;

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

/// Mask username for logging: "ktulu" → "kt***"
fn mask_username(username: &str) -> String {
    let visible = if username.len() <= 2 { username.len() } else { 2 };
    format!("{}***", &username[..visible])
}

/// Per-IP login attempt tracker for brute-force protection.
pub struct LoginRateLimiter {
    /// Maps IP → (failure count, window start).
    attempts: Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>,
}

const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOGIN_WINDOW_SECS: u64 = 60;

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the IP is rate-limited (too many failures).
    async fn is_limited(&self, ip: std::net::IpAddr) -> bool {
        let mut map = self.attempts.lock().await;
        if let Some((count, start)) = map.get(&ip) {
            if start.elapsed().as_secs() >= LOGIN_WINDOW_SECS {
                map.remove(&ip);
                return false;
            }
            *count >= MAX_LOGIN_ATTEMPTS
        } else {
            false
        }
    }

    /// Record a failed login attempt for an IP.
    async fn record_failure(&self, ip: std::net::IpAddr) {
        let mut map = self.attempts.lock().await;
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= LOGIN_WINDOW_SECS {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }

    /// Clear failures for an IP after successful login.
    async fn clear(&self, ip: std::net::IpAddr) {
        self.attempts.lock().await.remove(&ip);
    }
}

pub struct AppState {
    pub config: Config,
    pub auth: AuthProvider,
    pub sessions: Mutex<HashMap<String, usize>>,
    pub login_limiter: LoginRateLimiter,
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

#[derive(Debug, Serialize)]
pub struct TmuxSession {
    name: String,
    windows: u32,
    attached: bool,
}

/// Authenticated identity — either an email (CF) or username (password).
struct AuthIdentity {
    /// Key used for session counting (email or username).
    key: String,
    /// Display string for logs.
    display_name: String,
    user_config: UserConfig,
}

/// Extract and verify auth from headers, return identity on success.
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthIdentity, StatusCode> {
    match &state.auth {
        AuthProvider::Cloudflare(jwks) => {
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

            let claims = jwks
                .verify(&token)
                .await
                .map_err(|e| {
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
            })
        }
        AuthProvider::Password(pw_auth) => {
            let token = headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';').find_map(|c| {
                        let c = c.trim();
                        c.strip_prefix("tmw_session=").map(|t| t.to_string())
                    })
                })
                .ok_or(StatusCode::UNAUTHORIZED)?;

            let username = pw_auth
                .verify_session_token(&token)
                .ok_or(StatusCode::UNAUTHORIZED)?;

            let user_config = state
                .config
                .find_user_by_username(&username)
                .cloned()
                .ok_or_else(|| {
                    warn!(user = %mask_username(&username), "no user mapping found");
                    StatusCode::FORBIDDEN
                })?;

            Ok(AuthIdentity {
                display_name: mask_username(&username),
                key: username,
                user_config,
            })
        }
    }
}

/// POST /api/login — password auth login
#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let pw_auth = match &state.auth {
        AuthProvider::Password(pw) => pw,
        AuthProvider::Cloudflare(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    // Rate limit — 5 failed attempts per IP per minute
    let client_ip = addr.ip();
    if state.login_limiter.is_limited(client_ip).await {
        warn!(ip = %client_ip, "login rate-limited");
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Origin check — reject cross-origin login attempts
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        let origin_host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .unwrap_or(origin)
            .split(':')
            .next()
            .unwrap_or("");
        let host_name = host.split(':').next().unwrap_or("");
        if origin_host != host_name {
            warn!(origin = %origin, "rejected login: origin mismatch");
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    let user = match state.config.find_user_by_username(&body.username) {
        Some(u) => u.clone(),
        None => {
            warn!(user = %mask_username(&body.username), "login: unknown user");
            state.login_limiter.record_failure(client_ip).await;
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let hash = match &user.password_hash {
        Some(h) => h.clone(),
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let password = body.password.clone();
    let valid = match tokio::task::spawn_blocking(move || {
        PasswordAuth::verify_password(&hash, &password)
    })
    .await
    {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => {
            warn!(user = %mask_username(&body.username), "login: wrong password");
            false
        }
        Ok(Err(e)) => {
            error!(error = %e, "bcrypt error");
            false
        }
        Err(e) => {
            error!(error = %e, "spawn_blocking failed");
            false
        }
    };

    if !valid {
        state.login_limiter.record_failure(client_ip).await;
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state.login_limiter.clear(client_ip).await;
    let token = pw_auth.create_session_token(&body.username);
    let max_age = pw_auth.session_duration_secs();
    info!(user = %mask_username(&body.username), "login successful");

    Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            format!("tmw_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"),
        )
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"ok":true}"#))
        .unwrap()
        .into_response()
}

/// GET /api/sessions — list tmux sessions for the authenticated user
pub async fn sessions_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let identity = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Run `tmux list-sessions` as the target user
    let output = tokio::process::Command::new("/usr/bin/sudo")
        .args([
            "-u",
            &identity.user_config.unix_user,
            "/usr/bin/tmux",
            "list-sessions",
            "-F",
            "#{session_name}\t#{session_windows}\t#{session_attached}",
        ])
        .output()
        .await;

    let sessions: Vec<TmuxSession> = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 3 {
                        Some(TmuxSession {
                            name: parts[0].to_string(),
                            windows: parts[1].parse().unwrap_or(0),
                            attached: parts[2] != "0",
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }
        Err(_) => vec![],
    };

    Json(sessions).into_response()
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
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let output = tokio::process::Command::new("/usr/bin/sudo")
        .args(["-u", &identity.user_config.unix_user, "/usr/bin/tmux", "kill-session", "-t", &name])
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!(user = %identity.user_config.unix_user, session = %name, "killed tmux session");
            StatusCode::OK.into_response()
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warn!(user = %identity.user_config.unix_user, session = %name, error = %stderr, "kill-session failed");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            error!(error = %e, "failed to run tmux kill-session");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> Response {
    // Origin check for CF mode (SameSite=None cookies need server-side CSRF protection).
    // Password mode uses SameSite=Strict cookies, which handles CSRF.
    if matches!(state.config.parsed_auth_mode(), Ok(AuthMode::Cloudflare)) {
        if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
            let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
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
    }

    let identity = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Validate requested session name if provided
    let session_name = query.session.clone();
    if let Some(ref name) = session_name {
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    let state_clone = Arc::clone(&state);
    ws.on_upgrade(move |socket| {
        handle_socket(socket, state_clone, identity.key, identity.display_name, identity.user_config, session_name)
    })
    .into_response()
}

async fn handle_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    session_key: String,
    display_name: String,
    user_config: UserConfig,
    session_name: Option<String>,
) {
    // Atomic check + increment session limit
    {
        let mut sessions = state.sessions.lock().await;
        let count = sessions.get(&session_key).copied().unwrap_or(0);
        if count >= MAX_SESSIONS_PER_USER {
            warn!(user = %display_name, count, "session limit reached");
            return;
        }
        *sessions.entry(session_key.clone()).or_insert(0) += 1;
    }

    // Resolve unix user
    let mut resolved = match ResolvedUser::from_config(&user_config) {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "user resolution failed");
            decrement_session(&state, &session_key).await;
            return;
        }
    };

    // Override session name if provided in query
    if let Some(name) = session_name {
        resolved.tmux_session = name;
    }

    info!(
        user = %display_name,
        unix_user = %user_config.unix_user,
        session = %resolved.tmux_session,
        "spawning PTY"
    );

    // Spawn PTY with tmux
    let pty = match PtyMaster::spawn(&resolved) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "PTY spawn failed");
            decrement_session(&state, &session_key).await;
            return;
        }
    };

    let session_label = resolved.tmux_session.clone();
    run_bridge(socket, pty, state.config.terminal.ping_interval_secs, &display_name, &session_label).await;
    decrement_session(&state, &session_key).await;
    info!(user = %display_name, "session ended");
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

fn pty_resize(fd: &OwnedFd, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

enum WsInput {
    Data(Vec<u8>),
    Resize(u16, u16),
    Close,
}

async fn run_bridge(mut socket: WebSocket, pty: PtyMaster, ping_interval_secs: u64, user: &str, session: &str) {
    let user = user.to_string();
    let session = session.to_string();
    // dup() the PTY fd for resize ioctls — owns its own fd independently
    // so there's no use-after-close if the PtyMaster is dropped first.
    let resize_fd = nix::unistd::dup(unsafe { BorrowedFd::borrow_raw(pty.raw_fd()) }).ok();
    let (mut pty_read, mut pty_write) = tokio::io::split(pty);
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(16);
    let (ws_in_tx, mut ws_in_rx) = mpsc::channel::<WsInput>(16);

    // Task 1: WebSocket I/O loop — owns the socket
    let user1 = user.clone();
    let session1 = session.clone();
    let mut ws_task = tokio::spawn(async move {
        let mut ping_ticker = interval(Duration::from_secs(ping_interval_secs));
        loop {
            tokio::select! {
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
        while let Some(input) = ws_in_rx.recv().await {
            match input {
                WsInput::Data(data) => {
                    if let Err(e) = pty_write.write_all(&data).await {
                        warn!(user = %user, session = %session, error = %e, "PTY write error");
                        break;
                    }
                }
                WsInput::Resize(cols, rows) => {
                    if let Some(ref fd) = resize_fd {
                        pty_resize(fd, cols, rows);
                    }
                }
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

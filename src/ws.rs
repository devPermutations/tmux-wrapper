use crate::auth::JwksCache;
use crate::config::Config;
use crate::pty::PtyMaster;
use crate::user::ResolvedUser;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use nix::libc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
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

pub struct AppState {
    pub config: Config,
    pub jwks: JwksCache,
    pub sessions: Mutex<HashMap<String, usize>>,
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

/// Extract and verify JWT from headers, return claims + user config on success.
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, crate::config::UserConfig), StatusCode> {
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

    let claims = state
        .jwks
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

    Ok((claims.email, user_config))
}

/// GET /api/sessions — list tmux sessions for the authenticated user
pub async fn sessions_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let (_email, user_config) = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Run `tmux list-sessions` as the target user
    let output = tokio::process::Command::new("sudo")
        .args([
            "-u",
            &user_config.unix_user,
            "tmux",
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
    let (_email, user_config) = match authenticate(&state, &headers).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };

    // Validate session name
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let output = tokio::process::Command::new("sudo")
        .args(["-u", &user_config.unix_user, "tmux", "kill-session", "-t", &name])
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!(user = %user_config.unix_user, session = %name, "killed tmux session");
            StatusCode::OK.into_response()
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warn!(user = %user_config.unix_user, session = %name, error = %stderr, "kill-session failed");
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
    let (email, user_config) = match authenticate(&state, &headers).await {
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
        handle_socket(socket, state_clone, email, user_config, session_name)
    })
    .into_response()
}

async fn handle_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    email: String,
    user_config: crate::config::UserConfig,
    session_name: Option<String>,
) {
    // Atomic check + increment session limit
    {
        let mut sessions = state.sessions.lock().await;
        let count = sessions.get(&email).copied().unwrap_or(0);
        if count >= MAX_SESSIONS_PER_USER {
            warn!(user = %mask_email(&email), count, "session limit reached");
            return;
        }
        *sessions.entry(email.clone()).or_insert(0) += 1;
    }

    // Resolve unix user
    let mut resolved = match ResolvedUser::from_config(&user_config) {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "user resolution failed");
            decrement_session(&state, &email).await;
            return;
        }
    };

    // Override session name if provided in query
    if let Some(name) = session_name {
        resolved.tmux_session = name;
    }

    info!(
        user = %mask_email(&email),
        unix_user = %user_config.unix_user,
        session = %resolved.tmux_session,
        "spawning PTY"
    );

    // Spawn PTY with tmux
    let pty = match PtyMaster::spawn(&resolved) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "PTY spawn failed");
            decrement_session(&state, &email).await;
            return;
        }
    };

    run_bridge(socket, pty, state.config.terminal.ping_interval_secs).await;
    decrement_session(&state, &email).await;
    info!(user = %mask_email(&email), "session ended");
}

async fn decrement_session(state: &AppState, email: &str) {
    let mut sessions = state.sessions.lock().await;
    if let Some(count) = sessions.get_mut(email) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            sessions.remove(email);
        }
    }
}

fn pty_resize(fd: RawFd, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

enum WsInput {
    Data(Vec<u8>),
    Resize(u16, u16),
    Close,
}

async fn run_bridge(mut socket: WebSocket, pty: PtyMaster, ping_interval_secs: u64) {
    let pty_fd = pty.raw_fd();
    let (mut pty_read, mut pty_write) = tokio::io::split(pty);
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(64);
    let (ws_in_tx, mut ws_in_rx) = mpsc::channel::<WsInput>(64);

    // Task 1: WebSocket I/O loop — owns the socket
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
                            warn!(error = %e, "WebSocket recv error");
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
                    warn!(error = %e, "PTY read error");
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
                        warn!(error = %e, "PTY write error");
                        break;
                    }
                }
                WsInput::Resize(cols, rows) => {
                    pty_resize(pty_fd, cols, rows);
                }
                WsInput::Close => break,
            }
        }
    });

    // Wait for any task to finish
    tokio::select! {
        _ = &mut ws_task => {}
        _ = &mut pty_to_ws => {}
        _ = &mut ws_to_pty => {}
    }

    drop(ws_out_tx);
}

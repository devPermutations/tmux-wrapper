mod auth;
mod config;
mod helper;
mod helper_client;
mod helper_watch;
mod privdrop;
mod proto;
mod pty;
#[cfg(test)]
mod test_support;
mod tmux;
mod user;
mod ws;

use crate::auth::JwksCache;
use crate::config::{Config, UserConfig};
use crate::helper::run_helper;
use crate::helper_client::HelperClient;
use crate::privdrop::drop_privileges;
use crate::proto::seqpacket_pair;
use crate::user::{ResolvedUser, shares_identity};
use crate::ws::{AppState, kill_session_handler, sessions_handler, ws_handler};
use axum::Router;
use axum::routing::{delete, get};
use nix::sys::prctl;
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, Pid, fork, geteuid, getpid, getppid};
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{error, info, warn};

/// Startup runs as root on a single thread: resolve users, fork one helper
/// per user (each drops to that user), drop the front to `run_as`, and only
/// then start the tokio runtime. Nothing before the drop may start a thread
/// (no runtime, no reqwest client): `fork` must see a single-threaded process.
fn main() {
    tracing_subscriber::fmt::init();

    if !geteuid().is_root() {
        fatal("tmuxwrapper must start as root (it drops privileges itself)");
    }

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = Config::load(Path::new(&config_path))
        .unwrap_or_else(|e| fatal(&format!("failed to load config: {e}")));
    let run_as = match ResolvedUser::by_name(&config.run_as) {
        Ok(Some(user)) => user,
        Ok(None) => fatal(&format!(
            "system user '{}' not found — run deploy.sh",
            config.run_as
        )),
        Err(e) => fatal(&e),
    };

    // Unknown users are logged and skipped: their requests fail closed.
    let users: Vec<(&UserConfig, ResolvedUser)> = config
        .users
        .iter()
        .filter_map(|user| match ResolvedUser::from_config(user) {
            Ok(resolved) => Some((user, resolved)),
            Err(e) => {
                error!(error = %e, "no helper for this user");
                None
            }
        })
        .collect();
    if let Some(clash) = shares_identity(&run_as, users.iter().map(|(_, r)| r)) {
        fatal(&format!(
            "run_as '{}' shares uid/gid with unix_user '{}' — use a dedicated system user",
            run_as.name, clash.name
        ));
    }

    let helpers = fork_helpers(users, &config);

    if let Err(e) = drop_privileges(run_as.uid, run_as.gid, &[]) {
        fatal(&format!("front: {e}"));
    }
    info!(user = %run_as.name, "front dropped privileges");

    // The helpers' PDEATHSIG fires when the thread that forked them exits,
    // so that must be the thread that lives as long as the process: main,
    // which blocks here until shutdown.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal(&format!("failed to build tokio runtime: {e}")));
    rt.block_on(run_front(config, helpers));
}

/// Log and exit non-zero. Only for startup, before any input is handled.
fn fatal(msg: &str) -> ! {
    error!("{msg}");
    std::process::exit(1)
}

/// A forked helper as the front sees it: its unix user, pid and the front's
/// end of its socket.
struct ForkedHelper {
    unix_user: String,
    pid: Pid,
    sock: OwnedFd,
}

/// Fork one helper per resolved user and return them. Runs as root,
/// single-threaded.
fn fork_helpers(users: Vec<(&UserConfig, ResolvedUser)>, config: &Config) -> Vec<ForkedHelper> {
    // Guard the invariant the forks rely on (see main).
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    if !status
        .lines()
        .any(|l| l.split_whitespace().eq(["Threads:", "1"]))
    {
        fatal("refusing to fork helpers: process is not single-threaded");
    }
    let parent = getpid();
    let mut fronts: Vec<ForkedHelper> = Vec::new();
    for (user, resolved) in users {
        let (front, back) = seqpacket_pair()
            .unwrap_or_else(|e| fatal(&format!("failed to create helper socket: {e}")));
        // SAFETY: no other thread exists yet (no runtime, no reqwest client),
        // so the child is an ordinary single-threaded process and may run
        // ordinary Rust after the fork — no async-signal-safety restriction.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Keep only our own end: drop the front's end of our socket
                // and of every earlier helper's (their helper ends were
                // closed in the parent right after each fork).
                drop(front);
                fronts.clear();
                become_helper(back, user, resolved, config, parent)
            }
            Ok(ForkResult::Parent { child }) => {
                drop(back);
                info!(unix_user = %user.unix_user, pid = %child, "forked helper");
                fronts.push(ForkedHelper {
                    unix_user: user.unix_user.clone(),
                    pid: child,
                    sock: front,
                });
            }
            Err(e) => fatal(&format!("fork failed: {e}")),
        }
    }
    fronts
}

/// The forked child: drop to `resolved`, tie our life to the front's, set up
/// the user's environment and run the helper. Never returns.
fn become_helper(
    sock: OwnedFd,
    user: &UserConfig,
    resolved: ResolvedUser,
    config: &Config,
    parent: Pid,
) -> ! {
    if let Err(e) = drop_privileges(resolved.uid, resolved.gid, &[resolved.gid]) {
        fatal(&format!("helper for '{}': {e}", user.unix_user));
    }
    // After the drop: a credential change clears the parent-death signal.
    if let Err(e) = prctl::set_pdeathsig(Signal::SIGTERM) {
        fatal(&format!("helper: PR_SET_PDEATHSIG failed: {e}"));
    }
    if getppid() != parent {
        // The front died before PDEATHSIG was armed.
        warn!("helper: front already exited");
        std::process::exit(1);
    }
    let uid = resolved.uid.as_raw();
    // SAFETY: single-threaded child before any runtime.
    unsafe {
        std::env::set_var("HOME", &resolved.home);
        std::env::set_var("USER", &resolved.name);
        std::env::set_var("LOGNAME", &resolved.name);
        std::env::set_var("SHELL", &resolved.shell);
        std::env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{uid}/bus"),
        );
        std::env::remove_var("TMUX");
    }
    info!(unix_user = %user.unix_user, "helper dropped privileges");
    run_helper(
        sock,
        user.clone(),
        PathBuf::from(resolved.home),
        &config.cloudflare,
        config.terminal.max_sessions_per_user,
    )
}

/// The front, after the drop: helper watch, JWKS, helper clients, HTTP.
async fn run_front(config: Config, forked: Vec<ForkedHelper>) {
    // First, so a helper that already died is noticed before serving.
    let pids = forked
        .iter()
        .map(|h| (h.unix_user.clone(), h.pid))
        .collect();
    if let Err(e) = helper_watch::spawn(pids) {
        fatal(&format!("failed to install SIGCHLD handler: {e}"));
    }

    let listen_addr = config.listen.clone();

    let cf = &config.cloudflare;
    let jwks = JwksCache::new(&cf.resolved_jwks_url(), &cf.resolved_issuer(), &cf.audience);
    if let Err(e) = jwks.refresh().await {
        warn!(error = %e, "initial JWKS fetch failed (will retry in background)");
    }
    jwks.spawn_refresh_task(cf.jwks_refresh_secs);

    let helpers = forked
        .into_iter()
        .map(|h| {
            let client = HelperClient::new(h.sock)
                .unwrap_or_else(|e| fatal(&format!("failed to set up helper client: {e}")));
            (h.unix_user, client)
        })
        .collect();

    let state = Arc::new(AppState {
        jwks,
        config,
        sessions: Mutex::new(HashMap::new()),
        helpers,
    });

    let static_dir = state.config.static_dir.clone();
    let static_service = ServeDir::new(&static_dir);
    let no_cache = SetResponseHeaderLayer::overriding(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    let csp = SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:; img-src 'self'; media-src 'self' blob:; frame-ancestors 'none'",
        ),
    );
    let nosniff = SetResponseHeaderLayer::overriding(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let referrer = SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    let permissions = SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    let app: Router = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/sessions", get(sessions_handler))
        .route("/api/sessions/{name}", delete(kill_session_handler))
        .fallback_service(static_service)
        .layer(no_cache)
        .layer(csp)
        .layer(nosniff)
        .layer(referrer)
        .layer(permissions)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("failed to bind");

    info!(addr = %listen_addr, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => { info!("received SIGINT, shutting down"); }
        _ = sigterm.recv() => { info!("received SIGTERM, shutting down"); }
    }

    // Force exit after grace period — WebSocket sessions are long-lived
    // and won't close on their own during graceful shutdown.
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        info!("graceful shutdown timeout, forcing exit");
        std::process::exit(0);
    });
}

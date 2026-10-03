mod auth;
mod config;
mod helper;
mod helper_client;
mod proto;
mod pty;
#[cfg(test)]
mod test_support;
mod tmux;
mod user;
mod ws;

use crate::auth::JwksCache;
use crate::config::{CloudflareConfig, Config, UserConfig};
use crate::helper::HelperCtx;
use crate::helper_client::HelperClient;
use crate::proto::{AsyncSeqpacket, seqpacket_pair};
use crate::user::ResolvedUser;
use crate::ws::{AppState, kill_session_handler, sessions_handler, ws_handler};
use axum::Router;
use axum::routing::{delete, get};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config = Config::load(Path::new(&config_path)).expect("failed to load config");
    let listen_addr = config.listen.clone();

    let cf = &config.cloudflare;
    let jwks = JwksCache::new(&cf.resolved_jwks_url(), &cf.resolved_issuer(), &cf.audience);
    if let Err(e) = jwks.refresh().await {
        tracing::warn!(error = %e, "initial JWKS fetch failed (will retry in background)");
    }
    jwks.spawn_refresh_task(cf.jwks_refresh_secs);

    // Interim: Task 6 forks the helper and drops privileges instead.
    let helpers = config
        .users
        .iter()
        .filter_map(|user| {
            let client = spawn_in_process_helper(
                user,
                &config.cloudflare,
                config.terminal.max_sessions_per_user,
            )?;
            Some((user.unix_user.clone(), client))
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

/// Interim (replaced in Task 6): run `user`'s helper on its own thread and
/// current-thread runtime, in this process and with its privileges. `None`
/// (logged) if the unix user doesn't exist; that user's requests then fail.
fn spawn_in_process_helper(
    user: &UserConfig,
    cf: &CloudflareConfig,
    max_sessions: usize,
) -> Option<HelperClient> {
    let home = match ResolvedUser::from_config(user) {
        Ok(resolved) => resolved.home.into(),
        Err(e) => {
            tracing::error!(error = %e, "no helper for this user");
            return None;
        }
    };
    let (front, back) = seqpacket_pair().expect("failed to create helper socket");
    let user = user.clone();
    let jwks = JwksCache::new(&cf.resolved_jwks_url(), &cf.resolved_issuer(), &cf.audience);
    let refresh_secs = cf.jwks_refresh_secs;
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build helper runtime");
        rt.block_on(async move {
            let sock = AsyncSeqpacket::new(back).expect("bad helper socket");
            if let Err(e) = jwks.refresh().await {
                tracing::warn!(error = %e, "helper: initial JWKS fetch failed (will retry in background)");
            }
            jwks.spawn_refresh_task(refresh_secs);
            let ctx = HelperCtx {
                user,
                home,
                jwks,
                max_sessions,
                tmux_socket: None,
            };
            helper::serve(ctx, sock).await;
        });
    });
    Some(HelperClient::new(front).expect("failed to set up helper client"))
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

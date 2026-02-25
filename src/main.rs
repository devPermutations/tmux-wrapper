mod auth;
mod config;
mod password_auth;
mod pty;
mod user;
mod ws;

use crate::auth::{AuthProvider, JwksCache};
use crate::config::{AuthMode, Config};
use crate::password_auth::PasswordAuth;
use crate::ws::{AppState, kill_session_handler, login_handler, sessions_handler, ws_handler};
use axum::Router;
use axum::routing::{delete, get, post};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

#[tokio::main]
async fn main() {
    // Handle hash-password subcommand before anything else
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        hash_password_cmd();
        return;
    }

    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config = Config::load(Path::new(&config_path)).expect("failed to load config");
    let listen_addr = config.listen.clone();
    let auth_mode = config.parsed_auth_mode().expect("invalid auth_mode");

    // TLS warning for password mode on wildcard address
    if auth_mode == AuthMode::Password && config.listen.starts_with("0.0.0.0") {
        tracing::warn!(
            "password auth on 0.0.0.0 without TLS — credentials will be sent in plaintext. \
             Use a reverse proxy (nginx, caddy) with TLS in production."
        );
    }

    let auth = match auth_mode {
        AuthMode::Cloudflare => {
            let cf = config.cloudflare.as_ref().expect("cloudflare config required");
            let jwks = JwksCache::new(&cf.team_domain, &cf.audience);
            if let Err(e) = jwks.refresh().await {
                tracing::warn!(error = %e, "initial JWKS fetch failed (will retry in background)");
            }
            jwks.spawn_refresh_task(cf.jwks_refresh_secs);
            AuthProvider::Cloudflare(jwks)
        }
        AuthMode::Password => {
            info!("password auth mode — HMAC session key generated");
            AuthProvider::Password(PasswordAuth::new(config.terminal.session_duration_secs))
        }
    };

    let state = Arc::new(AppState {
        config,
        auth,
        sessions: Mutex::new(HashMap::new()),
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
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' wss:; img-src 'self'; frame-ancestors 'none'",
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
        .route("/api/login", post(login_handler))
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
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

fn hash_password_cmd() {
    eprintln!("Enter password: ");
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .expect("failed to read password");
    let password = password.trim_end_matches('\n').trim_end_matches('\r');
    if password.is_empty() {
        eprintln!("Error: empty password");
        std::process::exit(1);
    }
    let hash = bcrypt::hash(password, 12).expect("bcrypt hash failed");
    println!("{hash}");
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

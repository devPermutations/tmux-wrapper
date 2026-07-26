use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    #[allow(dead_code)]
    kty: String,
    n: String,
    e: String,
    #[allow(dead_code)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub email: String,
    pub sub: String,
    #[allow(dead_code)]
    pub aud: serde_json::Value,
    #[allow(dead_code)]
    pub exp: u64,
}

/// Retry delay after the `n`th consecutive failed JWKS fetch
/// (0-indexed): 5s, 10s, 20s, 40s, then capped at 60s.
pub(crate) fn backoff_secs(failure_count: u32) -> u64 {
    const BASE_SECS: u64 = 5;
    const CAP_SECS: u64 = 60;
    BASE_SECS
        .saturating_mul(1u64 << failure_count.min(63))
        .min(CAP_SECS)
}

#[derive(Clone)]
pub struct JwksCache {
    keys: Arc<RwLock<Vec<DecodingKey>>>,
    client: Client,
    jwks_url: String,
    audience: String,
    issuer: String,
}

impl JwksCache {
    pub fn new(team_domain: &str, audience: &str) -> Self {
        Self {
            keys: Arc::new(RwLock::new(Vec::new())),
            client: Client::new(),
            jwks_url: format!("https://{team_domain}.cloudflareaccess.com/cdn-cgi/access/certs"),
            audience: audience.to_string(),
            issuer: format!("https://{team_domain}.cloudflareaccess.com"),
        }
    }

    pub async fn refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(url = %self.jwks_url, "refreshing JWKS");
        let resp: JwksResponse = self.client.get(&self.jwks_url).send().await?.json().await?;

        let mut decoding_keys = Vec::new();
        for key in &resp.keys {
            match DecodingKey::from_rsa_components(&key.n, &key.e) {
                Ok(dk) => decoding_keys.push(dk),
                Err(e) => warn!("skipping invalid JWK: {e}"),
            }
        }

        info!(count = decoding_keys.len(), "cached JWKS keys");
        *self.keys.write().await = decoding_keys;
        Ok(())
    }

    async fn has_keys(&self) -> bool {
        !self.keys.read().await.is_empty()
    }

    /// Spawn the background JWKS refresh loop.
    ///
    /// If the caller's initial fetch failed (no keys cached yet), the loop
    /// starts in backoff mode instead of waiting a full `interval_secs` —
    /// otherwise a failed cold start would 401 every request until the first
    /// scheduled refresh. Any later failed refresh also drops into backoff
    /// (5s, 10s, 20s, ... capped at 60s) until a fetch succeeds, then the
    /// normal `interval_secs` cadence resumes.
    pub fn spawn_refresh_task(&self, interval_secs: u64) {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut failures: u32 = if cache.has_keys().await { 0 } else { 1 };
            loop {
                let sleep_secs = if failures == 0 {
                    interval_secs
                } else {
                    backoff_secs(failures - 1)
                };
                tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
                match cache.refresh().await {
                    Ok(()) => failures = 0,
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        warn!(
                            error = %e,
                            retry_in_secs = backoff_secs(failures - 1),
                            "JWKS refresh failed"
                        );
                    }
                }
            }
        });
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let keys = self.keys.read().await;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);

        for key in keys.iter() {
            match decode::<Claims>(token, key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(_) => continue,
            }
        }

        // If no key matched, try last error for diagnostics
        if let Some(key) = keys.last() {
            decode::<Claims>(token, key, &validation).map(|d| d.claims)
        } else {
            Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into())
        }
    }
}

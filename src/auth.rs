use crate::password_auth::PasswordAuth;
use jsonwebtoken::{DecodingKey, Validation, decode, Algorithm};
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

    pub fn spawn_refresh_task(&self, interval_secs: u64) {
        let cache = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                if let Err(e) = cache.refresh().await {
                    warn!("JWKS refresh failed: {e}");
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

#[derive(Clone)]
pub enum AuthProvider {
    Cloudflare(JwksCache),
    Password(PasswordAuth),
}

use crate::config::UserConfig;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
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
    #[allow(dead_code)]
    pub sub: String,
    #[allow(dead_code)]
    pub aud: serde_json::Value,
    pub exp: u64,
}

/// True iff the verified token's email is this user's, ignoring ASCII case.
// Wired into the privileged helper in a later task.
#[allow(dead_code)]
pub(crate) fn token_grants(user: &UserConfig, claims: &Claims) -> bool {
    claims.email.eq_ignore_ascii_case(&user.email)
}

/// Time left until a token with expiry `exp` (unix seconds) lapses, as of
/// `now` (unix seconds). Zero if it already has.
pub(crate) fn until_expiry(exp: u64, now: u64) -> Duration {
    Duration::from_secs(exp.saturating_sub(now))
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
    pub fn new(jwks_url: &str, issuer: &str, audience: &str) -> Self {
        Self {
            keys: Arc::new(RwLock::new(Vec::new())),
            // Explicit timeouts: a hung fetch would otherwise stall the
            // backoff/refresh loop forever (reqwest has no default timeout).
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build JWKS HTTP client"),
            jwks_url: jwks_url.to_string(),
            audience: audience.to_string(),
            issuer: issuer.to_string(),
        }
    }

    /// Test constructor: fixed keys, no network fetch.
    #[cfg(test)]
    pub fn with_static_keys(keys: Vec<DecodingKey>, issuer: &str, audience: &str) -> Self {
        let cache = Self::new("http://127.0.0.1:1/unused", issuer, audience);
        *cache.keys.try_write().expect("fresh cache is unlocked") = keys;
        cache
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

        // A fetch that yields zero usable keys is a failure, not a success:
        // returning Ok would reset the backoff and leave an empty keyset
        // (401ing every request) for a full jwks_refresh_secs.
        if decoding_keys.is_empty() {
            return Err(format!(
                "JWKS fetch from {} yielded no usable keys ({} JWKs in response)",
                self.jwks_url,
                resp.keys.len()
            )
            .into());
        }

        info!(count = decoding_keys.len(), "cached JWKS keys");
        *self.keys.write().await = decoding_keys;
        Ok(())
    }

    pub(crate) async fn has_keys(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{Claims, JwksCache, backoff_secs, token_grants, until_expiry};
    use crate::config::UserConfig;
    use crate::test_support;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const ISS: &str = "https://test.example";
    const AUD: &str = "aud-1";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn user(email: &str) -> UserConfig {
        UserConfig {
            email: email.into(),
            unix_user: "alice".into(),
            tmux_session: "main".into(),
        }
    }

    fn claims(email: &str) -> Claims {
        Claims {
            email: email.into(),
            sub: "s".into(),
            aud: serde_json::Value::Null,
            exp: 0,
        }
    }

    #[test]
    fn token_grants_matches_email_ignoring_case() {
        assert!(token_grants(
            &user("virgil@gmail.com"),
            &claims("virgil@gmail.com")
        ));
        assert!(token_grants(
            &user("virgil@gmail.com"),
            &claims("Virgil@Gmail.com")
        ));
        assert!(!token_grants(
            &user("virgil@gmail.com"),
            &claims("other@gmail.com")
        ));
    }

    #[tokio::test]
    async fn static_keys_verify_a_good_token() {
        let Some((_, dec)) = test_support::keys() else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let cache = JwksCache::with_static_keys(vec![dec], ISS, AUD);
        assert!(cache.has_keys().await);
        let tok = test_support::mint("a@b.com", AUD, ISS, now() + 300).unwrap();
        assert_eq!(cache.verify(&tok).await.unwrap().email, "a@b.com");
    }

    #[tokio::test]
    async fn wrong_audience_fails() {
        let Some((_, dec)) = test_support::keys() else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let cache = JwksCache::with_static_keys(vec![dec], ISS, AUD);
        let tok = test_support::mint("a@b.com", "other-aud", ISS, now() + 300).unwrap();
        assert!(cache.verify(&tok).await.is_err());
    }

    #[tokio::test]
    async fn expired_token_fails() {
        let Some((_, dec)) = test_support::keys() else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let cache = JwksCache::with_static_keys(vec![dec], ISS, AUD);
        let tok = test_support::mint("a@b.com", AUD, ISS, now() - 3600).unwrap();
        assert!(cache.verify(&tok).await.is_err());
    }

    #[test]
    fn expiry_in_the_future_is_the_remaining_time() {
        assert_eq!(until_expiry(1_000_090, 1_000_000), Duration::from_secs(90));
    }

    #[test]
    fn expired_or_expiring_now_is_zero() {
        assert_eq!(until_expiry(1_000_000, 1_000_000), Duration::ZERO);
        assert_eq!(until_expiry(999_000, 1_000_000), Duration::ZERO);
    }

    #[test]
    fn backoff_doubles_from_five_seconds_and_caps_at_sixty() {
        let schedule: Vec<u64> = (0..6).map(backoff_secs).collect();
        assert_eq!(schedule, vec![5, 10, 20, 40, 60, 60]);
    }

    #[test]
    fn backoff_never_overflows_on_long_outages() {
        assert_eq!(backoff_secs(u32::MAX), 60);
        assert_eq!(backoff_secs(63), 60);
        assert_eq!(backoff_secs(64), 60);
    }
}

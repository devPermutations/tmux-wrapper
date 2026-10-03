use serde::Deserialize;
use std::path::Path;

fn default_listen() -> String {
    "127.0.0.1:7681".to_string()
}

fn default_run_as() -> String {
    "tmuxwrapper".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// System user the unprivileged front runs as.
    #[serde(default = "default_run_as")]
    pub run_as: String,
    pub static_dir: String,
    pub cloudflare: CloudflareConfig,
    pub terminal: TerminalConfig,
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    pub team_domain: String,
    pub audience: String,
    pub jwks_refresh_secs: u64,
    /// Testing only: override the JWKS endpoint (https or loopback http).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Testing only: override the expected token issuer.
    #[serde(default)]
    pub issuer: Option<String>,
}

impl CloudflareConfig {
    pub fn resolved_jwks_url(&self) -> String {
        self.jwks_url.clone().unwrap_or_else(|| {
            format!(
                "https://{}.cloudflareaccess.com/cdn-cgi/access/certs",
                self.team_domain
            )
        })
    }

    pub fn resolved_issuer(&self) -> String {
        self.issuer
            .clone()
            .unwrap_or_else(|| format!("https://{}.cloudflareaccess.com", self.team_domain))
    }
}

fn default_max_sessions_per_user() -> usize {
    5
}

#[derive(Debug, Deserialize)]
pub struct TerminalConfig {
    pub ping_interval_secs: u64,
    /// Cap on distinct tmux sessions per user. Creating a new session past
    /// the cap is refused; attaching to an existing one is always allowed.
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub email: String,
    pub unix_user: String,
    pub tmux_session: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    fn from_toml_str(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen address '{}': {}", self.listen, e))?;
        let mut run_as_chars = self.run_as.chars();
        let run_as_ok = matches!(run_as_chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
            && run_as_chars
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if !run_as_ok || self.run_as == "root" {
            return Err(format!(
                "run_as '{}' is invalid or not allowed (must be non-root, [a-z_][a-z0-9_-]*)",
                self.run_as
            ));
        }
        if !Path::new(&self.static_dir).is_dir() {
            return Err(format!(
                "static_dir '{}' does not exist or is not a directory",
                self.static_dir
            ));
        }

        let cf = &self.cloudflare;
        if !cf
            .team_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!(
                "cloudflare.team_domain '{}' contains invalid characters (only [a-zA-Z0-9-] allowed)",
                cf.team_domain
            ));
        }
        if cf.audience.contains("REPLACE") {
            return Err(
                "cloudflare.audience is still a placeholder — set it to your CF Access AUD tag"
                    .into(),
            );
        }

        if let Some(url) = &cf.jwks_url {
            let ok = reqwest::Url::parse(url).is_ok_and(|u| {
                u.username().is_empty()
                    && u.password().is_none()
                    && match u.scheme() {
                        "https" => u.host_str().is_some(),
                        "http" => matches!(
                            u.host_str(),
                            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
                        ),
                        _ => false,
                    }
            });
            if !ok {
                return Err(format!(
                    "cloudflare.jwks_url '{url}' must be https:// or loopback http://"
                ));
            }
        }

        for user in &self.users {
            if user.email.is_empty() {
                return Err(format!(
                    "user with unix_user '{}' is missing 'email'",
                    user.unix_user
                ));
            }
            if user.unix_user.is_empty()
                || user.unix_user == "root"
                || !user
                    .unix_user
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "unix_user '{}' is invalid or not allowed (must be non-root, [a-zA-Z0-9_-])",
                    user.unix_user
                ));
            }
            if !user
                .tmux_session
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "tmux_session '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
                    user.tmux_session
                ));
            }
        }
        Ok(())
    }

    pub fn find_user(&self, email: &str) -> Option<&UserConfig> {
        self.users
            .iter()
            .find(|u| u.email.eq_ignore_ascii_case(email))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // static_dir = "." — cargo test runs from the crate root, which exists.
    const VALID: &str = r#"
listen = "127.0.0.1:7681"
static_dir = "."

[cloudflare]
team_domain = "myteam"
audience = "aud-tag-123"
jwks_refresh_secs = 3600

[terminal]
ping_interval_secs = 30

[[users]]
email = "You@Example.com"
unix_user = "alice"
tmux_session = "main"
"#;

    #[test]
    fn valid_config_parses_with_defaults() {
        let config = Config::from_toml_str(VALID).unwrap();
        assert_eq!(config.listen, "127.0.0.1:7681");
        // max_sessions_per_user defaults to 5 when omitted
        assert_eq!(config.terminal.max_sessions_per_user, 5);
    }

    #[test]
    fn listen_defaults_when_omitted() {
        let toml = VALID.replace("listen = \"127.0.0.1:7681\"\n", "");
        let config = Config::from_toml_str(&toml).unwrap();
        assert_eq!(config.listen, "127.0.0.1:7681");
    }

    #[test]
    fn max_sessions_per_user_is_configurable() {
        let toml = VALID.replace(
            "ping_interval_secs = 30",
            "ping_interval_secs = 30\nmax_sessions_per_user = 2",
        );
        let config = Config::from_toml_str(&toml).unwrap();
        assert_eq!(config.terminal.max_sessions_per_user, 2);
    }

    #[test]
    fn invalid_listen_rejected() {
        let toml = VALID.replace("127.0.0.1:7681", "not-an-addr");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("invalid listen address"), "got: {err}");
    }

    #[test]
    fn missing_static_dir_rejected() {
        let toml = VALID.replace(
            "static_dir = \".\"",
            "static_dir = \"/nonexistent-dir-xyz\"",
        );
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("static_dir"), "got: {err}");
    }

    #[test]
    fn missing_cloudflare_section_rejected() {
        let toml = VALID
            .replace("[cloudflare]", "")
            .replace("team_domain = \"myteam\"", "")
            .replace("audience = \"aud-tag-123\"", "")
            .replace("jwks_refresh_secs = 3600", "");
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn placeholder_audience_rejected() {
        let toml = VALID.replace("aud-tag-123", "REPLACE_WITH_CF_ACCESS_AUD_TAG");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("placeholder"), "got: {err}");
    }

    #[test]
    fn invalid_team_domain_rejected() {
        let toml = VALID.replace("myteam", "my.team/evil");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("team_domain"), "got: {err}");
    }

    #[test]
    fn user_missing_email_rejected() {
        let toml = VALID.replace("email = \"You@Example.com\"\n", "");
        // email is a required field — serde rejects the users entry
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn empty_email_rejected() {
        let toml = VALID.replace("You@Example.com", "");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("email"), "got: {err}");
    }

    #[test]
    fn root_unix_user_rejected() {
        let toml = VALID.replace("alice", "root");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("unix_user"), "got: {err}");
    }

    #[test]
    fn unix_user_shell_metacharacters_rejected() {
        let toml = VALID.replace("alice", "alice;rm");
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn non_ascii_unix_user_rejected() {
        // is_alphanumeric() would accept "josé"; the contract is [A-Za-z0-9_-].
        let toml = VALID.replace("alice", "josé");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("unix_user"), "got: {err}");
    }

    #[test]
    fn tmux_session_with_spaces_rejected() {
        let toml = VALID.replace("\"main\"", "\"main session\"");
        let err = Config::from_toml_str(&toml).unwrap_err().to_string();
        assert!(err.contains("tmux_session"), "got: {err}");
    }

    #[test]
    fn removed_keys_are_ignored_not_fatal() {
        // Keys from removed features (password auth, TTS) must not brick an
        // old config — serde ignores unknown fields. auth_mode goes before
        // the first table so it stays a top-level key.
        let toml = format!(
            "auth_mode = \"cloudflare\"\n{VALID}\n\
             [tts]\n\
             piper_binary = \"/opt/piper/piper\"\n"
        );
        assert!(Config::from_toml_str(&toml).is_ok());
    }

    #[test]
    fn removed_user_keys_are_ignored_not_fatal() {
        let toml = VALID.replace(
            "unix_user = \"alice\"",
            "unix_user = \"alice\"\nusername = \"alice\"\npassword_hash = \"$2b$12$x\"",
        );
        assert!(Config::from_toml_str(&toml).is_ok());
    }

    #[test]
    fn find_user_is_case_insensitive() {
        let config = Config::from_toml_str(VALID).unwrap();
        assert!(config.find_user("you@example.com").is_some());
        assert!(config.find_user("YOU@EXAMPLE.COM").is_some());
        assert_eq!(
            config.find_user("you@example.com").unwrap().unix_user,
            "alice"
        );
        assert!(config.find_user("intruder@example.com").is_none());
    }

    #[test]
    fn resolved_urls_default_to_cloudflare() {
        let config = Config::from_toml_str(VALID).unwrap();
        assert_eq!(
            config.cloudflare.resolved_jwks_url(),
            "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs"
        );
        assert_eq!(
            config.cloudflare.resolved_issuer(),
            "https://myteam.cloudflareaccess.com"
        );
    }

    #[test]
    fn jwks_and_issuer_overrides_are_used() {
        let toml = VALID.replace(
            "jwks_refresh_secs = 3600",
            "jwks_refresh_secs = 3600\njwks_url = \"http://127.0.0.1:8799/certs\"\nissuer = \"https://test.example\"",
        );
        let config = Config::from_toml_str(&toml).unwrap();
        assert_eq!(
            config.cloudflare.resolved_jwks_url(),
            "http://127.0.0.1:8799/certs"
        );
        assert_eq!(config.cloudflare.resolved_issuer(), "https://test.example");
    }

    fn with_jwks_url(url: &str) -> String {
        VALID.replace(
            "jwks_refresh_secs = 3600",
            &format!("jwks_refresh_secs = 3600\njwks_url = \"{url}\""),
        )
    }

    #[test]
    fn jwks_url_https_and_loopback_accepted() {
        for url in [
            "https://keys.example/certs",
            "http://127.0.0.1:8799/certs",
            "http://localhost:8799/certs",
            "http://[::1]:8799/certs",
        ] {
            assert!(Config::from_toml_str(&with_jwks_url(url)).is_ok(), "{url}");
        }
    }

    #[test]
    fn jwks_url_plain_http_remote_rejected() {
        for url in [
            "http://evil.example/certs",
            "ftp://127.0.0.1/certs",
            "http://127.0.0.1.evil.example/certs",
            "http://localhost.evil.example/certs",
            "http://127.0.0.1:80@evil.example/",
            "http://localhost:1@evil.example/",
            "https://user@keys.example/certs",
        ] {
            let err = Config::from_toml_str(&with_jwks_url(url))
                .unwrap_err()
                .to_string();
            assert!(err.contains("jwks_url"), "got: {err}");
        }
    }

    #[test]
    fn run_as_defaults_to_tmuxwrapper() {
        let config = Config::from_toml_str(VALID).unwrap();
        assert_eq!(config.run_as, "tmuxwrapper");
    }

    #[test]
    fn run_as_is_configurable() {
        let toml = format!("run_as = \"svc_front-1\"\n{VALID}");
        assert_eq!(Config::from_toml_str(&toml).unwrap().run_as, "svc_front-1");
    }

    #[test]
    fn run_as_root_or_malformed_rejected() {
        for bad in ["root", "", "Alice", "1abc", "a b", "a;b"] {
            let toml = format!("run_as = \"{bad}\"\n{VALID}");
            let err = Config::from_toml_str(&toml).unwrap_err().to_string();
            assert!(err.contains("run_as"), "{bad}: {err}");
        }
    }
}

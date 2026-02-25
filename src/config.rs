use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Cloudflare,
    Password,
}

fn default_auth_mode() -> String {
    "cloudflare".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: String,
    pub static_dir: String,
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    pub cloudflare: Option<CloudflareConfig>,
    pub terminal: TerminalConfig,
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    pub team_domain: String,
    pub audience: String,
    pub jwks_refresh_secs: u64,
}

fn default_session_duration_secs() -> u64 {
    86400
}

#[derive(Debug, Deserialize)]
pub struct TerminalConfig {
    pub ping_interval_secs: u64,
    #[serde(default = "default_session_duration_secs")]
    pub session_duration_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub email: Option<String>,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    pub unix_user: String,
    pub tmux_session: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn parsed_auth_mode(&self) -> Result<AuthMode, String> {
        match self.auth_mode.as_str() {
            "cloudflare" => Ok(AuthMode::Cloudflare),
            "password" => Ok(AuthMode::Password),
            other => Err(format!("unknown auth_mode '{other}' (expected 'cloudflare' or 'password')")),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let mode = self.parsed_auth_mode()?;

        self.listen.parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen address '{}': {}", self.listen, e))?;
        if !Path::new(&self.static_dir).is_dir() {
            return Err(format!("static_dir '{}' does not exist or is not a directory", self.static_dir));
        }

        match mode {
            AuthMode::Cloudflare => {
                let cf = self.cloudflare.as_ref()
                    .ok_or("auth_mode is 'cloudflare' but [cloudflare] section is missing")?;
                if !cf.team_domain.chars().all(|c| c.is_alphanumeric() || c == '-') {
                    return Err(format!(
                        "cloudflare.team_domain '{}' contains invalid characters (only [a-zA-Z0-9-] allowed)",
                        cf.team_domain
                    ));
                }
                if cf.audience.contains("REPLACE") {
                    return Err("cloudflare.audience is still a placeholder — set it to your CF Access AUD tag".into());
                }
                for user in &self.users {
                    if user.email.is_none() || user.email.as_ref().is_some_and(|e| e.is_empty()) {
                        return Err(format!(
                            "user with unix_user '{}' is missing 'email' (required in cloudflare mode)",
                            user.unix_user
                        ));
                    }
                }
            }
            AuthMode::Password => {
                for user in &self.users {
                    if user.username.is_none() || user.username.as_ref().is_some_and(|u| u.is_empty()) {
                        return Err(format!(
                            "user with unix_user '{}' is missing 'username' (required in password mode)",
                            user.unix_user
                        ));
                    }
                    if let Some(ref username) = user.username {
                        if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                            return Err(format!(
                                "username '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
                                username
                            ));
                        }
                    }
                    if user.password_hash.is_none() || user.password_hash.as_ref().is_some_and(|h| h.is_empty()) {
                        return Err(format!(
                            "user '{}' is missing 'password_hash' (required in password mode)",
                            user.username.as_deref().unwrap_or(&user.unix_user)
                        ));
                    }
                }
            }
        }

        for user in &self.users {
            if user.unix_user.is_empty()
                || user.unix_user == "root"
                || !user.unix_user.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "unix_user '{}' is invalid or not allowed (must be non-root, [a-zA-Z0-9_-])",
                    user.unix_user
                ));
            }
            if !user.tmux_session.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                return Err(format!(
                    "tmux_session '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
                    user.tmux_session
                ));
            }
        }
        Ok(())
    }

    pub fn find_user(&self, email: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| {
            u.email.as_ref().is_some_and(|e| e.eq_ignore_ascii_case(email))
        })
    }

    pub fn find_user_by_username(&self, username: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| {
            u.username.as_deref() == Some(username)
        })
    }
}

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: String,
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
}

#[derive(Debug, Deserialize)]
pub struct TerminalConfig {
    pub ping_interval_secs: u64,
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
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        self.listen.parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen address '{}': {}", self.listen, e))?;
        if !Path::new(&self.static_dir).is_dir() {
            return Err(format!("static_dir '{}' does not exist or is not a directory", self.static_dir));
        }
        if self.cloudflare.audience.contains("REPLACE") {
            return Err("cloudflare.audience is still a placeholder — set it to your CF Access AUD tag".into());
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
        self.users.iter().find(|u| u.email.eq_ignore_ascii_case(email))
    }
}

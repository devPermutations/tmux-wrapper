use serde::Deserialize;
use std::path::Path;

fn default_listen() -> String {
    "127.0.0.1:7681".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub static_dir: String,
    pub cloudflare: CloudflareConfig,
    pub terminal: TerminalConfig,
    pub tts: Option<TtsConfig>,
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

fn default_piper_binary() -> String {
    "/opt/piper/piper".to_string()
}

fn default_voices_dir() -> String {
    "/opt/piper/voices".to_string()
}

fn default_voice() -> String {
    "en_US-lessac-medium".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct TtsConfig {
    #[serde(default = "default_piper_binary")]
    pub piper_binary: String,
    #[serde(default = "default_voices_dir")]
    pub voices_dir: String,
    #[serde(default = "default_voice")]
    pub default_voice: String,
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
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen address '{}': {}", self.listen, e))?;
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
            .all(|c| c.is_alphanumeric() || c == '-')
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
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "unix_user '{}' is invalid or not allowed (must be non-root, [a-zA-Z0-9_-])",
                    user.unix_user
                ));
            }
            if !user
                .tmux_session
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
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

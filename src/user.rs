use crate::config::UserConfig;
use nix::unistd::{Gid, Uid, User};

pub struct ResolvedUser {
    pub uid: Uid,
    pub gid: Gid,
    pub home: String,
    pub shell: String,
    pub tmux_session: String,
}

impl ResolvedUser {
    pub fn from_config(user_config: &UserConfig) -> Result<Self, String> {
        let user = User::from_name(&user_config.unix_user)
            .map_err(|e| format!("user lookup failed for '{}': {e}", user_config.unix_user))?
            .ok_or_else(|| format!("unix user '{}' not found", user_config.unix_user))?;

        Ok(Self {
            uid: user.uid,
            gid: user.gid,
            home: user.dir.to_string_lossy().into_owned(),
            shell: user.shell.to_string_lossy().into_owned(),
            tmux_session: user_config.tmux_session.clone(),
        })
    }
}

use crate::config::UserConfig;
use nix::unistd::{Gid, Uid, User};

pub struct ResolvedUser {
    pub name: String,
    pub uid: Uid,
    pub gid: Gid,
    pub home: String,
    pub shell: String,
}

impl ResolvedUser {
    pub fn from_config(user_config: &UserConfig) -> Result<Self, String> {
        Self::by_name(&user_config.unix_user)?
            .ok_or_else(|| format!("unix user '{}' not found", user_config.unix_user))
    }

    /// `Ok(None)` if no such user exists.
    pub fn by_name(name: &str) -> Result<Option<Self>, String> {
        let user =
            User::from_name(name).map_err(|e| format!("user lookup failed for '{name}': {e}"))?;
        Ok(user.map(|user| Self {
            name: user.name,
            uid: user.uid,
            gid: user.gid,
            home: user.dir.to_string_lossy().into_owned(),
            shell: user.shell.to_string_lossy().into_owned(),
        }))
    }
}

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

/// The first of `users` that `run_as` shares a uid with, or whose primary gid
/// is `run_as`'s gid. Such a front would not be isolated from that helper.
pub fn shares_identity<'a>(
    run_as: &ResolvedUser,
    users: impl IntoIterator<Item = &'a ResolvedUser>,
) -> Option<&'a ResolvedUser> {
    users
        .into_iter()
        .find(|u| u.uid == run_as.uid || u.gid == run_as.gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, uid: u32, gid: u32) -> ResolvedUser {
        ResolvedUser {
            name: name.into(),
            uid: Uid::from_raw(uid),
            gid: Gid::from_raw(gid),
            home: format!("/home/{name}"),
            shell: "/bin/bash".into(),
        }
    }

    #[test]
    fn distinct_ids_do_not_clash() {
        let front = user("tmuxwrapper", 990, 990);
        let users = [user("ktulu", 1000, 1000), user("tim", 1001, 1001)];
        assert!(shares_identity(&front, &users).is_none());
        assert!(shares_identity(&front, &[]).is_none());
    }

    #[test]
    fn same_uid_under_another_name_clashes() {
        let front = user("alias", 1001, 990);
        let users = [user("ktulu", 1000, 1000), user("tim", 1001, 1001)];
        assert_eq!(shares_identity(&front, &users).unwrap().name, "tim");
    }

    #[test]
    fn front_gid_equal_to_a_helper_primary_gid_clashes() {
        let front = user("tmuxwrapper", 990, 1000);
        let users = [user("ktulu", 1000, 1000)];
        assert_eq!(shares_identity(&front, &users).unwrap().name, "ktulu");
    }
}

// Called by the helper (Task 4).
#![allow(dead_code)]

//! tmux operations, run as the current process user (the helper runs as the
//! target user, so there is no sudo). `socket: Option<&Path>` adds `-S <path>`
//! so tests can use a scratch server; production passes `None`.

use crate::proto::SessionInfo;
use std::io;
use std::path::Path;
use tokio::process::Command;

const TMUX: &str = "/usr/bin/tmux";

/// Session names may only contain [a-zA-Z0-9_-].
pub fn is_valid_session_name(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Tmux-session cap decision: refuse only when the requested name is NEW and
/// the user is already at the cap. Attaching to an existing session is always
/// allowed regardless of the cap.
pub fn refuses_new_session(existing: &[String], requested: &str, cap: usize) -> bool {
    !existing.iter().any(|s| s == requested) && existing.len() >= cap
}

/// What `tmux list-sessions` (run as the user) says about their tmux server.
#[derive(Debug, PartialEq)]
pub enum TmuxServer {
    Running(Vec<String>),
    NotRunning,
    /// The listing failed for some other reason (e.g. sudo misconfigured).
    Unknown,
}

pub fn classify_list_sessions(success: bool, stdout: &str, stderr: &str) -> TmuxServer {
    if success {
        return TmuxServer::Running(stdout.lines().map(str::to_string).collect());
    }
    // tmux 3.4: a stale socket says "no server running on <path>"; a missing
    // one says "error connecting to <path> (No such file or directory)".
    let no_socket = stderr.contains("error connecting")
        && (stderr.contains("No such file or directory") || stderr.contains("Connection refused"));
    if stderr.contains("no server running") || no_socket {
        TmuxServer::NotRunning
    } else {
        TmuxServer::Unknown
    }
}

fn tmux_command(socket: Option<&Path>) -> Command {
    let mut cmd = Command::new(TMUX);
    if let Some(sock) = socket {
        cmd.arg("-S").arg(sock);
    }
    cmd.env_remove("TMUX");
    cmd
}

/// Ask tmux whether the user's server is up and which sessions it has.
pub async fn query_server(socket: Option<&Path>) -> TmuxServer {
    let output = tmux_command(socket)
        .args(["list-sessions", "-F", "#{session_name}"])
        .output()
        .await;
    match output {
        Ok(out) => classify_list_sessions(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(_) => TmuxServer::Unknown,
    }
}

/// Start the user's `tmux-server.service` (D-012), so a server that exited
/// comes back in its clean systemd context. Relies on `XDG_RUNTIME_DIR` and
/// `DBUS_SESSION_BUS_ADDRESS` being set by the helper.
pub async fn start_server_unit() {
    let output = Command::new("/usr/bin/systemctl")
        .args(["--user", "start", "tmux-server.service"])
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => tracing::info!("started tmux-server.service"),
        Ok(out) => tracing::warn!(
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "could not start tmux-server.service"
        ),
        Err(e) => tracing::warn!(error = %e, "failed to run systemctl"),
    }
}

/// Parse `#{session_name}\t#{session_windows}\t#{session_attached}` lines.
fn parse_sessions(stdout: &str) -> Vec<SessionInfo> {
    stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                Some(SessionInfo {
                    name: parts[0].to_string(),
                    windows: parts[1].parse().unwrap_or(0),
                    attached: parts[2] != "0",
                })
            } else {
                None
            }
        })
        .collect()
}

/// The user's sessions; empty when there is no server or tmux fails.
pub async fn list_sessions(socket: Option<&Path>) -> Vec<SessionInfo> {
    let output = tmux_command(socket)
        .args([
            "list-sessions",
            "-F",
            "#{session_name}\t#{session_windows}\t#{session_attached}",
        ])
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => parse_sessions(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    }
}

/// Kill a session by exact name. `Ok(false)` means it (or the server) was not found.
pub async fn kill_session(name: &str, socket: Option<&Path>) -> io::Result<bool> {
    let out = tmux_command(socket)
        .args(["kill-session", "-t"])
        .arg(format!("={name}"))
        .output()
        .await?;
    if out.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("can't find session")
        || classify_list_sessions(false, "", &stderr) == TmuxServer::NotRunning
    {
        Ok(false)
    } else {
        Err(io::Error::other(format!(
            "tmux kill-session failed: {}",
            stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScratchTmux, tmux_available};

    #[test]
    fn session_names_allow_alphanumeric_underscore_dash() {
        assert!(is_valid_session_name("main"));
        assert!(is_valid_session_name("my-session_2"));
        assert!(is_valid_session_name("A1"));
    }

    #[test]
    fn session_names_reject_shell_and_path_metacharacters() {
        assert!(!is_valid_session_name("main session"));
        assert!(!is_valid_session_name("../etc"));
        assert!(!is_valid_session_name("a;rm -rf"));
        assert!(!is_valid_session_name("a|b"));
        assert!(!is_valid_session_name("a$b"));
        assert!(!is_valid_session_name("a.b"));
    }

    #[test]
    fn session_names_reject_non_ascii_alphanumerics() {
        // is_alphanumeric() would accept these; the contract is [A-Za-z0-9_-].
        assert!(!is_valid_session_name("café"));
        assert!(!is_valid_session_name("名前"));
    }

    #[test]
    fn new_session_under_cap_is_allowed() {
        let existing = vec!["a".to_string(), "b".to_string()];
        assert!(!refuses_new_session(&existing, "c", 3));
    }

    #[test]
    fn new_session_at_cap_is_refused() {
        let existing = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(refuses_new_session(&existing, "d", 3));
    }

    #[test]
    fn attach_to_existing_session_at_cap_is_allowed() {
        let existing = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(!refuses_new_session(&existing, "b", 3));
    }

    #[test]
    fn listing_with_sessions_means_running() {
        assert_eq!(
            classify_list_sessions(true, "main\nwork\n", ""),
            TmuxServer::Running(vec!["main".into(), "work".into()])
        );
    }

    #[test]
    fn missing_socket_means_not_running() {
        let stderr = "error connecting to /tmp/tmux-1000/default (No such file or directory)\n";
        assert_eq!(
            classify_list_sessions(false, "", stderr),
            TmuxServer::NotRunning
        );
    }

    #[test]
    fn stale_socket_means_not_running() {
        let stderr = "no server running on /tmp/tmux-1000/default\n";
        assert_eq!(
            classify_list_sessions(false, "", stderr),
            TmuxServer::NotRunning
        );
    }

    #[test]
    fn other_failures_are_unknown() {
        let denied = "error connecting to /tmp/tmux-1000/default (Permission denied)\n";
        assert_eq!(
            classify_list_sessions(false, "", denied),
            TmuxServer::Unknown
        );
        let sudo = "sudo: unknown user ghost\n";
        assert_eq!(classify_list_sessions(false, "", sudo), TmuxServer::Unknown);
    }

    #[tokio::test]
    async fn scratch_server_is_queried_listed_and_killed() {
        let Some(t) = ScratchTmux::start("base") else {
            eprintln!("skipping: /usr/bin/tmux not available");
            return;
        };
        let sock = Some(t.socket());
        assert_eq!(
            query_server(sock).await,
            TmuxServer::Running(vec!["base".into()])
        );
        let sessions = list_sessions(sock).await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "base");
        assert_eq!(sessions[0].windows, 1);
        assert!(!sessions[0].attached);

        assert!(t.new_detached("other"));
        assert!(kill_session("other", sock).await.unwrap());
        assert!(!kill_session("other", sock).await.unwrap());
        assert!(!kill_session("ba", sock).await.unwrap(), "exact match only");
        assert_eq!(list_sessions(sock).await.len(), 1);
    }

    #[tokio::test]
    async fn nonexistent_socket_means_not_running() {
        if !tmux_available() {
            eprintln!("skipping: /usr/bin/tmux not available");
            return;
        }
        let sock = std::env::temp_dir().join("tmuxwrapper-test-no-such-socket");
        assert_eq!(query_server(Some(&sock)).await, TmuxServer::NotRunning);
        assert!(list_sessions(Some(&sock)).await.is_empty());
        assert!(!kill_session("x", Some(&sock)).await.unwrap());
    }

    #[test]
    fn parse_sessions_reads_tab_separated_fields() {
        let s = parse_sessions("a\t2\t1\nb\t1\t0\nbroken\n");
        assert_eq!(
            s,
            vec![
                SessionInfo {
                    name: "a".into(),
                    windows: 2,
                    attached: true
                },
                SessionInfo {
                    name: "b".into(),
                    windows: 1,
                    attached: false
                },
            ]
        );
    }
}

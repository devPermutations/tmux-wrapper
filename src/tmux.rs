//! tmux operations, run as the current process user (the helper runs as the
//! target user, so nothing switches users). `socket: Option<&Path>` adds `-S <path>`
//! so tests can use a scratch server; production passes `None`.

use crate::proto::SessionInfo;
use std::io;
use std::path::Path;
use std::process::Output;
use std::time::Duration;
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
    /// The listing failed for some other reason (e.g. permission denied).
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

/// Every tmux / systemctl call gives up after this, so a hung tmux makes the
/// helper answer (Refused, or an empty list) well inside the front's 10 s
/// `HelperDead` timeout instead of stalling it into a restart.
pub(crate) const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `cmd` to completion, or kill it and fail with `TimedOut` after `limit`.
async fn output_within(mut cmd: Command, limit: Duration) -> io::Result<Output> {
    cmd.kill_on_drop(true);
    match tokio::time::timeout(limit, cmd.output()).await {
        Ok(output) => output,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("subprocess did not finish within {limit:?}"),
        )),
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
    let mut cmd = tmux_command(socket);
    cmd.args(["list-sessions", "-F", "#{session_name}"]);
    match output_within(cmd, SUBPROCESS_TIMEOUT).await {
        Ok(out) => classify_list_sessions(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "tmux list-sessions failed");
            TmuxServer::Unknown
        }
    }
}

/// Start the user's `tmux-server.service` (D-012), so a server that exited
/// comes back in its clean systemd context. Relies on `XDG_RUNTIME_DIR` and
/// `DBUS_SESSION_BUS_ADDRESS` being set by the helper.
pub async fn start_server_unit() {
    let mut cmd = Command::new("/usr/bin/systemctl");
    cmd.args(["--user", "start", "tmux-server.service"]);
    match output_within(cmd, SUBPROCESS_TIMEOUT).await {
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
    let mut cmd = tmux_command(socket);
    cmd.args([
        "list-sessions",
        "-F",
        "#{session_name}\t#{session_windows}\t#{session_attached}",
    ]);
    match output_within(cmd, SUBPROCESS_TIMEOUT).await {
        Ok(out) if out.status.success() => parse_sessions(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if classify_list_sessions(false, "", &stderr) != TmuxServer::NotRunning {
                tracing::warn!(stderr = %stderr.trim(), "tmux list-sessions failed");
            }
            Vec::new()
        }
        Err(e) => {
            tracing::warn!(error = %e, "tmux list-sessions failed");
            Vec::new()
        }
    }
}

/// Kill a session by exact name. `Ok(false)` means it (or the server) was not found.
pub async fn kill_session(name: &str, socket: Option<&Path>) -> io::Result<bool> {
    let mut cmd = tmux_command(socket);
    cmd.args(["kill-session", "-t"]).arg(format!("={name}"));
    let out = output_within(cmd, SUBPROCESS_TIMEOUT).await?;
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
        let other = "tmux: unknown failure\n";
        assert_eq!(
            classify_list_sessions(false, "", other),
            TmuxServer::Unknown
        );
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

    #[tokio::test]
    async fn a_subprocess_past_its_timeout_is_killed_and_reported() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let started = std::time::Instant::now();
        let err = output_within(cmd, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_subprocess_within_its_timeout_returns_its_output() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo hi"]);
        let out = output_within(cmd, Duration::from_secs(5)).await.unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hi\n");
    }

    /// A tmux server that never answers (SIGSTOPped) must not stall the
    /// helper: every operation gives up after the subprocess timeout.
    #[tokio::test]
    async fn a_hung_tmux_server_times_out_instead_of_stalling() {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let Some(t) = ScratchTmux::start("base") else {
            eprintln!("skipping: /usr/bin/tmux not available");
            return;
        };
        let out = std::process::Command::new(TMUX)
            .env_remove("TMUX")
            .arg("-S")
            .arg(t.socket())
            .args(["display-message", "-p", "#{pid}"])
            .output()
            .unwrap();
        let pid = Pid::from_raw(String::from_utf8_lossy(&out.stdout).trim().parse().unwrap());
        /// Resumes the server before `t` drops (kill-server would hang).
        struct Resume(Pid);
        impl Drop for Resume {
            fn drop(&mut self) {
                let _ = kill(self.0, Signal::SIGCONT);
            }
        }
        kill(pid, Signal::SIGSTOP).unwrap();
        let _resume = Resume(pid);

        let sock = Some(t.socket());
        let started = std::time::Instant::now();
        let (server, sessions, killed) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(
                query_server(sock),
                list_sessions(sock),
                kill_session("base", sock)
            )
        })
        .await
        .expect("tmux operations stalled on a hung server");
        assert_eq!(server, TmuxServer::Unknown);
        assert!(sessions.is_empty());
        assert!(killed.is_err());
        assert!(started.elapsed() >= SUBPROCESS_TIMEOUT);
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

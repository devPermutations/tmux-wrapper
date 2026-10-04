//! Eager detection of helper death. The front is the parent of every helper;
//! on each SIGCHLD it polls exactly those pids with `waitpid(pid, WNOHANG)`
//! (never `waitpid(-1)`, which would steal other children's statuses) and
//! exits non-zero if any helper is gone, so systemd restarts the service.

use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use tokio::signal::unix::{SignalKind, signal};
use tracing::error;

/// A helper that is no longer running.
#[derive(Debug, PartialEq)]
pub struct HelperExit {
    pub unix_user: String,
    pub pid: Pid,
    pub status: String,
}

/// Poll each helper once with `poll` and return the first that has exited.
/// `StillAlive` means keep running; anything else — an exit, a signal, or an
/// error such as ECHILD (the pid is no longer our child) — means it is gone.
pub fn first_exited(
    helpers: &[(String, Pid)],
    mut poll: impl FnMut(Pid) -> nix::Result<WaitStatus>,
) -> Option<HelperExit> {
    helpers.iter().find_map(|(unix_user, pid)| {
        let status = match poll(*pid) {
            Ok(WaitStatus::StillAlive) => return None,
            Ok(WaitStatus::Exited(_, code)) => format!("exited with status {code}"),
            Ok(WaitStatus::Signaled(_, sig, _)) => format!("killed by signal {}", sig.as_str()),
            Ok(other) => format!("{other:?}"),
            Err(e) => format!("waitpid failed: {e}"),
        };
        Some(HelperExit {
            unix_user: unix_user.clone(),
            pid: *pid,
            status,
        })
    })
}

/// Install the SIGCHLD listener, then check once (a helper may have died
/// between fork and now, and that SIGCHLD was not observed), then re-check
/// on every SIGCHLD. Exits the process when a helper is gone. Must be called
/// inside the runtime.
pub fn spawn(helpers: Vec<(String, Pid)>) -> std::io::Result<()> {
    let mut sigchld = signal(SignalKind::child())?;
    tokio::spawn(async move {
        loop {
            if let Some(exit) =
                first_exited(&helpers, |pid| waitpid(pid, Some(WaitPidFlag::WNOHANG)))
            {
                error!(
                    unix_user = %exit.unix_user,
                    pid = %exit.pid,
                    status = %exit.status,
                    "helper exited; front exiting"
                );
                std::process::exit(1);
            }
            if sigchld.recv().await.is_none() {
                error!("SIGCHLD stream closed; front exiting");
                std::process::exit(1);
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::errno::Errno;
    use nix::sys::signal::Signal;

    fn helpers() -> Vec<(String, Pid)> {
        vec![
            ("alice".to_string(), Pid::from_raw(100)),
            ("bob".to_string(), Pid::from_raw(200)),
        ]
    }

    #[test]
    fn all_alive_keeps_running() {
        let got = first_exited(&helpers(), |_| Ok(WaitStatus::StillAlive));
        assert_eq!(got, None);
    }

    #[test]
    fn exited_helper_is_reported_with_user_and_status() {
        let got = first_exited(&helpers(), |pid| {
            if pid.as_raw() == 200 {
                Ok(WaitStatus::Exited(pid, 3))
            } else {
                Ok(WaitStatus::StillAlive)
            }
        });
        assert_eq!(
            got,
            Some(HelperExit {
                unix_user: "bob".to_string(),
                pid: Pid::from_raw(200),
                status: "exited with status 3".to_string(),
            })
        );
    }

    #[test]
    fn killed_helper_is_reported_with_signal() {
        let got = first_exited(&helpers(), |pid| {
            Ok(WaitStatus::Signaled(pid, Signal::SIGKILL, false))
        });
        assert_eq!(
            got,
            Some(HelperExit {
                unix_user: "alice".to_string(),
                pid: Pid::from_raw(100),
                status: "killed by signal SIGKILL".to_string(),
            })
        );
    }

    #[test]
    fn waitpid_error_counts_as_gone() {
        let got = first_exited(&helpers(), |_| Err(Errno::ECHILD));
        assert_eq!(
            got.map(|e| e.status),
            Some("waitpid failed: ECHILD: No child processes".to_string())
        );
    }

    #[test]
    fn only_the_given_pids_are_polled() {
        let mut polled = Vec::new();
        first_exited(&helpers(), |pid| {
            polled.push(pid.as_raw());
            Ok(WaitStatus::StillAlive)
        });
        assert_eq!(polled, vec![100, 200]);
    }

    #[test]
    // The child is reaped by `first_exited`'s waitpid, not by `Child::wait`.
    #[allow(clippy::zombie_processes)]
    fn real_child_is_seen_alive_then_dead() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = Pid::from_raw(child.id() as i32);
        let watched = vec![("carol".to_string(), pid)];
        let poll = |pid| waitpid(pid, Some(WaitPidFlag::WNOHANG));
        assert_eq!(first_exited(&watched, poll), None);
        child.kill().expect("kill sleep");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let exit = loop {
            if let Some(exit) = first_exited(&watched, poll) {
                break exit;
            }
            assert!(std::time::Instant::now() < deadline, "child not reaped");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(exit.unix_user, "carol");
        assert_eq!(exit.status, "killed by signal SIGKILL");
    }
}

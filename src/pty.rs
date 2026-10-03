use crate::user::ResolvedUser;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::libc;
use nix::pty::openpty;
use nix::sys::signal::{self, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, Uid, fork, setsid};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct PtyMaster {
    async_fd: AsyncFd<OwnedFd>,
    /// Only the legacy `spawn` path owns a child; `from_fd` masters do not.
    child_pid: Option<Pid>,
}

impl PtyMaster {
    pub fn spawn(user: &ResolvedUser) -> io::Result<Self> {
        let pty = openpty(None, None).map_err(io::Error::other)?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        let uid = user.uid;
        let gid = user.gid;
        let home = user.home.clone();
        let shell = user.shell.clone();
        let session = user.tmux_session.clone();
        let username = user_name_from_uid(uid);

        // Safety: fork
        let fork_result = unsafe { fork() }.map_err(io::Error::other)?;

        match fork_result {
            ForkResult::Parent { child } => {
                // Close slave in parent
                drop(slave_fd);

                // Set master to non-blocking
                let raw = master_fd.as_raw_fd();
                let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
                unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };

                let async_fd = AsyncFd::new(master_fd).map_err(io::Error::other)?;

                Ok(PtyMaster {
                    async_fd,
                    child_pid: Some(child),
                })
            }
            ForkResult::Child => {
                // Close master in child
                drop(master_fd);

                // New session — abort if this fails
                if setsid().is_err() {
                    unsafe { libc::_exit(126) };
                }

                // Set controlling terminal
                let slave_raw = slave_fd.as_raw_fd();
                unsafe { libc::ioctl(slave_raw, libc::TIOCSCTTY, 0) };

                // Dup slave to stdin/stdout/stderr
                unsafe {
                    libc::dup2(slave_raw, 0);
                    libc::dup2(slave_raw, 1);
                    libc::dup2(slave_raw, 2);
                    if slave_raw > 2 {
                        libc::close(slave_raw);
                    }
                }

                // Reset all signal handlers and unblock all signals
                unsafe {
                    let empty: libc::sigset_t = std::mem::zeroed();
                    libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
                }
                for sig in [
                    signal::Signal::SIGPIPE,
                    signal::Signal::SIGINT,
                    signal::Signal::SIGTERM,
                    signal::Signal::SIGCHLD,
                    signal::Signal::SIGHUP,
                    signal::Signal::SIGQUIT,
                    signal::Signal::SIGTSTP,
                    signal::Signal::SIGTTIN,
                    signal::Signal::SIGTTOU,
                ] {
                    unsafe { signal::signal(sig, signal::SigHandler::SigDfl).ok() };
                }

                // Drop privileges: initgroups → setgid → setuid (setuid LAST)
                // CRITICAL: abort if any step fails to prevent running as root
                let cname = CString::new(username.as_str()).unwrap_or_default();
                if nix::unistd::initgroups(&cname, gid).is_err()
                    || nix::unistd::setgid(gid).is_err()
                    || nix::unistd::setuid(uid).is_err()
                {
                    unsafe { libc::_exit(126) };
                }
                // Verify we actually dropped root
                if nix::unistd::getuid().is_root() {
                    unsafe { libc::_exit(126) };
                }

                // Set environment using libc directly — Rust's std::env functions
                // acquire internal locks that may be deadlocked after fork()
                // in a multi-threaded (tokio) process.
                unsafe {
                    let home_c = CString::new(home.as_str()).unwrap_or_default();
                    let user_c = CString::new(username.as_str()).unwrap_or_default();
                    let shell_c = CString::new(shell.as_str()).unwrap_or_default();
                    libc::setenv(c"HOME".as_ptr(), home_c.as_ptr(), 1);
                    libc::setenv(c"USER".as_ptr(), user_c.as_ptr(), 1);
                    libc::setenv(c"SHELL".as_ptr(), shell_c.as_ptr(), 1);
                    libc::setenv(c"TERM".as_ptr(), c"xterm-256color".as_ptr(), 1);
                    libc::unsetenv(c"TMUX".as_ptr());
                }

                // chdir using libc — same reason as above
                unsafe {
                    let home_c = CString::new(home.as_str()).unwrap_or_default();
                    libc::chdir(home_c.as_ptr());
                }

                // Exec tmux
                let tmux = CString::new("/usr/bin/tmux").unwrap();
                let args = [
                    CString::new("tmux").unwrap(),
                    CString::new("new-session").unwrap(),
                    CString::new("-A").unwrap(),
                    CString::new("-s").unwrap(),
                    CString::new(session).unwrap(),
                    CString::new("-c").unwrap(),
                    CString::new(home.clone()).unwrap(),
                ];
                let arg_refs: Vec<&std::ffi::CStr> = args.iter().map(|a| a.as_c_str()).collect();
                nix::unistd::execvp(&tmux, &arg_refs).ok();

                // If exec fails
                unsafe { libc::_exit(127) };
            }
        }
    }

    /// Wrap an already-open PTY master (e.g. received from the helper). The
    /// child is not ours, so nothing is reaped on drop.
    #[allow(dead_code)] // Used by the helper client (Task 5).
    pub fn from_fd(fd: OwnedFd) -> io::Result<PtyMaster> {
        set_nonblocking(&fd)?;
        Ok(PtyMaster {
            async_fd: AsyncFd::new(fd)?,
            child_pid: None,
        })
    }

    /// Set the terminal size via TIOCSWINSZ on the master.
    #[allow(dead_code)] // Used by the helper client (Task 5).
    pub fn resize(&self, cols: u16, rows: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe { libc::ioctl(self.raw_fd(), libc::TIOCSWINSZ, &ws) };
    }

    pub fn raw_fd(&self) -> RawFd {
        self.async_fd.get_ref().as_raw_fd()
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        // Reaping can take up to the grace period; keep it off the runtime.
        if let Some(pid) = self.child_pid {
            std::thread::spawn(move || terminate_and_reap(pid));
        }
    }
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(())
}

/// Spawn `tmux new-session -A -s <session>` attached to a fresh PTY, as the
/// current user (no sudo). Returns the PTY master and the client process.
/// Must be called from within a tokio runtime. Dropping the master hangs the
/// client up, so `child.wait()` then completes.
#[allow(dead_code)] // Called by the helper (Task 4).
pub fn spawn_tmux_client(
    session: &str,
    home: &Path,
    socket: Option<&Path>,
) -> io::Result<(OwnedFd, tokio::process::Child)> {
    let pty = openpty(None, None).map_err(io::Error::from)?;
    let (master, slave) = (pty.master, pty.slave);
    // The child must not inherit the master, or dropping ours would never hang it up.
    fcntl(&master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
    fcntl(&slave, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;

    let mut cmd = tokio::process::Command::new("/usr/bin/tmux");
    if let Some(sock) = socket {
        cmd.arg("-S").arg(sock);
    }
    cmd.args(["new-session", "-A", "-s", session, "-c"])
        .arg(home)
        .current_dir(home)
        .env("TERM", "xterm-256color")
        .env_remove("TMUX")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // Safety: runs in the forked child; only async-signal-safe calls
    // (setsid, ioctl), no allocation, locks or std I/O.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn();
    // Drop the Command (and the parent's slave copies it owns) before returning,
    // on success and failure alike.
    drop(cmd);
    Ok((master, child?))
}

/// How long a hung-up tmux client gets to exit before SIGKILL.
const HANGUP_GRACE: Duration = Duration::from_secs(2);

/// Hang up the tmux client and reap it, escalating to SIGKILL if it ignores
/// SIGHUP. Blocks until the child is reaped, so call it off the runtime.
///
/// A single WNOHANG wait right after SIGHUP almost always runs before the
/// child has exited, which left a zombie behind for every closed tab.
pub(crate) fn terminate_and_reap(pid: Pid) {
    if kill(pid, Signal::SIGHUP).is_err() {
        // Already reaped (or never ours) — nothing to wait for.
        return;
    }
    let deadline = Instant::now() + HANGUP_GRACE;
    while Instant::now() < deadline {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(20)),
            _ => return,
        }
    }
    // The zombie-to-be holds the PID until reaped, so this can't hit a reused PID.
    let _ = kill(pid, Signal::SIGKILL);
    let _ = waitpid(pid, None);
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.async_fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.async_fd.get_ref().as_raw_fd();
            let unfilled = buf.initialize_unfilled();
            let n = unsafe {
                libc::read(
                    fd,
                    unfilled.as_mut_ptr() as *mut libc::c_void,
                    unfilled.len(),
                )
            };

            if n > 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            } else if n == 0 {
                return Poll::Ready(Ok(()));
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.async_fd.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.async_fd.get_ref().as_raw_fd();
            let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn user_name_from_uid(uid: Uid) -> String {
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{PtyMaster, spawn_tmux_client, terminate_and_reap};
    use crate::test_support::ScratchTmux;
    use nix::unistd::Pid;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// A reaped child has no /proc entry; a zombie still does (state Z).
    fn is_gone(pid: Pid) -> bool {
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Spawn `script` and wait until it prints its first line, so any traps
    /// it sets are installed before the test signals it.
    fn spawn(script: &str) -> Pid {
        let mut child = Command::new("/bin/sh")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        // Dropping std's Child does not wait; terminate_and_reap owns reaping.
        Pid::from_raw(child.id() as i32)
    }

    #[test]
    fn hung_up_child_is_reaped_not_left_a_zombie() {
        let pid = spawn("echo ready; exec sleep 30");
        terminate_and_reap(pid);
        assert!(
            is_gone(pid),
            "child {pid} left behind after terminate_and_reap"
        );
    }

    #[test]
    fn child_ignoring_sighup_is_killed_and_reaped() {
        let pid = spawn("trap '' HUP; echo ready; exec sleep 30");
        terminate_and_reap(pid);
        assert!(
            is_gone(pid),
            "SIGHUP-ignoring child {pid} survived terminate_and_reap"
        );
    }

    #[tokio::test]
    async fn tmux_client_gets_a_pty_and_exits_when_master_drops() {
        let Some(t) = ScratchTmux::start("base") else {
            eprintln!("skipping: /usr/bin/tmux not available");
            return;
        };
        let home = std::env::temp_dir();
        let (master, mut child) = spawn_tmux_client("t1", &home, Some(t.socket())).unwrap();
        let mut pty = PtyMaster::from_fd(master).unwrap();

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), pty.read(&mut buf))
            .await
            .expect("no output within 2s")
            .unwrap();
        assert!(n > 0, "expected terminal output from tmux client");

        pty.resize(100, 30);

        let sessions = crate::tmux::list_sessions(Some(t.socket())).await;
        assert!(sessions.iter().any(|s| s.name == "t1"), "{sessions:?}");

        drop(pty);
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .expect("client did not exit after master drop")
            .unwrap();

        assert!(
            crate::tmux::kill_session("t1", Some(t.socket()))
                .await
                .unwrap()
        );
        assert!(
            !crate::tmux::kill_session("t1", Some(t.socket()))
                .await
                .unwrap()
        );
    }
}

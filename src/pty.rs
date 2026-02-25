use crate::user::ResolvedUser;
use nix::libc;
use nix::pty::openpty;
use nix::sys::signal;
use nix::unistd::{setsid, ForkResult, Pid, Uid, fork};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct PtyMaster {
    async_fd: AsyncFd<OwnedFd>,
    child_pid: Pid,
}

impl PtyMaster {
    pub fn spawn(user: &ResolvedUser) -> io::Result<Self> {
        let pty = openpty(None, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        let uid = user.uid;
        let gid = user.gid;
        let home = user.home.clone();
        let shell = user.shell.clone();
        let session = user.tmux_session.clone();
        let username = user_name_from_uid(uid);

        // Safety: fork
        let fork_result = unsafe { fork() }.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        match fork_result {
            ForkResult::Parent { child } => {
                // Close slave in parent
                drop(slave_fd);

                // Set master to non-blocking
                let raw = master_fd.as_raw_fd();
                let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
                unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };

                let async_fd = AsyncFd::new(master_fd)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                Ok(PtyMaster {
                    async_fd,
                    child_pid: child,
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

                // Set environment (safe: we're in a forked child, single-threaded)
                unsafe {
                    std::env::set_var("HOME", &home);
                    std::env::set_var("USER", &username);
                    std::env::set_var("SHELL", &shell);
                    std::env::set_var("TERM", "xterm-256color");
                    std::env::remove_var("TMUX");
                }

                // chdir to home
                std::env::set_current_dir(&home).ok();

                // Exec tmux
                let tmux = CString::new("tmux").unwrap();
                let args = [
                    CString::new("tmux").unwrap(),
                    CString::new("new-session").unwrap(),
                    CString::new("-A").unwrap(),
                    CString::new("-s").unwrap(),
                    CString::new(session).unwrap(),
                ];
                let arg_refs: Vec<&std::ffi::CStr> = args.iter().map(|a| a.as_c_str()).collect();
                nix::unistd::execvp(&tmux, &arg_refs).ok();

                // If exec fails
                unsafe { libc::_exit(127) };
            }
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.async_fd.get_ref().as_raw_fd()
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.child_pid, nix::sys::signal::Signal::SIGHUP);
        let _ = nix::sys::wait::waitpid(
            self.child_pid,
            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
        );
    }
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
                libc::read(fd, unfilled.as_mut_ptr() as *mut libc::c_void, unfilled.len())
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
            let n = unsafe {
                libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
            };

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

//! The front's end of the front ↔ helper socket. One request, one reply,
//! serialised behind a mutex so replies cannot be paired with the wrong
//! request. A helper that times out or breaks the socket is dead for good:
//! the caller logs and exits, and systemd restarts the service.

use crate::proto::{AsyncSeqpacket, Request, Response};
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::error;

/// How long the helper gets to answer one request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The helper timed out, closed its socket, or sent something unreadable.
/// Callers `error!` and `std::process::exit(1)`.
#[derive(Debug, PartialEq)]
pub struct HelperDead;

pub struct HelperClient {
    /// `None` once the helper is dead: a late reply may still be queued, so
    /// the socket is never used again.
    sock: Arc<Mutex<Option<AsyncSeqpacket>>>,
    timeout: Duration,
}

impl HelperClient {
    /// Must be called within a tokio runtime.
    pub fn new(sock: OwnedFd) -> io::Result<HelperClient> {
        Self::with_timeout(sock, REQUEST_TIMEOUT)
    }

    fn with_timeout(sock: OwnedFd, timeout: Duration) -> io::Result<HelperClient> {
        Ok(HelperClient {
            sock: Arc::new(Mutex::new(Some(AsyncSeqpacket::new(sock)?))),
            timeout,
        })
    }

    /// Send `req` and wait for its reply (and the PTY fd, for `Opened`).
    ///
    /// The exchange runs on its own task holding the lock, so it completes
    /// even if this future is dropped (e.g. the HTTP client went away);
    /// otherwise the orphaned reply would be read by the next request. An
    /// orphaned reply's fd is closed.
    pub async fn request(&self, req: &Request) -> Result<(Response, Option<OwnedFd>), HelperDead> {
        let mut guard = Arc::clone(&self.sock).lock_owned().await;
        let req = req.clone();
        let timeout = self.timeout;
        let exchange = tokio::spawn(async move {
            let sock = guard.as_ref().ok_or(HelperDead)?;
            let send_recv = async {
                sock.send(&req, None).await?;
                sock.recv::<Response>().await
            };
            let failure = match tokio::time::timeout(timeout, send_recv).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(e)) => e.to_string(),
                Err(_) => format!("no reply within {timeout:?}"),
            };
            error!(error = %failure, "helper request failed");
            *guard = None;
            Err(HelperDead)
        });
        // A JoinError means the task panicked or the runtime is shutting down.
        exchange.await.unwrap_or(Err(HelperDead))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{self, SessionInfo, seqpacket_pair};
    use std::os::fd::AsFd;

    fn list(token: &str) -> Request {
        Request::List {
            token: token.into(),
        }
    }

    /// A reply naming one session after the request's token, so a reply
    /// paired with the wrong request is detectable.
    fn echo(req: &Request) -> Response {
        let Request::List { token } = req else {
            return Response::BadRequest;
        };
        Response::Sessions {
            sessions: vec![SessionInfo {
                name: token.clone(),
                windows: 1,
                attached: false,
            }],
        }
    }

    /// A fake helper on a thread: answers each request with `echo` after
    /// `delay(index)`, then exits (closing its end) after `count` requests.
    fn fake_helper(
        sock: OwnedFd,
        count: usize,
        delay: impl Fn(usize) -> std::time::Duration + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for i in 0..count {
                let Ok((req, _)) = proto::recv::<Request>(sock.as_fd()) else {
                    return;
                };
                std::thread::sleep(delay(i));
                let _ = proto::send(sock.as_fd(), &echo(&req), None);
            }
        })
    }

    #[tokio::test]
    async fn list_round_trips() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = fake_helper(back, 1, |_| std::time::Duration::ZERO);
        let client = HelperClient::new(front).unwrap();
        let (resp, fd) = client.request(&list("t1")).await.unwrap();
        assert_eq!(resp, echo(&list("t1")));
        assert!(fd.is_none());
        fake.join().unwrap();
    }

    /// The real 10 s timeout against a fake that answers after 11 s
    /// (about 10 s of wall time; the other tests run alongside it).
    #[tokio::test]
    async fn reply_after_eleven_seconds_is_helper_dead() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = fake_helper(back, 1, |_| std::time::Duration::from_secs(11));
        let client = HelperClient::new(front).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(client.request(&list("t1")).await.err(), Some(HelperDead));
        let waited = started.elapsed();
        assert!(
            (REQUEST_TIMEOUT..REQUEST_TIMEOUT + Duration::from_secs(5)).contains(&waited),
            "gave up after {waited:?}"
        );
        drop(client);
        fake.join().unwrap();
    }

    /// After a timeout the late reply is still queued; a client that kept
    /// using the socket would hand it to the next request.
    #[tokio::test]
    async fn a_timed_out_client_stays_dead() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = fake_helper(back, 2, |_| std::time::Duration::from_millis(300));
        let client = HelperClient::with_timeout(front, Duration::from_millis(100)).unwrap();
        assert_eq!(client.request(&list("t1")).await.err(), Some(HelperDead));
        // Let the late reply to "t1" arrive.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(client.request(&list("t2")).await.err(), Some(HelperDead));
        drop(client);
        fake.join().unwrap();
    }

    /// A caller dropped mid-request (an HTTP client that disconnected) must
    /// not leave its reply queued for the next caller.
    #[tokio::test]
    async fn a_cancelled_request_does_not_desync_the_next() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = fake_helper(back, 2, |i| {
            std::time::Duration::from_millis(if i == 0 { 300 } else { 0 })
        });
        let client = HelperClient::new(front).unwrap();
        let cancelled =
            tokio::time::timeout(Duration::from_millis(50), client.request(&list("t1"))).await;
        assert!(
            cancelled.is_err(),
            "first request should have been cancelled"
        );
        let (resp, _) = client.request(&list("t2")).await.unwrap();
        assert_eq!(resp, echo(&list("t2")));
        drop(client);
        fake.join().unwrap();
    }

    #[tokio::test]
    async fn helper_closing_the_socket_is_helper_dead() {
        let (front, back) = seqpacket_pair().unwrap();
        drop(back);
        let client = HelperClient::new(front).unwrap();
        assert_eq!(client.request(&list("t1")).await.err(), Some(HelperDead));
    }

    #[tokio::test]
    async fn helper_closing_mid_request_is_helper_dead() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = std::thread::spawn(move || {
            let _ = proto::recv::<Request>(back.as_fd());
            // `back` dropped here without a reply.
        });
        let client = HelperClient::new(front).unwrap();
        assert_eq!(client.request(&list("t1")).await.err(), Some(HelperDead));
        fake.join().unwrap();
    }

    #[tokio::test]
    async fn garbage_reply_is_helper_dead() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = std::thread::spawn(move || {
            let _ = proto::recv::<Request>(back.as_fd());
            nix::unistd::write(&back, b"not json").unwrap();
            back
        });
        let client = HelperClient::new(front).unwrap();
        assert_eq!(client.request(&list("t1")).await.err(), Some(HelperDead));
        drop(fake.join().unwrap());
    }

    /// Two tasks share one client; the fake answers the first request slowly,
    /// so without serialisation the second task could take the first reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_requests_each_get_their_own_reply() {
        let (front, back) = seqpacket_pair().unwrap();
        let fake = fake_helper(back, 20, |i| {
            std::time::Duration::from_millis(if i % 2 == 0 { 30 } else { 0 })
        });
        let client = std::sync::Arc::new(HelperClient::new(front).unwrap());
        let tasks: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|who| {
                let client = client.clone();
                tokio::spawn(async move {
                    for i in 0..10 {
                        let tok = format!("{who}{i}");
                        let (resp, _) = client.request(&list(&tok)).await.unwrap();
                        assert_eq!(resp, echo(&list(&tok)), "reply paired with wrong request");
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        fake.join().unwrap();
    }

    /// A field of `/proc/<pid>/status`, or `None` once the process is gone
    /// (reaped). A zombie keeps its entry, with `State: Z`.
    fn proc_status(pid: i32, field: &str) -> Option<String> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status.lines().find_map(|l| {
            l.strip_prefix(field)
                .and_then(|r| r.strip_prefix(':'))
                .map(|v| v.trim().to_string())
        })
    }

    /// Pids of the tmux clients attached to the scratch server.
    fn client_pids(socket: &std::path::Path) -> Vec<i32> {
        let out = std::process::Command::new("/usr/bin/tmux")
            .env_remove("TMUX")
            .arg("-S")
            .arg(socket)
            .args(["list-clients", "-F", "#{client_pid}"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "{what} within 3 s");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Review Focus 1: a WebSocket that disconnects right after `Open` drops
    /// the PTY without ever bridging it. The tmux client must be hung up and
    /// reaped (no zombie) by a real helper, here running in this process.
    #[tokio::test]
    async fn dropped_unbridged_pty_is_hung_up_and_reaped() {
        use crate::auth::JwksCache;
        use crate::config::UserConfig;
        use crate::helper::{HelperCtx, serve};
        use crate::test_support::{self, ScratchTmux};

        const ISS: &str = "https://test.example";
        const AUD: &str = "aud-1";
        const EMAIL: &str = "alice@example.com";
        let Some((_, dec)) = test_support::keys() else {
            eprintln!("skipping: openssl unavailable");
            return;
        };
        let Some(t) = ScratchTmux::start("base") else {
            eprintln!("skipping: /usr/bin/tmux not available");
            return;
        };
        let ctx = HelperCtx {
            user: UserConfig {
                email: EMAIL.into(),
                unix_user: "alice".into(),
                tmux_session: "main".into(),
            },
            home: std::env::temp_dir(),
            jwks: JwksCache::with_static_keys(vec![dec], ISS, AUD),
            max_sessions: 5,
            tmux_socket: Some(t.socket().to_path_buf()),
        };
        let (front, back) = seqpacket_pair().unwrap();
        let helper = tokio::spawn(serve(ctx, AsyncSeqpacket::new(back).unwrap()));
        let client = HelperClient::new(front).unwrap();

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let req = Request::Open {
            token: test_support::mint(EMAIL, AUD, ISS, exp).unwrap(),
            session: "base".into(),
        };
        let (resp, fd) = client.request(&req).await.unwrap();
        assert_eq!(resp, Response::Opened { expires_at: exp });
        let fd = fd.expect("Opened without an fd");

        let mut pid = 0;
        eventually("tmux client attached", || {
            pid = client_pids(t.socket()).first().copied().unwrap_or(0);
            pid != 0
        })
        .await;
        let our_pid = std::process::id().to_string();
        assert_eq!(
            proc_status(pid, "PPid").as_deref(),
            Some(our_pid.as_str()),
            "the in-process helper should be the tmux client's parent"
        );

        drop(fd);
        eventually("tmux client reaped", || proc_status(pid, "State").is_none()).await;
        let sessions = crate::tmux::list_sessions(Some(t.socket())).await;
        assert!(sessions.iter().all(|s| !s.attached), "{sessions:?}");

        drop(client);
        tokio::time::timeout(Duration::from_secs(3), helper)
            .await
            .expect("helper did not stop after the front closed")
            .unwrap();
    }
}

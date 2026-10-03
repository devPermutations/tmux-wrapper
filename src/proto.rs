//! Wire protocol between the unprivileged front and the per-user helper.
//!
//! One JSON message per `SOCK_SEQPACKET` datagram. `Response::Opened` is
//! accompanied by the PTY master fd, passed with `SCM_RIGHTS`.

use nix::cmsg_space;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, recvmsg, sendmsg, socketpair,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Open { token: String, session: String },
    List { token: String },
    Kill { token: String, name: String },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Opened { expires_at: u64 }, // accompanied by exactly one fd (PTY master)
    Sessions { sessions: Vec<SessionInfo> },
    Killed,
    NotFound,
    Refused { reason: String },
    Unauthorized,
    BadRequest,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SessionInfo {
    pub name: String,
    pub windows: u32,
    pub attached: bool,
}

pub const MAX_MESSAGE: usize = 64 * 1024;

/// Room for more fds than we ever expect, so extras are received (and closed)
/// instead of triggering MSG_CTRUNC.
const MAX_FDS: usize = 4;

fn invalid(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A connected `SOCK_SEQPACKET` pair, both ends close-on-exec.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?)
}

fn encode<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(msg).map_err(invalid)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(invalid("message exceeds MAX_MESSAGE"));
    }
    Ok(bytes)
}

fn send_bytes(sock: BorrowedFd, bytes: &[u8], fd: Option<BorrowedFd>) -> io::Result<()> {
    let iov = [IoSlice::new(bytes)];
    let raw: Vec<RawFd> = fd.iter().map(|f| f.as_raw_fd()).collect();
    let cmsgs: Vec<ControlMessage> = if raw.is_empty() {
        vec![]
    } else {
        vec![ControlMessage::ScmRights(&raw)]
    };
    loop {
        match sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::MSG_NOSIGNAL, None) {
            Ok(n) if n == bytes.len() => return Ok(()),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short send")),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// One recvmsg. Returns `WouldBlock` on a non-blocking empty socket.
fn recv_bytes(sock: BorrowedFd) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    let mut cmsg_buf = cmsg_space!([RawFd; MAX_FDS]);
    let (n, flags) = loop {
        let mut iov = [IoSliceMut::new(&mut buf)];
        match recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Ok(msg) => break (msg.bytes, msg.flags),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    // Parse the fds ourselves: nix's `cmsgs()` refuses to iterate after
    // MSG_CTRUNC, which would leak the fds the kernel did install.
    let fds = take_scm_rights(&cmsg_buf);
    // Dropping `fds` on any early return below closes everything received.
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(invalid("truncated message"));
    }
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    buf.truncate(n);
    // First fd is kept; any extras are dropped (closed).
    Ok((buf, fds.into_iter().next()))
}

/// Extract every `SCM_RIGHTS` fd from a recvmsg control buffer, taking
/// ownership of each. The buffer was zero-initialised, so a zero `cmsg_len`
/// ends the walk.
fn take_scm_rights(buf: &[u8]) -> Vec<OwnedFd> {
    use nix::libc::{SCM_RIGHTS, SOL_SOCKET, c_int, cmsghdr};
    const ALIGN: usize = std::mem::size_of::<usize>();
    let hdr = std::mem::size_of::<cmsghdr>();
    let hdr_data = hdr.div_ceil(ALIGN) * ALIGN;
    let mut fds = Vec::new();
    let mut off = 0;
    while off + hdr <= buf.len() {
        // SAFETY: bounds checked above; read_unaligned tolerates alignment.
        let h: cmsghdr = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
        let len = h.cmsg_len;
        if len < hdr || off + len > buf.len() {
            break;
        }
        if h.cmsg_level == SOL_SOCKET && h.cmsg_type == SCM_RIGHTS {
            let data = &buf[(off + hdr_data).min(off + len)..off + len];
            for c in data.chunks_exact(std::mem::size_of::<c_int>()) {
                let raw = c_int::from_ne_bytes(c.try_into().unwrap());
                // SAFETY: the kernel installed this fd in our table for us.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        off += len.div_ceil(ALIGN) * ALIGN;
    }
    fds
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(invalid)
}

/// Blocking send of one message, optionally with one fd.
#[allow(dead_code)] // Blocking variant: only tests use it so far.
pub fn send<T: Serialize>(sock: BorrowedFd, msg: &T, fd: Option<BorrowedFd>) -> io::Result<()> {
    send_bytes(sock, &encode(msg)?, fd)
}

/// Blocking receive of one message and its optional fd.
#[allow(dead_code)] // Blocking variant: only tests use it so far.
pub fn recv<T: DeserializeOwned>(sock: BorrowedFd) -> io::Result<(T, Option<OwnedFd>)> {
    let (bytes, fd) = recv_bytes(sock)?;
    Ok((decode(&bytes)?, fd))
}

/// Async wrapper over a non-blocking SEQPACKET socket.
pub struct AsyncSeqpacket(AsyncFd<OwnedFd>);

impl AsyncSeqpacket {
    /// Must be called within a tokio runtime.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let flags = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL)?);
        fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        Ok(Self(AsyncFd::new(fd)?))
    }

    pub async fn send<T: Serialize>(&self, msg: &T, fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let bytes = encode(msg)?;
        loop {
            let mut guard = self.0.writable().await?;
            match guard.try_io(|inner| send_bytes(inner.get_ref().as_fd(), &bytes, fd)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv<T: DeserializeOwned>(&self) -> io::Result<(T, Option<OwnedFd>)> {
        let (bytes, fd) = loop {
            let mut guard = self.0.readable().await?;
            match guard.try_io(|inner| recv_bytes(inner.get_ref().as_fd())) {
                Ok(res) => break res?,
                Err(_would_block) => continue,
            }
        };
        Ok((decode(&bytes)?, fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn samples_req() -> Vec<Request> {
        vec![
            Request::Open {
                token: "t".into(),
                session: "main".into(),
            },
            Request::List { token: "t".into() },
            Request::Kill {
                token: "t".into(),
                name: "n".into(),
            },
        ]
    }

    fn samples_resp() -> Vec<Response> {
        vec![
            Response::Opened { expires_at: 42 },
            Response::Sessions {
                sessions: vec![SessionInfo {
                    name: "a".into(),
                    windows: 2,
                    attached: true,
                }],
            },
            Response::Killed,
            Response::NotFound,
            Response::Refused { reason: "r".into() },
            Response::Unauthorized,
            Response::BadRequest,
        ]
    }

    #[test]
    fn json_round_trip_all_variants() {
        for r in samples_req() {
            let s = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
        }
        for r in samples_resp() {
            let s = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), r);
        }
    }

    #[test]
    fn open_json_shape() {
        let r: Request =
            serde_json::from_str(r#"{"op":"open","token":"t","session":"main"}"#).unwrap();
        assert_eq!(
            r,
            Request::Open {
                token: "t".into(),
                session: "main".into()
            }
        );
        assert_eq!(
            serde_json::to_string(&Response::Killed).unwrap(),
            r#"{"status":"killed"}"#
        );
    }

    fn pipe() -> (std::fs::File, std::fs::File) {
        // Close-on-exec: a tmux process spawned by a concurrent test must
        // not inherit the write end (it would look like a leak here).
        let (r, w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        (r.into(), w.into())
    }

    #[test]
    fn fd_passing_blocking() {
        let (a, b) = seqpacket_pair().unwrap();
        let (mut r, w) = pipe();
        send(
            a.as_fd(),
            &Response::Opened { expires_at: 7 },
            Some(w.as_fd()),
        )
        .unwrap();
        let (msg, fd): (Response, _) = recv(b.as_fd()).unwrap();
        assert_eq!(msg, Response::Opened { expires_at: 7 });
        let mut got = std::fs::File::from(fd.expect("fd"));
        got.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn received_fd_is_cloexec() {
        let (a, b) = seqpacket_pair().unwrap();
        let (_r, w) = pipe();
        send(a.as_fd(), &Response::Killed, Some(w.as_fd())).unwrap();
        let (_, fd): (Response, _) = recv(b.as_fd()).unwrap();
        let fd = fd.unwrap();
        let flags = fcntl(&fd, FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn no_fd_yields_none() {
        let (a, b) = seqpacket_pair().unwrap();
        send(a.as_fd(), &Response::Killed, None).unwrap();
        let (m, fd): (Response, _) = recv(b.as_fd()).unwrap();
        assert_eq!(m, Response::Killed);
        assert!(fd.is_none());
    }

    #[test]
    fn oversize_send_refused() {
        let (a, _b) = seqpacket_pair().unwrap();
        let big = Request::List {
            token: "x".repeat(MAX_MESSAGE),
        };
        let e = send(a.as_fd(), &big, None).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversize_recv_rejected() {
        let (a, b) = seqpacket_pair().unwrap();
        send_bytes(a.as_fd(), &vec![b'x'; MAX_MESSAGE + 10], None).unwrap();
        let e = recv::<Request>(b.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bad_json_rejected() {
        let (a, b) = seqpacket_pair().unwrap();
        send_bytes(a.as_fd(), b"not json", None).unwrap();
        let e = recv::<Request>(b.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn peer_closed_is_eof() {
        let (a, b) = seqpacket_pair().unwrap();
        drop(a);
        let e = recv::<Request>(b.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Send raw bytes with any number of fds, bypassing `send`'s limits.
    fn send_raw_fds(sock: &OwnedFd, bytes: &[u8], fds: &[RawFd]) {
        let iov = [IoSlice::new(bytes)];
        sendmsg::<()>(
            sock.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(fds)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
    }

    /// Assert every write end of this pipe is closed: a non-blocking read
    /// must see EOF (0 bytes), not WouldBlock (a leaked write end).
    fn assert_eof(reader: &std::fs::File, what: &str) {
        let fd = reader.as_fd();
        let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL).unwrap());
        fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        let mut buf = [0u8; 1];
        match (&*reader).read(&mut buf) {
            Ok(0) => {}
            other => panic!("{what}: write end leaked, read gave {other:?}"),
        }
    }

    #[test]
    fn extra_fds_are_closed() {
        let (a, b) = seqpacket_pair().unwrap();
        let (r1, w1) = pipe();
        let (r2, w2) = pipe();
        send_raw_fds(
            &a,
            &encode(&Response::Killed).unwrap(),
            &[w1.as_raw_fd(), w2.as_raw_fd()],
        );
        drop(w1);
        drop(w2);
        let (_, fd): (Response, _) = recv(b.as_fd()).unwrap();
        // The first fd is returned and still open; the extra must be closed.
        assert!(fd.is_some());
        assert_eof(&r2, "extra fd");
        drop(fd);
        assert_eof(&r1, "returned fd after drop");
    }

    #[test]
    fn fd_closed_on_decode_failure() {
        let (a, b) = seqpacket_pair().unwrap();
        let (r, w) = pipe();
        send_raw_fds(&a, b"not json", &[w.as_raw_fd()]);
        drop(w);
        let e = recv::<Request>(b.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eof(&r, "fd received with bad JSON");
    }

    #[test]
    fn fds_closed_on_ctrunc() {
        let (a, b) = seqpacket_pair().unwrap();
        let pipes: Vec<_> = (0..MAX_FDS + 1).map(|_| pipe()).collect();
        let raw: Vec<RawFd> = pipes.iter().map(|(_, w)| w.as_raw_fd()).collect();
        send_raw_fds(&a, &encode(&Response::Killed).unwrap(), &raw);
        let readers: Vec<_> = pipes.into_iter().map(|(r, _w)| r).collect();
        let e = recv::<Response>(b.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        for (i, r) in readers.iter().enumerate() {
            assert_eof(r, &format!("fd {i} after MSG_CTRUNC"));
        }
    }

    #[tokio::test]
    async fn async_round_trip_with_fd() {
        let (a, b) = seqpacket_pair().unwrap();
        let (a, b) = (
            AsyncSeqpacket::new(a).unwrap(),
            AsyncSeqpacket::new(b).unwrap(),
        );
        let (mut r, w) = pipe();
        // recv started before send exercises the WouldBlock path.
        let rx = tokio::spawn(async move { b.recv::<Response>().await });
        tokio::task::yield_now().await;
        a.send(&Response::Opened { expires_at: 9 }, Some(w.as_fd()))
            .await
            .unwrap();
        let (msg, fd) = rx.await.unwrap().unwrap();
        assert_eq!(msg, Response::Opened { expires_at: 9 });
        let mut got = std::fs::File::from(fd.unwrap());
        got.write_all(b"yo").unwrap();
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"yo");
    }

    #[tokio::test]
    async fn async_errors() {
        let (a, b) = seqpacket_pair().unwrap();
        let (a, b) = (
            AsyncSeqpacket::new(a).unwrap(),
            AsyncSeqpacket::new(b).unwrap(),
        );
        let big = Request::List {
            token: "x".repeat(MAX_MESSAGE),
        };
        assert_eq!(
            a.send(&big, None).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(a);
        assert_eq!(
            b.recv::<Request>().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

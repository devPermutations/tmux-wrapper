# Privilege separation — design

**Date:** 2026-10-03
**Status:** Draft for review
**Decisions:** D-110 (approach), D-109 (single user: Tim removed), D-012 (tmux server runs in its own user unit)

## Outcome

No code that parses network input runs as root, and a compromise of that code
yields no more than a stolen Cloudflare Access login already would.

Today the whole service runs as root (`CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE
CAP_FOWNER`, `NoNewPrivileges=no`) and shells out to `sudo -u <user> tmux` for
the session list and kill. Any bug in axum, hyper, the JWT path or our own
handlers is root — and since `ktulu` has `NOPASSWD: ALL` sudo, so is a shell as
`ktulu`.

## Constraints

- Phone-first web terminal; must keep working through Cloudflare Access with
  the behaviour shipped in Phases 0–2a (session cap, tmux-server guard, expiry
  close, reload-to-login).
- One binary, one systemd unit (D-110). No `sudo`.
- Virgil is remote: production is not swapped until a full end-to-end run has
  passed on a parallel instance, and the swap has a one-command rollback.

## Success criteria

1. After startup, `ps` shows no tmuxwrapper process running as root: the front
   runs as a dedicated system user `tmuxwrapper`, the helper as `ktulu` with no
   supplementary groups.
2. The front has no capabilities (`CapEff`/`CapPrm` = 0) and cannot regain uid 0.
3. The helper refuses any request whose token fails verification (bad
   signature, wrong aud/iss, expired, or email not mapped to its user), even
   when the front is bypassed — proven by a test that talks to the helper
   directly.
4. Terminals, the session picker, kill, the tmux-server guard, the session cap,
   expiry close and phone scrolling all behave as before (end-to-end run on the
   parallel instance).
5. No zombies after closing terminals; no `sudo` anywhere in the code.

## Architecture

```
systemd (root, CapabilityBoundingSet=CAP_SETUID CAP_SETGID, NoNewPrivileges=yes)
└─ tmuxwrapper  [root, single-threaded, before any runtime starts]
   ├─ parse config, resolve users
   ├─ for each user: socketpair(SOCK_SEQPACKET) + fork ──► helper
   │     setgroups([primary gid]) → setgid → setuid(user) → verify not root
   │     PR_SET_PDEATHSIG=SIGTERM; env HOME, USER, XDG_RUNTIME_DIR,
   │     DBUS_SESSION_BUS_ADDRESS; own tokio current-thread runtime;
   │     own JWKS cache; serves requests on its end of the socketpair
   └─ front: setgroups([]) → setgid/setuid(tmuxwrapper) → verify setuid(0)
         fails → build tokio runtime → bind 127.0.0.1:7681 → axum
```

The listen socket is bound after the drop (port 7681 needs no privilege).
Static files and the config are already world-readable / read before the drop.

### Front (unprivileged)

Unchanged HTTP surface: `/ws`, `/api/sessions`, `DELETE /api/sessions/{name}`,
static files, security headers. It still verifies the JWT itself (fast
rejection, picks the helper by email → unix user), but holds no authority: every
privileged action is a request to the helper carrying the original token.

### Helper (one per configured user; one in practice)

Runs as the user, without supplementary groups (tmux clients only need the
uid to reach `/tmp/tmux-<uid>/default`). Requests:

| Request | Helper does | Reply |
|---|---|---|
| `Open{token, session}` | verify token → tmux-server guard (start `tmux-server.service` via `systemctl --user` if down, else refuse) → session cap → spawn `tmux new-session -A -s <session>` on a new PTY | `Opened{expires_at}` + PTY master fd (SCM_RIGHTS), or `Refused{reason}` |
| `List{token}` | verify → `tmux list-sessions` | sessions |
| `Kill{token, name}` | verify → validate name → `tmux kill-session -t` | ok / not found |

Verification = signature against the helper's own JWKS fetch, `aud`, `iss`,
`exp`, and the email mapping to **this** helper's unix user. The front cannot
supply keys or skip the check.

PTY children are spawned with `tokio::process::Command` (`pre_exec`: `setsid`,
`TIOCSCTTY`), so tokio owns reaping — this replaces the hand-rolled fork/setuid
in `pty.rs` and the zombie reaper thread. When the front drops the master fd
the tmux client gets SIGHUP and exits; the helper's `child.wait()` reaps it.

### Front ↔ helper protocol

`SOCK_SEQPACKET` socketpair (message boundaries preserved). One JSON request,
one JSON reply, serialised behind a mutex in the front (single user, ≤5
terminals: contention is negligible). 10 s timeout per request.

### PTY handling in the front

`PtyMaster` wraps the received fd (AsyncFd read/write as today), resizes with
`TIOCSWINSZ` on it, and closes it on drop. No child pid in the front.

## Failure modes

| Failure | Behaviour |
|---|---|
| Helper exits or hangs (timeout) | Front logs and exits non-zero; systemd `Restart=on-failure` restarts the service. tmux sessions are unaffected (they live in `tmux-server.service`). |
| Front exits | `PDEATHSIG` terminates the helper; systemd restarts. |
| JWKS fetch fails in the helper at startup | Same backoff loop as the front; `Open` is refused ("auth keys unavailable") until it succeeds. |
| Privilege drop fails (either side) | Process exits before handling any input. |
| `tmuxwrapper` system user missing | Startup fails with a clear error; `deploy.sh` creates it. |

## Configuration

- New optional `run_as` (default `"tmuxwrapper"`): the front's system user.
- New optional `[cloudflare] jwks_url` / `issuer` overrides, **testing only**:
  let the end-to-end harness mint tokens with a local RSA key. Rejected unless
  the URL is `https://` or loopback.

## systemd unit changes

- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` (drop `CAP_DAC_OVERRIDE
  CAP_FOWNER`), `NoNewPrivileges=yes`.
- Add `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
  `SystemCallFilter=@system-service`, `LockPersonality=yes`,
  `RestrictRealtime=yes`, `ProtectHome=read-only` (verify tmux attach and
  `systemctl --user` still work under it).
- `ReadWritePaths=/tmp` only (tmux socket directory); drop `/home`.

## Testing

- **Unit:** protocol round-trip; token-to-user authorisation (wrong user,
  expired, bad aud); fd passing over a socketpair (send a pipe fd, read through
  it); privilege-drop helpers' "can't regain root" check (skipped unless root).
- **Helper bypass test:** drive a helper directly with forged, expired and
  wrong-user tokens → all refused, no PTY spawned.
- **End-to-end on a parallel instance** (root, transient unit with the new
  sandbox, `127.0.0.1:7682`, test JWKS served locally, test session name):
  open a terminal and round-trip `echo`; list; kill; tmux-server guard
  refusal; expiry close (short-lived token); no zombies after close; process
  uids and `CapEff` as in success criteria 1–2; kill the helper → service
  exits.
- **Phone:** after the swap, Virgil opens the app and scrolls a Claude pane.

## Rollout

1. Build and test entirely on the feature branch; parallel instance only.
2. Swap production with Virgil at a computer (decided; no automatic
   rollback). `deploy.sh` backs up the installed binary, static files and
   unit to `/opt/tmuxwrapper.bak-<YYYYmmdd-HHMMSS>/` first.
3. Rollback: `./rollback.sh [backup dir]` restores the binary, static files
   and previous unit together, `daemon-reload`s and restarts.

## Out of scope

Root-free design with a user-unit agent (rejected in D-110); Cloudflare Access
policy changes (Virgil, dashboard); Tim's access (removed, D-109).

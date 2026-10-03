# Privilege Separation Implementation Plan

> Execute with the `subagent-driven-development` skill or inline, task by task.

**Goal:** No tmuxwrapper code that parses network input runs as root, and a compromised front gains nothing beyond a stolen Access login.
**Architecture:** The binary starts as root, forks one helper per configured user (helper drops to that user, no supplementary groups), then drops the front to the `tmuxwrapper` system user before building the tokio runtime. The front keeps the HTTP surface and asks the helper — over a `SOCK_SEQPACKET` socketpair carrying JSON and SCM_RIGHTS fds — to open/list/kill; the helper re-verifies the Access JWT on every request.
**Tech stack:** Rust 2024, axum 0.8, tokio 1, nix 0.31, jsonwebtoken 9, serde_json; node 22 for existing JS tests.
**Spec:** `docs/specs/2026-10-03-privilege-separation.md` — the authority; read it alongside this plan.
**Build/test environment:** host, worktree `~/projects/tmuxwrapper-privsep` (branch `feat/privsep`). `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `node --test tests/*.test.js`. Root-only tests run via `sudo -E cargo test ... -- --ignored` only where a task says so.

## Global Constraints

- Never touch production: no edits to `/opt/tmuxwrapper`, `/etc/systemd/system/tmuxwrapper.service`, and never restart `tmuxwrapper.service`. The end-to-end run uses transient unit `tmuxwrapper-e2e` on `127.0.0.1:7682`.
- No `sudo` invocations anywhere in `src/`.
- CI must stay green: `cargo build --locked`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `node --test tests/*.test.js`.
- Allowed dependency changes: add nix features `socket` and `uio`; add `tokio-tungstenite` as a **dev-dependency** only. No other new crates.
- Front system user default: `tmuxwrapper`. Helper keeps only the user's primary gid (no supplementary groups).
- Front↔helper request timeout: 10 s. Max protocol message: 64 KiB.
- Unchanged user-visible behaviour and strings: WS close codes `4001` ("session expired") and `4004` (refusals); refusal reasons "tmux server isn't running — start tmux-server.service", "session limit reached — kill an old session first", "connection limit reached — close another terminal tab first".
- Session names: `[A-Za-z0-9_-]+` (existing `is_valid_session_name`).

## Review Focus

1. A WebSocket client disconnects while the helper is still opening its terminal → the received fd is dropped, the tmux client exits and the helper reaps it (no zombie). Test in Task 5.
2. The helper receives malformed JSON, an unknown `op`, or a >64 KiB message → replies `bad_request` (or drops the message) and keeps serving; the service does not crash. Test in Task 4.
3. Token email differs in case from config (`Virgil@Gmail.com`) → authorized exactly as the front's case-insensitive `find_user`. Test in Task 1.
4. The helper's JWKS isn't loaded yet (startup fetch failed) while the front's is → `open` returns `refused` with reason "auth keys unavailable — try again shortly", and succeeds after a refresh. Test in Task 4.
5. Two `open`s at once (two tabs) → serialised by the client mutex; both succeed within the timeout. Test in Task 5.

## File structure

| File | Responsibility |
|---|---|
| `src/config.rs` (modify) | Add `run_as`, `[cloudflare] jwks_url` / `issuer` overrides with validation. |
| `src/auth.rs` (modify) | `JwksCache` built from explicit URL/issuer; static-key constructor for tests; `token_grants` authorisation. |
| `src/proto.rs` (create) | Wire types and SCM_RIGHTS send/recv over SEQPACKET, sync + async. |
| `src/tmux.rs` (create) | tmux operations as the *current* user (moved from `ws.rs`, no sudo). |
| `src/pty.rs` (rewrite) | `spawn_tmux_client` via `tokio::process::Command` + `pre_exec`; `PtyMaster` wraps a received fd. |
| `src/helper.rs` (create) | Helper request handling, serve loop, `run_helper` entrypoint. |
| `src/helper_client.rs` (create) | Front-side client: serialised requests, timeout, exit on dead helper. |
| `src/privdrop.rs` (create) | Drop to a uid/gid set and prove root can't be regained. |
| `src/main.rs` (rewrite startup) | Fork helpers, drop front, then build runtime and serve. |
| `src/ws.rs` (modify) | Handlers call `HelperClient`; tmux/sudo code removed. |
| `src/user.rs` (modify) | Expose primary gid / home / username needed by helper. |
| `tmuxwrapper.service`, `deploy.sh`, `README.md` (modify) | Sandbox tightening, system user creation, docs. |
| `scripts/e2e-privsep.sh`, `tests/e2e_privsep.rs` (create) | Parallel-instance end-to-end run. |

---

### Task 1: Config overrides and token authorisation

**Files:** Modify `src/config.rs`, `src/auth.rs`; tests in-module.

**Interfaces:**
- Produces:
  - `Config.run_as: String` (serde default `"tmuxwrapper"`; validated `[a-z_][a-z0-9_-]*`, not `"root"`).
  - `CloudflareConfig.jwks_url: Option<String>`, `CloudflareConfig.issuer: Option<String>`; `CloudflareConfig::resolved_jwks_url(&self) -> String` (override or `https://{team_domain}.cloudflareaccess.com/cdn-cgi/access/certs`), `CloudflareConfig::resolved_issuer(&self) -> String` (override or `https://{team_domain}.cloudflareaccess.com`).
  - `JwksCache::new(jwks_url: &str, issuer: &str, audience: &str) -> JwksCache` (signature change; update the caller in `main.rs`).
  - `#[cfg(test)] JwksCache::with_static_keys(keys: Vec<jsonwebtoken::DecodingKey>, issuer: &str, audience: &str) -> JwksCache`.
  - `JwksCache::has_keys(&self) -> bool` (async; make it `pub(crate)` if currently private).
  - `pub(crate) fn token_grants(user: &UserConfig, claims: &Claims) -> bool` — true iff `claims.email` equals `user.email` ignoring ASCII case.

**Behaviour:** `jwks_url` override must be `https://…` or `http://127.0.0.1…` / `http://localhost…`; anything else is a config validation error. All existing validation unchanged.

**Tests:**
- No overrides → `resolved_jwks_url()`/`resolved_issuer()` give the Cloudflare URLs for the team domain.
- `jwks_url = "http://127.0.0.1:8799/certs"` accepted; `"http://evil.example/certs"` rejected.
- `run_as` default is `tmuxwrapper`; `run_as = "root"` rejected.
- `token_grants`: exact match true; `Virgil@Gmail.com` vs `virgil@gmail.com` true; other email false.
- `with_static_keys` + a token signed by a test RSA key (generate a PEM with `openssl genrsa` once and embed it as a test fixture string) verifies; wrong audience fails; expired fails.
Run: `cargo test config:: auth::`

**Acceptance:** tests pass; clippy/fmt clean; existing tests untouched and passing.

**Commit** per the commit policy.

---

### Task 2: Wire protocol and fd passing

**Files:** Create `src/proto.rs`; modify `Cargo.toml` (nix features `socket`, `uio`); register module in `main.rs`.

**Interfaces:**
- Produces (exact wire format, JSON, one message per SEQPACKET datagram):

```rust
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Open { token: String, session: String },
    List { token: String },
    Kill { token: String, name: String },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Opened { expires_at: u64 },           // accompanied by exactly one fd (PTY master)
    Sessions { sessions: Vec<SessionInfo> },
    Killed,
    NotFound,
    Refused { reason: String },
    Unauthorized,
    BadRequest,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SessionInfo { pub name: String, pub windows: u32, pub attached: bool }

pub const MAX_MESSAGE: usize = 64 * 1024;
```

  - `pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)>` (CLOEXEC).
  - `pub fn send<T: Serialize>(sock: BorrowedFd, msg: &T, fd: Option<BorrowedFd>) -> io::Result<()>`.
  - `pub fn recv<T: DeserializeOwned>(sock: BorrowedFd) -> io::Result<(T, Option<OwnedFd>)>` — blocking; `ErrorKind::UnexpectedEof` when the peer closed; `InvalidData` on oversize/truncated (`MSG_TRUNC`/`MSG_CTRUNC`) or bad JSON; any unexpected extra fds are closed.
  - `pub struct AsyncSeqpacket(AsyncFd<OwnedFd>)` with `new(OwnedFd)`, `async fn send<T>(&self, msg: &T, fd: Option<BorrowedFd<'_>>) -> io::Result<()>`, `async fn recv<T>(&self) -> io::Result<(T, Option<OwnedFd>)>` (non-blocking fd, same error semantics).
  - `SessionInfo` has the same JSON field names as `ws::TmuxSession`, which Task 5 replaces with it (so `/api/sessions` output is unchanged). Do not modify `ws.rs` in this task.

**Tests:**
- Request/Response JSON round-trip for every variant; `{"op":"open","token":"t","session":"main"}` deserialises to `Request::Open`.
- Send `Response::Opened` with the write end of a pipe; receive it; write through the received fd; read from the read end.
- Message larger than `MAX_MESSAGE` → `InvalidData`; peer closed → `UnexpectedEof`.
- Async variants: the same round-trip inside `#[tokio::test]`.
Run: `cargo test proto::`

**Acceptance:** tests pass; clippy/fmt clean.

**Commit** per the commit policy.

---

### Task 3: tmux operations and PTY spawning as the current user

**Files:** Create `src/tmux.rs`; modify `src/pty.rs` (add alongside the existing code); modify `src/ws.rs` only to import the moved pure functions from `tmux.rs`.

**Transition rule:** the crate must compile and all tests pass at the end of this task. Move the pure functions (`TmuxServer`, `classify_list_sessions`, `is_valid_session_name`, `refuses_new_session`) and their tests from `ws.rs` to `tmux.rs` and import them in `ws.rs`. Leave `ws.rs`'s sudo-based `query_tmux_server`/`start_tmux_server_unit`, the sudo session list/kill, and `PtyMaster::spawn`/`terminate_and_reap` in place — Task 5 deletes them.

**Interfaces:**
- Consumes: `proto::SessionInfo` (Task 2).
- Produces (`src/tmux.rs`, all run tmux as the current process user, no sudo; `socket: Option<&Path>` adds `-S <path>` for tests, `None` in production):
  - `pub enum TmuxServer { Running(Vec<String>), NotRunning, Unknown }` and `pub fn classify_list_sessions(success: bool, stdout: &str, stderr: &str) -> TmuxServer` (moved verbatim with tests).
  - `pub fn is_valid_session_name(name: &str) -> bool`, `pub fn refuses_new_session(existing: &[String], requested: &str, cap: usize) -> bool` (moved with tests).
  - `pub async fn query_server(socket: Option<&Path>) -> TmuxServer`.
  - `pub async fn start_server_unit()` — `systemctl --user start tmux-server.service` (relies on `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` set by the helper).
  - `pub async fn list_sessions(socket: Option<&Path>) -> Vec<SessionInfo>`.
  - `pub async fn kill_session(name: &str, socket: Option<&Path>) -> io::Result<bool>` (false = not found).
- Produces (`src/pty.rs`):
  - `pub fn spawn_tmux_client(session: &str, home: &Path, socket: Option<&Path>) -> io::Result<(OwnedFd, tokio::process::Child)>` — `openpty`; child via `tokio::process::Command::new("/usr/bin/tmux")` args `new-session -A -s <session> -c <home>` (plus `-S` when given), stdin/stdout/stderr = slave, `env TERM=xterm-256color`, `env_remove TMUX`, `current_dir(home)`, `pre_exec`: `setsid()` then `ioctl(0, TIOCSCTTY, 0)`; slave closed in the parent; returns the master fd.
  - `PtyMaster` gains `pub fn from_fd(fd: OwnedFd) -> io::Result<PtyMaster>` (sets O_NONBLOCK, wraps in AsyncFd, no child) and `pub fn resize(&self, cols: u16, rows: u16)`; its `child_pid` becomes `Option<Pid>` and `Drop` reaps only when it is `Some` (the legacy `spawn` path). `AsyncRead`/`AsyncWrite` unchanged.

**Tests:**
- Moved tests for `classify_list_sessions`, `is_valid_session_name`, `refuses_new_session` still pass.
- Scratch server (`tmux -S <tmpdir>/sock new-session -d -s base`): `query_server(Some(sock))` → `Running(["base"])`; `spawn_tmux_client("t1", …, Some(sock))` → reading the master yields bytes within 2 s; `list_sessions` includes `t1`; dropping the master fd → `child.wait()` completes within 3 s; `kill_session("t1")` → true, again → false; kill the scratch server at the end.
- `query_server(Some(<nonexistent>))` → `NotRunning`.
Run: `cargo test tmux:: pty::`

**Acceptance:** tests pass; `ws.rs` behaviour unchanged; clippy/fmt clean.

**Commit** per the commit policy.

---

### Task 4: Helper

**Files:** Create `src/helper.rs`.

**Interfaces:**
- Consumes: `proto::{Request, Response, SessionInfo, AsyncSeqpacket}` (Task 2); `tmux::*`, `pty::spawn_tmux_client` (Task 3); `auth::{JwksCache, Claims, token_grants}`, `config::UserConfig` (Task 1).
- Produces:
  - `pub struct HelperCtx { pub user: UserConfig, pub home: PathBuf, pub jwks: JwksCache, pub max_sessions: usize, pub tmux_socket: Option<PathBuf> }`.
  - `pub async fn handle(ctx: &HelperCtx, req: Request) -> (Response, Option<OwnedFd>)`.
  - `pub async fn serve(ctx: HelperCtx, sock: AsyncSeqpacket)` — loop: `recv` → `handle` → `send`; on `InvalidData` reply `BadRequest` and continue; on `UnexpectedEof` return. Spawned PTY children are moved into a task that awaits `child.wait()` (reaping).
  - `pub fn run_helper(sock: OwnedFd, user: UserConfig, home: PathBuf, cloudflare: &CloudflareConfig, max_sessions: usize) -> !` — builds a tokio **current-thread** runtime, creates `JwksCache::new(&cloudflare.resolved_jwks_url(), &cloudflare.resolved_issuer(), &cloudflare.audience)`, does an initial refresh (failure logged, not fatal), starts the refresh task, runs `serve` with `tmux_socket: None`, and exits 0 when the front goes away.

**Behaviour (`handle`):**
1. Every request: verify the token with `ctx.jwks.verify`; if no keys are loaded → `Refused { reason: "auth keys unavailable — try again shortly" }`; verification failure or `!token_grants(&ctx.user, &claims)` → `Unauthorized`.
2. `Open`: invalid session name → `BadRequest`. `query_server`; if `NotRunning` → `start_server_unit` then re-query; still `NotRunning` → `Refused` with the tmux-server reason. `Running(names)` and `refuses_new_session(names, session, max)` → `Refused` with the session-limit reason. `Unknown` → proceed (fail-open, as today, with the existing warning). Spawn → `Opened { expires_at: claims.exp }` + master fd.
3. `List` → `Sessions`. `Kill`: invalid name → `BadRequest`; `kill_session` → `Killed` / `NotFound`.

**Tests** (in-module; `HelperCtx` with `JwksCache::with_static_keys` and a scratch tmux socket):
- Bypass: `Open`/`List`/`Kill` with a token signed by a *different* key, an expired token, a wrong-audience token, and a valid token for a different email → `Unauthorized`, and no PTY fd returned.
- Empty-key cache → `Refused` with "auth keys unavailable — try again shortly".
- Valid token `Open` on the scratch server → `Opened` with an fd; reading it yields bytes.
- `serve` given a malformed JSON datagram → replies `BadRequest`, then answers a valid `List` on the same socket (Review Focus 2).
- `Open` at the session cap for a new name → `Refused` (session-limit reason); for an existing name → `Opened`.
Run: `cargo test helper::`

**Acceptance:** tests pass; clippy/fmt clean.

**Commit** per the commit policy.

---

### Task 5: Front-side helper client and handler switch-over

**Files:** Create `src/helper_client.rs`; modify `src/ws.rs` (handlers), `src/main.rs` (module registration only).

**Interfaces:**
- Consumes: `proto::*` (Task 2), `pty::PtyMaster::from_fd` (Task 3).
- Produces:
  - `pub struct HelperClient` with `pub fn new(sock: OwnedFd) -> io::Result<HelperClient>`.
  - `pub async fn request(&self, req: &Request) -> Result<(Response, Option<OwnedFd>), HelperDead>` — holds a `tokio::sync::Mutex` across send+recv; 10 s timeout; on timeout or I/O error returns `HelperDead`.
  - `pub struct HelperDead;` — callers log `error!` and call `std::process::exit(1)` (systemd restarts the service).
  - `AppState` gains `helpers: HashMap<String /* unix_user */, HelperClient>`.

**Behaviour (`ws.rs`):**
- Front still runs `authenticate` (header or `CF_Authorization` cookie), and now also keeps the raw token string in `AuthIdentity` to forward it.
- `GET /api/sessions` → `List`; `Sessions` → JSON array (same shape as today); `Unauthorized` → 401; anything else → 500.
- `DELETE /api/sessions/{name}` → `Kill`; `Killed` → 200, `NotFound` → 404, `BadRequest` → 400, `Unauthorized` → 401.
- WS: connection cap stays in the front. After upgrade → `Open`; `Opened{expires_at}` + fd → `PtyMaster::from_fd`, then `run_bridge` with `until_expiry(expires_at, now)` as today; `Refused{reason}` → `refuse_socket(reason)` (4004); `Unauthorized` → close 4001.
- `pty_resize` uses `PtyMaster::resize` (drop the dup'd raw fd).
- Delete `query_tmux_server`, `start_tmux_server_unit`, the sudo-based session list and kill, every `/usr/bin/sudo` use, and `ws::TmuxSession` (use `proto::SessionInfo`).
- In `pty.rs`, delete `PtyMaster::spawn`, `terminate_and_reap`, `user_name_from_uid`, the `child_pid` field and their tests (tokio reaps in the helper); `PtyMaster` is constructed only via `from_fd`.

**Tests:**
- `HelperClient` against a fake helper (thread on the other socketpair end): round-trip `List`; fake answers after 11 s → `HelperDead`; fake closes the socket → `HelperDead`.
- Two concurrent `request`s from two tasks → both answered correctly (Review Focus 5).
- Client receives `Opened` + fd but the caller drops it immediately (simulating a disconnected WS) → with a real helper on a scratch tmux socket, the spawned tmux client is reaped within 3 s: no `Z` child of the test process (Review Focus 1).
- `grep -rn sudo src/` → no matches (assert in a test or in the acceptance check).
Run: `cargo test helper_client:: ws::`

**Acceptance:** all tests pass; `grep -rn '/usr/bin/sudo' src/` empty; no `fork()`/`setuid` left in `pty.rs`; clippy/fmt clean.

**Commit** per the commit policy.

---

### Task 6: Privilege drop and startup orchestration

**Files:** Create `src/privdrop.rs`; rewrite startup in `src/main.rs`; modify `src/user.rs`.

**Interfaces:**
- Consumes: `helper::run_helper` (Task 4), `helper_client::HelperClient` (Task 5), `Config.run_as` (Task 1).
- Produces:
  - `pub fn drop_privileges(uid: Uid, gid: Gid, groups: &[Gid]) -> io::Result<()>` — `setgroups(groups)` → `setgid(gid)` → `setuid(uid)`; then verify `getuid/geteuid != 0` and that `setuid(0)` fails; any failure → `Err`.
  - `ResolvedUser` gains `name: String` (for env) and keeps `uid`, `gid`, `home`, `shell`.

**Behaviour (`main`):** plain `fn main()` (no `#[tokio::main]`):
1. Config-path argument handling as today; `tracing_subscriber` init; load config; resolve each user and the `run_as` system user (missing → exit with "system user '<name>' not found — run deploy.sh").
2. For each user: `seqpacket_pair()`, `fork()`. Child: close the front's end and all other helpers' ends; `prctl(PR_SET_PDEATHSIG, SIGTERM)` (exit if the parent already died); `drop_privileges(user.uid, user.gid, &[user.gid])`; set `HOME`, `USER`, `LOGNAME`, `SHELL`, `XDG_RUNTIME_DIR=/run/user/<uid>`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus`; `run_helper(...)`.
3. Parent: `drop_privileges(run_as.uid, run_as.gid, &[])`; build the multi-thread tokio runtime; construct `HelperClient`s and `AppState`; bind and serve exactly as today.
4. Fork must happen before any thread exists (no runtime, no reqwest client yet).

**Tests:**
- `#[ignore]` root-only test: in a forked child, `drop_privileges(65534, 65534, &[])` → `getuid()==65534`, `setuid(0)` fails, `/proc/self/status` `CapEff` is `0000000000000000`; child exits 0. Run: `sudo -E env PATH=$PATH cargo test privdrop:: -- --ignored`.
- Non-root: `drop_privileges` with the current uid/gid succeeds (no-op path).
Run: `cargo test privdrop::` and the sudo command above.

**Acceptance:** tests pass (including the ignored root test, run once by the orchestrator); `cargo run` with a valid local config starts, logs "listening", and `ps -o user,pid,ppid,cmd` shows the front as `run_as` and the helper as the configured user (manual check documented in the task report).

**Commit** per the commit policy.

---

### Task 7: Unit file, deploy script, docs

**Files:** Modify `tmuxwrapper.service`, `deploy.sh`, `README.md`, `config.toml` (example).

**Behaviour:**
- Unit: `CapabilityBoundingSet=CAP_SETUID CAP_SETGID`; `NoNewPrivileges=yes`; `ReadWritePaths=/tmp`; add `ProtectHome=read-only`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`, `LockPersonality=yes`, `RestrictRealtime=yes`; keep `KillMode=process`, `User=root`, `PrivateTmp=false`, existing Protect* lines and the session-saving comment.
- `deploy.sh`: before installing, create the system user if missing: `id tmuxwrapper >/dev/null 2>&1 || sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tmuxwrapper`. Everything else unchanged (keeps live config, restarts a running service).
- README: describe the process model (front as `tmuxwrapper`, helper as the user, token re-verification, no sudo) in the Features list and a short "Security model" section; document `run_as` and the testing-only `jwks_url`/`issuer` overrides.
- Example `config.toml`: add commented `# run_as = "tmuxwrapper"`.

**Tests:** `systemd-analyze verify tmuxwrapper.service` (warnings about the missing binary path are acceptable; syntax errors are not); `bash -n deploy.sh`.

**Acceptance:** both checks pass; production unit untouched (`diff` against `/etc/systemd/system/tmuxwrapper.service` shows only the intended changes, and nothing is installed).

**Commit** per the commit policy.

---

### Task 8: Parallel-instance end-to-end run

**Files:** Create `scripts/e2e-privsep.sh`, `tests/e2e_privsep.rs`; modify `Cargo.toml` (dev-dependency `tokio-tungstenite`).

**Behaviour (`scripts/e2e-privsep.sh`, run with sudo by the orchestrator):**
1. `cargo build --release`; ensure the `tmuxwrapper` system user exists (same command as `deploy.sh`).
2. Generate a throwaway RSA key in a temp dir; write `certs.json` (`{"keys":[{"kty":"RSA","n":…,"e":"AQAB","kid":"e2e"}]}`, `n` base64url from the modulus); serve it with `python3 -m http.server 8799 --bind 127.0.0.1 --directory <tmp>`.
3. Write a test config: `listen = "127.0.0.1:7682"`, `static_dir` = the worktree's `static/`, `[cloudflare] team_domain = "e2e"`, `audience = "e2e-aud"`, `jwks_url = "http://127.0.0.1:8799/certs.json"`, `issuer = "https://e2e.cloudflareaccess.com"`, one user `email = "e2e@example.com"`, `unix_user = "ktulu"`, `tmux_session = "e2e-main"`.
4. Start `systemd-run --unit tmuxwrapper-e2e --property=<each [Service] hardening line from tmuxwrapper.service> <release binary> <test config>`.
5. Run `cargo test --release --test e2e_privsep -- --ignored --test-threads=1` with env `E2E_KEY_PEM`, `E2E_URL=127.0.0.1:7682`.
6. Always: `systemctl stop tmuxwrapper-e2e`, stop the JWKS server, `tmux kill-session -t` any `e2e-*` sessions, remove the temp dir.

**Tests (`tests/e2e_privsep.rs`, all `#[ignore]`):**
- Process model: the unit's main PID runs as `tmuxwrapper` with `CapEff` 0; its child helper runs as `ktulu` with `Groups:` equal to ktulu's primary gid only; no process in the unit's cgroup runs as root.
- Terminal: WS to `/ws?session=e2e-a` with `Cf-Access-Jwt-Assertion` → send `echo e2e-$RANDOM\r` (tag 0x00) → the echo appears in output within 5 s.
- `GET /api/sessions` lists `e2e-a`; `DELETE /api/sessions/e2e-a` → 200; again → 404.
- Token for an unmapped email → 403 at the front; expired token → 401.
- Expiry: token with `exp = now + 5` → the WS closes with code 4001 within 10 s.
- No zombies: after closing all sockets and waiting 3 s, no `Z` process in the unit's cgroup.
- Helper death: `kill -9` the helper → the main process exits within 15 s (`systemctl is-active tmuxwrapper-e2e` → not active). Restart the unit for the next test.
- Front death: `kill -9` the main process → the helper is gone within 5 s (PDEATHSIG).

**Acceptance:** the script exits 0 with every test passing; its output is saved to `docs/plans/2026-10-03-privilege-separation-e2e.log` and committed.

**Commit** per the commit policy.

# tmux-wrapper

Single-binary web tmux terminal, fronted by Cloudflare Access.

The auth is the tunnel. The binary just runs tmux.

<p align="center">
  <img src="screenshots/main.jpg" width="240" alt="Session picker">
  <img src="screenshots/root.jpg" width="240" alt="Terminal session">
  <img src="screenshots/claude.jpg" width="240" alt="Claude Code on mobile">
</p>

```
browser ─► permutations cloudflare ─► your host (127.0.0.1:7681) ─► tmuxwrapper ─► tmux
            ↑                              ↑
            TLS terminates here            JWT verified here
            CF Access enforces who         (JWKS cached, refreshed periodically)
```

## Why this exists

The first version of this had two auth modes (local password + Cloudflare Access), a voice-output experiment, and shipped as Docker. The auth surface and TLS story were confusing. This one trims it to one path:

- **One auth mode:** Cloudflare Access. JWT in `Cf-Access-Jwt-Assertion`, verified against your team's JWKS. If the request reaches the binary, it's already authenticated. There is no password fallback in the code — not disabled, gone.
- **One transport:** the binary binds `127.0.0.1:7681`. TLS isn't its problem — Cloudflare terminates it, the tunnel carries plain HTTP from the edge to your box.
- **One artifact:** a Rust binary + a `config.toml` + a systemd unit. No Docker.

If you need local password auth or self-hosted TLS, this isn't the project for you.

## Features

- **Cloudflare Access auth** — JWT verified against your team's JWKS (cached, periodic refresh; failed fetches retry with backoff so a blip at boot doesn't lock everyone out). Open terminals close when the Access session behind them expires, and the client reloads through the Access login instead of looping on reconnect
- **Email → unix user** — the email in the access JWT maps to a real account on the box. Privilege-separated: the binary starts as root, forks a per-user helper that drops to that user (primary gid only), then drops the network-facing front to an unprivileged `tmuxwrapper` system user. The helper re-verifies every Access JWT itself, and there is no sudo
- **Tmux per user** — every session attaches to a named tmux session as the target unix user
- **Session caps** — at most 5 WebSocket connections per user, and a configurable cap on distinct tmux sessions (`max_sessions_per_user`, default 5). Creating a session past the cap is refused with a visible message; attaching to an existing one always works
- **Systemd-managed** — capability-bounded service that only *attaches*: each user's tmux server runs from their own `tmux-server.service` user unit (see `contrib/`), so panes never inherit the wrapper's sandbox. If a user's server is down (e.g. its last session was killed), the wrapper starts that unit; if it can't, the connection is refused with a visible message rather than starting a sandboxed server
- **PWA-ready** — installable on iOS/Android, touch-friendly key bar, dictation support, WebGL rendering
- **Phone scrolling** — finger travel maps to paced wheel ticks with momentum after a flick, so mouse-aware apps (Claude Code fullscreen, vim, less) and tmux copy-mode scroll like a native list; key-bar buttons for page up/down and jump to top/latest

## Quickstart

```bash
git clone https://github.com/devPermutations/tmux-wrapper.git
cd tmux-wrapper
cargo build --release
./deploy.sh
```

That installs the binary to `/opt/tmuxwrapper/`, copies static assets, and registers the systemd unit. Re-running it upgrades in place: an existing `/opt/tmuxwrapper/config.toml` is kept and a running service is restarted.

Before installing anything, `deploy.sh` copies the currently installed binary, static files and systemd unit (whichever exist) to `/opt/tmuxwrapper.bak-<YYYYmmdd-HHMMSS>/` and prints that path. To undo an upgrade:

```bash
./rollback.sh                                     # newest /opt/tmuxwrapper.bak-*
./rollback.sh /opt/tmuxwrapper.bak-20261003-201500  # or a specific backup
```

`rollback.sh` restores the binary, static files and unit together (an older binary may not run under a newer unit), runs `systemctl daemon-reload`, and restarts the service if it was running. It never touches `config.toml`.

Each unix user in the config needs a tmux server running from a user unit:

```bash
cp contrib/tmux-server.service ~/.config/systemd/user/
cp contrib/tmux-save-guarded ~/.local/bin/   # optional: guarded tmux-resurrect save on stop
systemctl --user enable --now tmux-server.service
sudo loginctl enable-linger "$USER"
```

On a first install, edit the config before starting:

```bash
sudo nano /opt/tmuxwrapper/config.toml
```

Set `cloudflare.audience` to your CF Access AUD tag (see [Cloudflare Access setup](#cloudflare-access-setup) below), then:

```bash
sudo systemctl start tmuxwrapper
sudo systemctl status tmuxwrapper
```

Point your CF Access app at the host and visit it from any browser.

## Configuration

`config.toml`:

```toml
listen = "127.0.0.1:7681"
static_dir = "./static"
# run_as = "tmuxwrapper"   # optional; user the front drops to

[cloudflare]
team_domain = "yourteam"                          # https://yourteam.cloudflareaccess.com
audience = "REPLACE_WITH_CF_ACCESS_AUD_TAG"       # from your CF Access app
jwks_refresh_secs = 3600

[terminal]
ping_interval_secs = 30
max_sessions_per_user = 5    # tmux sessions per user; attach is always allowed

[[users]]
email = "you@example.com"
unix_user = "youruser"
tmux_session = "main"
```

Add one `[[users]]` block per allowed user. Emails not in the list are rejected even if their Cloudflare JWT is valid.

`run_as` (default `tmuxwrapper`) is the system user the front process runs as; `deploy.sh` creates it. It must not equal any `unix_user` or share a uid or primary gid with one; startup refuses otherwise. The binary must be started as root and refuses to run otherwise.

For tests only, `[cloudflare]` accepts `jwks_url` and `issuer` overrides. `jwks_url` must be `https`, or `http` on `127.0.0.1`/`localhost`/`::1`, with no userinfo. Leave both unset in production.

## Cloudflare Access setup

1. Cloudflare dashboard → **Zero Trust** → **Access** → **Applications** → **Add an application** → **Self-hosted**.
2. Set the application domain to the hostname that will reach your tunnel (e.g. `term.example.com`).
3. Add an Access policy with the email(s) you'll list in `config.toml`.
4. After creating the application, open it and copy the **Application Audience (AUD) Tag**. That's the `audience` value.
5. Set your `team_domain` to the subdomain in your team URL (`https://<team_domain>.cloudflareaccess.com`).

Tunnel the application hostname (`term.example.com`) to `http://127.0.0.1:7681` on your host using `cloudflared` or a sidecar tunnel.

## Security model

The service starts as root, but the process that faces the network does not stay root:

- **Front** — HTTP/WebSocket handling and the first JWT check run as `run_as` (default `tmuxwrapper`), a no-login system user with no home and no supplementary groups.
- **Helper** — one per target unix user, forked while still root. It drops to that user (uid and primary gid only, no supplementary groups) and spawns the PTY. It re-verifies every Access JWT itself, so a compromised front can't ask for a terminal as someone it holds no valid token for.
- **No sudo** — nothing escalates after the drop.

The systemd unit backs this up:

```
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
LockPersonality=yes
RestrictRealtime=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
```

## Status

This is the code I run on my own server. It's stable enough for that. No guarantees beyond that — issues and PRs welcome but no SLA.

## License

MIT

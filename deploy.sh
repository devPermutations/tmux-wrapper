#!/bin/bash
# Install or upgrade tmuxwrapper under /opt. Safe to re-run: the live
# config.toml is never overwritten, and a running service is restarted.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/tmuxwrapper"
UNIT="/etc/systemd/system/tmuxwrapper.service"
BACKUP="/opt/tmuxwrapper.bak-$(date +%Y%m%d-%H%M%S)"

# Back up the installed binary, static files and unit before touching any of
# them; rollback.sh restores them together. config.toml is never replaced, so
# it is not backed up.
echo "==> Backing up the installed version"
if sudo test -e "$BACKUP"; then
    echo "    $BACKUP already exists; re-run in a second" >&2
    exit 1
fi
backup() {
    if sudo test -e "$1"; then
        sudo mkdir -p "$BACKUP"
        sudo cp -a "$1" "$BACKUP/$2"
    fi
}
backup "$DEST/tmuxwrapper" tmuxwrapper
backup "$DEST/static" static
backup "$UNIT" tmuxwrapper.service
if sudo test -d "$BACKUP"; then
    echo "    Backup: $BACKUP"
    echo "    Roll back with: $SRC/rollback.sh $BACKUP"
else
    echo "    Nothing installed yet; no backup taken"
fi

echo "==> Ensuring system user tmuxwrapper"
id tmuxwrapper >/dev/null 2>&1 || sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tmuxwrapper

echo "==> Installing binary"
sudo install -D -m 0755 "$SRC/target/release/tmuxwrapper" "$DEST/tmuxwrapper"

if sudo test -e "$DEST/config.toml"; then
    echo "==> Keeping existing $DEST/config.toml"
    fresh_config=0
else
    echo "==> Installing example config"
    sudo install -m 0644 "$SRC/config.toml" "$DEST/config.toml"
    fresh_config=1
fi

echo "==> Syncing static files"
sudo rsync -a --delete "$SRC/static/" "$DEST/static/"

echo "==> Installing systemd service"
sudo install -m 0644 "$SRC/tmuxwrapper.service" "$UNIT"
sudo systemctl daemon-reload
sudo systemctl enable tmuxwrapper

if [ "$fresh_config" = 1 ]; then
    echo ""
    echo "==> Installed. Before starting, edit the config:"
    echo "    sudo nano $DEST/config.toml"
    echo "    (set cloudflare.audience to your CF Access AUD tag)"
    echo ""
    echo "    Then: sudo systemctl start tmuxwrapper"
elif systemctl is-active --quiet tmuxwrapper; then
    echo "==> Restarting tmuxwrapper"
    sudo systemctl restart tmuxwrapper
    systemctl is-active tmuxwrapper
else
    echo "==> Upgraded. Start with: sudo systemctl start tmuxwrapper"
fi

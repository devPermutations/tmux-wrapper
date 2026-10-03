#!/bin/bash
# Roll back to a backup taken by deploy.sh. Restores the binary, static files
# and systemd unit together (an old binary does not work under a new unit),
# reloads systemd and restarts the service if it was running. Never touches
# config.toml.
#
# Usage: ./rollback.sh [/opt/tmuxwrapper.bak-YYYYmmdd-HHMMSS]
#        (default: the newest /opt/tmuxwrapper.bak-*)
set -euo pipefail

DEST="/opt/tmuxwrapper"
UNIT="/etc/systemd/system/tmuxwrapper.service"

if [ $# -gt 1 ]; then
    echo "usage: $0 [/opt/tmuxwrapper.bak-YYYYmmdd-HHMMSS]" >&2
    exit 2
fi
if [ $# -eq 1 ]; then
    BACKUP="${1%/}"
else
    shopt -s nullglob
    backups=(/opt/tmuxwrapper.bak-*)
    shopt -u nullglob
    if [ ${#backups[@]} -eq 0 ]; then
        echo "No /opt/tmuxwrapper.bak-* backup found" >&2
        exit 1
    fi
    # Timestamped names sort chronologically; glob results are sorted.
    BACKUP="${backups[${#backups[@]}-1]}"
fi

missing=()
for f in tmuxwrapper static tmuxwrapper.service; do
    sudo test -e "$BACKUP/$f" || missing+=("$f")
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "$BACKUP lacks: ${missing[*]} — refusing a partial rollback" >&2
    exit 1
fi

was_active=0
systemctl is-active --quiet tmuxwrapper && was_active=1

echo "==> Restoring binary, static files and unit from $BACKUP"
sudo install -m 0755 "$BACKUP/tmuxwrapper" "$DEST/tmuxwrapper"
sudo rsync -a --delete "$BACKUP/static/" "$DEST/static/"
sudo install -m 0644 "$BACKUP/tmuxwrapper.service" "$UNIT"
sudo systemctl daemon-reload

if [ "$was_active" = 1 ]; then
    echo "==> Restarting tmuxwrapper"
    sudo systemctl restart tmuxwrapper
    systemctl is-active tmuxwrapper
else
    echo "==> Restored. tmuxwrapper was not running; start with: sudo systemctl start tmuxwrapper"
fi

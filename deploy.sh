#!/bin/bash
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/tmuxwrapper"

echo "==> Creating $DEST"
sudo mkdir -p "$DEST/static/vendor"

echo "==> Copying binary"
sudo cp "$SRC/target/release/tmuxwrapper" "$DEST/tmuxwrapper"
sudo chmod +x "$DEST/tmuxwrapper"

echo "==> Copying config"
sudo cp "$SRC/config.toml" "$DEST/"

echo "==> Copying static files"
sudo cp "$SRC/static/"*.html "$SRC/static/"*.js "$SRC/static/"*.css "$SRC/static/"*.json "$SRC/static/"*.png "$DEST/static/"
sudo cp "$SRC/static/vendor/"* "$DEST/static/vendor/"

echo "==> Installing session-save helper"
sudo cp "$SRC/save-sessions.sh" "$DEST/save-sessions.sh"
sudo chmod +x "$DEST/save-sessions.sh"

echo "==> Installing systemd service"
sudo cp "$SRC/tmuxwrapper.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable tmuxwrapper

echo ""
echo "==> Deployed! Before starting, edit the config:"
echo "    sudo nano $DEST/config.toml"
echo "    (set cloudflare.audience to your CF Access AUD tag)"
echo ""
echo "    Then start with:"
echo "    sudo systemctl start tmuxwrapper"
echo "    sudo systemctl status tmuxwrapper"

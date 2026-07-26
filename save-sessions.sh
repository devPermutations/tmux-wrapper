#!/bin/bash
# Best-effort tmux-resurrect save for every user with a running tmux server.
# Called from the systemd unit's ExecStop so sessions can be restored after
# a service stop or reboot. Silent no-op if tmux-resurrect isn't installed.
set -u

users=$(ps -eo user=,comm= | grep -F 'tmux: server' | awk '{print $1}' | sort -u)

for u in $users; do
    home=$(getent passwd "$u" | cut -d: -f6)
    [ -n "$home" ] || continue
    save="$home/.tmux/plugins/tmux-resurrect/scripts/save.sh"
    [ -x "$save" ] || continue
    su - "$u" -c "$save" >/dev/null 2>&1 || true
done

exit 0

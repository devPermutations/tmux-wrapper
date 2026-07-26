#!/bin/bash
# Best-effort tmux-resurrect save for every user with a running tmux server.
# Called from the systemd unit's ExecStop so sessions can be restored after
# a service stop or reboot. Silent no-op if tmux-resurrect isn't installed.
set -u

# Match by uid, not username: `ps -eo user=` truncates names >8 chars to
# "name+", which then fails the getent lookup.
uids=$(ps -eo uid=,comm= | grep -F 'tmux: server' | awk '{print $1}' | sort -u)

for uid in $uids; do
    entry=$(getent passwd "$uid") || continue
    u=$(printf '%s' "$entry" | cut -d: -f1)
    home=$(printf '%s' "$entry" | cut -d: -f6)
    [ -n "$home" ] || continue
    save="$home/.tmux/plugins/tmux-resurrect/scripts/save.sh"
    [ -x "$save" ] || continue
    su - "$u" -c "$save" >/dev/null 2>&1 || true
done

exit 0

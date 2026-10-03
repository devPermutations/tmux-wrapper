#!/usr/bin/env bash
# End-to-end proof of privilege separation: runs the real release binary under
# a transient systemd unit with the production sandbox on 127.0.0.1:7682, then
# runs the black-box tests (tests/e2e_privsep.rs) and the helper/front death
# checks. Run as the normal user (needs passwordless `sudo -n` for systemd-run,
# systemctl stop/status of the unit, and killing the nobody front process).
#
#   scripts/e2e-privsep.sh
#
# Output is teed to docs/plans/2026-10-03-privilege-separation-e2e.log.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
LOG="$REPO/docs/plans/2026-10-03-privilege-separation-e2e.log"
mkdir -p "$(dirname "$LOG")"
: >"$LOG"
exec > >(tee -a "$LOG") 2>&1

UNIT=tmuxwrapper-e2e
ADDR=127.0.0.1:7682
JWKS_PORT=8799
TMP=""
JWKS_PID=""
FAILS=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
die() { echo "FATAL: $*"; exit 1; }

cleanup() {
  echo "--- cleanup"
  sudo -n systemctl stop "$UNIT" >/dev/null 2>&1
  [ -n "$JWKS_PID" ] && kill "$JWKS_PID" >/dev/null 2>&1
  kill_e2e_sessions
  [ -n "$TMP" ] && rm -rf "$TMP"
}
# Only ever touches sessions named e2e-*; '=' forces an exact name match.
kill_e2e_sessions() {
  tmux ls -F '#{session_name}' 2>/dev/null | grep '^e2e-' |
    xargs -r -I{} tmux kill-session -t '={}' >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

sudo -n true 2>/dev/null || die "passwordless sudo (sudo -n) is required"
for t in openssl python3 curl pgrep; do
  command -v "$t" >/dev/null || die "missing tool: $t"
done
sudo -n systemctl stop "$UNIT" >/dev/null 2>&1
kill_e2e_sessions

echo "--- build (release)"
cargo build --release || die "cargo build --release failed"

TMP="$(mktemp -d /tmp/tmuxwrapper-e2e.XXXXXX)" || die "mktemp failed"
chmod 755 "$TMP"
mkdir -p "$TMP/jwks" "$TMP/key"
chmod 755 "$TMP/jwks"
chmod 700 "$TMP/key"

# The unit's root has no CAP_DAC_OVERRIDE and /home/ktulu is 0750, so everything
# it reads lives in the world-readable temp dir.
cp target/release/tmuxwrapper "$TMP/tmuxwrapper" && chmod 755 "$TMP/tmuxwrapper"
cp -r static "$TMP/static" && chmod -R a+rX "$TMP/static"

echo "--- throwaway RSA key + JWKS"
KEY="$TMP/key/key.pem"
openssl genrsa -out "$KEY" 2048 2>/dev/null || die "openssl genrsa failed"
MODHEX="$(openssl rsa -in "$KEY" -noout -modulus | sed 's/^Modulus=//')"
if command -v xxd >/dev/null; then
  N="$(printf '%s' "$MODHEX" | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')"
else
  N="$(python3 -c 'import sys,base64;print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).decode().rstrip("="))' "$MODHEX")"
fi
[ -n "$N" ] || die "could not derive modulus"
printf '{"keys":[{"kty":"RSA","n":"%s","e":"AQAB","kid":"e2e"}]}\n' "$N" >"$TMP/jwks/certs.json"
chmod 644 "$TMP/jwks/certs.json"
python3 -m http.server "$JWKS_PORT" --bind 127.0.0.1 --directory "$TMP/jwks" >/dev/null 2>&1 &
JWKS_PID=$!
for _ in $(seq 1 50); do
  curl -fs "http://127.0.0.1:$JWKS_PORT/certs.json" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fs "http://127.0.0.1:$JWKS_PORT/certs.json" >/dev/null 2>&1 || die "JWKS server not up"

cat >"$TMP/config.toml" <<CFG
listen = "$ADDR"
static_dir = "$TMP/static"
run_as = "nobody"

[cloudflare]
team_domain = "e2e"
audience = "e2e-aud"
jwks_url = "http://127.0.0.1:$JWKS_PORT/certs.json"
issuer = "https://e2e.cloudflareaccess.com"
jwks_refresh_secs = 3600

[[users]]
email = "e2e@example.com"
unix_user = "ktulu"
tmux_session = "e2e-main"
CFG
chmod 644 "$TMP/config.toml"

# Every sandbox line of the production unit, parsed rather than copied.
PROPS=()
while IFS= read -r line; do
  PROPS+=("--property=$line")
done < <(awk '
  /^\[/ { in_svc = ($0 == "[Service]"); next }
  in_svc && /^[A-Za-z]+=/ {
    key = $0; sub(/=.*/, "", key)
    if (key ~ /^(Type|ExecStart|WorkingDirectory|Restart|RestartSec)$/) next
    print
  }' tmuxwrapper.service)
[ "${#PROPS[@]}" -gt 5 ] || die "failed to parse hardening properties from tmuxwrapper.service"
echo "--- unit properties: ${PROPS[*]}"

start_unit() {
  sudo -n systemctl stop "$UNIT" >/dev/null 2>&1
  sudo -n systemd-run --unit "$UNIT" --collect "${PROPS[@]}" \
    --property=WorkingDirectory="$TMP" \
    "$TMP/tmuxwrapper" "$TMP/config.toml" || return 1
  for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://$ADDR/" && return 0
    sleep 0.1
  done
  return 1
}

main_pid() { systemctl show -p MainPID --value "$UNIT.service"; }
helper_pid() {
  local m="$1" p
  for p in $(pgrep -P "$m"); do
    [ "$(cat "/proc/$p/comm" 2>/dev/null)" = tmuxwrapper ] && { echo "$p"; return 0; }
  done
  return 1
}
unit_active() { [ "$(systemctl is-active "$UNIT.service" 2>/dev/null)" = active ]; }
wait_gone() { # pid seconds
  local i
  for i in $(seq 1 $(($2 * 10))); do
    [ -d "/proc/$1" ] || return 0
    sleep 0.1
  done
  return 1
}

echo "--- start unit"
start_unit || die "unit did not come up on $ADDR (see: journalctl -u $UNIT)"
pass "unit started and listening on $ADDR"

echo "--- cargo e2e tests"
E2E_KEY_PEM="$KEY" E2E_URL="$ADDR" E2E_UNIT="$UNIT" \
  cargo test --release --test e2e_privsep -- --ignored --test-threads=1
if [ $? -eq 0 ]; then pass "cargo e2e tests"; else fail "cargo e2e tests"; fi

echo "--- helper death: kill -9 helper => main exits within 15 s"
start_unit || die "unit restart failed"
MAIN="$(main_pid)"
HELPER="$(helper_pid "$MAIN")"
if [ -z "$HELPER" ] || [ "${MAIN:-0}" -le 0 ]; then
  fail "helper death: could not find main ($MAIN) / helper ($HELPER)"
else
  kill -9 "$HELPER"
  gone=1
  for _ in $(seq 1 150); do
    if ! unit_active || [ ! -d "/proc/$MAIN" ]; then gone=0; break; fi
    sleep 0.1
  done
  if [ $gone -eq 0 ]; then pass "helper death: main exited"; else fail "helper death: main still running after 15 s"; fi
fi

echo "--- front death: kill -9 front => helper gone within 5 s"
start_unit || die "unit restart failed"
MAIN="$(main_pid)"
HELPER="$(helper_pid "$MAIN")"
if [ -z "$HELPER" ] || [ "${MAIN:-0}" -le 0 ]; then
  fail "front death: could not find main ($MAIN) / helper ($HELPER)"
else
  sudo -n kill -9 "$MAIN"
  if wait_gone "$HELPER" 5; then pass "front death: helper exited"; else fail "front death: helper $HELPER still alive after 5 s"; fi
fi

echo "---"
if [ "$FAILS" -eq 0 ]; then
  echo "RESULT: ALL CHECKS PASSED"
  exit 0
fi
echo "RESULT: $FAILS CHECK(S) FAILED"
exit 1

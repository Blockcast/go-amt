#!/usr/bin/env bash
# Install smoke test for the Blockcast shred receiver.
#
# Proves, against the packaged binary rather than the source tree, that:
#   1. the documented erasure scoring definition reproduces exactly,
#   2. /healthz is readiness-shaped (unhealthy until the first packet),
#   3. ingress, egress and unparsed-shred counters move on /metrics,
#   4. packets fan out byte-identically to every configured destination,
#   5. SIGTERM is a graceful shutdown that exits 0 and prints the receipt.
#
# Usage: packaging/smoke-test.sh [path-to-binary]
#
# Requires: bash, curl. python3 is optional and enables the byte-identity
# check; without it that one step is skipped rather than silently passing.

set -euo pipefail

BINARY="${1:-./blockcast-shreds}"
FEED_PORT="${SMOKE_FEED_PORT:-21000}"
SINK_PORT="${SMOKE_SINK_PORT:-21001}"
HTTP_PORT="${SMOKE_HTTP_PORT:-21080}"

WORKDIR="$(mktemp -d)"
GW_PID=""
SINK_PID=""
FAILURES=0

cleanup() {
  # Job-control notices for the killed helpers go to the shell's stderr, not the
  # subshell's, so they are silenced here rather than on the kill itself —
  # otherwise a clean run ends with a "Killed" line that reads like a failure.
  {
    [ -n "$GW_PID" ] && kill -KILL "$GW_PID" 2>/dev/null && wait "$GW_PID"
    [ -n "$SINK_PID" ] && kill -KILL "$SINK_PID" 2>/dev/null && wait "$SINK_PID"
  } >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

check_eq() {
  # check_eq <description> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1 ($3)"; else fail "$1: expected '$2', got '$3'"; fi
}

metric() {
  # metric <name-with-labels> -> value, or "absent"
  local line
  line="$(grep -F "$1" "$WORKDIR/metrics.txt" 2>/dev/null | head -1 || true)"
  if [ -z "$line" ]; then echo "absent"; else echo "${line##* }"; fi
}

[ -x "$BINARY" ] || { echo "smoke: $BINARY is not executable" >&2; exit 2; }
echo "smoke: testing $BINARY"

# ---------------------------------------------------------------------------
# 1. Documented scoring definition, from the binary's embedded capture.
#
# These three numbers are the contract stated in docs/operations/install.md.
# The capture is embedded in the binary, so this step needs no network and no
# repository checkout — it is exactly what an operator can run post-install.
# ---------------------------------------------------------------------------
echo "[1/5] embedded fixture reproduces the documented scoring definition"
"$BINARY" selftest --fixture --json > "$WORKDIR/selftest.json"
check_eq "sets_total"       "7" "$(grep -o '"sets_total": *[0-9]*'  "$WORKDIR/selftest.json" | head -1 | tr -dc 0-9)"
check_eq "sets_erased"      "2" "$(grep -o '"sets_erased": *[0-9]*' "$WORKDIR/selftest.json" | head -1 | tr -dc 0-9)"
# 2/7 to six decimal places; compared as a prefix so the check does not depend
# on float formatting.
erasure="$(grep -o '"erasure_fraction": *[0-9.]*' "$WORKDIR/selftest.json" | head -1 | sed 's/.*: *//')"
case "$erasure" in
  0.285714*) pass "erasure_fraction ($erasure)" ;;
  *)         fail "erasure_fraction: expected 0.285714…, got '$erasure'" ;;
esac

# ---------------------------------------------------------------------------
# 2. Start the receiver with a fan-out destination pointed at a local sink.
# ---------------------------------------------------------------------------
echo "[2/5] receiver starts and serves /healthz + /metrics"
if command -v python3 >/dev/null 2>&1; then
  python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $SINK_PORT))
with open('$WORKDIR/sink.bin', 'wb') as f:
    while True:
        data, _ = s.recvfrom(65535)
        f.write(data); f.flush()
" &
  SINK_PID=$!
  sleep 0.5
fi

"$BINARY" \
  --listen "127.0.0.1:$FEED_PORT" \
  --dest-ip-ports "127.0.0.1:$SINK_PORT" \
  --http-addr "127.0.0.1:$HTTP_PORT" \
  --json > "$WORKDIR/receipt.json" 2> "$WORKDIR/receiver.err" &
GW_PID=$!

for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT/metrics" 2>/dev/null && break
  sleep 0.1
done
curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT/metrics" 2>/dev/null \
  || { echo "smoke: receiver never served /metrics" >&2; cat "$WORKDIR/receiver.err" >&2; exit 1; }
pass "/metrics is serving"

# ---------------------------------------------------------------------------
# 3. /healthz is readiness-shaped: unhealthy until a packet has arrived.
#    This is why it is not a safe liveness probe — a restart loop would never
#    clear it. Asserted here so that property cannot regress unnoticed.
# ---------------------------------------------------------------------------
echo "[3/5] /healthz is unhealthy before the first packet"
check_eq "/healthz before traffic" "503" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/healthz")"

# ---------------------------------------------------------------------------
# 4. Drive one datagram. It is deliberately NOT a valid shred: that exercises
#    the documented guarantee that a malformed header increments
#    shreds_unparsed_total and otherwise leaves delivery byte-identical.
# ---------------------------------------------------------------------------
echo "[4/5] one malformed datagram: delivered, forwarded, counted as unparsed"
printf 'not-a-valid-shred-header' > "/dev/udp/127.0.0.1/$FEED_PORT"
sleep 0.8
curl -fsS "http://127.0.0.1:$HTTP_PORT/metrics" > "$WORKDIR/metrics.txt"

check_eq "ingress_packets_total"  "1" "$(metric 'bcast_shred_gw_ingress_packets_total{feed="default"}')"
check_eq "egress_packets_total"   "1" "$(metric 'bcast_shred_gw_egress_packets_total{feed="default"}')"
check_eq "shreds_unparsed_total"  "1" "$(metric 'bcast_shred_gw_shreds_unparsed_total{feed="default"}')"
check_eq "fanout_dropped_total"   "0" "$(metric 'bcast_shred_gw_fanout_dropped_packets_total{feed="default"}')"
check_eq "fanout_write_errors"    "0" "$(metric 'bcast_shred_gw_fanout_write_errors_total{feed="default"}')"
check_eq "/healthz after traffic" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/healthz")"

if [ -n "$SINK_PID" ]; then
  if [ "$(cat "$WORKDIR/sink.bin" 2>/dev/null)" = "not-a-valid-shred-header" ]; then
    pass "fan-out is byte-identical to ingress"
  else
    fail "fan-out payload differs from ingress"
  fi
else
  echo "  skip  fan-out byte-identity (python3 not available)"
fi

# NOTE: the erasure, shreds_per_second and gap_events series are deliberately
# NOT asserted here. They are published but never written — see BLO-28442.
# Asserting their current values would lock that defect in as expected
# behaviour; asserting the correct values would fail until it is fixed.

# ---------------------------------------------------------------------------
# 5. SIGTERM is the graceful path: exit 0, with the receipt on stdout.
# ---------------------------------------------------------------------------
echo "[5/5] SIGTERM shuts down gracefully and prints the receipt"
kill -TERM "$GW_PID"
gw_status=0
wait "$GW_PID" || gw_status=$?
GW_PID=""
check_eq "exit status" "0" "$gw_status"

if grep -q '"unique_shreds_total"' "$WORKDIR/receipt.json" 2>/dev/null; then
  pass "receipt written to stdout"
else
  fail "no receipt on stdout"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "smoke: PASS"
else
  echo "smoke: FAIL ($FAILURES check(s))"
  exit 1
fi

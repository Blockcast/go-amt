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
# Requires: bash, curl, and a way to bind a local UDP sink (python3 or nc).
#
# The sink is mandatory, not optional. Byte-identity is the only assertion in
# this script that proves a forwarded packet reached a destination at all: the
# fan-out socket is unconnected (receiver/fanout.go: net.ListenUDP + WriteTo), so
# a send to a closed local port succeeds and never surfaces ICMP
# port-unreachable. With no sink bound, egress_packets_total still reads 1 and
# fanout_write_errors_total still reads 0 — the counter checks cannot substitute
# for the sink, and every other step is indifferent to fan-out. Skipping it would
# leave a run that exits 0 having proven nothing about delivery.
#
# Set SMOKE_ALLOW_NO_SINK=1 to run the remaining steps without a sink. That is an
# explicit, loudly-reported downgrade for a host with neither interpreter — never
# the default.

set -euo pipefail

BINARY="${1:-./blockcast-shreds}"
FEED_PORT="${SMOKE_FEED_PORT:-21000}"
SINK_PORT="${SMOKE_SINK_PORT:-21001}"
HTTP_PORT="${SMOKE_HTTP_PORT:-21080}"

WORKDIR="$(mktemp -d)"
GW_PID=""
SINK_PID=""
SINK_KIND=""
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

# Bind the sink BEFORE the receiver, and wait for the bind to be observable
# rather than sleeping: a listener that binds after the datagram is sent loses it
# and fails the byte-identity check for a reason that has nothing to do with the
# binary under test.
sink_is_bound() {
  if command -v ss >/dev/null 2>&1; then
    ss -lun 2>/dev/null | grep -q ":$SINK_PORT\b"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lun 2>/dev/null | grep -q ":$SINK_PORT\b"
  else
    # No way to observe the bind; fall back to the readiness marker the python
    # sink writes for itself, and to a bounded settle for nc.
    [ -f "$WORKDIR/sink.ready" ]
  fi
}

wait_for_sink() {
  # Bounded wait for the sink to be observably bound.
  local _
  for _ in $(seq 1 40); do
    sink_is_bound && return 0
    sleep 0.1
  done
  return 1
}

# Try each sink implementation and confirm it actually bound before accepting it.
# Falling through on failure rather than dying keeps this robust across netcat
# variants, whose -u -l argument forms differ, while still failing closed if no
# candidate works.
if command -v python3 >/dev/null 2>&1; then
  python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $SINK_PORT))
open('$WORKDIR/sink.ready', 'w').close()
with open('$WORKDIR/sink.bin', 'wb') as f:
    while True:
        data, _ = s.recvfrom(65535)
        f.write(data); f.flush()
" &
  SINK_PID=$!
  if wait_for_sink; then
    SINK_KIND="python3"
  else
    kill -KILL "$SINK_PID" 2>/dev/null || true
    SINK_PID=""
  fi
fi

if [ -z "$SINK_KIND" ] && command -v nc >/dev/null 2>&1; then
  nc -u -l 127.0.0.1 "$SINK_PORT" > "$WORKDIR/sink.bin" 2>/dev/null &
  SINK_PID=$!
  if wait_for_sink; then
    SINK_KIND="nc"
  else
    kill -KILL "$SINK_PID" 2>/dev/null || true
    SINK_PID=""
  fi
fi

if [ -n "$SINK_KIND" ]; then
  pass "fan-out sink bound on 127.0.0.1:$SINK_PORT ($SINK_KIND)"
elif [ "${SMOKE_ALLOW_NO_SINK:-0}" = "1" ]; then
  SINK_KIND="none"
  printf '  WARN  no UDP sink could be bound (tried python3, nc).\n'
  printf '  WARN  SMOKE_ALLOW_NO_SINK=1 is set, so continuing WITHOUT the only\n'
  printf '  WARN  assertion that proves fan-out delivers. Counters cannot cover\n'
  printf '  WARN  it: the fan-out socket is unconnected, so a send to a closed\n'
  printf '  WARN  port succeeds. This run does not verify delivery.\n'
else
  echo "smoke: could not bind a fan-out sink on 127.0.0.1:$SINK_PORT." >&2
  echo "smoke: tried python3 and nc; neither is present or neither bound." >&2
  echo "smoke: byte-identity is the only proof that fan-out delivers; the" >&2
  echo "smoke: counters pass with nothing listening, so skipping it silently" >&2
  echo "smoke: would make this script exit 0 having proven no delivery." >&2
  echo "smoke: install python3, or set SMOKE_ALLOW_NO_SINK=1 to accept an" >&2
  echo "smoke: explicitly unverified run." >&2
  exit 2
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

# /dev/udp is fire-and-forget, so poll for the counter to move rather than
# sleeping a fixed interval and hoping. Still fails closed: if the packet never
# lands, the loop times out and the check_eq below reports the real value.
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$HTTP_PORT/metrics" > "$WORKDIR/metrics.txt" 2>/dev/null || true
  [ "$(metric 'bcast_shred_gw_ingress_packets_total{feed="default"}')" = "1" ] && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$HTTP_PORT/metrics" > "$WORKDIR/metrics.txt"

check_eq "ingress_packets_total"  "1" "$(metric 'bcast_shred_gw_ingress_packets_total{feed="default"}')"
check_eq "egress_packets_total"   "1" "$(metric 'bcast_shred_gw_egress_packets_total{feed="default"}')"
check_eq "shreds_unparsed_total"  "1" "$(metric 'bcast_shred_gw_shreds_unparsed_total{feed="default"}')"
check_eq "fanout_dropped_total"   "0" "$(metric 'bcast_shred_gw_fanout_dropped_packets_total{feed="default"}')"
check_eq "fanout_write_errors"    "0" "$(metric 'bcast_shred_gw_fanout_write_errors_total{feed="default"}')"
check_eq "/healthz after traffic" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/healthz")"

if [ "$SINK_KIND" = "none" ]; then
  # Reached only under an explicit SMOKE_ALLOW_NO_SINK=1. Reported as a failure-
  # shaped line rather than a quiet "skip" so it cannot be read as a pass.
  printf '  UNVERIFIED  fan-out byte-identity: no sink was bound (SMOKE_ALLOW_NO_SINK=1).\n'
  printf '  UNVERIFIED  delivery is NOT proven by this run.\n'
else
  # The sink flushes per datagram, but the write races this read; poll briefly.
  for _ in $(seq 1 30); do
    [ -s "$WORKDIR/sink.bin" ] && break
    sleep 0.1
  done
  if [ "$(cat "$WORKDIR/sink.bin" 2>/dev/null)" = "not-a-valid-shred-header" ]; then
    pass "fan-out is byte-identical to ingress"
  else
    fail "fan-out payload differs from ingress (sink got: '$(cat "$WORKDIR/sink.bin" 2>/dev/null)')"
  fi
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

#!/usr/bin/env bash
# Runs the Python relay test suites against this Worker under `wrangler dev`.
# The Python tests are the protocol's executable spec; passing here means the
# Worker speaks the same wire protocol byte for byte.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
PY="$ROOT/.venv/bin/python"
PORT="${PORT:-8790}"

OP="$($PY -c "from switchboard import crypto; k=crypto.Keypair.generate(); print(k.ed25519_seed.hex()+':'+k.x25519_secret.hex()+' '+k.ed25519_pub)")"
OP_SECRET="${OP% *}"; OP_PUB="${OP#* }"
LOG="$(mktemp -t switchboard-worker)"
STATE="$(mktemp -d -t switchboard-state)"

start() {  # start <profile> [extra --var flags]
  npx wrangler dev --port "$PORT" --persist-to "$STATE/$1" --var "TEST_RESET:1" --var "OPERATORS:$OP_PUB" "${@:2}" > "$LOG" 2>&1 &
  DEV_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$PORT/v1/guide" > /dev/null 2>&1 && return 0
    sleep 1
  done
  echo "wrangler dev did not come up; log:" >&2; tail -30 "$LOG" >&2; exit 1
}
stop() { pkill -P "$DEV_PID" 2>/dev/null || true; kill "$DEV_PID" 2>/dev/null || true; wait "$DEV_PID" 2>/dev/null || true; }
trap 'stop' EXIT

export SWITCHBOARD_TEST_RELAY_URL="http://127.0.0.1:$PORT" SWITCHBOARD_TEST_OPERATOR="$OP_SECRET"

echo "== default profile: relay + end-to-end suites =="
start default
SWITCHBOARD_TEST_RELAY_PROFILE=default "$PY" -m pytest -q --no-header -p no:warnings "$ROOT/tests/test_relay.py" "$ROOT/tests/test_e2e.py" "$@"
stop

echo "== tiny-limits profile: rate limit tests =="
start tiny --var "PUBLISH_PER_HOUR_T0:2" --var "REGISTER_PER_HOUR_PER_IP:2"
SWITCHBOARD_TEST_RELAY_PROFILE=tiny "$PY" -m pytest -q --no-header -p no:warnings "$ROOT/tests/test_relay.py" -k "rate_limit" "$@"
stop
trap - EXIT
echo "conformance: all passed against the Worker"

#!/usr/bin/env bash
# test-flower-training.sh - Post-envelope verification: Hub → bind → Flower run evidence
# Usage: ./test-flower-training.sh <envelope_id>

set -euo pipefail

ENVELOPE_ID="${1:-}"
if [[ -z "$ENVELOPE_ID" ]]; then
  echo "Usage: $0 <envelope_id>"
  exit 1
fi

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
pass() { printf "\033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "\033[33m!\033[0m %s\n" "$*"; }
fail() { printf "\033[31m✗\033[0m %s\n" "$*"; exit 1; }
hr()   { printf "\n%s\n\n" "────────────────────────────────────────"; }

need_container() {
  local name="$1"
  docker ps -a --format '{{.Names}}' | grep -qx "$name" || fail "Missing container: $name"
}

is_running() {
  local name="$1"
  docker ps --format '{{.Names}}' | grep -qx "$name"
}

ensure_running() {
  local name="$1"
  if is_running "$name"; then
    return 0
  fi
  warn "$name is not running (likely exited due to retry window). Restarting..."
  docker restart "$name" >/dev/null
  sleep 2
  is_running "$name" || fail "$name failed to start"
  pass "$name restarted"
}

log_has() {
  local name="$1"
  local pat="$2"
  docker logs "$name" 2>&1 | grep -qE "$pat"
}

bold "=== Post-Envelope Flow Test (Hub → bind → training evidence) ==="
echo "Envelope ID: $ENVELOPE_ID"

# --- Step 0: Preflight (handles client retry timeout issue) ---
hr
bold "Step 0: Preflight container liveness"
need_container fc-hub
need_container flower-server
need_container flower-client-even
need_container flower-client-odd

# Hub/server should be long-lived; clients may exit if you wait too long.
ensure_running fc-hub
ensure_running flower-server
ensure_running flower-client-even
ensure_running flower-client-odd

# --- Step 1: Hub received envelope event ---
hr
bold "Step 1: Verify Hub received envelope event"
if log_has fc-hub "$ENVELOPE_ID"; then
  pass "Hub received envelope event"
  docker logs fc-hub 2>&1 | grep "Envelope.*$ENVELOPE_ID" | tail -3 || true
else
  fail "Hub did not log the envelope. Check: docker logs fc-hub"
fi

# --- Step 2: Hub attempted binding (success OR already-bound conflict) ---
hr
bold "Step 2: Verify Hub bound (or attempted to bind) flower_server"
if log_has fc-hub "Successfully bound flower_server"; then
  pass "Hub successfully bound flower_server"
elif log_has fc-hub "409|Conflict|already bound|Failed to bind backend flower_server"; then
  warn "Hub reports flower_server bind conflict (likely already bound from a previous run)."
  warn "If you intended to run a fresh envelope/training, reset with:"
  echo "  docker restart flower-server flower-client-even flower-client-odd"
  echo "  then rerun Test #1 to create a new envelope."
else
  fail "No binding outcome found in Hub logs. Check: docker logs fc-hub | tail -200"
fi

# --- Step 3: Flower server received binding for this envelope ---
hr
bold "Step 3: Verify flower-server received binding for this envelope"
# Accept any reasonable binding log signature; keep it tolerant to log phrasing changes.
if log_has flower-server "$ENVELOPE_ID"; then
  pass "flower-server log references envelope_id"
  docker logs flower-server 2>&1 | grep "$ENVELOPE_ID" | tail -5 || true
else
  warn "flower-server logs do not mention the envelope id yet."
  warn "This can happen if the server is still waiting for binding or the log format changed."
  echo "  Check: docker logs flower-server | tail -200"
fi

# --- Step 4: Training lifecycle (start/completion) ---
hr
bold "Step 4: Verify Flower server started"
sleep 15
if docker logs flower-server 2>&1 | grep -qE "Starting Flower"; then
  pass "Flower gRPC server started"
else
  fail "Flower server did not start"
fi

# --- Step 5: Client participation (clients may exit after completion) ---
hr
bold "Step 5: Monitor client participation (up to 60s)"
echo "Watching for client activity..."
timeout 30 bash -c '
  while true; do
    EVEN=$(docker logs flower-client-even 2>&1 | grep -c "Connection attempt\|Connected" || echo 0)
    ODD=$(docker logs flower-client-odd 2>&1 | grep -c "Connection attempt\|Connected" || echo 0)
    echo -ne "\rEven client: $EVEN attempts | Odd client: $ODD attempts"
    sleep 2
  done
' || true
echo ""

if docker logs flower-client-even 2>&1 | grep -qE "Training completed|completed|Finished|done"; then
  pass "Even client completed its run"
else
  warn "Even client not showing completion yet (may still be training, or log phrasing differs)."
fi

if docker logs flower-client-odd 2>&1 | grep -qE "Training completed|completed|Finished|done"; then
  pass "Odd client completed its run"
else
  warn "Odd client not showing completion yet (may still be training, or log phrasing differs)."
fi

# --- Step 6: Evidence check (vault run.json, if present) ---
hr
bold "Step 6: Check evidence persisted under vault/<envelope_id>/ (if enabled)"
VAULT_DIR="../vfp-governance/verifier/vault/${ENVELOPE_ID}"
RUN_JSON="${VAULT_DIR}/run.json"

if [[ -f "$RUN_JSON" ]]; then
  pass "Found evidence: $RUN_JSON"
  # print a short preview without jq dependency
  head -50 "$RUN_JSON" || true
else
  warn "No run.json found at $RUN_JSON"
  warn "If evidence persistence is expected, check the flower-server container’s vault mount and logs."
fi

hr
bold "=== Summary ==="
echo "Envelope: $ENVELOPE_ID"
echo ""
echo "Useful logs:"
echo "  docker logs fc-hub | tail -200"
echo "  docker logs flower-server | tail -200"
echo "  docker logs flower-client-even | tail -200"
echo "  docker logs flower-client-odd  | tail -200"
echo ""
echo "If clients exited due to the ~10-minute retry window, restart them:"
echo "  docker restart flower-client-even flower-client-odd"
echo ""
echo "If hub reports bind conflict (409), reset server + clients before a new envelope:"
echo "  docker restart flower-server flower-client-even flower-client-odd"

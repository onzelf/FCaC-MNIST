#!/usr/bin/env bash
# test-flower-training.sh - Verify Hub coordination and Flower training

set -euo pipefail

ENVELOPE_ID="${1:-}"
if [[ -z "$ENVELOPE_ID" ]]; then
  echo "Usage: $0 <envelope_id>"
  exit 1
fi

LAN="${LAN:-192.168.1.25}"

CRT="../vfp-governance/verifier/certs/hub.crt"
KEY="../vfp-governance/verifier/certs/hub.key"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
pass() { printf "\033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "\033[31m✗\033[0m %s\n" "$*"; exit 1; }
hr()   { printf "\n%s\n\n" "────────────────────────────────────────"; }

bold "=== Post-Envelope Flow Test ==="
echo "Envelope ID: $ENVELOPE_ID"

hr
bold "Step 1: Verify Hub received envelope"
sleep 2
if docker logs fc-hub 2>&1 | grep -q "$ENVELOPE_ID"; then
  pass "Hub received envelope event"
  docker logs fc-hub 2>&1 | grep "$ENVELOPE_ID" | tail -3
else
  fail "Hub did not receive envelope"
fi

hr
bold "Step 2: Verify Hub bound flower_server"
if docker logs fc-hub 2>&1 | grep -q "Successfully bound flower_server"; then
  pass "Hub successfully bound backend"
else
  fail "Hub did not bind backend"
fi

hr
bold "Step 3: Verify flower_server bound to envelope"
if docker logs flower-server 2>&1 | grep -q "Binding to.*$ENVELOPE_ID"; then
  pass "flower_server received binding"
  docker logs flower-server 2>&1 | grep "$ENVELOPE_ID" | tail -5
else
  fail "flower_server did not bind"
fi

hr
bold "Step 4: Check authorization (start, train)"
if docker logs flower-server 2>&1 | grep -q "Authorization.*PERMIT"; then
  pass "Operations authorized"
  docker logs flower-server 2>&1 | grep "Authorization" | tail -3
else
  fail "Authorization failed"
fi

hr
bold "Step 5: Verify Flower server started"
if docker logs flower-server 2>&1 | grep -qE "Starting Flower"; then
  pass "Flower gRPC server started"
else
  fail "Flower server did not start"
fi

hr
bold "Step 6: Monitor client connections (30s)"
echo "Watching for client connections..."
timeout 30 bash -c '
  while true; do
    EVEN=$(docker logs flower-client-even 2>&1 | grep -c "Connection attempt\|Connected" || echo 0)
    ODD=$(docker logs flower-client-odd 2>&1 | grep -c "Connection attempt\|Connected" || echo 0)
    echo -ne "\rEven client: $EVEN attempts | Odd client: $ODD attempts"
    sleep 2
  done
' || true
echo ""

if docker logs flower-client-even 2>&1 | grep -q "Training completed\|Flower.*complete"; then
  pass "Even client completed training"
else
  echo "Even client still connecting or training..."
fi

if docker logs flower-client-odd 2>&1 | grep -q "Training completed\|Flower.*complete"; then
  pass "Odd client completed training"
else
  echo "Odd client still connecting or training..."
fi

hr
bold "Step 7: Check training completion"
sleep 5
if docker logs flower-server 2>&1 | grep -qE "Training completed"; then
  pass "Training completed successfully"
else
  echo "Training may still be in progress, checking logs:"
  docker logs flower-server 2>&1 | tail -10
fi

hr
bold "Step 8: Test prediction endpoints"
echo "Testing flower-server /predict endpoint..."

exit 1
##################################################

# Test prediction (should work if authorized)
PRED_RESP=$(curl -sf "http://127.0.0.1:8081/predict" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"input_data": [1,2,3], "context": {"client_id": "clientA"}}' || echo "FAILED")

if [[ "$PRED_RESP" == "FAILED" ]]; then
  echo "Prediction endpoint not ready or denied"
else
  echo "$PRED_RESP" | jq .
  pass "Prediction endpoint accessible"
fi

hr
bold "Step 9: Test policy enforcement (label restrictions)"
echo "Testing clientA prediction on allowed label..."
curl -sf "http://127.0.0.1:8081/predict" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"input_data": [1,2,3], "context": {"client_id": "clientA", "label": 2}}' \
  | jq . || echo "Request failed"

echo ""
echo "Testing clientA prediction on denied label (3)..."
curl -sf "http://127.0.0.1:8081/predict" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"input_data": [1,2,3], "context": {"client_id": "clientA", "label": 3}}' \
  | jq . || echo "Expected: should be denied"

hr
bold "=== Summary ==="
echo "Envelope: $ENVELOPE_ID"
echo ""
echo "Check detailed logs:"
echo "  docker logs fc-hub"
echo "  docker logs flower-server"
echo "  docker logs flower-client-even"
echo "  docker logs flower-client-odd"
echo ""
echo "Check verifier chain:"
echo "  cat verifier/events/events.log | jq ." 
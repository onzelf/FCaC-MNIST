#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Test #3C — (Legacy) deterministic E2E via Hub /predict
#
# This script is kept for non-UI, CLI-only regression checking.
# Test #4 (UI) is the primary E2E demonstrator.
#
# Post-Test#4 update:
#   - ECT minting is performed by issuer containers (org-admin credentials)
# ============================================================

ENVELOPE_ID="${1:-}"
if [[ -z "$ENVELOPE_ID" ]]; then
  echo "Usage: $0 <envelope_id>" >&2
  exit 1
fi

HUB_URL="${HUB_URL:-http://127.0.0.1:8080}"
FLOWER_URL="${FLOWER_URL:-http://flower-server:8081}"   # internal from hub

ISSUER_A_CONTAINER=${ISSUER_A_CONTAINER:-issuer-hospitala}

HTU="${HTU:-https://verifier.local/admission/check}"

CAC="../vfp-governance/verifier/certs/ca.crt"
CRT="../vfp-governance/verifier/certs/hub.crt"
KEY="../vfp-governance/verifier/certs/hub.key"
CURL_MTLS=( -sS --cacert "$CAC" --cert "$CRT" --key "$KEY" )

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need jq
need python3
need curl
need docker

mint_ect_via_issuer() {
  local issuer_container="$1"
  local who="$2"
  local cohort="$3"
  local holder_pub_b64="$4"

  docker exec -i "${issuer_container}" python3 - <<PY
import json
import requests
payload = {"who": "${who}", "cohort": "${cohort}", "holder_pub_b64": "${holder_pub_b64}"}
r = requests.post("http://127.0.0.1:8080/mint", json=payload, timeout=20)
print(json.dumps({"status": r.status_code, "body": r.json() if r.headers.get('content-type','').startswith('application/json') else r.text}))
PY
}

extract_ect() {
  jq -r '.body.ect // .body.ect_jws // empty'
}

make_dpop() {
  local priv_hex="$1"
  local pub_b64="$2"
  local nonce="$3"
  local jti="$4"
  python3 make_dpop_jwt_eddsa.py "${priv_hex}" "${pub_b64}" "${nonce}" "${jti}" "POST" "${HTU}"
}

echo "== 0) (Optional) register flower backend in Hub =="
curl -sS -X POST "http://127.0.0.1:8080/backends/register" \
  -H "Content-Type: application/json" \
  -d '{"type":"flower","url":"http://flower-server:8081"}' || true
echo


echo "== 1) Generate holder keys =="
python3 gen_member_keys.py --who Martinez | sed 's/^/[keys] /' || true
PUB_B64=$(cat holder_keys/Martinez.pubb64)
PRIV_HEX=$(cat holder_keys/Martinez.privhex)

echo "== 2) Mint ECT (Martinez, EVEN_ONLY) via issuer-hospitala =="
MINT_RAW=$(mint_ect_via_issuer "${ISSUER_A_CONTAINER}" "Martinez" "EVEN_ONLY" "${PUB_B64}")
echo "${MINT_RAW}" | jq .
ECT=$(echo "${MINT_RAW}" | extract_ect)
[[ -n "${ECT}" ]] || { echo "ERROR: mint returned no ect"; exit 1; }

NONCE="nonce-$(date +%s)"
JTI="jti-$(date +%s)"
DPOP=$(make_dpop "${PRIV_HEX}" "${PUB_B64}" "${NONCE}" "${JTI}")

echo "== 3) E2E predict via Hub =="
PRED_REQ="{\"envelope_id\":\"${ENVELOPE_ID}\",\"cohort\":\"EVEN_ONLY\",\"digit\":2,\"topk\":3,\"jti\":\"${JTI}\"}"

curl -sS "${HUB_URL}/predict" \
  -H "Content-Type: application/json" \
  -H "Authorization: ECT ${ECT}" \
  -H "DPoP: ${DPOP}" \
  -H "X-DPoP-Nonce: ${NONCE}" \
  -d "${PRED_REQ}" | jq .

echo "Done."

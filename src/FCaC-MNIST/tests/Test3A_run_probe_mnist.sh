#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Test #3A — MNIST (as clinical imaging) admission probes
#
# Post-Test#4 update:
#   - ECT minting is performed by issuer containers (org-admin credentials)
#   - This script keeps probing /admission/check directly (mTLS hub cert)
#
# Cohort→Issuer mapping (PoC convention):
#   - EVEN_ONLY, ODD_PLUS  -> issuer-hospitala
#   - ODD_ONLY             -> issuer-hospitalb
# ============================================================

# -------- Config --------
PORT=${PORT:-8443}
VERIFIER_BASE="https://verifier.local:${PORT}"

CAC="../vfp-governance/verifier/certs/ca.crt"
CRT="../vfp-governance/verifier/certs/hub.crt"
KEY="../vfp-governance/verifier/certs/hub.key"

CURL_MTLS=( -sS --cacert "$CAC" --cert "$CRT" --key "$KEY" )

ISSUER_A_CONTAINER=${ISSUER_A_CONTAINER:-issuer-hospitala}
ISSUER_B_CONTAINER=${ISSUER_B_CONTAINER:-issuer-hospitalb}

# HTU must match verifier expectation (same as Test#2)
HTU="https://verifier.local/admission/check"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need jq
need python3
need docker

mint_ect_via_issuer() {
  local issuer_container="$1"
  local who="$2"
  local cohort="$3"
  local holder_pub_b64="$4"

  # Call issuer HTTP endpoint from inside the issuer container (no host port needed).
  docker exec -i "${issuer_container}" python3 - <<PY
import json, sys
import requests
payload = {"who": "${who}", "cohort": "${cohort}", "holder_pub_b64": "${holder_pub_b64}"}
r = requests.post("http://127.0.0.1:8080/mint", json=payload, timeout=20)
print(json.dumps({"status": r.status_code, "body": r.json() if r.headers.get('content-type','').startswith('application/json') else r.text}))
PY
}

extract_ect() {
  # Accept either {ect:..} (normalized) or {ect_jws:..} (verifier legacy)
  jq -r '.body.ect // .body.ect_jws // empty'
}

# -------- Generate holder keys --------
echo "== 1) Generate holder keys =="
python3 gen_member_keys.py --who Martinez | sed 's/^/[keys] /' || true
PUB_B64=$(cat holder_keys/Martinez.pubb64)
PRIV_HEX=$(cat holder_keys/Martinez.privhex)

# -------- Wait for /health --------
echo "== 2) Wait for /health =="
for i in {1..30}; do
  sleep 0.3
  echo -n "."
  if curl "${CURL_MTLS[@]}" "${VERIFIER_BASE}/health" >/dev/null; then break; fi
done
echo

make_dpop() {
  local nonce="$1"
  local jti="$2"
  python3 make_dpop_jwt_eddsa.py "${PRIV_HEX}" "${PUB_B64}" "${nonce}" "${jti}" "POST" "${HTU}"
}

probe() {
  local ect="$1"
  local dpop="$2"
  local nonce="$3"
  local req_json="$4"

  echo "${req_json}"
  curl "${CURL_MTLS[@]}" -X POST "${VERIFIER_BASE}/admission/check" \
    -H "Authorization: ECT ${ect}" \
    -H "DPoP: ${dpop}" \
    -H "X-DPoP-Nonce: ${nonce}" \
    -H 'content-type: application/json' \
    -d "${req_json}" | jq .
}

# ============================================================
# Scenario S1 — predictor_even (EVEN_ONLY)
# ============================================================
echo
echo "===================="
echo "Scenario S1: predictor_even (EVEN_ONLY)"
echo "===================="

echo "== 3) Mint ECT via issuer-hospitala =="
MINT_RAW=$(mint_ect_via_issuer "${ISSUER_A_CONTAINER}" "Martinez" "EVEN_ONLY" "${PUB_B64}")
echo "${MINT_RAW}" | jq .
ECT=$(echo "${MINT_RAW}" | extract_ect)
[[ -n "${ECT}" ]] || { echo "ERROR: mint returned no ect"; exit 1; }

NONCE="test-nonce-$(date +%s)"
JTI="jti-even-$(date +%s)"
DPoP=$(make_dpop "${NONCE}" "${JTI}")

echo "== 4) Probe ALLOW (EVEN_ONLY) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"EVEN_ONLY","jti":"'"${JTI}"'"}'

echo
echo "== 5) Probe DENY (ODD_ONLY) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"ODD_ONLY","jti":"'"${JTI}"'"}'

echo
echo "== 6) Probe DENY (ODD_PLUS) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"ODD_PLUS","jti":"'"${JTI}"'"}'

echo
echo "== 7) Probe DENY (wrong purpose=model_training) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_training","cohort":"EVEN_ONLY","jti":"'"${JTI}"'"}'

# ============================================================
# Scenario S2 — predictor_odd (ODD_ONLY)
# ============================================================
echo
echo "===================="
echo "Scenario S2: predictor_odd (ODD_ONLY)"
echo "===================="

echo "== 8) Mint ECT via issuer-hospitalb =="
MINT_RAW=$(mint_ect_via_issuer "${ISSUER_B_CONTAINER}" "Hepburn" "ODD_ONLY" "${PUB_B64}")
echo "${MINT_RAW}" | jq .
ECT=$(echo "${MINT_RAW}" | extract_ect)
[[ -n "${ECT}" ]] || { echo "ERROR: mint returned no ect"; exit 1; }

NONCE="test-nonce-$(date +%s)"
JTI="jti-odd-$(date +%s)"
DPoP=$(make_dpop "${NONCE}" "${JTI}")

echo "== 9) Probe ALLOW (ODD_ONLY) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"ODD_ONLY","jti":"'"${JTI}"'"}'

echo
echo "== 10) Probe DENY (EVEN_ONLY) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"EVEN_ONLY","jti":"'"${JTI}"'"}'

# ============================================================
# Scenario S3 — predictor_odd_plus (ODD_PLUS)
# ============================================================
echo
echo "===================="
echo "Scenario S3: predictor_odd_plus (ODD_PLUS)"
echo "===================="

echo "== 11) Mint ECT via issuer-hospitala =="
MINT_RAW=$(mint_ect_via_issuer "${ISSUER_A_CONTAINER}" "Martinez" "ODD_PLUS" "${PUB_B64}")
echo "${MINT_RAW}" | jq .
ECT=$(echo "${MINT_RAW}" | extract_ect)
[[ -n "${ECT}" ]] || { echo "ERROR: mint returned no ect"; exit 1; }

NONCE="test-nonce-$(date +%s)"
JTI="jti-oddplus-$(date +%s)"
DPoP=$(make_dpop "${NONCE}" "${JTI}")

echo "== 12) Probe ALLOW (ODD_PLUS) =="
probe "${ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"ODD_PLUS","jti":"'"${JTI}"'"}'

echo
echo "== 13) Probe DENY (tampered ECT) =="
# tamper signature segment while keeping 3 segments
IFS='.' read -r h p s <<<"${ECT}"
INVALID_ECT="${h}.${p}.${s%?}X"
#echo ${INVALID_ECT}
probe "${INVALID_ECT}" "${DPoP}" "${NONCE}" '{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"ODD_PLUS","jti":"'"${JTI}"'"}'

echo "Done."

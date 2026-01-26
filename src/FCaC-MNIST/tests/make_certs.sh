#!/usr/bin/env bash
set -euo pipefail

# Where to write certs (relative to repo root)
CERT_DIR="$(cd "$(dirname "$0")/.."; pwd)/verifier/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[make_certs] cleaning old material in $CERT_DIR"
rm -v -f *.key *.crt *.csr *.p12 *.srl 2>/dev/null || true

# --------------------------------------------
# Parameters
# --------------------------------------------
P12_PASS="<set password>"                             
DAYS_CA=3650
DAYS_LEAF=825

# Subjects (CNs)
CN_CA="fcac-demo-ca"
CN_VERIFIER="verifier.local"
CN_HUB="hub"
CN_ORG_A="org_HospitalA_admin"
CN_ORG_B="org_HospitalB_admin"

echo "[make_certs] generating CA: $CN_CA"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -subj "/CN=${CN_CA}" -sha256 -days "$DAYS_CA" -out ca.crt

echo "[make_certs] generating verifier server cert: $CN_VERIFIER"
openssl genrsa -out verifier.key 2048
openssl req -new -key verifier.key -subj "/CN=${CN_VERIFIER}" -out verifier.csr
openssl x509 -req -in verifier.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days "$DAYS_LEAF" -out verifier.crt
rm -f verifier.csr

echo "[make_certs] generating hub mTLS client cert: $CN_HUB"
openssl genrsa -out hub.key 2048
openssl req -new -key hub.key -subj "/CN=${CN_HUB}" -out hub.csr
openssl x509 -req -in hub.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days "$DAYS_LEAF" -out hub.crt
rm -f hub.csr

echo "[make_certs] generating orgA admin client cert: $CN_ORG_A"
openssl genrsa -out orgA-admin.key 2048
openssl req -new -key orgA-admin.key -subj "/CN=${CN_ORG_A}" -out orgA-admin.csr
openssl x509 -req -in orgA-admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days "$DAYS_LEAF" -out orgA-admin.crt
rm -f orgA-admin.csr

echo "[make_certs] generating orgB admin client cert: $CN_ORG_B"
openssl genrsa -out orgB-admin.key 2048
openssl req -new -key orgB-admin.key -subj "/CN=${CN_ORG_B}" -out orgB-admin.csr
openssl x509 -req -in orgB-admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days "$DAYS_LEAF" -out orgB-admin.crt
rm -f orgB-admin.csr

# ---- Android-friendly PKCS#12 for admins (password = <password>) ----
# Use the exact PBE/MAC combo that worked for you.
echo "[make_certs] exporting admin PKCS#12 bundles (password = ${P12_PASS})"
openssl pkcs12 -export \
  -inkey orgA-admin.key -in orgA-admin.crt \
  -certfile ca.crt  \
  -name "HospitalA Admin" \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -out orgA-admin.p12 \
  -passout pass:${P12_PASS}

openssl pkcs12 -export \
  -inkey orgB-admin.key -in orgB-admin.crt \
  -certfile ca.crt \
  -name "HospitalB Admin" \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -out orgB-admin.p12 \
  -passout pass:${P12_PASS}

# Quick sanity (won't print secrets; just integrity)
echo " "
echo "[make_certs] verifying PKCS#12 integrity"
openssl pkcs12 -info -in orgA-admin.p12 -noout -passin pass:${P12_PASS} >/dev/null
openssl pkcs12 -info -in orgB-admin.p12 -noout -passin pass:${P12_PASS} >/dev/null

echo "[make_certs] done."
ls -lh ca.crt verifier.crt hub.crt orgA-admin.p12 orgB-admin.p12

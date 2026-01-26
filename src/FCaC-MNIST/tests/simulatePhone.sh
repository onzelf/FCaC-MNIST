LAN=192.168.1.25   # put your LAN IP
BASE="https://${LAN}:8443"

echo "Start Session for Phone A"
# Simulate Phone A (HospitalA-admin)
curl -sk \
  --cert ../vfp-governance/verifier/vault/HospitalA-admin.crt \
  --key  ../vfp-governance/verifier/vault/HospitalA-admin.key \
  "${BASE}/verify-start"



echo "Start Session for Phone B"
# Simulate Phone B (HospitalB-admin)
curl -sk \
  --cert ../vfp-governance/verifier/vault/HospitalB-admin.crt \
  --key  ../vfp-governance/verifier/vault/HospitalB-admin.key \
  "${BASE}/verify-start"


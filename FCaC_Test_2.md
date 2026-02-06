 
## 🧪 Test #2 — Trust chain admission: ECT + DPoP (/admission/check) 
**Outcome**: The system admits/denies an operation based on:
- ✅ a valid **Envelope Capability Token (ECT)** (JWT / JWS)
- ✅ a request-bound **DPoP proof** (JWT)
- ✅ **capability tuple match** (compiled at mint time, checked at admission time)

### Overview

### mTLS roles (after Test#4 hardening)
- `/mint_ect` is restricted to **organization admin** client certificates (e.g., `org_HospitalA_admin`, `org_HospitalB_admin`).
- `/admission/check` is called by the **Hub** using `hub.crt/hub.key`.

1. Generate a member keypair (holder keys)
2. Mint an ECT bound to the holder (via `cnf.jkt`). **Minting is performed by an org-admin authority** (in Test#4 this is delegated to per-organization issuer containers; in this test script we call the verifier mint endpoint using the organization admin mTLS certificate).
3. Generate DPoP for a specific method+URL (`htm`, `htu`) and nonce/jti
4. Call `/admission/check` with headers:
   - `Authorization: ECT <token>`
   - `DPoP: <dpop-jwt>`
   - `X-DPoP-Nonce: <nonce>`
   
### Run the trust chain script
```bash
./Test2A_run_probe_eddsa_nginx.sh
```

If you need to mint under HospitalB instead of HospitalA, run:
```bash
MINT_CRT=../vfp-governance/verifier/certs/HospitalB-admin.crt \
MINT_KEY=../vfp-governance/verifier/certs/HospitalB-admin.key \
./Test2A_run_probe_eddsa_nginx.sh
```

The script uses helper utilities:
- `gen_member_keys.py` (generates holder keys)
- `make_dpop_jwt_eddsa.py` (generates canonical DPoP JWT)

### ⚠️ HTU canonicalization note (important)

In this PoC, nginx forwards Host as `verifier.local` (without port). Therefore, the verifier may reconstruct `REQ_HTU` without an explicit port:

**DPoP HTU used by client:**
```
https://verifier.local:8443/admission/check
```

**Verifier reconstructed HTU:**
```
https://verifier.local/admission/check
```
> If you observe `dpop_htu_mismatch`, standardize HTU in the script to match what the verifier reconstructs or implement a proxy-aware port-aware reconstruction in the verifier. For this PoC we standardize the test HTU.

### Expected results
```python
== 5) Probe ALLOW ==
{"resource":"TUMOR_MEASUREMENTS","action":"read","agg":"aggregated","pii":false,"contact":false,"jti":"jti-1769530367"}
{
  "allow": true,
  "reason": null
}
== 6) Probe DENY (wrong purpose) ==
{"resource":"PET-CT","action":"train","purpose":"model_prediction","cohort":"A","jti":"jti-1769530367"}
{
  "allow": false,
  "reason": "capability_violation"
}
== 7) Probe DENY (wrong cohort B) ==
{"resource":"PET-CT","action":"train","purpose":"model_training","cohort":"B","jti":"jti-1769530367"}
{
  "allow": false,
  "reason": "capability_violation"
}
== 8) Probe DENY (binding mismatch with different key) ==
[keys-intruder] generated PRIVHEX: 4f65d99858d885185456fc270441092746f661c60f5dacfd768b2b0f7e64b40f for intruder
[keys-intruder] generated PUBB64 : gA3cERwKMx1j3sA9knvHNjrLvcPStbRKrFn_GAKfBgI for intruder
{
  "allow": false,
  "reason": "dpop_binding_mismatch"
}
```
---

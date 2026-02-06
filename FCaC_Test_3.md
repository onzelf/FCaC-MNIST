## 🧪  Test #3 — MNIST “clinical imaging” prediction with FCaC admission

 Test #3 extends the PoC from “admission only” (Test #2) to **admission + guarded inference**. MNIST digits are treated as a stand-in for **clinical imaging resources (PET-CT)**, and cohorts (`EVEN_ONLY`, `ODD_ONLY`, `ODD_PLUS`) act like regulated “patient groups / study strata” to demonstrate scope enforcement.
 
### Test3A — Admission probes (`Test3A_run_probe_mnist.sh`)
Goal: validate that **capability minting + `/admission/check`** behaves correctly for prediction requests, using the same governance logic as Test #2.

What it does:
- mints ECTs (via issuer containers holding org-admin credentials) for different cohorts,
- probes `/admission/check` with MNIST-as-clinical operational requests like:

```json
{"resource":"PET-CT","action":"read","purpose":"model_prediction","cohort":"EVEN_ONLY","jti":"..."}
```
- checks expected outcomes:
-  **ALLOW** for matching cohort/capability
-  **DENY** with `capability_violation` for wrong cohort
-  **DENY** for tampered ECT (signature verification failure)

What it proves:
> Admission decisions are **cryptographically bound** to the minted capability set (cohort scope cannot be changed post-mint without denial).
---
### Test3B — Prediction via Hub with ECT/DPoP (`Test3B_run_predict_via_hub.sh`)

Goal: validate that prediction requests traverse the intended boundary:

**Client → Hub → `/admission/check` (mTLS + ECT/DPoP) → federated service**

What it does:
- calls `Hub /predict` with `Authorization: ECT …`, `DPoP`, and `X-DPoP-Nonce`,
- Hub calls `/admission/check`,
- on allow, Hub forwards internally to `flower-server:/predict_image`.

What it proves:
> ECT/DPoP are actually exercised on the prediction path (not just on probes), and “wrong cohort” is rejected **at the admission layer** before execution.
---
### Test3C — CLI E2E regression check (`Test3C_e2e.sh`) (optional)
This script is kept as a **non-UI** deterministic regression check (mint → predict). The primary end-to-end demonstrator is **Test #4 (UI)**.

---
## Important security notes
-  **No bypass of protected federated service:**  `flower-server` is **not published to the host** (no `127.0.0.1:8081->8081/tcp`). It is reachable only on the internal Docker network; external callers must go through the Hub boundary.

-  **TLS SAN requirement:** Hub→Verifier TLS verification requires the verifier-proxy server certificate to include a **SubjectAltName (SAN)** for the hostname used (e.g., `DNS:verifier.local`). CN-only certificates are rejected by strict TLS clients.

Quick check (should print nothing):

```bash

docker  ps  --format  'table {{.Names}}\t{{.Ports}}' | grep  -i  flower-server | grep  -F  --  '->'

```
----------


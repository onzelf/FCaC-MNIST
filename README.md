 # 🔐 Federated Computing as Code (FCaC)
## PoC — Proof-Carrying Admission + Envelope-Bound Operations


[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![OpenTofu](https://img.shields.io/badge/OpenTofu-Compatible-844FBA?logo=terraform&logoColor=white)](https://opentofu.org/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)

---
## 📋 Overview

This repository contains a working **Proof-of-Concept (PoC)** for **Federated Computing as Code (FCaC)**. It demonstrates:

✅ **Sovereignty Envelope** creation with a KYO (Key Your Organization) workflow, producing an ACTIVE envelope and publishing an envelope-created event

✅ **Operational effect of an envelope**: the Hub consumes the envelope event and binds a backend (flower_server) which then runs Flower federated training and persists evidence to a vault-like directory

✅ **Stateless admission via ECT + DPoP**: a request is admitted or denied using cryptographic proof-of-possession and capability tuples encoded in a signed token

> ⚠️ **Disclaimer**: This PoC is designed to be demonstrative, not production-grade. The objective is to show the FCaC trust chain and the boundary guarantees using existing cryptographic standards and minimal moving parts.

---
## 📝 Quickstart Checklist

1. ✅ `tofu apply`
2. ✅ `bash Test_createEnvelope.sh` → obtain `envelope_id`
3. ✅   Verify evidence under `verifier/vault/<envelope_id>/...`
4. ✅ `bash run_probe_eddsa.sh` → ALLOW/DENY admission checks
5. ✅   For a new training run:
   - Create new envelope again
   - Restart flower-server + clients if needed
   
   ----
## 🏗️ Architecture (PoC view)

### Key Components

| Component | Description |
|-----------|-------------|
| 🔒 **nginx (mTLS proxy)** | Terminates TLS, enforces client identity (CN allowlists), forwards identity headers |
| 🔍 **verifier-app** | Envelope workflow endpoints (`/verify-start`, `/session/claim`, `/beta/bind/*`)<br>Admission endpoints (`/mint_ect`, `/admission/check`)<br>Publishes envelope-created events to Redis |
| 📨 **redis** | Event bus for envelope-created events |
| 🎯 **hub** | Subscribes to `fcac:envelopes:created`, binds the backend(s) as required |
| 🌸 **flower-server / flower-clients** | Run FL training and produce evidence (`run.json`) per envelope |

### Two Execution Planes

```
┌─────────────────────────────────────────────────────────────┐
│  Stateless Admission Plane                                  │
│  /admission/check verifies cryptographic proofs +           │
│  capability tuples. No runtime policy interpretation        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Stateful Workflow Plane                                    │
│  Envelope creation, binding approvals, operational          │
│  orchestration, and training runs                           │
└─────────────────────────────────────────────────────────────┘
```

<img src="FCAC_v6.png" width="75%">

---

## 📁 Repo Layout

Key directories and their purpose:

```
infra-tofu
└── Terraform configuration file (HCL)

vfp-core

vfp-governance/verifier/state/
├── Runtime state mounted into verifier-app
└── (policy, binds, envelopes, etc.)

vfp-governance/verifier/certs/
├── TLS/mTLS certificates
└── (server cert, CA, client certs)

vfp-governance/verifier/vault/
├── "Secure enclave simulation"
└── Training writes run evidence here

tests/
└── Test suites (shell and helper python scripts)
```

---

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:

- ✅ **Docker Engine** installed
- ✅ **OpenTofu** (or Terraform) installed
- ✅ **Python 3** (for helper scripts used by Test #2)
- ✅ Your **local machine** shall resolve `verifier.local` in `/etc/hosts`	


### Generating cerificates

```bash
cd tests
./make_certs.sh
```
The following pairs will be generated:  
```
vfp-governance/verifier/certs/ca.crt (ca.key)
vfp-governance/verifier/certs/hub.crt (hub.jey)
vfp-governance/verifier/certs/HospitalA-admin.crt (HospitalA-admin.key)
vfp-governance/verifier/certs/HospitalB-admin.crt (HospitalB-admin.key)
vfp-governance/verifier/certs/verifier.crt  (verifier.key)
```

### Build + Provision

From repo root:

```bash
cd infra/tofu
tofu init
tofu apply -auto-approve
```

This starts the docker network and containers (nginx proxy, verifier-app, redis, hub, flower components).


 |  IMAGE |  PORTS |       NAMES |
 |-----------------|--------------|-------------|
 |    fcac/flower-client:local  |     |                                        flower-client-even |
|    fcac/frontend:local     |        127.0.0.1:8082->80/tcp   |            fcac-frontend |
|    fcac/flower-client:local  |         |                                 flower-client-odd |
|    fcac/flower-server:local  |          |          flower-server|
|    fcac/hub:local           |      127.0.0.1:8080->8080/tcp  |            fc-hub|
|    fcac/verifier-proxy:local  |    80/tcp, verifier.local:8443->8443/tcp  | verifier-proxy |
|    fcac/verifier-app:local   |    127.0.0.1:9000->9000/tcp   |           verifier-app |
|    redis:7-alpine          |       6379/tcp    |                          redis |
|fcac/issuer:local | 8080/tcp | issuer-hospitala |
|fcac/issuer:local | 8080/tcp | issuer-hospitalb |
--- 
## Unitary Tests

### 🧪 Test #1 — Envelope creation (KYO) + operational trigger (Flower training) [ see here](https://github.com/onzelf/FCaC-MNIST/blob/main/FCaC_Test_1.md)

### 🧪 Test #2 — Stateless Admission with ECT + DPoP [ see here](https://github.com/onzelf/FCaC-MNIST/blob/main/FCaC_Test_2.md)

### 🧪 Test #3 — MNIST “clinical imaging” prediction with FCaC admission [ see here](https://github.com/onzelf/FCaC-MNIST/blob/main/FCaC_Test_3.md)


## E2E   — UI demonstrator (Admin mint → User governed predict)

E2E adds a minimal web UI that drives the same governed execution path as the CLI tests, but with a user friedly interface ![ ](E2E_UI.png)

### Preconditions
This E2E test assumes you already have:
-   a valid **`ENVELOPE_ID`** (UUID), and
-   a trained model persisted under the vault, e.g.:
    -   `/vault/<ENVELOPE_ID>/model.pth`
    -   `/vault/<ENVELOPE_ID>/run.json`
        
You obtain this by running **Test #1A** (session/envelope creation) and training at least once (**Test #1B** / FL run). If you do not have an `ENVELOPE_ID` + persisted model, the UI will mint tokens but prediction will return `model_not_ready`.

### Bring the stack up
From the repo root:

`tofu apply -auto-approve` 

Verify containers are running:

`docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'` 

You should see: `fcac-frontend`, `fc-hub`, `verifier-proxy`, `flower-server`, `issuer-hospitala`, `issuer-hospitalb`, `redis`, plus the two flower clients.

### Confirm the model exists for your envelope

Replace with your envelope:

`ENVELOPE_ID="<uuid>" docker exec -it flower-server sh -lc "ls -l /vault/${ENVELOPE_ID}/ || true"` 

Expected: `model.pth` and `run.json`.

### Open the UI

The frontend is published on the host at:
`http://127.0.0.1:8082/`
    

If you do not see the page, check:

`curl -i http://127.0.0.1:8082/ | head docker logs fcac-frontend --tail 50` 

### Use the UI (two-step protocol)

The UI follows the same two-step protocol as the CLI E2E:
1. **Step A: Admin step (mint).**  
An organization-specific **issuer container** (e.g., `issuer-hospitala` / `issuer-hospitalb`) mints an ECT for a selected member and cohort. The issuer holds the organization’s admin credentials and is the only component that calls verifier `/mint_ect`.
2. **Step B: User step (execute).**  
The UI submits `{who, envelope_id, cohort, digit}` to the boundary endpoint. The **Hub** calls `/admission/check` with presented **ECT + DPoP + nonce**, and **only on allow** forwards internally to `flower-server:/predict_image`. The model output is cohort-scoped (procedural check + logits masking).

#### Step A — Admin tab (mint)
1.  Open **Admin** tab.
2.  Enter/select the **member name** (PoC users: `Martinez`, `Hepburn`).
3.  Select a **cohort**:
    -   `EVEN_ONLY` / `ODD_PLUS` (HospitalA / Martinez)
    -   `ODD_ONLY` (HospitalB / Hepburn)
4.  Click **Mint ECT**.
    
Expected:
-   A token appears in the ECT field (copied for use by the User tab).
-   If mint fails, the UI shows a structured error (e.g., `capability_violation`).
    
#### Step B — User tab (governed predict)

1.  Open **User** tab.
2.  Paste/keep the minted **ECT** (already filled if using the same page).
3.  Paste the **ENVELOPE_ID** (the one with a trained model).
4.  Choose a cohort and click a digit button.
    
Expected (ALLOW):
-   Admission shows `allow=true`.
-   Prediction returns a digit + probability.
-   The UI displays the image used for prediction.

Expected (DENY):
-   Admission shows `allow=false` with a reason (e.g., `capability_violation`).
-   No prediction is executed.
    

### Troubleshooting
-   **`model_not_ready`**: your `ENVELOPE_ID` has no persisted model under `/vault/<ENVELOPE_ID>/model.pth`.
-   **Mint works but predict denies**: cohort/token mismatch (minted cohort ≠ requested cohort).
-   **Predict 422**: UI request missing required fields (envelope_id, ect, etc.)—check browser console and frontend logs.
-   **TLS hostname issues Hub→Verifier**: verify `verifier-proxy` serves a SAN-enabled cert for the hostname used (see TLS note).

### What this proves.
-   **Separation of duties:** Hub does not mint; minting authority is org-scoped at issuers.
-   **Constitutional enforcement before execution:** `/admission/check` gates the service call.
-   **Cryptographic integrity:** tampered ECT or wrong cohort yields denial (`Signature verification failed` / `capability_violation`).
-   **No bypass:** `flower-server` is internal-only; external callers must go through the boundary.
 
 ---

### MNIST as a clinical surrogate.
In this PoC, MNIST is used purely as a _stand-in_ for clinical imaging to keep the ML layer simple while exercising FCaC governance end-to-end. A “digit class” (0–9) represents a categorical clinical outcome or imaging label (e.g., a diagnostic class, a triage bucket, or an imaging-derived category). The intent is not realism of the dataset, but realism of the _governance surface_: who is allowed to run prediction, under what scope, and with what verifiable evidence.

**Cohorts as governance scopes over label disclosure.**  
The cohort field (e.g., `EVEN_ONLY`, `ODD_ONLY`, `ODD_PLUS`) represents a governance-defined scope that restricts which classes may be produced/disclosed by a prediction service. Concretely, each cohort maps to an allowed set of classes (digits). This models a common clinical pattern: a given organization or role may be permitted to obtain only a restricted subset of outcomes (approved indications, protocol-scoped labels, jurisdictional restrictions, etc.) even if the computation infrastructure is shared.

**Two-layer enforcement: constitutional admission + procedural masking.**  
The PoC demonstrates enforcement at two distinct layers:

1.  **Constitutional layer (admission control):** the Hub submits an operational manifest including `{resource, action, purpose, cohort, jti}` to `/admission/check`. The verifier admits or denies based on the ECT’s minted capabilities and policy scope. This is the FCaC “hard gate”: if denied, execution does not proceed.
    
2.  **Procedural layer (service-side restriction):** once admitted, the prediction service enforces the cohort restriction at inference time by constraining the model’s outputs to the cohort’s allowed class set (e.g., masking logits so disallowed classes cannot be returned). This ensures that even when prediction is allowed, the disclosed result remains within the permitted label-space.
    

**Why this surrogate is meaningful.**  
Although digits are artificial, the governance problem is real: in cross-silo settings, it is common to share a model or service while restricting _which results_ a given party may obtain. The MNIST/cohort mapping provides a minimal, inspectable way to demonstrate (i) cryptographically verifiable admission decisions, (ii) scope-carrying tokens (ECT + DPoP), and (iii) deterministic, auditable enforcement at the service boundary.

---
### Out of scope in this PoC.
-   production-grade member IAM lifecycle (enrollment/revocation), strong end-user auth
-   hardened wallet/key storage (attestation, secure enclaves for holder keys)
-   prompt→request compilation (LLM UX) and safe projection to constitutional tuples
-   production hardening (rate limits, monitoring, multi-tenant isolation)
-  `envelope_id` is used by the service to select the persisted model artifact, but it is not yet part of the minting/admission tuple.

---
## ✅ What the PoC Proves

### Boundary guarantees (what FCaC enforces)

- ✅ **Proof-carrying admission**: Every admitted operation presents cryptographic proof of origin, permission, and possession
- ✅ **Stateless verifier on the request path**: Admission is a pure verification step relying on trust anchors and token claims; no centralized mutable policy evaluation is required at runtime
- ✅ **Envelope-bound workflow trigger**: Once quorum/KYO completes, envelope issuance triggers operational actions (here: training), producing auditable evidence

### What FCaC does NOT attempt to solve here

- ❌ Full procedural governance (ABAC engines, organizational policies, human workflows) beyond a minimal KYO gate
- ❌ Production-grade orchestration and lifecycle management (explicit unbind endpoints, multi-backend reconciliation, robust retries)
- ❌ Model persistence as a secured artifact (planned enhancement)

---

## 🔧 Practical Troubleshooting

| Issue | Solution |
|-------|----------|
| **"400 plain HTTP request sent to HTTPS port"** | You used `http://...:8443`. Use `https://...:8443` |
| **"SSL CN mismatch" when using the IP** | Use `https://verifier.local:8443` (or reissue cert with IP SAN for a demo environment) |
| **"dpop_htu_mismatch"** | Your DPoP `htu` must match verifier's reconstructed HTU (proxy and port canonicalization). Standardize HTU in tests or implement forwarded-port reconstruction in the verifier |
| **"409 Conflict" binding backend (hub → flower-server)** | Restart the flower server to clear prior binding state:<br>`docker restart flower-server`<br>`docker restart flower-client-even flower-client-odd` |
| **"curl/jq not found" inside a container** | Use a container that has tooling (hub) or query from host |

---
## 🚀 Next Enhancements

- [ ] Persist model checkpoints under `vault/<envelope_id>/...` (separate track; not required for the core FCaC evidence story)
- [ ] Add a minimal frontend for `/predict`, gated by `/admission/check`
- [ ] Add a backend "unbind/reset" endpoint to avoid needing container restart between envelopes

---

## 📄 License

Apache 2.0

---

<div align="center">

**Built by S*elf for demonstrating Federated Computing as Code @ Paris 2026**

</div>


 

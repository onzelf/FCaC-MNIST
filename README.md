

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
- ✅ Your local machine can resolve `verifier.local` (recommended)

### Build + Provision

From repo root:

```bash
tofu init -auto-approve
tofu apply -aiti-approve
```

This starts the docker network and containers (nginx proxy, verifier-app, redis, hub, flower components).

---

## 🔐 Critical TLS/mTLS Notes (Do Not Skip)

### 1️⃣ Hostname vs IP

Your server certificate is issued to `verifier.local` (CN/SAN). Browser-grade clients may reject IP URLs.

**Recommended base URL:**
```
https://verifier.local:8443
```

> ⚠️ If you use an IP URL on a strict client, you may see "site can't be reached" due to hostname mismatch.

### 2️⃣ "curl -k" is not a real test

Using `-k` disables server validation. It is acceptable for quick debugging but not for validating the trust chain.

**Prefer:**
```bash
curl --cacert <CA> --cert <CLIENT_CRT> --key <CLIENT_KEY> https://verifier.local:8443/...
```

### 3️⃣ mTLS enforcement is endpoint-specific

Some endpoints are public (`/attest`, optionally `/health`). Sensitive endpoints require mTLS CN allowlists:

- `/verify-start` expects **admin CN**
- `/admission/check` expects **hub CN**

---

## 🧪 Test #1 — Envelope creation (KYO) + operational trigger (Flower training)

**Outcome**: You create an ACTIVE envelope and the system triggers a Flower training run bound to that envelope, producing evidence (metrics) under the vault. The intuition behind the envelope creation is to certify admission control to the system similar to what happen when passing the control at the border to entry a Country. 

### Step 1: Start verification session (KYO)

The admin initiates `/verify-start` and receives a 6-digit code.

**Typical call (admin client cert):**

```bash
curl -s \
  --cacert vfp-governance/verifier/certs/ca.crt \
  --cert   vfp-governance/verifier/vault/HospitalA-admin.crt \
  --key    vfp-governance/verifier/vault/HospitalA-admin.key \
  https://verifier.local:8443/verify-start
```

This returns an HTML page containing the 6-digit verification code.

### Step 2: Claim session (Hub)

Hub claims the code and obtains a session handle.

The envelope creation script (`Test_createEnvelope_v3.sh`) automates the full flow:
- `/beta/bind/init`
- `/verify-start` (admin KYO)
- `/session/claim` (hub)
- `/beta/bind/approve` (hub)

**Run:**

```bash
bash Test_createEnvelope_v3.sh
```

**Expected output includes:**
```
✓ Envelope created: <envelope_id>
```

verifier-app publishes a Redis event on `fcac:envelopes:created`

### Step 3: Confirm training evidence exists

Training evidence is written by the Flower server side under the vault path for that envelope.

**Check:**
```
vfp-governance/verifier/vault/<envelope_id>/run.json
```

### 🔄 Operational workflow: rerun training for a new envelope

Each envelope is treated as a bounded execution context. If you create a new envelope and want a new run, a minimal PoC reset is:

```bash
docker restart flower-server
docker restart flower-client-even flower-client-odd
```

> 💡 **Why this is needed**: The flower-server control plane can refuse rebinding with 409 Conflict if it still considers itself bound to a previous envelope. Restarting the server resets that in-memory binding latch.

### 🛠️ Debugging without curl/jq inside slim images

Some containers do not have curl/jq. Use a container that does (e.g., hub) to query internal services:

```bash
docker exec -it fc-hub sh -lc 'curl -s http://flower-server:8081/status | python -m json.tool'
```

---

## 🧪 Test #2 — Trust chain admission: ECT + DPoP (/admission/check)

**Outcome**: The system admits/denies an operation based on:
- ✅ a valid **Envelope Capability Token (ECT)** (JWT / JWS)
- ✅ a request-bound **DPoP proof** (JWT)
- ✅ **capability tuple match** (compiled at mint time, checked at admission time)

### Overview

1. Generate a member keypair (holder keys)
2. Mint an ECT bound to the holder (via `cnf.jkt`)
3. Generate DPoP for a specific method+URL (`htm`, `htu`) and nonce/jti
4. Call `/admission/check` with headers:
   - `Authorization: ECT <token>`
   - `DPoP: <dpop-jwt>`
   - `X-DPoP-Nonce: <nonce>`

### Run the trust chain script

```bash
bash run_probe_eddsa.sh
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

This is a known, documented PoC trade-off.

### Expected results

**An allowed request returns:**
```json
{ "allow": true }
```

**A denied request returns:**
```json
{ "allow": false, "reason": "<reason_code>" }
```

**Typical denial reasons include:**
- `dpop_binding_mismatch`
- `dpop_jti_mismatch`
- `capability_violation`

---

## ✅ What the PoC Proves

### Boundary guarantees (what FCaC enforces)

✅ **Proof-carrying admission**: Every admitted operation presents cryptographic proof of origin, permission, and possession

✅ **Stateless verifier on the request path**: Admission is a pure verification step relying on trust anchors and token claims; no centralized mutable policy evaluation is required at runtime

✅ **Envelope-bound workflow trigger**: Once quorum/KYO completes, envelope issuance triggers operational actions (here: training), producing auditable evidence

### What FCaC does NOT attempt to solve here

❌ Full procedural governance (ABAC engines, organizational policies, human workflows) beyond a minimal KYO gate

❌ Production-grade orchestration and lifecycle management (explicit unbind endpoints, multi-backend reconciliation, robust retries)

❌ Model persistence as a secured artifact (planned enhancement)

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

## 📝 Quickstart Checklist

1. ✅ `tofu apply`
2. ✅ `bash Test_createEnvelope_v3.sh` → obtain `envelope_id`
3. ✅ Verify evidence under `verifier/vault/<envelope_id>/...`
4. ✅ `bash run_probe_eddsa.sh` → ALLOW/DENY admission checks
5. ✅ For a new training run:
   - Create new envelope again
   - Restart flower-server + clients if needed

---

## 📄 License

Apache 2.0

---

<div align="center">

**Built by S*elf for demonstrating Federated Computing as Code**

</div>




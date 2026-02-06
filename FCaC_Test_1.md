
## 🧪 Test #1 — Envelope creation (KYO) + operational trigger (Flower training)

>**Objective**: Envelope issuance triggers real, auditable execution (KYO → training → evidence).

Flower training starts **because envelope creation emits a constitutional event**, not because a training request is authorized. When an envelope transitions to `ACTIVE`, the verifier publishes an _envelope-created event_ on a shared event bus. The Hub subscribes to this event and binds the Flower server to the envelope context. The Flower server, once bound, starts training automatically. No authorization logic exists inside the Flower server; admission and authorization are completed **before** the workflow starts.

> **Why training starts automatically after envelope creation.**  
In FCaC, an envelope is not a permission but a constitutional execution context. When an envelope becomes ACTIVE, the verifier emits a single envelope-created event that signals the existence of a new, governance-approved context. The Hub subscribes to this event and binds the relevant Core services to the envelope. In the PoC, this binding unblocks the Flower server, which starts federated training automatically. No authorization logic exists inside the training service itself: all governance decisions are completed prior to execution. This separation ensures that operational services remain purely procedural, while sovereignty constraints are enforced exclusively at the boundary.

### Step 1: Start verification session (KYO)

Admins initiate `/verify-start` and receives a 6-digit code using the command
```bash
./simulatePhone.sh
```
The script actually call 
```bash
curl -s \
  --cacert vfp-governance/verifier/certs/ca.crt \
  --cert   vfp-governance/verifier/vault/HospitalA-admin.crt \
  --key    vfp-governance/verifier/vault/HospitalA-admin.key \
  https://verifier.local:8443/verify-start
```
> It is also possible to load the hospital certificates on an Android device and  trigger the `verify-start` API endpoint.

### Step 2: Claim session (Hub)

Hub claims the code and obtains a session handle.

The envelope creation script (`Test_createEnvelope_v3.sh`) automates this flow:
- `/beta/bind/init`
- `/verify-start` (admin KYO)
- `/session/claim` (hub)
- `/beta/bind/approve` (hub)

**Run:**

```bash
cd tests
./Test1A_createEnvelope.sh
```

**Expected output includes:**
```
✓ Envelope created: b51d3869-4a95-40d5-bea8-064ecd813693
Run post-envelope test:
./Test1B_postEnvelope.sh b51d3869-4a95-40d5-bea8-064ecd813693
```
verifier-app publishes a Redis event on `fcac:envelopes:created`

### Step 3: post-Envelope test

Once the envelope has been created the Flower services registered with the hub can start. Training evidence is written by the Flower server side under the vault path for that envelope.

> **Client retry and “completion” logs.** Flower clients start as short-lived jobs and attempt to connect to the Flower server for up to `MAX_RETRIES × RETRY_INTERVAL` (~10 minutes). Early “connection failed” messages are expected if the server is not yet bound/ready. When `start_numpy_client()` returns, the client prints a completion line and exits; this indicates that the client session ended without raising, not a formal proof of training. The authoritative success signals are the Flower server run summary and the persisted evidence file `/vault/<envelope_id>/run.json`.

### Run the post-envelope script
```
./Test1B_postEnvelope.sh <envelope_id>
<envelope_id> is the ACTIVE envelope
```
 
the script checks that the Post-Envelope Flow Test (Hub → bind → Flower run evidence) is valid for the ACTIVE envelope:
 
e.g. Envelope ID: b51d3869-4a95-40d5-bea8-064ecd813693
 
- Step 0: Preflight container liveness
- Step 1: Verify Hub received envelope event
- Step 2: Verify Hub bound (or attempted to bind) flower_server
- Step 3: Verify flower-server references this envelope
- Step 4: Wait for training completion (authoritative: /status)
{"status":"bound","envelope_id":"b51d3869-4a95-40d5-bea8-064ecd813693","bound":true,"training":{"rounds":1,"loss":0.9048528075218201,"accuracy":0.7715,"started_at":1769523792.7784934,"ended_at":null,"status":"training","error":null}}
 ... 
 {"status":"bound","envelope_id":"b51d3869-4a95-40d5-bea8-064ecd813693","bound":true,"training":{"rounds":10,"loss":0.15646830201148987,"accuracy":0.952,"started_at":1769523792.7784934,"ended_at":1769523968.8421922,"status":"done","error":null}}
✓ Training completed (per /status) 
- Step 5: Verify evidence in /vault/<envelope_id>/run.json (inside flower-server)
```python
{
  "envelope_id": "b51d3869-4a95-40d5-bea8-064ecd813693",
  "fraction_evaluate": 1.0,
  "fraction_fit": 1.0,
  "min_available_clients": 2,
  "num_rounds": 10,
  "policy_hash": "sha256:e903476586378a81fb970c6863050e6428d5f458940dcf7a1eabd70c9476a329",
  "scope": {
    "backend": "flower_server",
    "model": "FedMNIST-v1"
  },
  "training": {
    "accuracy": 0.952,
    "ended_at": 1769523968.8421922,
    "error": null,
    "loss": 0.15646830201148987,
    "rounds": 10,
    "started_at": 1769523792.7784934,
    "status": "done"
  }
}
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


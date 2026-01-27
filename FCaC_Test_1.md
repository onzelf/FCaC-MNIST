## From Test #1 to Flower training

### Step 0 — What Test #1 really does

When running **Test #1 (envelope creation)**, we are _not_ requesting training.
but   **creating a constitutional execution context** (i.e. the sovereignty envelope).

This happens via:

-   `/verify-start` (KYO)
-   `/session/claim`
-   `/beta/bind/init`
-   `/beta/bind/approve`
    

At the end of this sequence, the envelope becomes **ACTIVE**.

----------

### Step 1 — Verifier emits an envelope-created event (this is the key)

When the envelope becomes ACTIVE, the verifier executes this logic (simplified):

```python 
envelope_event = { "envelope_id": eid,
 "policy_hash": env["policy_hash"], 
 "scope": env["scope"], 
 "participants": [...], 
 "valid_until": ...
}
publish("fcac:envelopes:created", envelope_event)` 
```

**Important properties of this event:**

-   It is emitted **once**, at envelope activation.
-   It is **not a request**.
-   It is **not authorized**.
-   It is **constitutional**, not procedural.
    
This event says:
> “An execution context with these constraints now exists.”

----------

### Step 2 — The Hub subscribes to envelope-created events

The Hub runs a background subscriber:  
```python 
subscribe("fcac:envelopes:created")
``` 

When it receives the event, it decides **what operational workflows are implied by this envelope**.

In the PoC, the rule is simple and explicit:
-   If `scope.backend == "flower_server"`, then bind the Flower server.
    
This decision is **procedural**, local to the Hub, and _not_ a governance decision.

----------

### Step 3 — Hub binds the Flower server to the envelope

The Hub calls the Flower server control plane:

```http 
 POST /bind_envelope {
  "envelope_id": "...",
  "policy_hash": "...",
  "scope": {...}
}```
```
This is **not authorization**.  
It is **context injection**.

The Flower server:
-   records the envelope_id
-   records the policy_hash
-   unblocks its execution latch

If the server is already bound, it returns `409` (which is why restarting the server is currently the reset mechanism).

----------

### Step 4 — Flower server starts training automatically

Inside the Flower server, the main thread looks like:

```python
start_fastapi_control_plane()
wait_until_envelope_bound()
start_flower_training()` 
```

So training starts **because**:

-   the envelope exists
-   the Hub bound the server
-   the latch is released
    

There is **no runtime authorization check** in the server.

This is the **correct FCaC architecture**.

----------

## What does _not_ happen anymore

### ❌ No authorization needed inside the Flower server

In a previous  versions, the logic was:

-   “check token”
-   “check permissions
-   “check requester”
    
That was wrong because it:

-   mixed constitutional governance with procedural execution
-   turned the server into a policy enforcement point (IAM smell)
    

Now:

-   the server **assumes** it is allowed to run
-   because it was bound to an envelope
-   and that binding was only possible after governance succeeded
    

----------

### ❌ No training request passes through `/admission/check`

Training is **not** an admitted request.

Admission (`/admission/check`) is for:

-   operational API calls
-   prediction requests
-   data access
-   runtime actions initiated by agents

Training is a **workflow implied by envelope existence**, not a request.

----------
## Summary

> **Why training starts automatically after envelope creation.**  
> In FCaC, an envelope is not a permission but a constitutional execution context. When an envelope becomes ACTIVE, the verifier emits a single envelope-created event that signals the existence of a new, governance-approved context. The Hub subscribes to this event and binds the relevant Core services to the envelope. In the PoC, this binding unblocks the Flower server, which starts federated training automatically. No authorization logic exists inside the training service itself: all governance decisions are completed prior to execution. This separation ensures that operational services remain purely procedural, while sovereignty constraints are enforced exclusively at the boundary.

> **Envelope binding and workflow execution.**  
FCaC does not prescribe operational behavior. It establishes the conditions under which a service may enter a governed execution context. In the proof-of-concept, the Flower server is configured to interpret envelope binding as authorization to execute a predefined federated learning workflow. This behavior is analogous to a ***smart contract***: the envelope constitutes the enabling condition, while the training logic remains procedural, local to the service, and agreed independently of governance. Other services could interpret the same envelope differently or take no action at all.

> **Client lifecycle.**  
In the proof-of-concept, Flower clients are modeled as short-lived participants rather than persistent services. Each client joins a federated execution, participates for the agreed number of rounds, and then exits. This reflects realistic cross-silo settings in which organizations explicitly opt into each governed execution. As a result, running a new envelope requires restarting the client containers, ensuring fresh consent and preventing state leakage across envelopes.
----------

## Why this is  a strong design

This pattern is powerful because it scales:

-   You can trigger **multiple workflows** from the same envelope.
-   You can have **different hubs** react differently to the same envelope.
-   You can audit _why_ a workflow existed by pointing to the envelope.
-   You can prove that **no execution occurred without governance**.

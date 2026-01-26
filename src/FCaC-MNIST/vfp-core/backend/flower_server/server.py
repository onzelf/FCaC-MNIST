 # backends/flower_server/server.py
# FastAPI (control plane) + Flower server (data plane)
#
# Test #3 scope:
# - Hub binds envelope -> training starts
# - Persist artifact to VAULT_ROOT/<envelope_id>/run.json
# - No authorization or admission logic in this service

from __future__ import annotations

import json
import os, time, requests
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import flwr as fl
from fastapi import FastAPI, HTTPException, Request
import uvicorn
from flwr.server.strategy import FedAvg

# ----------------------------
# Configuration
# ----------------------------

NUM_ROUNDS = int(os.environ.get("NUM_ROUNDS", "3"))
MIN_AVAILABLE_CLIENTS = int(os.environ.get("MIN_AVAILABLE_CLIENTS", "2"))
FRACTION_FIT = float(os.environ.get("FRACTION_FIT", "1.0"))
FRACTION_EVALUATE = float(os.environ.get("FRACTION_EVALUATE", "1.0"))

# Simulated enclave boundary (mounted by OpenTofu)
VAULT_ROOT = Path(os.environ.get("VAULT_ROOT", "/vault"))

# Kept for compatibility (not used in Test #3)
VERIFIER_URL = os.environ.get("VERIFIER_URL", "https://verifier-proxy:8443")
VERIFY_TLS = os.environ.get("VERIFY_TLS", "0") == "1"
HUB_CERT: Tuple[str, str] = (
    os.environ.get("HUB_CERT_CRT", "/run/certs/hub.crt"),
    os.environ.get("HUB_CERT_KEY", "/run/certs/hub.key"),
)

HUB_URL = os.environ.get("HUB_URL", "http://fc-hub:8080")

def register_with_hub():
    payload = {"type": "flower_server", "url": "http://flower-server:8081"}
    for i in range(60):
        try:
            r = requests.post(f"{HUB_URL}/backend/register", json=payload, timeout=5)
            if r.status_code == 200:
                print("[flower-server] registered with hub", flush=True)
                return
            print(f"[flower-server] register HTTP {r.status_code}: {r.text[:200]}", flush=True)
        except Exception as e:
            print(f"[flower-server] hub not ready ({i+1}/60): {e}", flush=True)
        time.sleep(1)
    raise RuntimeError("could not register with hub")

# ----------------------------
# State (workflow)
# ----------------------------

app = FastAPI()

envelope_config: Optional[Dict[str, Any]] = None
envelope_bound = threading.Event()  # set when Hub binds the envelope

training_metrics: Dict[str, Any] = {
    "rounds": 0,
    "loss": None,
    "accuracy": None,
    "started_at": None,
    "ended_at": None,
    "status": "idle",  # idle | bound | training | done | failed
    "error": None,
}


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def persist_run_artifact(envelope_id: str, payload: Dict[str, Any]) -> Path:
    outdir = VAULT_ROOT / envelope_id
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / "run.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[flower_server:{now()}] persisted artifact: {path}", flush=True)
    return path


# ----------------------------
# Flower strategy (captures metrics)
# ----------------------------

class MetricsFedAvg(FedAvg):
    def aggregate_evaluate(self, server_round, results, failures):
        # This hook runs after evaluation aggregation each round (if clients evaluate).
        # We record whatever we can as "run evidence" for Test #3.
        try:
            # flwr returns list of (client_proxy, EvaluateRes)
            if results:
                losses = [float(res.loss) for _, res in results if res and res.loss is not None]
                accs = []
                for _, res in results:
                    if res and res.metrics and "accuracy" in res.metrics:
                        try:
                            accs.append(float(res.metrics["accuracy"]))
                        except Exception:
                            pass

                avg_loss = sum(losses) / max(1, len(losses)) if losses else None
                avg_acc = sum(accs) / max(1, len(accs)) if accs else None

                training_metrics["rounds"] = int(server_round)
                if avg_loss is not None:
                    training_metrics["loss"] = float(avg_loss)
                if avg_acc is not None:
                    training_metrics["accuracy"] = float(avg_acc)

                if avg_loss is not None and avg_acc is not None:
                    print(
                        f"[flower_server] Round {server_round}: loss={avg_loss:.4f}, accuracy={avg_acc:.4f}",
                        flush=True,
                    )
                elif avg_loss is not None:
                    print(
                        f"[flower_server] Round {server_round}: loss={avg_loss:.4f}",
                        flush=True,
                    )

        except Exception as e:
            print(f"[flower_server:{now()}] WARN: metrics aggregation failed: {e}", flush=True)

        return super().aggregate_evaluate(server_round, results, failures)


# ----------------------------
# FastAPI endpoints (control plane)
# ----------------------------

@app.get("/status")
async def status():
    if envelope_config is None:
        return {
            "status": "waiting_for_binding",
            "envelope_id": None,
            "training": training_metrics,
        }

    return {
        "status": envelope_config.get("status", "bound"),
        "envelope_id": envelope_config.get("envelope_id"),
        "bound": envelope_bound.is_set(),
        "training": training_metrics,
    }


@app.post("/bind_envelope")
async def bind_envelope(req: Request):
    """
    Workflow hook called by Hub once the envelope is ACTIVE (quorum complete).
    this is the only trigger condition: bind => start training.
    """
    global envelope_config

    data = await req.json()
    envelope_id = data.get("envelope_id")
    if not envelope_id:
        raise HTTPException(400, "missing envelope_id")

    if envelope_config is not None:
        raise HTTPException(409, f"already bound to {envelope_config.get('envelope_id')}")

    envelope_config = {
        "envelope_id": envelope_id,
        "policy_hash": data.get("policy_hash"),
        "scope": data.get("scope", {}),
        "status": "bound",
        "bound_at": int(time.time()),
    }

    training_metrics["status"] = "bound"
    training_metrics["error"] = None

    envelope_bound.set()

    print(f"[flower_server:{now()}] Envelope bound: {envelope_id}. Training will start.", flush=True)
    return {"bound": True, "envelope_id": envelope_id, "status": "bound"}


@app.post("/predict_image")
async def predict_image(_: Request):
    """
    Stub for Enhancement #3.
    Prediction should be exposed via frontend and guarded by /admission/check,
    not embedded here as an authorization surface.
    """
    raise HTTPException(501, "predict_not_enabled_in_test3")


def start_fastapi():
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")


# ----------------------------
# Main (data plane)
# ----------------------------

if __name__ == "__main__":
    print(f"[flower_server:{now()}] Starting up...", flush=True)

    # Start control-plane API
    fastapi_thread = threading.Thread(target=start_fastapi, daemon=True)
    fastapi_thread.start()

    # Register backend with Hub 
    register_with_hub()

    print("[flower_server] Waiting for Hub binding...", flush=True)
    envelope_bound.wait()

    assert envelope_config is not None
    envelope_id = envelope_config["envelope_id"]

    # Start Flower training
    try:
        training_metrics["started_at"] = time.time()
        training_metrics["status"] = "training"

        strategy = MetricsFedAvg(
            fraction_fit=FRACTION_FIT,
            fraction_evaluate=FRACTION_EVALUATE,
            min_available_clients=MIN_AVAILABLE_CLIENTS,
        )

        print(
            f"[flower_server:{now()}] Starting Flower gRPC server on 0.0.0.0:8080 "
            f"(rounds={NUM_ROUNDS}, min_clients={MIN_AVAILABLE_CLIENTS})",
            flush=True,
        )

        fl.server.start_server(
            server_address="0.0.0.0:8080",
            config=fl.server.ServerConfig(num_rounds=NUM_ROUNDS),
            strategy=strategy,
        )

        training_metrics["ended_at"] = time.time()
        training_metrics["status"] = "done"

        print(f"[flower_server:{now()}] Training completed", flush=True)

        # Persist run evidence to vault/<envelope_id>/run.json
        persist_run_artifact(envelope_id, {
            "envelope_id": envelope_id,
            "policy_hash": envelope_config.get("policy_hash"),
            "scope": envelope_config.get("scope", {}),
            "num_rounds": NUM_ROUNDS,
            "min_available_clients": MIN_AVAILABLE_CLIENTS,
            "fraction_fit": FRACTION_FIT,
            "fraction_evaluate": FRACTION_EVALUATE,
            "training": training_metrics,
        })

    except Exception as ex:
        training_metrics["ended_at"] = time.time()
        training_metrics["status"] = "failed"
        training_metrics["error"] = str(ex)

        print(f"[flower_server:{now()}] FATAL ERROR in Flower: {ex}", flush=True)

        # Persist failure evidence too (useful in PoC)
        try:
            persist_run_artifact(envelope_id, {
                "envelope_id": envelope_id,
                "status": "failed",
                "error": str(ex),
                "training": training_metrics,
            })
        except Exception as persist_ex:
            print(f"[flower_server:{now()}] WARN: could not persist failure artifact: {persist_ex}", flush=True)

        raise

    # Keep process alive after training for observability (status endpoint)
    threading.Event().wait()

import os
import time
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

ORG = os.getenv("ORG", "").strip()  # e.g., org://HospitalA
VERIFIER_URL = os.getenv("VERIFIER_URL", "https://verifier-proxy:8443").rstrip("/")

VERIFY_TLS = os.getenv("VERIFY_TLS", "0").strip()
CA_CRT = os.getenv("CA_CRT", "/run/certs/ca.crt")
ADMIN_CRT = os.getenv("ADMIN_CRT", "/run/certs/admin.crt")
ADMIN_KEY = os.getenv("ADMIN_KEY", "/run/certs/admin.key")

# PoC: org-scoped cohort -> cap_profile mapping (constitutional capability profiles)
CAP_BY_ORG_AND_COHORT: Dict[str, Dict[str, str]] = {
    "org://HospitalA": {
        "EVEN_ONLY": "capset:predictor_even",
        "ODD_PLUS":  "capset:predictor_odd_plus",
    },
    "org://HospitalB": {
        "ODD_ONLY":  "capset:predictor_odd",
    },
}

def _verify_arg():
    if VERIFY_TLS in ("0","false","False",""):
        return False
    return CA_CRT

class MintReq(BaseModel):
    who: str
    cohort: str
    holder_pub_b64: str
    nbf: Optional[str] = None
    exp: Optional[str] = None

@app.get("/rights")
def rights():
    return {"org": ORG, "cohorts": sorted(CAP_BY_ORG_AND_COHORT.get(ORG, {}).keys())}

@app.post("/mint")
def mint(req: MintReq):
    if not ORG:
        raise HTTPException(500, "issuer_not_configured:missing_ORG")

    cap = CAP_BY_ORG_AND_COHORT.get(ORG, {}).get(req.cohort)
    if not cap:
        raise HTTPException(403, f"cohort_not_allowed:{req.cohort}")

    # Default validity window (1h) if not provided
    now = int(time.time())
    nbf = req.nbf or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 60))
    exp = req.exp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600))

    try:
        r = requests.post(
            f"{VERIFIER_URL}/mint_ect",
            json={
                "holder_pub_b64": req.holder_pub_b64,
                "cap_profiles": [cap],
                "nbf": nbf,
                "exp": exp,
            },
            timeout=15,
            verify=_verify_arg(),
            cert=(ADMIN_CRT, ADMIN_KEY),
        )
        if r.status_code != 200:
            raise HTTPException(r.status_code, r.text)
        out = r.json()
        ect = out.get("ect_jws")
        if not ect:
            raise HTTPException(502, f"mint_failed:no_ect_jws:{out}")

        # Optional sanity check (correct for compact JWS)
        if ect.count(".") < 2:
            raise HTTPException(502, f"mint_failed:not_compact_jws:{out}")

        return {"ect": ect}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"verifier_error:{e}")

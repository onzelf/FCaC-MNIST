import base64
import json
import os
import time
from typing import Dict, Tuple

import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

RIGHTS_TEXT = """Users (PoC)

Martinez (Hospital A): cohorts EVEN_ONLY, ODD_PLUS
Hepburn  (Hospital B): cohorts ODD_ONLY

Two-step UI:
1) Admin tab mints an ECT for the selected user+cohort (issuer call).
2) User tab performs governed /predict using that ECT (Hub -> /admission/check -> service).
"""

# ---- Network targets ----
HUB_URL       = os.getenv("HUB_URL", "http://fc-hub:8080").rstrip("/")
ISSUER_A_URL  = os.getenv("ISSUER_A_URL", "http://issuer-hospitala:8080").rstrip("/")
ISSUER_B_URL  = os.getenv("ISSUER_B_URL", "http://issuer-hospitalb:8080").rstrip("/")

# HTU convention used inside DPoP JWT (Hub will forward to verifier)
DPoP_HTU = os.getenv("DPoP_HTU", "https://verifier.local/admission/check")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# Holder keypair (no wallet, no disk): stable for container lifetime only.
_HOLDER_SK = ed25519.Ed25519PrivateKey.generate()
_HOLDER_PUB_B64 = _b64u(_HOLDER_SK.public_key().public_bytes_raw())


def _jws_eddsa(sk: ed25519.Ed25519PrivateKey, header: Dict, payload: Dict) -> str:
    h = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    msg = f"{h}.{p}".encode("ascii")
    sig = sk.sign(msg)
    return f"{h}.{p}.{_b64u(sig)}"


def _make_dpop_and_nonce(jti: str) -> Tuple[str, str]:
    nonce = f"ui-nonce-{int(time.time())}"
    header = {
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _HOLDER_PUB_B64},
    }
    payload = {
        "htu": DPoP_HTU,
        "htm": "POST",
        "iat": int(time.time()),
        "jti": jti,
        "nonce": nonce,
    }
    return _jws_eddsa(_HOLDER_SK, header, payload), nonce


def _issuer_for(who: str) -> str:
    # PoC wiring: member selection chooses org issuer.
    if who == "Martinez":
        return ISSUER_A_URL
    if who == "Hepburn":
        return ISSUER_B_URL
    return ISSUER_A_URL


def ui_mint(req) -> Dict:
    try:
        issuer = _issuer_for(req.who)
        r = requests.post(
            f"{issuer}/mint",
            json={"who": req.who, "cohort": req.cohort, "holder_pub_b64": _HOLDER_PUB_B64},
            timeout=15,
        )
        out = r.json()
        if r.status_code != 200:
            return {"ok": False, "error": out}
        ect = out.get("ect")
        if not ect: # or ect.count(".") != 2:
            return {"ok": False, "error": "mint_failed:bad_ect_format", "raw": out}
        return {"ok": True, "ect": ect, "holder_pub_b64": _HOLDER_PUB_B64, "issuer": issuer}
    except Exception as e:
        return {"ok": False, "error": f"mint_error:{e}"}


def ui_predict_with_ect(req) -> Dict:
    ect = (req.ect or "").strip()
    if not ect or ect.count(".") != 2:
        return {"admission": {"allow": False, "reason": "bad_ect_format"}, "executed": False}

    dpop, nonce = _make_dpop_and_nonce(req.jti)

    try:
        r = requests.post(
            f"{HUB_URL}/predict",
            headers={
                "Authorization": f"ECT {ect}",
                "DPoP": dpop,
                "X-DPoP-Nonce": nonce,
                "Content-Type": "application/json",
            },
            json={
                "envelope_id": req.envelope_id,
                "cohort": req.cohort,
                "digit": req.digit,
                "topk": req.topk,
                "jti": req.jti,
            },
            timeout=30,
        )
        return r.json()
    except Exception as e:
        return {"admission": {"allow": False, "reason": f"hub_error:{e}"}, "executed": False}

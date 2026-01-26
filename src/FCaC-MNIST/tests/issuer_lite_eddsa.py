#!/usr/bin/env python3
# Minimal E2E issuer + gatekeeper probe (2 artifacts: ECT + DPoP)
# Keeps your directory layout and helper scripts unchanged.

import base64, hashlib, json, os, time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel, Field
import jwt  # pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# ---------- paths ----------
APP_DIR   = Path(__file__).resolve().parent
ROOT_DIR  = APP_DIR.parent 
print("ROOT -> ",ROOT_DIR)

CERTS_DIR  = ROOT_DIR / "vfp-governance" / "verifier" / "certs"
STATE_DIR  = ROOT_DIR / "vfp-governance"/ "verifier" / "state"
POLICY_PATH = STATE_DIR / "policy.json"
VAULT_ROOT = ROOT_DIR / "vfp-governance" / "verifier" / "vault"  # (not used by this minimal E2E)
print("POLICY: ",POLICY_PATH)


# ---------- config ----------
ISS = os.environ.get("ISS", "http://127.0.0.1:9100")
AUD_FALLBACK = os.environ.get("AUD", "svc:fl-gateway:eu")
print("AUD: ",AUD_FALLBACK)
ORG_KEY_KID = os.environ.get("ORG_KEY_KID", "HospitalA-key")
ORG_KEY_FILE = os.environ.get("ORG_KEY_FILE", str(CERTS_DIR / "HospitalA-admin.key"))  # PEM (EC or RSA)
POLICY_ALLOWLIST = {x for x in os.environ.get("ALLOWED_POLICY_HASHES","").split(",") if x.strip()}

# ---------- utils ----------
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_to_bytes(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def jcs_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_b64u(b: bytes) -> str:
    return b64u(hashlib.sha256(b).digest())

def rfc7638_thumbprint_okp_ed25519(pub_b64u: str) -> str:
    # JWK OKP(Ed25519): required members in lexicographic order
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": pub_b64u}
    return sha256_b64u(jcs_bytes(jwk))

def load_org_key_and_alg():
    pem = Path(ORG_KEY_FILE).read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = key.curve.name.lower()
        alg = "ES256" if "p-256" in curve or "secp256r1" in curve else "ES384" if "384" in curve else "ES512"
    elif isinstance(key, rsa.RSAPrivateKey):
        alg = "RS256"
    else:
        raise RuntimeError("Unsupported org private key type (need EC or RSA PEM)")
    return pem, key.public_key(), alg

def load_policy() -> Dict[str, Any]:
    pol = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    for k in ("version","ops","cap_profiles","meta"):
        if k not in pol:
            raise RuntimeError(f"policy.json missing '{k}'")
    return pol

def compute_policy_hash(policy: Dict[str, Any]) -> str:
    return sha256_b64u(jcs_bytes(policy))

def pick_caps(policy: Dict[str, Any], cap_profiles: List[str]) -> List[Dict[str, Any]]:
    ops = policy["ops"]; profs = policy["cap_profiles"]
    op_ids: List[str] = []
    for pid in cap_profiles:
        entry = profs.get(pid)
        if not entry:
            raise HTTPException(400, f"cap_profile '{pid}' not found in policy.cap_profiles")
        for op_id in entry.get("cap", []):
            if op_id not in ops:
                raise HTTPException(400, f"op_id '{op_id}' from profile '{pid}' not found in policy.ops")
            if op_id not in op_ids:
                op_ids.append(op_id)
    caps: List[Dict[str, Any]] = []
    for op_id in op_ids:
        op = ops[op_id]; cap={}
        for k in ("resource","action","purpose","scope","flags"):
            if k in op and op[k] not in ({}, [], None, ""):
                cap[k] = op[k]
        caps.append(cap)
    # compile-time prohibitions
    prohibitions = set(policy.get("caveats", {}).get("prohibitions", []))
    if "no_export_raw" in prohibitions:
        caps = [c for c in caps if not (c.get("action")=="export" and c.get("flags",{}).get("datatype")=="raw")]
    # dedupe
    seen=set(); uniq=[]
    for c in caps:
        k=json.dumps(c,sort_keys=True)
        if k not in seen: seen.add(k); uniq.append(c)
    return uniq

def now_epoch() -> int: return int(time.time())

def iso_to_epoch(s: str) -> int:
    return int(datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc).timestamp())

def cap_matches_request(cap: Dict[str, Any], req: Dict[str, Any]) -> bool:
    if cap.get("resource") != req.get("resource"): return False
    if cap.get("action")   != req.get("action"):   return False
    if "purpose" in cap and cap["purpose"] != req.get("purpose"): return False
    if "scope" in cap and isinstance(cap["scope"],dict):
        if "cohort" in cap["scope"]:
            if req.get("cohort") not in cap["scope"]["cohort"]: return False
    if "flags" in cap and isinstance(cap["flags"],dict):
        for k,v in cap["flags"].items():
            if req.get(k) != v: return False
    return True

# ---------- models ----------
class MintReq(BaseModel):
    holder_pub_b64: str = Field(..., description="Ed25519 public key, base64url (from gen_member_keys.py)")
    cap_profiles: List[str] = Field(..., description="cap profile ids to grant (must exist in policy.cap_profiles)")
    nbf: str
    exp: str

class MintResp(BaseModel):
    ect_jws: str
    policy_hash: str
    alg: str
    kid: str

class ProbeReq(BaseModel):
    resource: str
    action: str
    purpose: Optional[str] = None
    cohort: Optional[str] = None
    agg: Optional[str] = None
    pii: Optional[bool] = None
    contact: Optional[bool] = None
    jti: Optional[str] = None  # echoed in DPoP signed content

class ProbeResp(BaseModel):
    allow: bool
    reason: Optional[str] = None

# ---------- app ----------
app = FastAPI(title="Issuer + Probe (ECT + DPoP, Ed25519 holder)")

_policy = load_policy()
_policy_hash = compute_policy_hash(_policy)
_org_priv_pem, _org_pub, _alg = load_org_key_and_alg()
_aud = _policy.get("caveats",{}).get("audience", AUD_FALLBACK)
print("_aud: ",_aud)

@app.get("/health")
def health():
    return {
        "ok": True,
        "policy_path": str(POLICY_PATH),
        "policy_hash": _policy_hash,
        "alg": _alg,
        "iss": ISS,
        "aud": _aud,
    }

@app.post("/mint_ect", response_model=MintResp)
def mint_ect(req: MintReq):
    caps = pick_caps(_policy, req.cap_profiles)
    if not caps:
        raise HTTPException(400, "selected profiles produce empty capability set")
    jkt = rfc7638_thumbprint_okp_ed25519(req.holder_pub_b64)

    payload = {
        "iss": ISS,
        "aud": _aud,
        "iat": now_epoch(),
        "nbf": iso_to_epoch(req.nbf),
        "exp": iso_to_epoch(req.exp),
        "policy": {
            "policy_id": _policy["meta"]["policy_id"],
            "manifest_id": _policy["meta"]["manifest_id"],
            "policy_hash": _policy_hash
        },
        "cnf": { "jkt": jkt },
        "cap": caps
    }
    headers = {"alg": _alg, "kid": ORG_KEY_KID, "typ":"JWT"}
    ect_jws = jwt.encode(payload, _org_priv_pem, algorithm=_alg, headers=headers)
    return MintResp(ect_jws=ect_jws, policy_hash=_policy_hash, alg=_alg, kid=ORG_KEY_KID)

@app.post("/probe", response_model=ProbeResp)
def probe(
    request: Request,
    body: ProbeReq,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    dpop_header: Optional[str] = Header(None, alias="DPoP"),
    dpop_nonce: Optional[str] = Header(None, alias="X-DPoP-Nonce"),
):

    
    # 1) ECT
    if not authorization or not authorization.startswith("ECT "):
        return ProbeResp(allow=False, reason="missing_ect")
    ect_jws = authorization.split(" ",1)[1].strip()
    try:
        ect = jwt.decode(ect_jws, _org_pub, algorithms=["ES256","ES384","ES512","RS256"], 
                         options={"require":["iss","nbf","exp","policy","cnf","cap"],
                                  "verify_aud": False})
    except Exception as e:
        return ProbeResp(allow=False, reason=f"ect_sig_or_claims:{e}")
    
    if ect.get("iss") != ISS: return ProbeResp(allow=False, reason="iss_mismatch")
    if ect.get("aud") != _aud: return ProbeResp(allow=False, reason="aud_mismatch")

    now = now_epoch()
    if not (ect["nbf"] <= now <= ect["exp"]): return ProbeResp(allow=False, reason="ect_time_window")
    if POLICY_ALLOWLIST and ect["policy"].get("policy_hash") not in POLICY_ALLOWLIST:
        return ProbeResp(allow=False, reason="policy_hash_not_allowed")
    
    # 2) DPoP (custom Ed25519 object from make_dpop.py)
    if not dpop_header:
        return ProbeResp(allow=False, reason="missing_dpop")
    if body.jti is None:
        return ProbeResp(allow=False, reason="missing_jti")

    try:
        parts = dpop_header.split(".")
        if len(parts) != 3:
            return ProbeResp(allow=False, reason="dpop_format:not_jws_compact")

        def b64u_decode(s: str) -> bytes:
            pad = "=" * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s + pad)

        hdr = json.loads(b64u_decode(parts[0]).decode("utf-8"))
        pl  = json.loads(b64u_decode(parts[1]).decode("utf-8"))
        sig = b64u_decode(parts[2])

        if hdr.get("typ") != "dpop+jwt":
            return ProbeResp(allow=False, reason="dpop_typ")
        if hdr.get("alg") != "EdDSA":
            return ProbeResp(allow=False, reason="dpop_alg")

        jwk = hdr.get("jwk") or {}
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
            return ProbeResp(allow=False, reason="dpop_jwk")

        # Verify signature (Ed25519 over ASCII "b64(header).b64(payload)")
        from nacl import signing
        vk = signing.VerifyKey(b64u_decode(jwk["x"]))
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        vk.verify(signing_input, sig)

    except Exception as e:
        return ProbeResp(allow=False, reason=f"dpop_verify:{e}")

    # Enforce htm/htu/nonce/jti
    try:
        htm = str(pl.get("htm","")).upper()
        htu = str(pl.get("htu",""))
        jti = str(pl.get("jti",""))
        nonce_claim = str(pl.get("nonce",""))

        if htm != request.method.upper():
            return ProbeResp(allow=False, reason="dpop_htm_mismatch")

        # Canonical htu = full URL without query string
        req_htu = str(request.url).split("?", 1)[0]
        if htu != req_htu:
            return ProbeResp(allow=False, reason="dpop_htu_mismatch")

        if jti != body.jti:
            return ProbeResp(allow=False, reason="dpop_jti_mismatch")

        # Optional nonce binding (if you send it; empty allowed)
        if (dpop_nonce or "") != nonce_claim:
            return ProbeResp(allow=False, reason="dpop_nonce_mismatch")

    except Exception as e:
        return ProbeResp(allow=False, reason=f"dpop_claims:{e}")

    # Bind DPoP key to ECT.cnf.jkt (RFC7638 thumbprint of OKP(Ed25519) JWK)
    if ect.get("cnf",{}).get("jkt") != rfc7638_thumbprint_okp_ed25519(jwk["x"]):
        return ProbeResp(allow=False, reason="dpop_binding_mismatch")
      
    # 3) Tuple match
    req_tuple = {
        "resource": body.resource,
        "action": body.action,
        "purpose": body.purpose,
        "cohort": body.cohort,
        "agg": body.agg,
        "pii": body.pii,
        "contact": body.contact,
    }
    for cap in ect.get("cap", []):
        if cap_matches_request(cap, req_tuple):
            return ProbeResp(allow=True)
    return ProbeResp(allow=False, reason="capability_violation")


# ---------- runner ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("issuer_lite_eddsa:app", host="127.0.0.1", port=9100, reload=False)


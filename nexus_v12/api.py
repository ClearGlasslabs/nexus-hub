"""Optional FastAPI gateway enforcing network, token, and rate-limit controls.

The application intentionally has no default search provider. Operators must
inject an approved provider and configure OIDC/JWKS, trusted IPs, and storage
outside the repository. No secrets belong in source control.
"""
from __future__ import annotations

import ipaddress
import os
import time
from collections import defaultdict, deque

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .policy import AuthorizationLevel, QueryAuthorization
from .service import NexusV12

app = FastAPI(title="Nexus V12", version="12.0.0", docs_url=None, redoc_url=None)
bearer = HTTPBearer(auto_error=True)
_windows: dict[str, deque[float]] = defaultdict(deque)


def _allowed_ip(host: str) -> bool:
    configured = [x.strip() for x in os.getenv("NEXUS_TRUSTED_CIDRS", "").split(",") if x.strip()]
    if not configured:
        return False
    address = ipaddress.ip_address(host)
    return any(address in ipaddress.ip_network(c, strict=False) for c in configured)


def _rate_limit(identity: str) -> None:
    now = time.monotonic()
    q = _windows[identity]
    while q and now - q[0] > 60:
        q.popleft()
    limit = int(os.getenv("NEXUS_RATE_LIMIT_PER_MINUTE", "30"))
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    q.append(now)


def require_token(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """Fail closed; production deployments should validate JWTs with an OIDC JWKS verifier."""
    client = request.client.host if request.client else ""
    if not _allowed_ip(client):
        raise HTTPException(status_code=403, detail="source network is not allowlisted")
    if credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=401, detail="bearer token required")
    # Token verification belongs at the deployment boundary or an injected
    # OIDC middleware. Never accept a caller-supplied user id as authentication.
    identity = os.getenv("NEXUS_AUTH_VERIFIED_SUB")
    if not identity:
        raise HTTPException(status_code=503, detail="OIDC verifier is not configured")
    _rate_limit(identity)
    return identity


# Provider wiring is deliberately explicit. A deployment must set this before
# enabling the endpoint; an empty provider list is safe but non-functional.
engine = NexusV12(providers=[])


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "module": "nexus-v12"}


@app.post("/v1/reverse-image")
async def reverse_image(
    request: Request,
    image: UploadFile = File(...),
    user_id: str = Depends(require_token),
) -> dict:
    purpose = request.headers.get("x-purpose-code", "")
    legal_basis = request.headers.get("x-legal-basis", "")
    consent = request.headers.get("x-consent-confirmed", "false").lower() == "true"
    authorization = QueryAuthorization(
        user_id=user_id,
        level=AuthorizationLevel.L2,
        purpose_code=purpose,
        legal_basis=legal_basis,
        consent_confirmed=consent,
    )
    raw = await image.read()
    report = engine.search(raw, authorization)
    return {
        "query_hash": report.query_hash,
        "timestamp": report.timestamp,
        "purpose_code": report.purpose_code,
        "matches": [m.__dict__ for m in report.matches],
        "risk": report.risk,
        "retention_expiry": report.retention_expiry,
        "audit_event_hash": report.audit_event_hash,
    }

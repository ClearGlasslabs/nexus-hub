"""Production-oriented FastAPI gateway for Nexus V12."""
from __future__ import annotations

import ipaddress
import os

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .audit_store import PostgresAuditStore
from .oidc import OIDCVerifier
from .policy import AuthorizationLevel, QueryAuthorization
from .provider_http import VettedHttpProvider
from .rate_limit import AnomalyLimiter
from .service import NexusV12

app = FastAPI(title="Nexus V12", version="12.1.0", docs_url=None, redoc_url=None)
bearer = HTTPBearer(auto_error=True)
verifier = OIDCVerifier()
limiter = AnomalyLimiter()


def _providers() -> list[VettedHttpProvider]:
    if os.getenv("NEXUS_PROVIDER_URL"):
        try:
            return [VettedHttpProvider()]
        except ValueError as exc:
            raise RuntimeError("configured provider failed security validation") from exc
    return []


def _allowed_ip(host: str) -> bool:
    configured = [x.strip() for x in os.getenv("NEXUS_TRUSTED_CIDRS", "").split(",") if x.strip()]
    if not configured:
        return False
    try:
        address = ipaddress.ip_address(host)
        return any(address in ipaddress.ip_network(c, strict=False) for c in configured)
    except ValueError:
        return False


def require_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> str:
    client = request.client.host if request.client else ""
    if not _allowed_ip(client):
        raise HTTPException(status_code=403, detail="source network is not allowlisted")
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="bearer token required")
    try:
        identity = verifier.verify(credentials.credentials)
        limiter.check(identity.subject)
        return identity.subject
    except PermissionError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=401, detail="invalid access token") from exc


def _audit_store() -> PostgresAuditStore:
    try:
        return PostgresAuditStore()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="durable audit store is not configured") from exc


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "module": "nexus-v12", "mode": "fail-closed"}


@app.post("/v1/reverse-image")
async def reverse_image(
    request: Request,
    image: UploadFile = File(...),
    user_id: str = Depends(require_identity),
) -> dict:
    max_bytes = int(os.getenv("NEXUS_MAX_IMAGE_BYTES", "10485760"))
    raw = await image.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise HTTPException(status_code=413, detail="image exceeds configured byte limit")

    purpose = request.headers.get("x-purpose-code", "")
    legal_basis = request.headers.get("x-legal-basis", "")
    consent = request.headers.get("x-consent-confirmed", "false").lower() == "true"
    law_doc = request.headers.get("x-law-enforcement-documented", "false").lower() == "true"
    authorization = QueryAuthorization(
        user_id=user_id,
        level=AuthorizationLevel.L2,
        purpose_code=purpose,
        legal_basis=legal_basis,
        consent_confirmed=consent,
        law_enforcement_documented=law_doc,
    )
    try:
        engine = NexusV12(providers=_providers())
        report = engine.search(raw, authorization)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    _audit_store().append(report.audit_event, report.audit_event_hash)
    return {
        "query_hash": report.query_hash,
        "timestamp": report.timestamp,
        "purpose_code": report.purpose_code,
        "matches": [m.__dict__ for m in report.matches],
        "risk": report.risk,
        "retention_expiry": report.retention_expiry,
        "audit_event_hash": report.audit_event_hash,
    }

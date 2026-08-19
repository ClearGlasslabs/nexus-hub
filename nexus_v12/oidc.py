"""OIDC/JWT verification boundary.

Production requires issuer, audience and JWKS configuration. Tokens are never
logged or persisted. The verifier fails closed when configuration is missing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient


@dataclass(frozen=True)
class Identity:
    subject: str
    claims: dict[str, Any]


class OIDCVerifier:
    def __init__(self) -> None:
        self.issuer = os.getenv("NEXUS_OIDC_ISSUER", "").rstrip("/")
        self.audience = os.getenv("NEXUS_OIDC_AUDIENCE", "")
        self.jwks_url = os.getenv("NEXUS_OIDC_JWKS_URL", "")
        self._jwks = PyJWKClient(self.jwks_url) if self.jwks_url else None

    def verify(self, token: str) -> Identity:
        if not token or not self.issuer or not self.audience or not self._jwks:
            raise ValueError("OIDC verifier is not fully configured")
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        subject = str(claims["sub"]).strip()
        if not subject:
            raise ValueError("OIDC subject is empty")
        return Identity(subject=subject, claims=claims)

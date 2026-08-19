"""Fail-closed authorization and privacy policy for Nexus V12."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import re


class AuthorizationLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4

AUTHORIZED_PURPOSES = {
    "fraud",
    "brand",
    "consent_identity_verification",
    "security",
    "missing_persons_law_enforcement",
}

PROHIBITED_PURPOSES = {
    "stalking", "harassment", "doxxing", "unauthorized_surveillance",
    "employment_screening", "dating", "social_engineering", "mass_profiling",
}


@dataclass(frozen=True)
class QueryAuthorization:
    user_id: str
    level: AuthorizationLevel
    purpose_code: str
    legal_basis: str
    consent_confirmed: bool = False
    law_enforcement_documented: bool = False


def validate_authorization(auth: QueryAuthorization) -> None:
    if not auth.user_id.strip():
        raise ValueError("user_id is required")
    if auth.level < AuthorizationLevel.L1:
        raise PermissionError("L0 accounts cannot execute image searches")
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", auth.purpose_code):
        raise ValueError("purpose_code must be a stable lowercase audit identifier")
    purpose_family = auth.purpose_code.split("_")[0]
    if auth.purpose_code in PROHIBITED_PURPOSES or purpose_family in PROHIBITED_PURPOSES:
        raise PermissionError("purpose is prohibited")
    if purpose_family not in AUTHORIZED_PURPOSES and auth.purpose_code not in AUTHORIZED_PURPOSES:
        raise PermissionError("purpose is not on the authorized allowlist")
    if not auth.legal_basis.strip():
        raise PermissionError("documented legal basis is required")
    if auth.purpose_code == "consent_identity_verification" and not auth.consent_confirmed:
        raise PermissionError("explicit consent is required for identity verification")
    if auth.purpose_code == "missing_persons_law_enforcement" and not auth.law_enforcement_documented:
        raise PermissionError("valid legal documentation is required")


def retention_expiry(now_epoch: int, authorized_days: int | None = None) -> int:
    days = 7 if authorized_days is None else authorized_days
    if days < 1 or days > 7:
        raise ValueError("retention must be between 1 and 7 days")
    return now_epoch + days * 86_400

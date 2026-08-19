import pytest

from nexus_v12.policy import AuthorizationLevel, QueryAuthorization, retention_expiry, validate_authorization


def auth(purpose: str = "fraud_investigation_2026_08_19") -> QueryAuthorization:
    return QueryAuthorization("test-user", AuthorizationLevel.L2, purpose, "documented-security-purpose")


def test_authorized_purpose_family_is_accepted():
    validate_authorization(auth())


def test_prohibited_purpose_is_rejected():
    with pytest.raises(PermissionError):
        validate_authorization(auth("stalking"))


def test_identity_verification_requires_consent():
    with pytest.raises(PermissionError):
        validate_authorization(auth("consent_identity_verification"))


def test_retention_cannot_exceed_seven_days():
    with pytest.raises(ValueError):
        retention_expiry(0, 8)

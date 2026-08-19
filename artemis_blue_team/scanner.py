"""Fail-closed, privacy-minimized image information protection scanner.

The scanner is deliberately local-only. It accepts optional OCR text supplied by
an approved local OCR engine, but never performs external enrichment or identity
inference. Suspected secret values are never returned.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import math
import re
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

try:  # Optional dependency; metadata inspection remains safe if absent.
    from PIL import Image, ExifTags
except ImportError:  # pragma: no cover
    Image = None
    ExifTags = {}


RETENTION_REPORT_DAYS = 30
MAX_TEMP_RETENTION_HOURS = 24
MAX_ORIGINAL_RETENTION_DAYS = 7

_SECRET_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.I)),
    ("CONNECTION_STRING", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+", re.I)),
    ("WEBHOOK_URL", re.compile(r"https://(?:hooks\.|discord(?:app)?\.com/api/webhooks/)[^\s]+", re.I)),
]

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\b(?:port|tcp|udp)\s*[:=]?\s*(\d{1,5})\b", re.I)
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
_HASH_RE = re.compile(r"\b[a-f0-9]{32,128}\b", re.I)
_VULN_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z-]{8,})\b", re.I)
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_./+=:-]{24,}\b")
_PERSONAL_LABEL_RE = re.compile(r"\b(?:driver.?license|passport|medical record|patient|employee id|customer id|social security|SIN|DOB|date of birth)\b", re.I)
_FACE_LABEL_RE = re.compile(r"\b(?:face|facial|portrait|selfie|headshot)\b", re.I)
_QR_LABEL_RE = re.compile(r"\b(?:QR code|barcode|UPC|EAN)\b", re.I)


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _safe_region(region: str = "embedded text") -> str:
    return region[:80]


def _finding(category: str, severity: str, observation: str, reason: str, action: str, region: str = "embedded text") -> dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "location": _safe_region(region),
        "observation": observation,
        "exposure_reason": reason,
        "recommended_action": action,
        "redaction_required": severity in {"MEDIUM", "HIGH", "CRITICAL"},
    }


@dataclass(frozen=True)
class ScanRequest:
    declared_purpose: str
    authorization_status: str
    requesting_user: str = "minimized"
    authorization_level: str = "L0"


class ArtemisScanner:
    """Perform deterministic defensive inspection without identity inference."""

    def __init__(self, report_retention_days: int = RETENTION_REPORT_DAYS) -> None:
        if not 1 <= report_retention_days <= 30:
            raise ValueError("report retention must be between 1 and 30 days")
        self.report_retention_days = report_retention_days

    def scan(self, image_bytes: bytes, request: ScanRequest, *, ocr_text: str = "", visual_labels: Iterable[str] = ()) -> dict[str, Any]:
        if not isinstance(image_bytes, (bytes, bytearray)) or not image_bytes:
            raise ValueError("image bytes are required")
        timestamp = _utc()
        input_sha = _sha256(bytes(image_bytes))
        audit_id = "artemis-" + secrets.token_hex(16)
        findings: list[dict[str, Any]] = []
        metadata_findings = self._metadata_findings(bytes(image_bytes))
        findings.extend(self._scan_text(ocr_text))
        findings.extend(self._scan_labels(visual_labels))
        findings.extend(self._binary_indicators(bytes(image_bytes)))

        # Authorization is a gate, never an inference. No external processing occurs here.
        auth = request.authorization_status if request.authorization_status in {"AUTHORIZED", "UNCLEAR", "REJECTED"} else "UNCLEAR"
        if auth != "AUTHORIZED":
            findings.append(_finding(
                "BUSINESS_CONFIDENTIAL", "HIGH",
                "Authorization is not established; analysis remains local-only.",
                "Sensitive visual processing without an established purpose and authorization can create privacy and governance risk.",
                "Obtain documented authorization before any sharing, enrichment, or external processing.",
                "request metadata",
            ))

        risk = self._risk(findings)
        classification = self._classification(risk, auth)
        return {
            "mission_id": audit_id,
            "timestamp": timestamp,
            "input_sha256": input_sha,
            "declared_purpose": request.declared_purpose,
            "authorization_status": auth,
            "classification": classification,
            "risk_level": risk,
            "findings": findings,
            "metadata_findings": metadata_findings,
            "publication_actions": self._actions(classification, findings),
            "human_review_required": risk in {"HIGH", "CRITICAL"},
            "secret_rotation_required": any(f["category"] == "SECRET" and f["severity"] == "CRITICAL" for f in findings),
            "retention": {
                "original_image": "DELETE_AFTER_PROCESSING",
                "temporary_derivatives": "DELETE_AFTER_PROCESSING",
                "report_retention_days": self.report_retention_days,
            },
            "audit": {
                "audit_id": audit_id,
                "stored_data": "HASH_AND_MINIMIZED_REPORT_ONLY",
            },
        }

    def _scan_text(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        results: list[dict[str, Any]] = []
        for kind, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                results.append(_finding("SECRET", "CRITICAL", f"Suspected {kind} detected; value suppressed.", "Credentials or active authorization material may enable unauthorized access.", "Block publication and rotate/revoke through the approved security process."))
        if _PERSONAL_LABEL_RE.search(text):
            results.append(_finding("PII", "HIGH", "Sensitive personal-data label detected; values suppressed.", "Regulated or identifying information can cause privacy harm if published.", "Mask or remove the affected region and review the applicable privacy basis."))
        if _FACE_LABEL_RE.search(text):
            results.append(_finding("BIOMETRIC", "HIGH", "Face-related visual/text indicator detected; no identity inference performed.", "Facial imagery can create biometric/privacy risk.", "Mask or crop faces before public release."))
        if _QR_LABEL_RE.search(text):
            results.append(_finding("SECRET", "HIGH", "QR/barcode indicator detected; contents not decoded.", "Codes can contain credentials, links, identifiers, or operational data.", "Remove or fully mask the code unless decoding is explicitly authorized."))
        if _VULN_RE.search(text):
            results.append(_finding("VULNERABILITY", "HIGH", "Vulnerability identifier detected; no endpoint validation performed.", "Vulnerability context combined with identifiable assets can increase operational risk.", "Remove asset relationships and sensitive vulnerability context before publication."))
        for match in _IPV4_RE.finditer(text):
            try:
                ip = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local):
                severity = "MEDIUM"
            else:
                severity = "HIGH"
            results.append(_finding("INFRASTRUCTURE", severity, "IP address detected; exact value suppressed.", "Network addressing can expose infrastructure or security topology.", "Remove or replace with a generic asset label before public release."))
        if _EMAIL_RE.search(text):
            results.append(_finding("PII", "MEDIUM", "Email address detected; exact value suppressed.", "Contact information can facilitate targeting or privacy harm.", "Mask or remove unless publication is explicitly authorized."))
        if _URL_RE.search(text):
            results.append(_finding("INFRASTRUCTURE", "MEDIUM", "URL detected; exact URL suppressed.", "Internal paths or service endpoints can expose operational details.", "Review host/path and remove internal or sensitive URLs."))
        if _PORT_RE.search(text):
            results.append(_finding("INFRASTRUCTURE", "MEDIUM", "Network port reference detected; exact value suppressed.", "Ports can reveal service exposure and architecture.", "Remove port information from public imagery."))
        if _UUID_RE.search(text) or _HASH_RE.search(text):
            results.append(_finding("INFRASTRUCTURE", "LOW", "Identifier/hash-like value detected; exact value suppressed.", "Identifiers may become sensitive when correlated with internal systems.", "Remove if not already public and operationally necessary."))
        for candidate in _HIGH_ENTROPY_RE.findall(text):
            if len(candidate) >= 24 and _entropy(candidate) >= 4.0 and not _URL_RE.fullmatch(candidate):
                results.append(_finding("SECRET", "HIGH", "High-entropy string may be credential material; value suppressed.", "Unstructured high-entropy strings can represent secrets or session material.", "Treat as potentially secret, block public release, and validate/rotate through the approved process."))
                break
        return results

    def _scan_labels(self, labels: Iterable[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        normalized = {str(x).strip().lower() for x in labels}
        if normalized & {"face", "faces", "person", "portrait"}:
            results.append(_finding("BIOMETRIC", "HIGH", "Face detected; identity inference was not performed.", "Facial imagery can create biometric/privacy exposure.", "Mask or crop the face before public release.", "visual region"))
        if normalized & {"driver_license", "passport", "identity_document", "health_record"}:
            results.append(_finding("PII", "HIGH", "Sensitive document detected; values suppressed.", "Identity or regulated records can cause privacy harm.", "Fully mask/crop the document and require human review.", "visual region"))
        if normalized & {"qr", "qr_code", "barcode"}:
            results.append(_finding("SECRET", "HIGH", "QR/barcode detected; contents were not decoded.", "Codes can contain secrets or operational links.", "Remove or fully mask the code unless explicitly authorized.", "visual region"))
        if normalized & {"license_plate", "plate"}:
            results.append(_finding("PII", "HIGH", "License plate detected; value suppressed.", "Vehicle identifiers can contribute to tracking/privacy harm.", "Mask the plate before public release.", "visual region"))
        return results

    def _binary_indicators(self, data: bytes) -> list[dict[str, Any]]:
        # Never decode QR/barcodes from raw binary. This check only identifies a conservative
        # possibility from common file signatures; a dedicated authorized detector can add labels.
        if b"-----BEGIN " in data:
            return [_finding("SECRET", "CRITICAL", "Private-key marker detected in image payload; value suppressed.", "Embedded key material could enable unauthorized access.", "Quarantine, rotate/revoke, and preserve evidence only under approved incident response.", "image payload")]
        return []

    def _metadata_findings(self, data: bytes) -> list[dict[str, str]]:
        if Image is None:
            return [{"field": "EXIF", "risk": "Metadata inspection dependency unavailable; metadata status is uncertain.", "action": "REMOVE"}]
        try:
            with Image.open(io.BytesIO(data)) as image:
                exif = image.getexif()
                if not exif:
                    return []
                risky = []
                for key, value in exif.items():
                    name = ExifTags.TAGS.get(key, str(key))
                    if name in {"GPSInfo", "Make", "Model", "DateTime", "DateTimeOriginal", "Artist", "Software", "Copyright"}:
                        risky.append({"field": name, "risk": "May disclose location, device, timestamp, author, or software information.", "action": "REMOVE"})
                return risky or [{"field": "EXIF", "risk": "Embedded metadata exists and should be minimized.", "action": "REMOVE"}]
        except Exception:
            return [{"field": "EXIF", "risk": "Metadata could not be reliably inspected.", "action": "REMOVE"}]

    @staticmethod
    def _risk(findings: list[dict[str, Any]]) -> str:
        levels = {f["severity"] for f in findings}
        if "CRITICAL" in levels:
            return "CRITICAL"
        if "HIGH" in levels:
            return "HIGH"
        if "MEDIUM" in levels:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _classification(risk: str, authorization: str) -> str:
        if risk == "CRITICAL":
            return "DO_NOT_SHARE"
        if risk == "HIGH":
            return "INTERNAL_ONLY"
        if risk == "MEDIUM":
            return "SHARE_AFTER_REDACTION"
        if authorization != "AUTHORIZED":
            return "INTERNAL_ONLY"
        return "SAFE_TO_SHARE"

    @staticmethod
    def _actions(classification: str, findings: list[dict[str, Any]]) -> list[str]:
        actions: list[str] = ["Remove EXIF metadata before publication."]
        if classification == "DO_NOT_SHARE":
            actions.insert(0, "Block publication and quarantine the derivative under approved incident-response controls.")
        elif classification == "INTERNAL_ONLY":
            actions.insert(0, "Do not publish externally; require authorized human review.")
        elif classification == "SHARE_AFTER_REDACTION":
            actions.insert(0, "Apply the smallest effective redactions and re-scan the rendered output before release.")
        else:
            actions.insert(0, "No sensitive finding exceeded the configured publication threshold; retain only the minimized report.")
        if any(f["category"] == "SECRET" for f in findings):
            actions.append("Never reproduce suspected secret values; rotate/revoke confirmed credentials through the approved process.")
        if any(f["category"] == "BIOMETRIC" for f in findings):
            actions.append("Do not perform facial identification or identity inference; mask/crop faces where publication is not authorized.")
        return actions


def json_report(report: dict[str, Any]) -> str:
    """Serialize a report as deterministic JSON without exposing suppressed values."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

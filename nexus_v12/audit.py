"""Tamper-evident, PII-minimized audit records."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import time


@dataclass(frozen=True)
class AuditEvent:
    timestamp: int
    user_id_hash: str
    purpose_code: str
    query_hash: str
    sources: tuple[str, ...]
    retention_expiry: int
    action: str


class AuditChain:
    """Append-only hash chain; store events in an authenticated private sink."""

    def __init__(self) -> None:
        self._previous = "0" * 64

    def append(self, event: AuditEvent) -> str:
        payload = json.dumps(asdict(event), sort_keys=True, separators=(",", ":"))
        entry = f"{self._previous}:{payload}".encode()
        current = hashlib.sha256(entry).hexdigest()
        self._previous = current
        return current


def new_event(*, user_id: str, purpose_code: str, query_hash: str,
              sources: tuple[str, ...], retention_expiry: int,
              action: str = "search") -> AuditEvent:
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return AuditEvent(
        timestamp=int(time.time()),
        user_id_hash=user_id_hash,
        purpose_code=purpose_code,
        query_hash=query_hash,
        sources=tuple(sorted(sources)),
        retention_expiry=retention_expiry,
        action=action,
    )

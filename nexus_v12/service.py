"""Provider-agnostic reverse-image-search orchestration.

External providers are deliberately injected. This module does not scrape,
query breached datasets, perform HLR/email tracking, or identify a person.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
import time

from .audit import AuditChain, new_event
from .crypto import query_digest, sanitize_image
from .policy import QueryAuthorization, retention_expiry, validate_authorization


@dataclass(frozen=True)
class Match:
    url: str
    confidence: float
    source: str


class SearchProvider(Protocol):
    name: str

    def search(self, image_bytes: bytes, limit: int) -> list[Match]: ...


@dataclass(frozen=True)
class SearchReport:
    query_hash: str
    timestamp: int
    purpose_code: str
    matches: tuple[Match, ...]
    risk: str
    retention_expiry: int
    audit_event_hash: str


class NexusV12:
    def __init__(self, providers: list[SearchProvider], audit: AuditChain | None = None) -> None:
        self.providers = providers
        self.audit = audit or AuditChain()

    def search(self, raw_image: bytes, auth: QueryAuthorization, *, limit: int = 10) -> SearchReport:
        validate_authorization(auth)
        if not 1 <= limit <= 50:
            raise ValueError("limit must be 1..50")

        sanitized = sanitize_image(raw_image)
        query_hash, salt = query_digest(sanitized)
        expiry = retention_expiry(int(time.time()))
        matches: list[Match] = []
        source_names: list[str] = []
        try:
            for provider in self.providers:
                source_names.append(provider.name)
                matches.extend(provider.search(sanitized, limit))
            matches = [m for m in matches if 0.0 <= m.confidence <= 1.0]
            matches.sort(key=lambda m: m.confidence, reverse=True)
            matches = matches[:limit]
            risk = self._risk(matches, auth)
            event = new_event(
                user_id=auth.user_id,
                purpose_code=auth.purpose_code,
                query_hash=query_hash,
                sources=tuple(source_names),
                retention_expiry=expiry,
            )
            event_hash = self.audit.append(event)
            return SearchReport(query_hash, event.timestamp, auth.purpose_code,
                                tuple(matches), risk, expiry, event_hash)
        finally:
            # Salt is query-scoped and never returned or persisted.
            del salt
            del sanitized

    @staticmethod
    def _risk(matches: list[Match], auth: QueryAuthorization) -> str:
        if not matches:
            return "LOW"
        top = matches[0].confidence
        if auth.level < 2 or top < 0.70:
            return "MEDIUM"
        if top >= 0.90 and len(matches) > 1:
            return "HIGH"
        return "MEDIUM"

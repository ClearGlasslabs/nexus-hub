"""Durable audit storage abstraction.

PostgreSQL is the production target. The SQL schema uses a trigger to prevent
UPDATE/DELETE on audit rows. The application only appends events.
"""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Iterable

from .audit import AuditEvent


class AuditStore:
    def append(self, event: AuditEvent, event_hash: str) -> None:
        raise NotImplementedError

    def purge_expired(self, now: int | None = None) -> int:
        raise NotImplementedError


class PostgresAuditStore(AuditStore):
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv("NEXUS_AUDIT_DATABASE_URL", "")
        if not self.dsn:
            raise RuntimeError("NEXUS_AUDIT_DATABASE_URL is required")

    def append(self, event: AuditEvent, event_hash: str) -> None:
        import psycopg
        payload = asdict(event)
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO nexus_audit_events
                    (event_hash, event_timestamp, user_id_hash, purpose_code,
                     query_hash, sources, retention_expiry, action)
                    VALUES (%s,to_timestamp(%s),%s,%s,%s,%s,%s,%s)""",
                    (event_hash, event.timestamp, payload["user_id_hash"],
                     event.purpose_code, event.query_hash, list(event.sources),
                     datetime.fromtimestamp(event.retention_expiry, timezone.utc),
                     event.action),
                )
            conn.commit()

    def purge_expired(self, now: int | None = None) -> int:
        import psycopg
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM nexus_query_objects WHERE expires_at <= now()"
                )
                count = cur.rowcount
            conn.commit()
        return count

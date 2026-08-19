CREATE TABLE IF NOT EXISTS nexus_audit_events (
  id BIGSERIAL PRIMARY KEY,
  event_hash CHAR(64) NOT NULL UNIQUE,
  event_timestamp TIMESTAMPTZ NOT NULL,
  user_id_hash CHAR(64) NOT NULL,
  purpose_code VARCHAR(64) NOT NULL,
  query_hash CHAR(64) NOT NULL,
  sources TEXT[] NOT NULL,
  retention_expiry TIMESTAMPTZ NOT NULL,
  action VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS nexus_query_objects (
  query_hash CHAR(64) PRIMARY KEY,
  object_key TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

REVOKE UPDATE, DELETE, TRUNCATE ON nexus_audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON nexus_query_objects FROM PUBLIC;

CREATE OR REPLACE FUNCTION nexus_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Nexus audit events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS nexus_audit_no_update_delete ON nexus_audit_events;
CREATE TRIGGER nexus_audit_no_update_delete
BEFORE UPDATE OR DELETE ON nexus_audit_events
FOR EACH ROW EXECUTE FUNCTION nexus_audit_immutable();

-- Cleanup runs with a dedicated role granted DELETE on nexus_query_objects only.
-- The audit table remains immutable for every application role.

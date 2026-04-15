-- migrations/072_create_source_artifacts.sql
-- Create the source_artifacts table referenced by the validate_edge_reference
-- trigger (migration 066_widen_edges_for_artifacts.sql).
--
-- Evidence: migration 066 widened the edge entity type CHECK constraint to
-- include 'source_artifact' and updated the referential integrity trigger to
-- validate against source_artifacts, but never created the table, causing
-- "relation source_artifacts does not exist" at edge insertion time.
--
-- Reasoning: The table must exist before any code path can call
-- validate_edge_reference() with entity_type = 'source_artifact', because
-- PL/pgSQL parses the entire CASE expression body at first-call time.

CREATE TABLE IF NOT EXISTS source_artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    artifact_type TEXT NOT NULL DEFAULT 'generic',
    source_url  TEXT,
    content_hash BYTEA,
    properties  JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS source_artifacts_agent_id_idx
    ON source_artifacts (agent_id);

-- migrations/060_prov_o_agent_typing.sql
-- PROV-O First-Class Persons & Agent Typing
-- Spec: docs/superpowers/specs/2026-03-21-prov-o-persons-design.md

-- ── 1. Agents table: promoted identifier columns ──

ALTER TABLE agents ADD COLUMN IF NOT EXISTS orcid VARCHAR(19) UNIQUE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS ror_id VARCHAR(9) UNIQUE;

-- ORCID format: 0000-0000-0000-000X (ISO 7064 Mod 11,2)
ALTER TABLE agents ADD CONSTRAINT orcid_format
    CHECK (orcid IS NULL OR orcid ~ '^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$');

-- ROR format: 9-char compact identifier (e.g., 0abcdef12)
ALTER TABLE agents ADD CONSTRAINT ror_format
    CHECK (ror_id IS NULL OR ror_id ~ '^0[a-z0-9]{6}\d{2}$');

-- ── 2. Edges table: temporal validity columns ──

ALTER TABLE edges ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ;
ALTER TABLE edges ADD COLUMN IF NOT EXISTS valid_to TIMESTAMPTZ;

ALTER TABLE edges ADD CONSTRAINT temporal_ordering
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from);

CREATE INDEX IF NOT EXISTS idx_edges_temporal ON edges (valid_from, valid_to)
    WHERE valid_from IS NOT NULL;

-- ── 3. Backfill: label human authors as 'person' ──

UPDATE agents
SET labels = array_append(labels, 'person')
WHERE properties->>'type' = 'human_author'
  AND NOT ('person' = ANY(labels));

-- Label remaining agents as 'software_agent'
UPDATE agents
SET labels = array_append(labels, 'software_agent')
WHERE NOT ('person' = ANY(labels))
  AND NOT ('software_agent' = ANY(labels))
  AND NOT ('organization' = ANY(labels))
  AND NOT ('instrument' = ANY(labels));

-- ── 4. Backfill: promote ORCID from JSONB to structured column ──

UPDATE agents
SET orcid = properties->>'orcid'
WHERE properties->>'orcid' IS NOT NULL
  AND orcid IS NULL
  AND properties->>'orcid' ~ '^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$';

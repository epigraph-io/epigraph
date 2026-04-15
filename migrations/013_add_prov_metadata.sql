-- Migration 013: PROV-O metadata and Activities table
--
-- Adds W3C PROV-O vocabulary mapping to edges and introduces
-- an Activities table for tracking ingestion/extraction/reasoning runs.

-- 1. Add prov_type column to edges for PROV-O vocabulary mapping
ALTER TABLE edges ADD COLUMN IF NOT EXISTS prov_type VARCHAR(100);

-- Backfill existing edges with PROV-O types based on relationship + entity types
UPDATE edges SET prov_type = 'prov:wasAttributedTo'
  WHERE relationship = 'authored_by' AND prov_type IS NULL;

UPDATE edges SET prov_type = 'prov:wasGeneratedBy'
  WHERE relationship = 'derived_from' AND prov_type IS NULL;

UPDATE edges SET prov_type = 'prov:used'
  WHERE relationship = 'uses_evidence' AND prov_type IS NULL;

UPDATE edges SET prov_type = 'prov:wasDerivedFrom'
  WHERE relationship = 'supports' AND source_type = 'evidence' AND prov_type IS NULL;

UPDATE edges SET prov_type = 'prov:wasInformedBy'
  WHERE relationship = 'supports' AND source_type = 'claim' AND prov_type IS NULL;

UPDATE edges SET prov_type = 'prov:wasRevisionOf'
  WHERE relationship = 'supersedes' AND prov_type IS NULL;

-- 2. Activities table: extraction runs, ingestion jobs, reasoning steps
CREATE TABLE IF NOT EXISTS activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_type VARCHAR(100) NOT NULL,  -- 'extraction', 'ingestion', 'reasoning'
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    agent_id UUID REFERENCES agents(id),
    description TEXT,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activities_agent_id ON activities(agent_id);
CREATE INDEX IF NOT EXISTS idx_activities_activity_type ON activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_activities_started_at ON activities(started_at);

-- 3. Expand valid entity types to include 'activity'
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'activity') AND
    target_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'activity')
);

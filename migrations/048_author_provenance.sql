-- Migration: Author provenance + claim methodology storage
-- Apply with: psql $DATABASE_URL < migrations/048_author_provenance.sql
-- Safe to run multiple times (IF NOT EXISTS / DO NOTHING guards throughout)

-- 1. Add properties JSONB column to claims (stores methodology, reasoning_chain, etc.)
ALTER TABLE claims ADD COLUMN IF NOT EXISTS properties JSONB;
CREATE INDEX IF NOT EXISTS idx_claims_methodology
  ON claims USING gin ((properties -> 'methodology'));
CREATE INDEX IF NOT EXISTS idx_claims_properties
  ON claims USING gin (properties);
COMMENT ON COLUMN claims.properties IS
  'Structured metadata: methodology, section, reasoning_chain, asserted_by_authors, source_doi, extraction_persona';

-- 2. Add properties JSONB column to agents (already present in some deployments — safe)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS properties JSONB;
CREATE INDEX IF NOT EXISTS idx_agents_properties
  ON agents USING gin (properties);
COMMENT ON COLUMN agents.properties IS
  'For human authors: full_name, orcid, affiliations, email, type=human_author. For digital agents: source, model, etc.';

-- 3. Add properties JSONB column to edges (already present in some deployments — safe)
ALTER TABLE edges ADD COLUMN IF NOT EXISTS properties JSONB;
CREATE INDEX IF NOT EXISTS idx_edges_properties
  ON edges USING gin (properties);
COMMENT ON COLUMN edges.properties IS
  'Edge-level metadata: for AUTHORED edges: position, is_corresponding, contributions (CRediT roles)';

-- Done.
SELECT 'migration 048_author_provenance: OK' AS status;

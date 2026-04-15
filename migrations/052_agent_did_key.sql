-- Migration: Add did_key index for agent identity lookups
-- Apply with: psql $DATABASE_URL < migrations/052_agent_did_key.sql
-- Safe to run multiple times (IF NOT EXISTS guards)

-- Index on agents properties->>'did_key' for fast did:key lookups
CREATE INDEX IF NOT EXISTS idx_agents_did_key
  ON agents ((properties->>'did_key'))
  WHERE properties->>'did_key' IS NOT NULL;

COMMENT ON INDEX idx_agents_did_key IS
  'Fast lookup of agents by W3C did:key identifier (deterministic from ORCID or name hash)';

-- Done.
SELECT 'migration 052_agent_did_key: OK' AS status;

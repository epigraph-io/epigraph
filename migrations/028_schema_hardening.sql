-- Migration: 028_schema_hardening
-- Description: Promote JSONB-stored fields to proper schema columns for spec fidelity
--
-- Evidence:
-- - Planning doc §1.1 specifies evidence.modality, agent.agent_type, agent.is_active
-- - These were stored in JSONB properties but should be queryable columns
-- - competence_scopes used for BBA discount in Phase 7 but only in JSONB
--
-- Reasoning:
-- - Dedicated columns enable SQL filtering and indexing
-- - Defaults preserve backward compatibility with existing data
-- - VARCHAR(50) sufficient for enum-like type values
--
-- Verification:
-- - Existing queries unaffected (new columns have defaults)
-- - cargo test --lib passes

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS modality VARCHAR(50) DEFAULT 'text';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_type VARCHAR(50) DEFAULT 'human';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS competence_scopes JSONB DEFAULT '[]';

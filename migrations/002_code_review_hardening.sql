-- Migration 002: Code review hardening
-- Adds missing indexes, unique constraints, and schema clarifications
-- identified in code review 2026-04-15

-- 1. Composite index on edges for path queries
--    (note: idx_edges_unique_triple covers the same columns with a UNIQUE constraint;
--     this non-unique index is added for query planner flexibility on non-unique paths)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_source_target_rel
    ON edges(source_id, target_id, relationship);

-- 2. idx_claims_agent_id already exists in 001_initial_schema.sql — skipped.

-- 3. Missing index on bp_messages.factor_id
--    (the existing UNIQUE constraint covers (factor_id, variable_id, direction) but
--     a standalone factor_id index improves single-column lookups and joins)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bp_messages_factor_id
    ON bp_messages(factor_id);

-- 4. UNIQUE constraint on claims deduplication
--    Prevents the same agent from submitting duplicate claims;
--    different agents CAN make the same claim independently.
ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
    UNIQUE (content_hash, agent_id);

-- 5. Clarify ON DELETE behaviour for activities.agent_id
--    Activities are audit trail; preserve them as orphaned records when an agent
--    is deleted (RESTRICT is the Postgres default, which is already in place).
COMMENT ON COLUMN activities.agent_id IS 'Agent that performed the activity; nullable to support agent deletion without losing audit trail';
ALTER TABLE activities ALTER COLUMN agent_id DROP NOT NULL;

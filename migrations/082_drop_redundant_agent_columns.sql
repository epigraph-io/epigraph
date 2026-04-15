-- Drop redundant columns from agents table
-- is_active: replaced by state VARCHAR column (migration 074)
-- competence_scopes: replaced by agent_capabilities table (migration 075)
-- Neither column is referenced by any Rust code for the agents table.

-- Note: is_active is used on the coalitions table (political.rs) — that's unrelated.
-- competence_scopes is read from agents.properties JSONB, not this column.

ALTER TABLE agents DROP COLUMN IF EXISTS is_active;
ALTER TABLE agents DROP COLUMN IF EXISTS competence_scopes;

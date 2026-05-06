-- Step-level versioning (spec 2026-05-05-step-level-versioning-design.md).
-- Adds stable lineage identity to level=2 (steps) and level=3 (operations) claims.
-- NULL means "not in a versioned lineage" (legacy claims; all level=0/1 claims).
-- Edge types `supersedes` and `revises` capture chain + branch semantics —
-- `supersedes` is already in routes/edges.rs::VALID_RELATIONSHIPS;
-- `revises` is added in this same PR.
ALTER TABLE claims ADD COLUMN IF NOT EXISTS step_lineage_id UUID;

CREATE INDEX IF NOT EXISTS idx_claims_step_lineage_id
    ON claims(step_lineage_id)
    WHERE step_lineage_id IS NOT NULL;

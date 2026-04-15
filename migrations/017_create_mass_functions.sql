-- Migration 017: Mass functions table
--
-- Stores serialized mass functions (BBAs) for claims within frames.
-- Each mass function represents one source's evidence about a claim.
--
-- Evidence:
-- - dekg-planning-doc.md: mass functions are the core DS data structure
-- - TBM requires storing per-source BBAs for combination
--
-- Reasoning:
-- - masses stored as JSONB for flexibility (key = JSON array of hypothesis indices)
-- - source_agent_id nullable: system-generated mass functions have no agent
-- - UNIQUE constraint prevents duplicate entries per (claim, frame, agent)
-- - conflict_k stored for audit trail (how conflicting was the last combination?)

CREATE TABLE mass_functions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    frame_id UUID NOT NULL REFERENCES frames(id) ON DELETE CASCADE,
    source_agent_id UUID REFERENCES agents(id),  -- which agent contributed this evidence
    masses JSONB NOT NULL,                        -- {"[0]": 0.7, "[0,1]": 0.2, "[0,1,2]": 0.1}
    conflict_k DOUBLE PRECISION,                  -- K from last combination
    combination_method VARCHAR(50),               -- 'dempster', 'tbm_conjunctive', 'discount'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (claim_id, frame_id, source_agent_id)
);

CREATE INDEX idx_mass_functions_claim ON mass_functions(claim_id);
CREATE INDEX idx_mass_functions_frame ON mass_functions(frame_id);

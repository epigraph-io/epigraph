-- Factor graph: hyperedges connecting multiple claims.
-- Each factor defines a potential (constraint) over a set of claim variables.

CREATE TABLE IF NOT EXISTS factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    factor_type VARCHAR(100) NOT NULL,
    variable_ids UUID[] NOT NULL,
    potential JSONB NOT NULL DEFAULT '{}',
    description TEXT,
    frame_id UUID REFERENCES frames(id),
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT factors_min_variables CHECK (array_length(variable_ids, 1) >= 2)
);

CREATE INDEX IF NOT EXISTS idx_factors_type ON factors(factor_type);
CREATE INDEX IF NOT EXISTS idx_factors_frame ON factors(frame_id) WHERE frame_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_factors_variables ON factors USING GIN(variable_ids);

-- Message cache for belief propagation iterations.
CREATE TABLE IF NOT EXISTS bp_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    direction VARCHAR(20) NOT NULL CHECK (direction IN ('factor_to_var', 'var_to_factor')),
    factor_id UUID NOT NULL REFERENCES factors(id) ON DELETE CASCADE,
    variable_id UUID NOT NULL,
    message JSONB NOT NULL,
    iteration INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (factor_id, variable_id, direction)
);

-- Migration 049: Experimental Epistemic Loop
--
-- Creates schema for hypotheses, experiments, results, and extends
-- edge/factor infrastructure for frame-scoped hypothesis isolation.

-- 1. Ensure hypothesis_assessment frame exists (binary: supported/unsupported)
INSERT INTO frames (name, description, hypotheses)
VALUES (
    'hypothesis_assessment',
    'Binary frame for evaluating hypotheses: supported vs unsupported',
    ARRAY['supported', 'unsupported']
)
ON CONFLICT (name) DO NOTHING;

-- 2. Ensure research_validity frame exists
INSERT INTO frames (name, description, hypotheses)
VALUES (
    'research_validity',
    'Standard frame for research claim validity assessment',
    ARRAY['supported', 'unsupported']
)
ON CONFLICT (name) DO NOTHING;

-- 3. Create experiments table
CREATE TABLE IF NOT EXISTS experiments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hypothesis_id   UUID NOT NULL REFERENCES claims(id),
    created_by      UUID NOT NULL REFERENCES agents(id),
    method_ids      UUID[],
    protocol        TEXT,
    protocol_source JSONB,
    status          VARCHAR(20) NOT NULL DEFAULT 'designed'
                    CHECK (status IN ('designed','running','collecting','analyzing','complete','failed')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis ON experiments(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status);
CREATE INDEX IF NOT EXISTS idx_experiments_created_by ON experiments(created_by);

-- 4. Create experiment_results table
CREATE TABLE IF NOT EXISTS experiment_results (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id         UUID NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    data_source           VARCHAR(30) NOT NULL CHECK (data_source IN ('manual','simulation','instrument')),
    raw_measurements      JSONB NOT NULL DEFAULT '[]',
    measurement_count     INT NOT NULL DEFAULT 0,
    effective_random_error JSONB,
    processed_data        JSONB,
    status                VARCHAR(20) NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','processing','complete','error')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_experiment_results_experiment ON experiment_results(experiment_id);
CREATE INDEX IF NOT EXISTS idx_experiment_results_status ON experiment_results(status);

-- 5. Extend edge entity type CHECK constraint
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN ('claim','agent','evidence','trace','node','activity',
                    'paper','perspective','community','context','frame',
                    'experiment','experiment_result','analysis') AND
    target_type IN ('claim','agent','evidence','trace','node','activity',
                    'paper','perspective','community','context','frame',
                    'experiment','experiment_result','analysis')
);

-- 6. Extend validate_edge_reference() for new entity types
--    Also fixes pre-existing gap: perspective/community/context/frame/activity were
--    allowed by CHECK but not validated (fell to ELSE FALSE in migration 043).
CREATE OR REPLACE FUNCTION validate_edge_reference(
    entity_id UUID,
    entity_type VARCHAR
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'             THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'             THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'          THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'             THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'             THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'          THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'experiment'        THEN EXISTS (SELECT 1 FROM experiments WHERE id = entity_id)
        WHEN 'experiment_result' THEN EXISTS (SELECT 1 FROM experiment_results WHERE id = entity_id)
        WHEN 'perspective'       THEN EXISTS (SELECT 1 FROM perspectives WHERE id = entity_id)
        WHEN 'community'         THEN EXISTS (SELECT 1 FROM communities WHERE id = entity_id)
        WHEN 'context'           THEN EXISTS (SELECT 1 FROM contexts WHERE id = entity_id)
        WHEN 'frame'             THEN EXISTS (SELECT 1 FROM frames WHERE id = entity_id)
        WHEN 'activity'          THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'node'              THEN TRUE
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql STABLE;

-- 7. Cascade delete triggers for new tables (matching migration 043 pattern)
CREATE TRIGGER experiments_cascade_edges
    BEFORE DELETE ON experiments
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('experiment');

CREATE TRIGGER experiment_results_cascade_edges
    BEFORE DELETE ON experiment_results
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('experiment_result');

-- 8. Replace factor unique index to include frame_id
--    Allows same (factor_type, variable_ids) pair in different frames
DROP INDEX IF EXISTS idx_factors_type_vars;
CREATE UNIQUE INDEX idx_factors_type_vars_frame
    ON factors (factor_type, variable_ids, COALESCE(frame_id, '00000000-0000-0000-0000-000000000000'));

-- 9. Extend auto_create_factor_from_edge() with hypothesis frame scoping
CREATE OR REPLACE FUNCTION auto_create_factor_from_edge()
RETURNS TRIGGER AS $$
DECLARE
    ft VARCHAR;
    s  DOUBLE PRECISION;
    potential JSONB;
    var_ids UUID[];
    hyp_frame_id UUID;
    is_hypothesis BOOLEAN := FALSE;
BEGIN
    -- Only for claim-to-claim edges
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Look up factor type for this relationship
    SELECT e.factor_type, e.strength INTO ft, s
    FROM edge_to_factor_type(NEW.relationship) e
    LIMIT 1;

    -- Skip relationships we don't map to factors
    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    -- Build potential and variable_ids
    IF ft = 'mutual_exclusion' THEN
        potential := '{}'::jsonb;
    ELSE
        potential := jsonb_build_object('strength', s);
    END IF;

    -- Consistent ordering: smaller UUID first
    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    -- Check if either variable is an unpromoted hypothesis
    SELECT EXISTS (
        SELECT 1 FROM claims
        WHERE id IN (NEW.source_id, NEW.target_id)
          AND labels @> ARRAY['hypothesis']
          AND (properties->>'hypothesis_status') IS DISTINCT FROM 'promoted'
    ) INTO is_hypothesis;

    IF is_hypothesis THEN
        SELECT id INTO hyp_frame_id FROM frames WHERE name = 'hypothesis_assessment' LIMIT 1;
    END IF;

    -- Insert factor with frame scoping
    INSERT INTO factors (factor_type, variable_ids, potential, description, properties, frame_id)
    VALUES (
        ft,
        var_ids,
        potential,
        format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        jsonb_build_object('source_edge_id', NEW.id, 'relationship', NEW.relationship),
        hyp_frame_id
    )
    ON CONFLICT (factor_type, variable_ids, COALESCE(frame_id, '00000000-0000-0000-0000-000000000000'))
    DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 10. Trigger for shared_evidence factor creation
CREATE OR REPLACE FUNCTION create_shared_evidence_factor()
RETURNS TRIGGER AS $$
DECLARE
    other_claim_id UUID;
    hyp_frame_id UUID;
    var_ids UUID[];
BEGIN
    -- Only for provides_evidence edges from analysis to claim
    IF NEW.relationship != 'provides_evidence'
       OR NEW.source_type != 'analysis'
       OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    SELECT id INTO hyp_frame_id FROM frames WHERE name = 'hypothesis_assessment' LIMIT 1;

    -- Find all other claims this analysis already provides_evidence to
    FOR other_claim_id IN
        SELECT target_id FROM edges
        WHERE source_id = NEW.source_id
          AND source_type = 'analysis'
          AND target_type = 'claim'
          AND relationship = 'provides_evidence'
          AND target_id != NEW.target_id
    LOOP
        -- Build sorted variable_ids
        IF NEW.target_id < other_claim_id THEN
            var_ids := ARRAY[NEW.target_id, other_claim_id];
        ELSE
            var_ids := ARRAY[other_claim_id, NEW.target_id];
        END IF;

        -- Create pairwise shared_evidence factor
        INSERT INTO factors (factor_type, variable_ids, potential, description, properties, frame_id)
        VALUES (
            'shared_evidence',
            var_ids,
            jsonb_build_object('strength', 0.7),
            format('Shared evidence via analysis %s', NEW.source_id),
            jsonb_build_object('analysis_id', NEW.source_id),
            hyp_frame_id
        )
        ON CONFLICT (factor_type, variable_ids, COALESCE(frame_id, '00000000-0000-0000-0000-000000000000'))
        DO NOTHING;
    END LOOP;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER edges_shared_evidence
    AFTER INSERT ON edges
    FOR EACH ROW
    EXECUTE FUNCTION create_shared_evidence_factor();

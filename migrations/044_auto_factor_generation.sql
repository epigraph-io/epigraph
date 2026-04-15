-- Migration 044: Auto-generate factors from claim-to-claim edges
--
-- When a claim-to-claim edge is inserted, automatically create a factor
-- connecting those two claims. The factor type depends on the edge relationship:
--
--   supports, CORROBORATES, same_as, evidential_support → evidential_support
--   CONTRADICTS, REFUTES, mutual_exclusion              → mutual_exclusion
--   decomposes_to, refines, derived_from                → evidential_support (weaker)
--
-- This ensures the factor graph stays in sync with the edge graph without
-- requiring every ingestion path to manually create factors.
--
-- Evidence:
-- - Factor graph layer exists but has zero factors in production
-- - BP engine (bp.rs) is fully functional but has nothing to propagate over
-- - All ingestion paths create edges but never factors
--
-- Reasoning:
-- - Trigger-based approach covers ALL ingestion paths (submit, batch, harvest, scripts)
-- - Avoids modifying 6+ endpoint handlers individually
-- - Factor is idempotent: ON CONFLICT skips duplicates
-- - Strength values derived from relationship semantics

-- Map relationship → (factor_type, strength)
CREATE OR REPLACE FUNCTION edge_to_factor_type(rel VARCHAR)
RETURNS TABLE(factor_type VARCHAR, strength DOUBLE PRECISION) AS $$
BEGIN
    RETURN QUERY SELECT t.ft, t.s::DOUBLE PRECISION FROM (VALUES
        -- Strong positive relationships
        ('supports'::VARCHAR,       'evidential_support'::VARCHAR, 0.8),
        ('SUPPORTS',                'evidential_support', 0.8),
        ('CORROBORATES',            'evidential_support', 0.85),
        ('same_as',                 'evidential_support', 0.95),
        ('equivalent_to',           'evidential_support', 0.95),
        ('evidential_support',      'evidential_support', 0.8),

        -- Negative relationships → mutual exclusion
        ('CONTRADICTS',             'mutual_exclusion', 0.0),
        ('contradicts',             'mutual_exclusion', 0.0),
        ('REFUTES',                 'mutual_exclusion', 0.0),
        ('challenges',              'mutual_exclusion', 0.0),

        -- Structural decomposition → weaker evidential support
        ('decomposes_to',           'evidential_support', 0.6),
        ('refines',                 'evidential_support', 0.65),
        ('derived_from',            'evidential_support', 0.5),
        ('derives_from',            'evidential_support', 0.5),
        ('specializes',             'evidential_support', 0.55),
        ('produced',                'evidential_support', 0.5)
    ) AS t(rel_name, ft, s)
    WHERE t.rel_name = rel;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Trigger function: auto-create factor when a claim-to-claim edge is inserted
CREATE OR REPLACE FUNCTION auto_create_factor_from_edge()
RETURNS TRIGGER AS $$
DECLARE
    ft VARCHAR;
    s  DOUBLE PRECISION;
    potential JSONB;
    var_ids UUID[];
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

    -- Consistent ordering: smaller UUID first to avoid duplicates
    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    -- Insert factor (skip if this exact pair+type already exists)
    INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
    VALUES (
        ft,
        var_ids,
        potential,
        format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        jsonb_build_object('source_edge_id', NEW.id, 'relationship', NEW.relationship)
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER edges_auto_factor
    AFTER INSERT ON edges
    FOR EACH ROW
    EXECUTE FUNCTION auto_create_factor_from_edge();

-- Add a unique constraint on factors to prevent duplicate (type, variable pair) factors.
-- This enables the ON CONFLICT DO NOTHING above.
CREATE UNIQUE INDEX IF NOT EXISTS idx_factors_type_vars
    ON factors (factor_type, variable_ids);

-- Backfill: create factors for all existing claim-to-claim edges
INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
SELECT DISTINCT ON (e.factor_type, var_ids)
    e.factor_type,
    CASE WHEN ed.source_id < ed.target_id
         THEN ARRAY[ed.source_id, ed.target_id]
         ELSE ARRAY[ed.target_id, ed.source_id]
    END AS var_ids,
    CASE WHEN e.factor_type = 'mutual_exclusion'
         THEN '{}'::jsonb
         ELSE jsonb_build_object('strength', e.strength)
    END AS potential,
    format('Backfilled from %s edge', ed.relationship) AS description,
    jsonb_build_object('relationship', ed.relationship) AS properties
FROM edges ed
CROSS JOIN LATERAL edge_to_factor_type(ed.relationship) e
WHERE ed.source_type = 'claim' AND ed.target_type = 'claim'
ON CONFLICT DO NOTHING;

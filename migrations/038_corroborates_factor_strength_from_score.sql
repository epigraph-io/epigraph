-- Use the cross-source matcher's per-edge confidence as the factor strength
-- for CORROBORATES edges it emits, instead of the constant 0.85 from
-- edge_to_factor_type. See docs/superpowers/specs/2026-05-21-cross-source-
-- matching-design.md §4 — high-confidence corroborations should exert more
-- BP influence than borderline ones.
--
-- Only matcher-tagged edges (`properties.source = 'cross_source_matcher'`)
-- pick up the override; manually-curated CORROBORATES edges and older
-- backfills continue to use the constant fallback so this is a behavior
-- change scoped to T16's policy-layer writes.

CREATE OR REPLACE FUNCTION auto_create_factor_from_edge()
RETURNS TRIGGER AS $$
DECLARE
    ft  VARCHAR;
    fwd DOUBLE PRECISION;
    rev DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
    matcher_score DOUBLE PRECISION;
BEGIN
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims (unchanged from migration 090).
    IF EXISTS (SELECT 1 FROM claims WHERE id = NEW.source_id AND COALESCE(is_current, true) = false)
       OR EXISTS (SELECT 1 FROM claims WHERE id = NEW.target_id AND COALESCE(is_current, true) = false) THEN
        RETURN NEW;
    END IF;

    SELECT factor_type, forward_strength, reverse_strength
    INTO ft, fwd, rev
    FROM edge_to_factor_type(NEW.relationship);

    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    -- Matcher-derived evidential_support edges carry their own per-edge
    -- strength in properties.score. Use it (clamped to [0, 1]) instead of
    -- the constant fallback so calibration of the matcher flows through.
    IF ft = 'evidential_support'
       AND NEW.properties ? 'source'
       AND NEW.properties->>'source' = 'cross_source_matcher'
       AND NEW.properties ? 'score' THEN
        matcher_score := (NEW.properties->>'score')::double precision;
        IF matcher_score IS NOT NULL THEN
            fwd := GREATEST(0.0, LEAST(1.0, matcher_score));
            rev := fwd;
        END IF;
    END IF;

    IF ft = 'mutual_exclusion' THEN
        pot := '{}';
    ELSIF ft = 'directional_support' THEN
        pot := jsonb_build_object(
            'forward_strength', fwd,
            'reverse_strength', rev,
            'source_var', NEW.source_id::text
        );
    ELSE
        pot := jsonb_build_object('strength', fwd);
    END IF;

    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
    VALUES (
        ft,
        var_ids,
        pot,
        format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        jsonb_build_object(
            'source_edge_id', NEW.id,
            'relationship', NEW.relationship,
            'edge_source_id', NEW.source_id,
            'edge_target_id', NEW.target_id
        )
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

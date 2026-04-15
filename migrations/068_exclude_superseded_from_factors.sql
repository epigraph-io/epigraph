-- 068_exclude_superseded_from_factors.sql
-- Prevent superseded claims from participating in belief propagation.
-- Two changes:
-- 1. Guard auto_create_factor_from_edge() to skip non-current claims
-- 2. Cleanup trigger: delete factors when a claim becomes non-current

-- 1. Replace the auto-factor trigger function with a guarded version
CREATE OR REPLACE FUNCTION auto_create_factor_from_edge()
RETURNS TRIGGER AS $$
DECLARE
    ft VARCHAR;
    s  DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
BEGIN
    -- Only process claim-to-claim edges
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims
    IF EXISTS (SELECT 1 FROM claims WHERE id = NEW.source_id AND COALESCE(is_current, true) = false)
       OR EXISTS (SELECT 1 FROM claims WHERE id = NEW.target_id AND COALESCE(is_current, true) = false) THEN
        RETURN NEW;
    END IF;

    -- Look up factor type for this relationship
    SELECT factor_type, strength INTO ft, s FROM edge_to_factor_type(NEW.relationship);
    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    -- Build potential
    IF ft = 'mutual_exclusion' THEN
        pot := '{}';
    ELSE
        pot := jsonb_build_object('strength', s);
    END IF;

    -- Order variable IDs deterministically
    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    INSERT INTO factors (factor_type, variable_ids, potential, description)
    VALUES (ft, var_ids, pot, 'Auto-generated from edge ' || NEW.id::text)
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 2. Cleanup trigger: delete factors when a claim is superseded
CREATE OR REPLACE FUNCTION deactivate_superseded_factors()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_current = false AND COALESCE(OLD.is_current, true) = true THEN
        DELETE FROM factors WHERE NEW.id = ANY(variable_ids);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Only create trigger if it doesn't already exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'claims_deactivate_factors') THEN
        CREATE TRIGGER claims_deactivate_factors
            AFTER UPDATE OF is_current ON claims
            FOR EACH ROW EXECUTE FUNCTION deactivate_superseded_factors();
    END IF;
END
$$;

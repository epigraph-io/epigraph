-- 090_directional_factor_graph.sql
--
-- Overhaul factor graph: add directional_support factor type, clean up
-- incorrect mappings, and backfill complete factor graph.
--
-- Problems solved:
--   1. EvidentialSupport is bidirectional symmetric, but most relationships
--      (decomposes_to, supports, refines, derived_from) are directional.
--   2. 'produced' mapped agent provenance as epistemic support (Bad Actor violation).
--   3. 'supersedes' mapped lifecycle ops as epistemic support (evidence migrates).
--   4. Migration 068 dropped properties from trigger, losing relationship metadata.
--   5. 48K+ edges with clear epistemic signal had no factor mapping at all.
--
-- New factor type: directional_support
--   Potential: {"forward_strength": N, "reverse_strength": M, "source_var": "uuid"}
--   BP engine applies different strength per direction. Zero strength = neutral (0.5).
--
-- Relationship mapping review (30 types audited):
--   Symmetric (evidential_support): CORROBORATES, same_as, equivalent_to,
--     variant_of, definitional_variant_of, analogous
--   Directional (directional_support): decomposes_to (fwd=0, rev=0.6),
--     supports/SUPPORTS/provides_evidence (0.7/0.15), refines (0.6/0.2),
--     derived_from/derives_from (0.5/0.15), specializes (0.55/0.15),
--     enables (0.3/0.6), has_method_capability (0.6/0.4), INFORMS (0.4/0.1)
--   Anti-correlated (mutual_exclusion): CONTRADICTS, contradicts, REFUTES, challenges
--   Removed: produced (provenance), supersedes/SUPERSEDES (lifecycle)
--   Unmapped (not epistemic): same_source, continues_argument, elaborates,
--     section_follows, RELATES_TO, relates_to, reviews

BEGIN;

-- 1. Replace edge_to_factor_type with widened signature (forward + reverse).
DROP FUNCTION IF EXISTS edge_to_factor_type(VARCHAR);
CREATE FUNCTION edge_to_factor_type(rel VARCHAR)
RETURNS TABLE(factor_type VARCHAR, forward_strength DOUBLE PRECISION, reverse_strength DOUBLE PRECISION) AS $$
BEGIN
    RETURN QUERY SELECT t.ft, t.fwd::DOUBLE PRECISION, t.rev::DOUBLE PRECISION FROM (VALUES
        -- Symmetric positive (evidential_support: fwd = rev)
        ('CORROBORATES'::VARCHAR,       'evidential_support'::VARCHAR, 0.85, 0.85),
        ('same_as',                     'evidential_support', 0.95, 0.95),
        ('equivalent_to',              'evidential_support', 0.95, 0.95),
        ('evidential_support',         'evidential_support', 0.8,  0.8),
        ('variant_of',                 'evidential_support', 0.65, 0.65),
        ('definitional_variant_of',    'evidential_support', 0.9,  0.9),
        ('analogous',                  'evidential_support', 0.2,  0.2),

        -- Negative relationships (mutual_exclusion)
        ('CONTRADICTS',                'mutual_exclusion', 0.0, 0.0),
        ('contradicts',                'mutual_exclusion', 0.0, 0.0),
        ('REFUTES',                    'mutual_exclusion', 0.0, 0.0),
        ('challenges',                 'mutual_exclusion', 0.0, 0.0),

        -- Directional: parent → child (zero forward: parent truth does NOT push to children)
        ('decomposes_to',              'directional_support', 0.0, 0.6),

        -- Directional: evidence → conclusion
        ('supports',                   'directional_support', 0.7,  0.15),
        ('SUPPORTS',                   'directional_support', 0.7,  0.15),
        ('provides_evidence',          'directional_support', 0.7,  0.15),

        -- Directional: refined → general
        ('refines',                    'directional_support', 0.6,  0.2),

        -- Directional: derivative → source
        ('derived_from',               'directional_support', 0.5,  0.15),
        ('derives_from',               'directional_support', 0.5,  0.15),

        -- Directional: specific → general
        ('specializes',                'directional_support', 0.55, 0.15),

        -- Directional: prerequisite
        ('enables',                    'directional_support', 0.3,  0.6),

        -- Directional: method → capability
        ('has_method_capability',      'directional_support', 0.6,  0.4),

        -- Directional: weak informational
        ('INFORMS',                    'directional_support', 0.4,  0.1)
    ) AS t(rel_name, ft, fwd, rev)
    WHERE t.rel_name = rel;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- 2. Replace trigger to handle new types and restore properties storage.
CREATE OR REPLACE FUNCTION auto_create_factor_from_edge()
RETURNS TRIGGER AS $$
DECLARE
    ft  VARCHAR;
    fwd DOUBLE PRECISION;
    rev DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
BEGIN
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims
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

-- 3. Rebuild all factors.
TRUNCATE factors, bp_messages;

INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
SELECT DISTINCT ON (e.factor_type, var_ids)
    e.factor_type,
    CASE WHEN ed.source_id < ed.target_id
         THEN ARRAY[ed.source_id, ed.target_id]
         ELSE ARRAY[ed.target_id, ed.source_id]
    END AS var_ids,
    CASE
        WHEN e.factor_type = 'mutual_exclusion' THEN '{}'::jsonb
        WHEN e.factor_type = 'directional_support' THEN
            jsonb_build_object(
                'forward_strength', e.forward_strength,
                'reverse_strength', e.reverse_strength,
                'source_var', ed.source_id::text
            )
        ELSE jsonb_build_object('strength', e.forward_strength)
    END AS potential,
    format('Backfilled from %s edge %s', ed.relationship, ed.id) AS description,
    jsonb_build_object(
        'relationship', ed.relationship,
        'source_edge_id', ed.id,
        'edge_source_id', ed.source_id,
        'edge_target_id', ed.target_id
    ) AS properties
FROM edges ed
CROSS JOIN LATERAL edge_to_factor_type(ed.relationship) e
JOIN claims sc ON sc.id = ed.source_id AND COALESCE(sc.is_current, true) = true
JOIN claims tc ON tc.id = ed.target_id AND COALESCE(tc.is_current, true) = true
WHERE ed.source_type = 'claim' AND ed.target_type = 'claim'
ON CONFLICT DO NOTHING;

COMMIT;

-- 102_derived_from_uppercase_factor.sql
--
-- Add DERIVED_FROM (uppercase) to the factor type mapping.
--
-- Problem: paraphrase_full_sweep.py creates edges with relationship='DERIVED_FROM'
-- (uppercase) but migration 090 only mapped lowercase 'derived_from' and
-- 'derives_from'. The uppercase variant falls through edge_to_factor_type()
-- as NULL, so none of the 36,791 DERIVED_FROM edges generate factors — the
-- paraphrase-probe claims (18,989 created on 2026-04-11) have no BP coupling
-- to their source atoms.
--
-- Semantics for DERIVED_FROM (paraphrase → source atom):
--   forward_strength = 0.0: the synthetic paraphrase must NOT push belief onto
--     the source atom — it has no independent evidence. Matches decomposes_to
--     forward=0 rationale: derived artifact does not validate origin.
--   reverse_strength = 0.6: the source atom's belief flows strongly into the
--     paraphrase (the paraphrase is a restatement; if the original is well-
--     supported, the restatement should inherit that support).
--
-- This is intentionally asymmetric and different from lowercase derived_from
-- (fwd=0.5, rev=0.15), which models general derivative claims where the
-- derivative's truth IS evidence for the source.

BEGIN;

-- 1. Update edge_to_factor_type to include DERIVED_FROM.
--    Must drop and recreate: IMMUTABLE function, no ALTER.
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

        -- Directional: derivative → source (general case)
        --   Derivative truth implies source validity at 0.5;
        --   source weakly supports derivative at 0.15.
        ('derived_from',               'directional_support', 0.5,  0.15),
        ('derives_from',               'directional_support', 0.5,  0.15),

        -- Directional: synthetic paraphrase → source atom
        --   Forward=0: paraphrase has no independent evidence, must not
        --     push onto source truth.
        --   Reverse=0.6: source atom belief flows strongly into paraphrase
        --     (a restatement inherits its origin's epistemic state).
        ('DERIVED_FROM',               'directional_support', 0.0,  0.6),

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

-- 2. Backfill factors for all existing DERIVED_FROM edges that lack factors.
--    ON CONFLICT DO NOTHING: safe to re-run.
INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
SELECT DISTINCT ON (var_ids)
    'directional_support' AS factor_type,
    CASE WHEN ed.source_id < ed.target_id
         THEN ARRAY[ed.source_id, ed.target_id]
         ELSE ARRAY[ed.target_id, ed.source_id]
    END AS var_ids,
    jsonb_build_object(
        'forward_strength', 0.0,
        'reverse_strength', 0.6,
        'source_var', ed.source_id::text
    ) AS potential,
    format('Backfilled from DERIVED_FROM edge %s', ed.id) AS description,
    jsonb_build_object(
        'relationship', 'DERIVED_FROM',
        'source_edge_id', ed.id,
        'edge_source_id', ed.source_id,
        'edge_target_id', ed.target_id
    ) AS properties
FROM edges ed
JOIN claims sc ON sc.id = ed.source_id AND COALESCE(sc.is_current, true) = true
JOIN claims tc ON tc.id = ed.target_id AND COALESCE(tc.is_current, true) = true
WHERE ed.source_type = 'claim'
  AND ed.target_type = 'claim'
  AND ed.relationship = 'DERIVED_FROM'
-- ORDER BY var_ids, ed.id makes DISTINCT ON deterministic: for any given
-- claim pair, the earliest edge (lowest UUID) wins, ensuring a stable
-- source_var in the stored potential.
ORDER BY var_ids, ed.id
ON CONFLICT DO NOTHING;

COMMIT;

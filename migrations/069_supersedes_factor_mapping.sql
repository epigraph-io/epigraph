-- 069_supersedes_factor_mapping.sql
-- Add 'supersedes' to the edge_to_factor_type mapping so supersession edges
-- generate evidential_support factors (strength 0.65, consistent with derived_from).
-- Note: migration 068's guard ensures this only fires when both claims are current.

CREATE OR REPLACE FUNCTION edge_to_factor_type(rel VARCHAR)
RETURNS TABLE(factor_type VARCHAR, strength DOUBLE PRECISION) AS $$
BEGIN
    -- Preserve all existing mappings from migration 044 exactly,
    -- adding only the new 'supersedes' mapping.
    RETURN QUERY SELECT t.ft, t.s::DOUBLE PRECISION FROM (VALUES
        -- Strong positive relationships (unchanged from 044)
        ('supports'::VARCHAR,       'evidential_support'::VARCHAR, 0.8),
        ('SUPPORTS',                'evidential_support', 0.8),
        ('CORROBORATES',            'evidential_support', 0.85),
        ('same_as',                 'evidential_support', 0.95),
        ('equivalent_to',           'evidential_support', 0.95),
        ('evidential_support',      'evidential_support', 0.8),

        -- Negative relationships (unchanged from 044)
        ('CONTRADICTS',             'mutual_exclusion', 0.0),
        ('contradicts',             'mutual_exclusion', 0.0),
        ('REFUTES',                 'mutual_exclusion', 0.0),
        ('challenges',              'mutual_exclusion', 0.0),

        -- Structural decomposition (unchanged from 044)
        ('decomposes_to',           'evidential_support', 0.6),
        ('refines',                 'evidential_support', 0.65),
        ('derived_from',            'evidential_support', 0.5),
        ('derives_from',            'evidential_support', 0.5),
        ('specializes',             'evidential_support', 0.55),
        ('produced',                'evidential_support', 0.5),

        -- NEW: supersession mapping
        ('supersedes',              'evidential_support', 0.65)
    ) AS t(rel_name, ft, s)
    WHERE t.rel_name = rel;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

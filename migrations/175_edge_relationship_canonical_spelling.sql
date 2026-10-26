-- 175_edge_relationship_canonical_spelling.sql
-- The schema half of one canonical (lower-case) spelling for the four
-- case-folded edge relationships: supports, contradicts, corroborates,
-- refutes (`epigraph_core::edge::relationships::CASE_FOLDED_RELATIONSHIPS`).
-- Backlog 3ce5e00c (U014 PR-2).
--
-- ===================================================================
-- WHY
--
-- `edges.relationship` holds those four relationships in two spellings. MCP
-- `link_epistemic` writes lower case; the HTTP edge route, the DS evidence
-- writers and the cross-source matcher wrote `SUPPORTS` / `CONTRADICTS` /
-- `CORROBORATES`. The writers now store the lower-case spelling
-- (`canonical_relationship`, called by every `EdgeRepository` insert), and
-- readers already match both (`relationship_spellings`, U014 PR-1). Two
-- pieces of schema still key on ONE spelling and would silently break the
-- moment the matcher writes `corroborates`:
--
--   1. `edge_to_factor_type` (latest body: migration 011). Its table has
--      `CORROBORATES` but no `corroborates`, and `REFUTES` but no `refutes`.
--      `auto_create_factor_from_edge` (trigger `edges_auto_factor`) returns
--      early when the lookup is NULL, so a lower-case `corroborates` or
--      `refutes` claim/claim edge has never had a belief-propagation factor.
--      Once the matcher writes `corroborates`, every new matcher edge would
--      be factorless.
--   2. `edges_symmetric_relationship_uniq` (migration 090). Its predicate is
--      `relationship IN ('CORROBORATES', 'contradicts')`, so a new matcher
--      `corroborates` row would fall outside the only database-level dedup
--      the matcher's symmetric write has.
--
-- ===================================================================
-- WHAT THIS DOES
--
--   1. Re-states 011's `edge_to_factor_type` VERBATIM plus two rows:
--      ('corroborates', evidential_support, 0.85, 0.85) and
--      ('refutes', mutual_exclusion, 0, 0), the strengths of their upper-case
--      spellings. A closed addition, never a `lower(rel)` lookup: 011 keeps
--      `DERIVED_FROM` (0.0 / 0.6) and `derived_from` (0.5 / 0.15) as
--      DIFFERENT relationships, and a blanket fold would merge them.
--      BEHAVIOUR CHANGE, recorded: a lower-case `corroborates` / `refutes`
--      claim/claim edge written by MCP `link_epistemic` now gets a factor at
--      INSERT, as its upper-case twin always did. Existing rows are not
--      touched (the trigger is AFTER INSERT only).
--   2. Rebuilds `edges_symmetric_relationship_uniq` keyed on
--      `lower(relationship)` with the predicate
--      `lower(relationship) IN ('corroborates', 'contradicts')` and 090's
--      other conjuncts unchanged. `lower()` is IMMUTABLE, so it is legal in
--      an index key and predicate. While the data is mixed, a legacy matcher
--      `CORROBORATES` row and a new matcher `corroborates` row over one pair
--      are ONE key, which is exactly the dedup 090 promised.
--
-- NOT HERE: rewriting existing rows. The fold of ~tens of thousands of legacy
-- upper-case rows is an operator step, `docs/runbooks/edge-relationship-
-- casefold.sql` (backup table, batch, undo), because an UPDATE of `edges`
-- fires `edges_validate_refs` on every row and a single dangling endpoint
-- would abort this migration and the api's boot with it.
--
-- ===================================================================
-- DEPLOY PRECONDITION (same census shape as 090's)
--
-- The new key is coarser than 090's: a pair holding BOTH an in-force matcher
-- `CORROBORATES` row and an in-force matcher `corroborates` row (or both
-- spellings of `contradicts`) fails the CREATE, and a failed migration panics
-- the api on restart. The matcher wrote exactly one spelling of each
-- (`CORROBORATES`, `contradicts`) before this change, so the expected answer
-- is zero rows; run it anyway on any database with real data:
--
--   SELECT LEAST(source_id,target_id) AS a, GREATEST(source_id,target_id) AS b,
--          lower(relationship::text) AS rel, count(*)
--     FROM public.edges
--    WHERE lower(relationship::text) IN ('corroborates','contradicts')
--      AND source_type = 'claim' AND target_type = 'claim'
--      AND properties->>'source' = 'cross_source_matcher'
--      AND valid_to IS NULL
--    GROUP BY 1,2,3
--   HAVING count(*) > 1;
--
-- Not CONCURRENTLY: sqlx wraps each migration in a transaction (090's
-- reasoning). Idempotent: CREATE OR REPLACE, DROP INDEX IF EXISTS.
-- Undo: re-run 011's `edge_to_factor_type` body and 090's index statement
-- (both files are unchanged and re-runnable).

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- 1. edge_to_factor_type: 011's body plus the two lower-case spellings.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION edge_to_factor_type(rel VARCHAR)
RETURNS TABLE(factor_type VARCHAR, forward_strength DOUBLE PRECISION, reverse_strength DOUBLE PRECISION) AS $$
BEGIN
    RETURN QUERY SELECT t.ft, t.fwd::DOUBLE PRECISION, t.rev::DOUBLE PRECISION FROM (VALUES
        -- Symmetric positive (evidential_support: fwd = rev)
        ('CORROBORATES'::VARCHAR,       'evidential_support'::VARCHAR, 0.85, 0.85),
        ('corroborates',               'evidential_support', 0.85, 0.85),
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
        ('refutes',                    'mutual_exclusion', 0.0, 0.0),
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

-- -------------------------------------------------------------------
-- 2. The matcher's symmetric unique index, keyed on the canonical spelling.
-- -------------------------------------------------------------------
DROP INDEX IF EXISTS edges_symmetric_relationship_uniq;

CREATE UNIQUE INDEX edges_symmetric_relationship_uniq
    ON public.edges USING btree (
        LEAST(source_id, target_id),
        GREATEST(source_id, target_id),
        lower((relationship)::text)
    )
    WHERE (lower((relationship)::text) IN ('corroborates', 'contradicts')
           AND (source_type)::text = 'claim'
           AND (target_type)::text = 'claim'
           AND properties ->> 'source' = 'cross_source_matcher'
           AND valid_to IS NULL);

COMMENT ON INDEX public.edges_symmetric_relationship_uniq IS
  'Symmetric dedup for the matcher-written claim-claim edges in the two '
  'symmetric relationships EdgeRepository::create_symmetric_if_absent is called '
  'with, keyed on the canonical (lower-case) spelling so a legacy upper-case row '
  'and a canonical row over one pair are one key. Backs the read guard in that '
  'function. Keyed on the same (pair + properties->>''source'') identity '
  'MatchCandidateRepo::retire uses, so an operator-authored edge over the same '
  'pair is unaffected. alternative_of is covered separately by '
  'edges_alternative_of_symmetric_uniq. Migration 090, re-keyed by 175.';

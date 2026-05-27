-- 041_same_source_papers_function.sql
--
-- Predicate: do claims a and b share a source paper, traversing the
-- transitive closure of {asserts, same_source, section_follows,
-- continues_argument, decomposes_to}?
--
-- Used by edges.rs::trigger_edge_ds_recomputation to set a smaller
-- source_strength on intra-source evidential BBAs (Shafer reliability
-- discount). See docs/superpowers/specs/2026-05-27-alternative-and-dependency-edges-design.md.

CREATE OR REPLACE FUNCTION same_source_papers(a UUID, b UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
AS $$
DECLARE
    result BOOLEAN;
BEGIN
    IF a = b THEN
        RETURN TRUE;
    END IF;

    -- Postgres parses `WITH RECURSIVE x AS (anchor UNION recursive)` as a
    -- two-branch UNION: the anchor MUST be the left side and must not
    -- self-reference. We therefore use ONE recursive branch that walks
    -- intra-source edges in either direction via a CASE expression, rather
    -- than two separate recursive branches that would put a recursive
    -- reference inside the anchor.
    WITH RECURSIVE
    seeds AS (
        SELECT e.source_id AS paper_id
        FROM edges e
        WHERE e.target_id = a
          AND e.relationship = 'asserts'
    ),
    paper_a_closure AS (
        -- Anchor: claims directly asserted by any of a's source papers.
        SELECT e.target_id AS claim_id
        FROM seeds s
        JOIN edges e
          ON e.source_id = s.paper_id
         AND e.relationship = 'asserts'
        UNION
        -- Recursive: follow intra-source edges in either direction.
        SELECT
            CASE
                WHEN e2.source_id = pac.claim_id THEN e2.target_id
                ELSE e2.source_id
            END AS claim_id
        FROM paper_a_closure pac
        JOIN edges e2
          ON (e2.source_id = pac.claim_id OR e2.target_id = pac.claim_id)
         AND e2.relationship IN (
             'same_source', 'section_follows',
             'continues_argument', 'decomposes_to'
         )
    )
    SELECT EXISTS (
        SELECT 1 FROM paper_a_closure WHERE claim_id = b
    ) INTO result;

    RETURN COALESCE(result, FALSE);
END;
$$;

COMMENT ON FUNCTION same_source_papers(UUID, UUID) IS
'True iff claim a and claim b share a source paper via the transitive closure of '
'{asserts, same_source, section_follows, continues_argument, decomposes_to}. '
'Drives intra-source source_strength discounting in trigger_edge_ds_recomputation.';

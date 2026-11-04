-- ===================================================================
-- edge-relationship-casefold.sql: rewrite LEGACY edge rows of the four
-- case-folded relationships (supports, contradicts, corroborates, refutes)
-- into their lower-case canonical spelling. Backlog 3ce5e00c (U014 PR-3).
-- Undo: edge-relationship-casefold-undo.sql (same directory).
--
-- READ FIRST
--   * Run AFTER migration 175 is applied (175 makes `edge_to_factor_type` and
--     the matcher's unique index spelling-blind; without it, folding a matcher
--     `CORROBORATES` row moves it out of 090's index predicate).
--   * Run on the migration (superuser) DSN, in a quiet window: one
--     transaction, row locks on every folded edge, `lock_timeout` 3s.
--   * Take a fresh full backup first.
--   * Writers already store the canonical spelling and readers match both
--     spellings (`relationship_spellings`), so nothing depends on this having
--     run. It makes the stored data match what the writers now write, which
--     is what the readers that name only the lower-case spelling
--     (`sheaf.rs`, `routes/computation.rs`, `alternative_set.rs`,
--     `dispute_batch`, `semantic_graph_neighbors`) need to see the legacy
--     rows: AFTER THIS RUNS THEY SEE THEM (scope ruling 4.1, default "accept").
--
-- WHAT IT FOLDS: every row whose `relationship` is a non-lower-case spelling
-- of a case-folded relationship (`SUPPORTS`, `Contradicts`, ...), EXCEPT
--   * a SIGNED row (`signature`, `signer_id` or `content_hash` set): the edge
--     attestation digest covers `relationship`, so folding it would make an
--     honest signature read as "changed since signed". Left as is, counted.
--   * a row whose endpoint no longer validates (`validate_edge_reference`):
--     `edges_validate_refs` fires on every UPDATE and would abort the whole
--     run on one dangling row. Left as is, counted.
-- Every folded row's id and old spelling go to
-- `ops_backup.edges_relationship_casefold` first, which is what the undo
-- reads. Re-running is a no-op for rows already folded (idempotent); a row
-- folded once is never re-recorded.
--
-- FACTORS: the fold changes `edges.relationship` only. The `factors` row an
-- edge got at INSERT keeps the old spelling in `properties->>'relationship'`
-- and its description (no reader compares those to the edge's folded
-- spelling: `FactorRepository` matches only `decomposes_to`, lower-cased).
-- Edges that were INSERTED lower-case `corroborates` / `refutes` before
-- migration 175 have no factor at all (011 had no row for them); 175 fixes
-- new INSERTs only, so those stay factorless until the planned factor
-- rewire / backfill step.
--
-- WHAT IT DOES NOT DO: deduplicate. After the fold, a pair that held
-- `A CONTRADICTS B` and `B contradicts A` (or one pair in both spellings) has
-- two in-force rows of one symmetric relationship. Retracting one needs the
-- edge-keyed BBA withdrawal (`EdgeRepository::withdraw_edge_bbas_conn`) and a
-- belief recompute, which is not SQL's job; the census at the end of this
-- file lists those groups (by owner group) for that follow-up.
--
-- Pre-measure (read-only), on the deployed database:
--   SELECT relationship, source_type, target_type, count(*)
--     FROM public.edges
--    WHERE lower(relationship::text) IN ('supports','contradicts','corroborates','refutes')
--    GROUP BY 1,2,3 ORDER BY 1,2,3;
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Fail closed on a DSN row-level security filters: `edges` is FORCE RLS, so
-- on any other role every statement below would silently see only the rows
-- that role may read, and the report would look complete.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles
                    WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'casefold: run on the migration (superuser) DSN; % is subject to row-level security on edges', current_user
            USING ERRCODE = '42501';
    END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS ops_backup;
REVOKE ALL ON SCHEMA ops_backup FROM PUBLIC;

CREATE TABLE IF NOT EXISTS ops_backup.edges_relationship_casefold (
    edge_id          uuid PRIMARY KEY,
    old_relationship varchar(100) NOT NULL,
    folded_at        timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON ops_backup.edges_relationship_casefold FROM PUBLIC;

-- 1. Record what is about to change (and only what may change).
INSERT INTO ops_backup.edges_relationship_casefold (edge_id, old_relationship)
SELECT e.id, e.relationship
  FROM public.edges e
 WHERE lower(e.relationship::text) IN ('supports', 'contradicts', 'corroborates', 'refutes')
   AND e.relationship::text <> lower(e.relationship::text)
   AND e.signature IS NULL AND e.signer_id IS NULL AND e.content_hash IS NULL
   AND public.validate_edge_reference(e.source_id, e.source_type)
   AND public.validate_edge_reference(e.target_id, e.target_type)
ON CONFLICT (edge_id) DO NOTHING;

-- 2. Fold exactly the recorded rows that still carry their recorded spelling.
UPDATE public.edges e
   SET relationship = lower(b.old_relationship::text)
  FROM ops_backup.edges_relationship_casefold b
 WHERE e.id = b.edge_id
   AND e.relationship = b.old_relationship;

-- 3. Report.
DO $$
DECLARE
    folded   bigint;
    signed   bigint;
    dangling bigint;
BEGIN
    SELECT count(*) INTO folded FROM ops_backup.edges_relationship_casefold;
    SELECT count(*) INTO signed
      FROM public.edges e
     WHERE lower(e.relationship::text) IN ('supports', 'contradicts', 'corroborates', 'refutes')
       AND e.relationship::text <> lower(e.relationship::text)
       AND (e.signature IS NOT NULL OR e.signer_id IS NOT NULL OR e.content_hash IS NOT NULL);
    SELECT count(*) INTO dangling
      FROM public.edges e
     WHERE lower(e.relationship::text) IN ('supports', 'contradicts', 'corroborates', 'refutes')
       AND e.relationship::text <> lower(e.relationship::text)
       AND e.signature IS NULL AND e.signer_id IS NULL AND e.content_hash IS NULL
       AND NOT (public.validate_edge_reference(e.source_id, e.source_type)
                AND public.validate_edge_reference(e.target_id, e.target_type));
    RAISE NOTICE 'casefold: % rows recorded as folded (all runs); left unfolded: % signed, % with a dangling endpoint',
        folded, signed, dangling;
END $$;

COMMIT;

-- 4. Census for the symmetric-pair dedup follow-up (read-only). In-force
--    claim/claim groups of one symmetric relationship over one unordered pair,
--    split by owner group so a cross-owner group is visible as such.
SELECT LEAST(e.source_id, e.target_id)    AS a,
       GREATEST(e.source_id, e.target_id) AS b,
       lower(e.relationship::text)        AS relationship,
       e.owner_group_id,
       count(*)                           AS rows,
       array_agg(e.id ORDER BY e.created_at, e.id) AS edge_ids
  FROM public.edges e
 WHERE lower(e.relationship::text) IN ('contradicts', 'corroborates')
   AND e.source_type = 'claim' AND e.target_type = 'claim'
   AND (e.valid_to IS NULL OR e.valid_to > now())
 GROUP BY 1, 2, 3, 4
HAVING count(*) > 1
 ORDER BY rows DESC, a, b;

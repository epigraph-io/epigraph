-- 355: declare `papers.abstract_text` and `papers.properties`, and the
-- application role's INSERT on them, so a database migrated from empty has
-- the `papers` columns and column grants a deployed database already carries
-- (backlog 158b7ce4).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- A deployed database's `papers` carries two columns no migration creates:
--
--   * `abstract_text text` (nullable, no default). Read by
--     `scripts/run_assessment_worker.py` (`get_paper_abstract`), so it is in
--     use and is declared here, not dropped.
--   * `properties jsonb NOT NULL DEFAULT '{}'::jsonb`. No crate reads it
--     (`MethodRepository::get_source_papers` still returns `pub_year` as
--     `None`). A deployed copy may hold data, so dropping it would be
--     destructive; it is declared instead.
--
-- 255 grants `epigraph_app` INSERT on every `papers` column but `licence`,
-- reading the column list from the catalog when it runs. Where these two
-- columns predated 255, they gained INSERT; on a database migrated from
-- empty they did not exist, so the two databases' column ACLs differ.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. Adds each column only where it is missing, with the deployed
--      definition. The check reads `pg_attribute` first, so where both
--      columns already exist no ALTER TABLE runs and `papers` is not locked.
--   2. Grants `epigraph_app` INSERT on both, as 255 does for every column but
--      `licence`. NOT UPDATE: 255 lets the application UPDATE `title` and
--      `journal` only (an allowlist, held by 255's LIC09 check and by
--      `paper_licence_operator_only.rs`). Granting a privilege the role
--      already holds changes nothing.
--
-- Where both columns and both grants predate this file (a deployed database
-- that ran 255 after they appeared) it changes nothing, so it has nothing to
-- reverse there. No undo runbook ships: an undo would have to DROP the
-- columns, nothing records which database this file created them on, and on
-- a deployed database that would destroy data. No binary depends on it; no
-- deploy order.
--
-- `papers` carries tenancy (246); a column adds no row and needs no policy.

SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                    WHERE attrelid = 'public.papers'::regclass
                      AND attname = 'abstract_text' AND NOT attisdropped) THEN
        ALTER TABLE public.papers ADD COLUMN abstract_text text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                    WHERE attrelid = 'public.papers'::regclass
                      AND attname = 'properties' AND NOT attisdropped) THEN
        ALTER TABLE public.papers ADD COLUMN properties jsonb NOT NULL DEFAULT '{}'::jsonb;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT INSERT (abstract_text, properties) ON public.papers TO epigraph_app';
    END IF;
END $$;

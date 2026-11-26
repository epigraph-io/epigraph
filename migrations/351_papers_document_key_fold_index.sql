-- 351: an index for the bare-DOI miss path of the `papers` document-key
-- lookup, usable under `papers`' row security (backlog cc71759f).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- `epigraph_db::repos::paper::document_key_rows_in_sql` (every `papers`
-- lookup by document key, `PaperRepository::get_or_create` included) finds a
-- row by its exact spellings on `papers_doi_idx` (246). Only when there is
-- none (a new paper's first ingest) does its second arm look for a legacy row
-- keyed on a case variant of a DOI resolver prefix (backlog f3a3ca54), with
-- `lower(doi) = ANY (SELECT lower(s) FROM unnest(<spellings>) s)`. No index
-- served that arm, so every first ingest of a DOI scanned `papers`.
--
-- A plain `lower(doi)` expression index does not help the application. Since
-- 246 `papers` is FORCE RLS, so for every session but a superuser's the
-- lookup runs under its policy, and PostgreSQL evaluates a qual that is not
-- LEAKPROOF only AFTER the policy qual: it can be no index condition.
-- `pg_catalog.lower(text)` is not marked LEAKPROOF. Measured on a fresh
-- database under `SET ROLE epigraph_app`: with a plain `lower(doi)` index the
-- arm is a join FILTER over a full index scan, not an index condition
-- (`papers_document_key_fold_index.rs` keeps that as a calibration). The same
-- trap, and the same fix, as 335/336.
--
-- ===================================================================
-- 2. WHAT IT ADDS
-- ===================================================================
--
-- * `public.epigraph_document_key_fold(text) RETURNS text`: `SELECT
--   pg_catalog.lower(p_key)`, `LANGUAGE sql IMMUTABLE STRICT LEAKPROOF
--   PARALLEL SAFE SECURITY INVOKER`, `SET search_path = pg_catalog, pg_temp`.
--     - LEAKPROOF is TRUE of it: `lower` on a stored text value returns the
--       folded text and raises on no value (a stored value is validly
--       encoded; a collation that cannot be determined is a property of the
--       call, not of the row), so it reveals nothing about a row through an
--       error or a side effect.
--     - The SET clause keeps it from being inlined: an inlined body is the
--       bare `lower`, which is not leakproof. (It also satisfies 271's rule.)
--     - IMMUTABLE (as `lower` is), so it can be indexed.
--     - EXECUTE stays with PUBLIC: a pure function of its argument that reads
--       no table, and EVERY role that inserts a `papers` row initialises the
--       index expression and is ACL-checked for it.
--     - Owner `epigraph_maintenance` when present, as 335's accessor.
-- * `papers_doi_fold_idx ON papers (epigraph_document_key_fold(doi))`. The
--   lookup's case-variant arm now folds with this function, so its
--   comparison is an index condition under row security.
--
-- NOT CONCURRENTLY: the function and the index ship in one slot, and a
-- `-- no-transaction` file holds exactly one statement. The build takes a
-- SHARE lock on `papers` (writes wait; reads do not) for the time it takes to
-- fold and sort every `doi`, as 246 built its three `papers` indexes. The
-- lock wait is bounded by `lock_timeout`; a timeout fails the migration with
-- nothing changed, and it can be re-run.
--
-- PRECONDITION (LKP02, 42501): only a superuser may declare a function
-- LEAKPROOF. The migration runner is a superuser on every deployment (212,
-- 238, 335); on a runner that is not, this refuses with nothing changed
-- instead of creating a non-leakproof wrapper whose index the application
-- could never use.
--
-- DEPLOY ORDER: migrate BEFORE the binary of this change (its lookup names
-- the function). An older binary runs on 351 unchanged (it never names the
-- function, and the index only costs its writes the fold).
--
-- UNDO: `docs/runbooks/351-undo.sql` (roll the binary back first).
SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF NOT COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r
                      WHERE r.rolname = current_user), false) THEN
        RAISE EXCEPTION 'LKP02: 351 declares a LEAKPROOF function, which only a superuser may '
                        'do; run the migrations as a superuser; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_document_key_fold(p_key text)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.lower(p_key)
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_document_key_fold(text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 351 fold '
                     'stays owned by the migration runner.';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS papers_doi_fold_idx
    ON public.papers (public.epigraph_document_key_fold(doi));

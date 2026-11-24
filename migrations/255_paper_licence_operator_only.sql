-- 255: `papers.licence` is set by the operator only, and every operator set
-- is audited (backlog 9ee6799d).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 226 added `papers.licence`, which the document ingest writers read to
-- decide whether an evidence row may keep a verbatim source passage
-- (`passage_retention_permitted` in `epigraph-mcp/src/tools/ingestion.rs`).
-- 226 left "operator sets it" as a CONVENTION: `papers` is a REGISTRY table
-- on which 077 granted `epigraph_app` table-level INSERT and UPDATE, so any
-- application session (any holder of the application DSN, or a future
-- request-path bug) could mark a paper open-licensed and make every later
-- ingest of it store publisher text. Three moves did that:
--
--   * `UPDATE papers SET licence = 'CC0-1.0' WHERE ...` on an existing paper;
--   * `INSERT INTO papers (doi, title, licence) VALUES (...)` for a DOI not
--     yet ingested (or `INSERT ... ON CONFLICT (doi) DO UPDATE SET licence`),
--     which the next ingest of that DOI finds and reads;
--   * RE-POINTING a paper that already carries an open licence:
--     `UPDATE papers SET doi = '<paywalled DOI>' WHERE id = <open paper>`.
--     Ingest finds its paper BY DOI (`PaperRepository::get_or_create`) and
--     then reads that row's licence (`PaperRepository::licence`), so the
--     paywalled DOI would read as open, and the DOI can be moved back
--     afterwards. Closing `licence` alone leaves this open.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `epigraph_app` loses table-level INSERT and UPDATE on `public.papers`.
--      The REVOKE comes first: a table-level REVOKE also revokes that
--      privilege's column grants (217). It gets back:
--        * INSERT on every column EXCEPT `licence`, read from the catalog, so
--          a column a deployed database carries beyond this tree stays
--          insertable. An INSERT that does not name `licence` still works (it
--          defaults to NULL); one that names it is refused 42501.
--        * UPDATE on `title` and `journal` ONLY, an allowlist: every
--          request-path UPDATE and both `ON CONFLICT DO UPDATE` arms set only
--          those two (a conflict target needs SELECT, not UPDATE, on `doi`).
--          So `doi` and `id`, the keys ingest finds a paper and its licence
--          by, cannot be moved, and a licensed row cannot be re-pointed onto
--          another DOI. A later column is not updatable until a migration
--          grants it by name.
--      SELECT and DELETE are untouched: the request path reads `licence`, and
--      a DELETE then re-INSERT yields a NULL licence, which retains nothing.
--   2. `public.epigraph_set_paper_licence(paper uuid, licence text, reason
--      text)` is the operator path: a SECURITY DEFINER on 172's form
--      (`search_path = pg_catalog, pg_temp`, every public object qualified),
--      owned by `epigraph_maintenance`, EXECUTE revoked from PUBLIC and from
--      `epigraph_app`. It refuses a blank reason and an unknown paper, locks
--      the row, sets the licence (NULL clears it; 226's CHECK still refuses a
--      blank or padded value), writes ONE `security_events` row
--      `paper.licence_set` (paper, DOI, previous and new licence, reason,
--      session user) and returns the previous licence.
--   3. A RESTRICTIVE insert policy reserves the `paper.licence` event-type
--      prefix (ignoring case and surrounding blanks) for a privileged
--      session or a maintenance-owned definer frame, stamped `now()`, as
--      123 does for `platform.`. Without it an application session could
--      forge a licence audit row through 077's `agent_id IS NULL` arm.
--   4. Re-states the column comment: operator-only is now enforced.
--   5. Refuses (`LIC09`, nothing applied) if, after 1, `epigraph_app` can
--      still INSERT `licence`, or UPDATE any column but `title` and `journal`,
--      by any route (a grant to PUBLIC, or membership in a role that holds
--      it).
--
-- ===================================================================
-- 2. WHAT IT CANNOT CLOSE
-- ===================================================================
--
--   * The maintenance DSN. `epigraph_maintenance` keeps 070's table-level
--     UPDATE on `papers` (the definer runs as it), so a holder of that DSN can
--     still `UPDATE papers SET licence` (or `doi`) without the audit row.
--     The application role can neither write a licence nor move a licensed
--     paper onto another DOI; provenance against the maintenance DSN waits
--     for the elevation batch, as in 123.
--   * `evidence.raw_content`. The application role can still write publisher
--     text into an evidence row directly, without any licence. That is a
--     separate, larger decision (backlog 9ee6799d's fix sketch).
--   * Licences set before this migration. They carry no audit row; an
--     operator should review every non-NULL `papers.licence` once.
--
-- ===================================================================
-- 3. THE OPERATOR PATH
-- ===================================================================
--
-- On the maintenance DSN (a login that is a member of
-- `epigraph_maintenance`), by paper id (DOI spellings are canonicalised in
-- the application, `canonical_document_key`, so look the id up first):
--
--   SELECT id, doi, licence FROM papers WHERE doi = '10.1234/example';
--   SELECT epigraph_set_paper_licence('<paper id>', 'CC-BY-4.0',
--                                     'publisher page states CC BY 4.0');
--   SELECT epigraph_set_paper_licence('<paper id>', NULL, 'licence withdrawn');
--
-- `papers` carries no tenancy (127), so there is no policy to restate.
-- No binary depends on this migration: every application writer of `papers`
-- (`PaperRepository::get_or_create`, `POST /api/v1/papers`) INSERTs only
-- `doi`, `title` and `journal`, and UPDATEs only `title` and `journal`.
-- Undo: docs/runbooks/255-undo.sql.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 4. THE COLUMN GRANTS
-- ===================================================================
DO $$
DECLARE
    v_cols text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        RETURN;
    END IF;
    SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO v_cols
      FROM pg_attribute a
     WHERE a.attrelid = 'public.papers'::regclass
       AND a.attnum > 0
       AND NOT a.attisdropped
       AND a.attname <> 'licence';
    EXECUTE 'REVOKE INSERT, UPDATE ON public.papers FROM epigraph_app';
    EXECUTE format('GRANT INSERT (%s) ON public.papers TO epigraph_app', v_cols);
    -- An allowlist, not "every column but licence": UPDATE of `doi` (or `id`)
    -- would re-point an open-licensed row onto a paywalled DOI.
    EXECUTE 'GRANT UPDATE (title, journal) ON public.papers TO epigraph_app';
END $$;

-- ===================================================================
-- 5. THE OPERATOR DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_set_paper_licence(
    p_paper uuid, p_licence text, p_reason text)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_doi  text;
    v_prev text;
    v_n    bigint;
BEGIN
    IF p_paper IS NULL THEN
        RAISE EXCEPTION 'LIC01: setting a licence needs the paper id; nothing was changed'
            USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'LIC02: setting a licence needs a reason (where the licence was '
                        'read); nothing was changed' USING ERRCODE = '22023';
    END IF;

    SELECT p.doi, p.licence INTO v_doi, v_prev
      FROM public.papers p WHERE p.id = p_paper FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'LIC03: no paper %; nothing was changed', p_paper
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.papers SET licence = p_licence WHERE id = p_paper;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'LIC04: the licence of paper % was not changed (% rows); nothing '
                        'was changed', p_paper, v_n USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('paper.licence_set', NULL, true,
            pg_catalog.jsonb_build_object(
                'paper_id', p_paper,
                'doi', v_doi,
                'previous', v_prev,
                'licence', p_licence,
                'reason', p_reason,
                'principal_id', public.epigraph_principal_id(),
                'session_user', session_user::text,
                'migration', 255));
    RETURN v_prev;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_set_paper_licence(uuid, text, text) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_set_paper_licence(uuid, text, text) '
                'FROM epigraph_app';
    END IF;
    -- Under a non-member owner the definer's audit INSERT is refused by the
    -- `security_events` policies, so every set fails 42501 with nothing
    -- written (closed and loud); `epigraph-tenancy-backfill verify` checks
    -- the owner (DEFERRED_DEFINER_FUNCTIONS).
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        ALTER FUNCTION public.epigraph_set_paper_licence(uuid, text, text)
            OWNER TO epigraph_maintenance;
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_set_paper_licence(uuid, text, text) '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 6. THE AUDIT ROW IS THE DEFINER'S ALONE
-- ===================================================================
-- `left(..., 13)` is `paper.licence`. Lower-cased and trimmed, so
-- `Paper.Licence_set` is the reserved prefix too, not a look-alike an
-- application session may write.
DROP POLICY IF EXISTS security_events_paper_licence_privileged ON public.security_events;
CREATE POLICY security_events_paper_licence_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 13)) <> 'paper.licence'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- ===================================================================
-- 7. THE COLUMN COMMENT
-- ===================================================================
COMMENT ON COLUMN public.papers.licence IS
    'SPDX-style licence of the source (e.g. CC-BY-4.0). NULL = unknown, treated as '
    'all rights reserved: ingest stores a passage locator and hash, never the text. '
    'Never written by ingest (migration 226, backlog 8709d128). The application role '
    'cannot write it, nor UPDATE doi or id to move a licensed row onto another DOI; an '
    'operator sets it through epigraph_set_paper_licence on the maintenance DSN, which '
    'audits each set (migration 255, backlog 9ee6799d).';

-- ===================================================================
-- 8. THE END STATE
-- ===================================================================
DO $$
DECLARE
    v_bad text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        RETURN;
    END IF;
    SELECT string_agg(x.what, ', ' ORDER BY x.what) INTO v_bad
      FROM (SELECT 'INSERT (licence)' AS what
             WHERE has_column_privilege('epigraph_app', 'public.papers', 'licence', 'INSERT')
            UNION ALL
            SELECT format('UPDATE (%s)', a.attname)
              FROM pg_attribute a
             WHERE a.attrelid = 'public.papers'::regclass
               AND a.attnum > 0
               AND NOT a.attisdropped
               AND a.attname NOT IN ('title', 'journal')
               AND has_column_privilege('epigraph_app', 'public.papers', a.attnum, 'UPDATE')) x;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'LIC09: epigraph_app can still % on papers after 255''s REVOKE (a grant '
                        'to PUBLIC, or membership in a role that holds it); writing licence, or '
                        'moving doi or id, makes a paper read as open-licensed; nothing was applied',
                        v_bad
            USING ERRCODE = '55000';
    END IF;
END $$;

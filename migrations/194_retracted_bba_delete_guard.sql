-- 194: a RETRACTED mass function (BBA) is never deleted except by the
-- audited purge definer (H10; operator rulings R-79 / R-103; SPEC section
-- 7.3 H10, section 10.1 S-1).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 184 made a retracted BBA "excluded from every fold, kept for
-- audit". Nothing in the schema kept it: any DELETE removed it, including the
-- ones the `ON DELETE CASCADE` foreign keys from `claims` and `frames`
-- perform (`mass_functions_claim_id_fkey`, `mass_functions_frame_id_fkey`,
-- 001), so a writer of a claim's group deleting its claim took every
-- retracted row on it with it, and 117's cascade definer deleted retracted
-- edge-keyed rows on both of its arms.
--
-- The guard's only exception is a PURGE GRANT, a row in a table only the purge
-- definer writes. It is deliberately NOT a session setting and NOT
-- `epigraph_definer_bypass()`: PostgreSQL runs an FK referential action as the
-- owner of the referencing table, so inside the cascade a claim delete starts
-- the definer-bypass test can be true, and any session can set a setting
-- (SPEC section 7.1, "No setting where an FK action can act").
--
-- ===================================================================
-- 1. WHAT IT CREATES
-- ===================================================================
--
--   (1) `public.mass_function_purge_grants (mf_id, xact_id, granted_by,
--       reason)`: one row names one `mass_functions` id for the transaction
--       that wrote it (`xact_id` defaults to `pg_current_xact_id()`). Owned by
--       the migration runner; `REVOKE ALL ... FROM PUBLIC, epigraph_app`
--       (077's default privileges would otherwise make it app-writable);
--       `epigraph_maintenance` gets exactly SELECT, INSERT, DELETE, which its
--       two definers below need.
--   (2) `public.epigraph_mf_purge_granted(uuid) RETURNS boolean`: STABLE
--       SECURITY DEFINER, owner `epigraph_maintenance`, 172's form
--       (`search_path = pg_catalog, pg_temp`, every name qualified): true when
--       a grant names the id for THIS transaction. EXECUTE revoked from
--       PUBLIC, granted to `epigraph_app` and `epigraph_maintenance` (the
--       guard runs as the invoker; it answers one boolean about an id the
--       caller named, for grants its own transaction wrote), and to the owner
--       of `mass_functions` when that owner is not a superuser, because the
--       guard runs as that owner inside an FK cascade (section 3).
--   (3) `public.epigraph_purge_mass_functions(uuid[], text) RETURNS integer`:
--       SECURITY DEFINER, owner `epigraph_maintenance`, 172's form. Refuses a
--       reason outside 1..2000 characters (22023, nothing deleted). Inserts one
--       grant per distinct id; deletes those `mass_functions` rows (retracted
--       or live) in a SEPARATE statement, so the guard sees the grants; deletes
--       its grant rows; appends ONE `security_events` row
--       `mass_functions.purge` (`agent_id` = the session principal, if any)
--       carrying each deleted row whole (`to_jsonb`: id, claim, frame,
--       perspective, `retracted_at`, masses ...), the reason and the counts;
--       returns how many rows it deleted. EXECUTE only to
--       `epigraph_maintenance` (revoked from PUBLIC and `epigraph_app`).
--   (4) The guard `public.mass_functions_retracted_delete_guard()` (SECURITY
--       INVOKER, `search_path = pg_catalog, pg_temp`, qualified) and its
--       trigger `mass_functions_retracted_delete_guard` `BEFORE DELETE ...
--       FOR EACH ROW WHEN (OLD.retracted_at IS NOT NULL)` (a delete of live
--       rows never calls it). A delete of a retracted row without a grant for
--       the current transaction is refused `SR09` (SQLSTATE 42501; the row's id
--       in DETAIL), and the statement, with any cascade that reached it, writes
--       nothing.
--   (5) The re-body of `public.epigraph_cascade_delete_edge_bbas(uuid[],
--       text)` from 117's body ("THE CASCADE DEFINER, OWNER ARM ONLY"), with
--       exactly two deltas, each marked `194:` in the body: `AND retracted_at
--       IS NULL` on the privileged `epigraph_bypass()` arm's DELETE, and `AND
--       m.retracted_at IS NULL` on the owner arm's candidate select, which
--       feeds both the CD02 count and the ids the owner arm deletes. A
--       retracted row is therefore neither deleted (no SR09 inside a cascade)
--       nor counted as another writer's row. The header states
--       `SET search_path = pg_catalog, public, pg_temp`, not 117's `pg_catalog,
--       public`: `CREATE OR REPLACE` replaces `proconfig` with the body, and
--       restating 117's header would revert slot 190's `pg_temp`-last path.
--       Owner and ACL are kept by `CREATE OR REPLACE`.
--
-- NOT CHANGED: 115's `epigraph_dedup_move_bbas` (no caller; 117 revoked the
-- application's EXECUTE). After 194 the guard refuses any retracted-row delete
-- it attempts.
--
-- ===================================================================
-- 2. CLAIM AND FRAME HARD-DELETES: PURGE, THEN DELETE
-- ===================================================================
--
-- A claim or frame whose delete would cascade onto a retracted BBA is refused
-- SR09. The documented order is: purge that claim's or frame's retracted rows
-- through `epigraph_purge_mass_functions` (with the reason for the delete) on
-- the maintenance connection, then delete the claim or frame in the same
-- transaction or a later one. `epigraph-operator delete-frames` does this.
--
-- ===================================================================
-- 3. WHO THE GUARD DEFENDS AGAINST, AND THE RESIDUAL
-- ===================================================================
--
-- The guard defends against every session that is not a maintenance login,
-- including inside an FK cascade such a session starts: the application role
-- holds no privilege on the grant table and cannot execute the purge definer.
--
-- RESIDUAL (184 section 3's words): the maintenance role holds INSERT on the
-- grant table, because its definers need it, and maintenance logins inherit
-- that. So a login on the maintenance role itself could insert a grant row
-- directly (as it could disable the trigger), which is outside what this guard
-- defends. Every other delete of a retracted row is the purge definer's, and
-- audited there. Tightening this needs a dedicated NOLOGIN owner role that no
-- login is a member of (SPEC OD-9).
--
-- THE FK-CASCADE INVOKER. Inside a cascade from `claims` or `frames` the
-- guard runs as the owner of `mass_functions`. A superuser owner executes
-- every function. A non-superuser owner is granted EXECUTE on the helper here;
-- if the table's owner later changes to another non-superuser role, re-grant
-- it, or every claim or frame delete that cascades onto a retracted row fails
-- closed with "permission denied for function" instead of SR09 (nothing is
-- deleted either way). TRUNCATE is out of scope (077 grants the application
-- role no TRUNCATE).
--
-- ===================================================================
-- 4. DEPLOY, PRECONDITION AND UNDO
-- ===================================================================
--
-- DEPLOY ORDER (binding): migrate 194 only after the release that keeps
-- retracted rows on every privileged delete path (SPEC section 11 phase 1,
-- K4a) is installed on EVERY binary that can delete `mass_functions` rows on
-- a privileged connection (SPEC section 10.1 lists them). A binary still on an
-- older build deletes a retracted row, the guard refuses it, and the whole
-- administrative cascade aborts and is replayed for ever. The purge callers
-- (`epigraph-operator delete-frames`) are installed after the migrate.
--
-- PRECONDITION: the opening block refuses (55000, nothing changed) unless
-- `md5(prosrc)` of `epigraph_cascade_delete_edge_bbas(uuid[], text)` is 117's
-- (`39f3eacd53e7717a323759ec91b5c2c0`) AND its `proconfig` is exactly
-- 117's `search_path=pg_catalog, public` or slot 190's
-- `search_path=pg_catalog, public, pg_temp` (190 changes `proconfig` only,
-- so the md5 is the same either way; 194 does not depend on 190).
-- Predeploy check: `SELECT md5(prosrc), proconfig FROM pg_proc WHERE oid =
-- to_regprocedure('public.epigraph_cascade_delete_edge_bbas(uuid[], text)')`.
--
-- The migration runs in one transaction; creating the trigger takes a SHARE
-- ROW EXCLUSIVE lock on `mass_functions` (catalog-only, no scan), bounded by
-- `lock_timeout`.
--
-- UNDO: `docs/runbooks/194-undo.sql` (drops the trigger, the guard, the purge
-- definer, the helper and the grant table, and restores 117's body with
-- `CREATE OR REPLACE`, stating `pg_catalog, public, pg_temp`).
--
-- Checked before claiming: no migration on main, open PR, origin branch or
-- local worktree carries a `194`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. PRECONDITION
-- ===================================================================
DO $$
DECLARE
    v_md5 text;
    v_config text[];
BEGIN
    SELECT pg_catalog.md5(p.prosrc), p.proconfig INTO v_md5, v_config
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_cascade_delete_edge_bbas(uuid[], text)');
    IF v_md5 IS DISTINCT FROM '39f3eacd53e7717a323759ec91b5c2c0' THEN
        RAISE EXCEPTION '194: public.epigraph_cascade_delete_edge_bbas(uuid[], text) is not the '
                        'body 194 re-states (117''s, md5 39f3eacd53e7717a323759ec91b5c2c0); found '
                        'md5 %. Another migration re-bodied it, or 117 is not applied; nothing '
                        'was changed', COALESCE(v_md5, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the definer with every '
                         'delta instead of this one.';
    END IF;
    IF v_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']::text[]
       AND v_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']::text[] THEN
        RAISE EXCEPTION '194: public.epigraph_cascade_delete_edge_bbas(uuid[], text) has proconfig '
                        '%, which is neither 117''s (search_path=pg_catalog, public) nor slot '
                        '190''s (search_path=pg_catalog, public, pg_temp); nothing was changed',
                        COALESCE(v_config::text, '(none)')
            USING ERRCODE = '55000',
                  HINT = 'Find what set the path and reconcile it before applying 194.';
    END IF;
END $$;

-- ===================================================================
-- 1. THE PURGE-GRANT TABLE
-- ===================================================================
CREATE TABLE public.mass_function_purge_grants (
    mf_id       uuid NOT NULL,
    xact_id     xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
    granted_by  uuid,
    reason      text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) BETWEEN 1 AND 2000),
    PRIMARY KEY (mf_id, xact_id)
);
COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migration 194 (H10): one row names one mass_functions id that the purge definer is about to '
    'delete in THIS transaction (xact_id). Written and cleared only by '
    'epigraph_purge_mass_functions; read only through epigraph_mf_purge_granted. The application '
    'role holds no privilege on it.';
COMMENT ON COLUMN public.mass_function_purge_grants.granted_by IS
    'Migration 194: the purge definer''s session principal, when the session is stamped.';

REVOKE ALL ON public.mass_function_purge_grants FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.mass_function_purge_grants '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 2. THE GRANT HELPER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_mf_purge_granted(p_id uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM public.mass_function_purge_grants g
                    WHERE g.mf_id = p_id
                      AND g.xact_id = pg_catalog.pg_current_xact_id());
END $$;
COMMENT ON FUNCTION public.epigraph_mf_purge_granted(uuid) IS
    'Migration 194 (H10): true when a purge grant names this mass_functions id for the current '
    'transaction. The retracted-row delete guard''s only exception.';
REVOKE EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) FROM PUBLIC;

-- ===================================================================
-- 3. THE PURGE DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_purge_mass_functions(p_ids uuid[], p_reason text)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_reason text := pg_catalog.btrim(COALESCE(p_reason, ''));
    v_ids uuid[];
    v_rows jsonb;
    v_n integer;
BEGIN
    IF v_reason = '' OR pg_catalog.length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'a purge of mass functions needs a reason of 1 to 2000 characters; '
            'nothing was deleted'
            USING ERRCODE = '22023';
    END IF;
    v_ids := ARRAY(SELECT DISTINCT u.id
                     FROM pg_catalog.unnest(COALESCE(p_ids, ARRAY[]::uuid[])) AS u(id)
                    WHERE u.id IS NOT NULL);
    IF pg_catalog.cardinality(v_ids) = 0 THEN
        RETURN 0;
    END IF;

    -- The grants first, in their own statement: the guard on the DELETE below
    -- reads them, and the parts of one statement share one snapshot, so a
    -- grant written by a sibling CTE would be invisible to it.
    INSERT INTO public.mass_function_purge_grants (mf_id, granted_by, reason)
    SELECT u.id, v_principal, v_reason FROM pg_catalog.unnest(v_ids) AS u(id);

    WITH gone AS (
        DELETE FROM public.mass_functions m
         WHERE m.id = ANY (v_ids)
        RETURNING m.*
    )
    SELECT pg_catalog.count(*)::integer,
           COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(g) ORDER BY g.id),
                    '[]'::jsonb)
      INTO v_n, v_rows
      FROM gone g;

    DELETE FROM public.mass_function_purge_grants gr
     WHERE gr.mf_id = ANY (v_ids)
       AND gr.xact_id = pg_catalog.pg_current_xact_id();

    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('mass_functions.purge', v_principal, true,
                pg_catalog.jsonb_build_object(
                    'reason',    v_reason,
                    'requested', pg_catalog.cardinality(v_ids),
                    'deleted',   v_n,
                    'rows',      v_rows,
                    'migration', 194));
    END IF;
    RETURN v_n;
END $$;
COMMENT ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) IS
    'Migration 194 (H10): the one audited delete of retracted mass functions. Grants, deletes, '
    'clears its grants and writes one mass_functions.purge security event carrying every deleted '
    'row and the reason. Maintenance role only.';
REVOKE EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_mf_purge_granted(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_purge_mass_functions(uuid[], text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) '
                'FROM epigraph_app';
    END IF;
END $$;

-- The FK-cascade invoker (section 3 of the header): the guard runs as the
-- owner of `mass_functions` inside a cascade from `claims` or `frames`.
DO $$
DECLARE
    v_owner name;
    v_super boolean;
BEGIN
    SELECT r.rolname, r.rolsuper INTO v_owner, v_super
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE c.oid = 'public.mass_functions'::pg_catalog.regclass;
    IF NOT v_super THEN
        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO %I', v_owner);
    END IF;
END $$;

-- ===================================================================
-- 4. THE GUARD
-- ===================================================================
-- SECURITY INVOKER, and it tests the grant ONLY (no setting, no
-- `epigraph_definer_bypass()`): see the header, section 0.
CREATE OR REPLACE FUNCTION public.mass_functions_retracted_delete_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF public.epigraph_mf_purge_granted(OLD.id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'SR09: a retracted mass function is deleted only through '
        'epigraph_purge_mass_functions, which records the row and the reason; a claim or frame '
        'delete that would cascade onto one is refused too (purge its retracted rows first); '
        'nothing was deleted'
        USING ERRCODE = '42501', DETAIL = OLD.id::text;
END $$;
COMMENT ON FUNCTION public.mass_functions_retracted_delete_guard() IS
    'Migration 194 (H10): refuses SR09 the delete of a retracted mass function that no purge '
    'grant of the current transaction names, FK cascades included.';

DROP TRIGGER IF EXISTS mass_functions_retracted_delete_guard ON public.mass_functions;
CREATE TRIGGER mass_functions_retracted_delete_guard
    BEFORE DELETE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.retracted_at IS NOT NULL)
    EXECUTE FUNCTION public.mass_functions_retracted_delete_guard();

-- ===================================================================
-- 5. THE CASCADE DEFINER, RETRACTED ROWS KEPT
-- ===================================================================
-- 117's body; deltas: the two `194:` lines, and the path states `pg_temp`
-- last (SPEC section 7.1, SF-12).
CREATE OR REPLACE FUNCTION public.epigraph_cascade_delete_edge_bbas(
    p_edge_ids uuid[], p_cause text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := COALESCE(public.epigraph_writable_groups(), ARRAY[]::uuid[]);
        v_g uuid[] := COALESCE(public.epigraph_session_groups(), ARRAY[]::uuid[]);
        v_total bigint; v_refused bigint; v_n bigint; v_ids uuid[];
BEGIN
    IF p_cause IS NULL OR p_cause NOT IN ('dedup_retracted_edge', 'retraction_cascade',
                                          'match_candidate_retire') THEN
        RAISE EXCEPTION 'CD01: unknown cascade cause %; nothing was deleted', p_cause
            USING ERRCODE = '22023';
    END IF;
    IF p_edge_ids IS NULL OR cardinality(p_edge_ids) = 0 THEN
        RETURN 0;
    END IF;
    -- A privileged SESSION (maintenance login or superuser; `session_user`,
    -- which a definer frame does not change) is the plain statement. This is
    -- where the application's administrative cascade lands.
    IF public.epigraph_bypass() THEN
        -- 194: a retracted row is kept (H10; rulings R-79 / R-103).
        DELETE FROM public.mass_functions WHERE perspective_id = ANY (p_edge_ids)
            AND retracted_at IS NULL;
        GET DIAGNOSTICS v_n = ROW_COUNT;
        RETURN v_n;
    END IF;

    -- Any other session: its OWN rows only. Every candidate it can read is
    -- classified, locked so the verdict and the delete see the same rows.
    SELECT count(*),
           count(*) FILTER (WHERE NOT (mf.owner_group_id = ANY (v_w))),
           COALESCE(array_agg(mf.id), ARRAY[]::uuid[])
      INTO v_total, v_refused, v_ids
      FROM (SELECT m.id, m.owner_group_id
              FROM public.mass_functions m
             WHERE m.perspective_id = ANY (p_edge_ids)
               -- 194: a retracted row is neither deleted nor counted toward CD02.
               AND m.retracted_at IS NULL
               AND (m.visibility = 'public' OR m.owner_group_id = ANY (v_g))
               FOR UPDATE) mf;
    IF v_refused > 0 THEN
        RAISE EXCEPTION 'CD02: % of % edge-keyed mass function(s) for these edges are not '
            'this session''s to delete (cause %); another writer''s rows are removed only '
            'by the administrative cascade on the maintenance connection; nothing was deleted',
            v_refused, v_total, p_cause
            USING ERRCODE = '42501';
    END IF;
    IF v_total = 0 THEN
        RETURN 0;
    END IF;

    DELETE FROM public.mass_functions mf WHERE mf.id = ANY (v_ids);
    GET DIAGNOSTICS v_n = ROW_COUNT;

    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('derived.cascade_bba_delete', v_principal, true,
                jsonb_build_object(
                    'cause',              p_cause,
                    'edge_ids',           to_jsonb(p_edge_ids),
                    'deleted',            v_n,
                    'arms',               jsonb_build_object('owner', v_n),
                    'writable_group_ids', to_jsonb(v_w),
                    'migration',          117));
    END IF;
    RETURN v_n;
END $$;

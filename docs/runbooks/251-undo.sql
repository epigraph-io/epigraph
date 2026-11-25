-- ===================================================================
-- 251-undo.sql: take migration 251 (the retracted-BBA grant ledger and its
-- NOLOGIN owner, backlog 6bdac68f) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST. Once undone, a maintenance login can again write a row of
-- `mass_function_purge_grants` and then delete a retracted mass function with
-- no audit row, and can again clear a retraction (set
-- `epigraph.mf_unretract_id` and UPDATE the retract columns to NULL) with no
-- audit row: 194's and 184's documented residual. The purge and the
-- un-retract keep working for their callers either way. Install a
-- `delete-frames` that predates 251 with it (its census expects 194's grant
-- writes; the one built with 251 reads the shape and accepts either).
--
-- KEEP THE LEDGER FIRST if you want it: the undo drops 251's columns (who
-- granted, who consumed, the row each grant admitted). For example, as the
-- migration login:
--     \copy (SELECT * FROM public.mass_function_purge_grants) TO 'ledger-251.csv' CSV HEADER
--
-- WHAT IT DOES
--   * Restores, byte for byte with `CREATE OR REPLACE` (never DROP, which
--     would drop the triggers that call the guards and reset the definers'
--     owners and ACLs), the five bodies 251 re-stated, each on its path at
--     250 but one: 184's `epigraph_mass_function_retract_guard()` goes back
--     on `pg_catalog, public, pg_temp`, NOT 184's `pg_catalog, public`. That
--     is the safer path (pg_temp searched last), the one backlog eff4aaf5's
--     interim mitigation sets, and one 251's precondition accepts; restoring
--     184's path would undo that mitigation. 194's
--     `mass_functions_retracted_delete_guard()`,
--     `epigraph_mf_purge_granted(uuid)` and `epigraph_purge_mass_functions(
--     uuid[], text)` (`pg_catalog, pg_temp`), and 184's
--     `epigraph_unretract_mass_function(uuid, text, uuid, uuid)` (190's
--     `pg_catalog, public, pg_temp` and the marker setting).
--   * Gives `epigraph_mf_purge_granted(uuid)` back to `epigraph_maintenance`
--     with 194's EXECUTE grants.
--   * Drops `epigraph_mf_guard_grant`, `epigraph_mf_guard_consume` and
--     `epigraph_bba_guard_owner_faults`.
--   * Puts the table back in 194's shape: deletes the unretract grants and
--     every purge grant but the first of each (id, transaction), drops 251's
--     columns, constraints and index, restores the (mf_id, xact_id) key, and
--     gives `epigraph_maintenance` 194's SELECT, INSERT, DELETE back.
--   * Revokes everything `epigraph_bba_guard_owner` holds in this database.
--
-- WHAT IT LEAVES: the role `epigraph_bba_guard_owner` (roles are
-- cluster-wide, and another database of the cluster may still use it), and
-- 251's `_sqlx_migrations` row. Once no database of the cluster has 251
-- applied, drop the role by hand as a superuser:
--     DROP ROLE epigraph_bba_guard_owner;
-- Re-introducing 251 is a NEW migration (or a re-run of 251's text, whose
-- preconditions accept the bodies this file restores). Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- ORDER: refuse while migration 274 is in place. 274's retract definer
-- writes a `retract` grant through `epigraph_mf_guard_grant`, which this
-- undo drops, so every retraction would then fail (42883), and 251's text
-- re-applied refuses the kind (22023); undo 274 first (`274-undo.sql`).
-- Keyed on the definer calling the grant function with kind `retract`,
-- not on an md5, so a later re-statement that keeps the dependency is
-- still caught.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
                WHERE p.oid = pg_catalog.to_regprocedure(
                          'public.epigraph_retract_mass_function(uuid, text, uuid, uuid)')
                  AND p.prosrc LIKE '%epigraph_mf_guard_grant(''retract''%') THEN
        RAISE EXCEPTION '251-undo refuses: epigraph_retract_mass_function writes a retract grant '
                        '(migration 274) through what this undo drops; nothing was changed'
            USING ERRCODE = '55000',
                  HINT = 'Run docs/runbooks/274-undo.sql first (undo newest first), then this file.';
    END IF;
END $$;

-- Migration 184's body, verbatim; its path lists pg_temp last (see WHAT IT
-- DOES), so the md5 is 184's and the proconfig is the interim mitigation's.
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    -- R-103: no session or frame re-writes a retracted row's assessment.
    IF TG_ARGV[0] = 'rewrite' THEN
        RAISE EXCEPTION 'RT07: mass function % is retracted; a write to its key (claim, frame, '
            'source agent, perspective) is refused until it is un-retracted; nothing was written',
            OLD.id
            USING ERRCODE = '42501', DETAIL = OLD.id::text;
    END IF;
    -- R-103: only section 2b's definer clears a retraction.
    IF TG_ARGV[0] = 'clear' THEN
        IF public.epigraph_definer_bypass()
           AND current_setting('epigraph.mf_unretract_id', true) = OLD.id::text THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'RT06: a retracted mass function is made live again only through '
            'epigraph_unretract_mass_function (which records who, why and an audit row); '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'RT06: a mass function is retracted only through '
        'epigraph_retract_mass_function (which records the retractor and an audit row); '
        'nothing was written'
        USING ERRCODE = '42501';
END $$;

-- Migration 194's body, verbatim.
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

-- Migration 194's body, verbatim (before the table goes back to 194's shape:
-- 251's bodies name its columns).
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

-- Migration 184's body, verbatim, on 190's path.
CREATE OR REPLACE FUNCTION public.epigraph_unretract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
SET epigraph.mf_unretract_id = ''
AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: un-retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session un-retracts no mass function; '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: an un-retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability in the WHERE, as in section 2.
    SELECT mf.* INTO v_row
      FROM public.mass_functions mf
     WHERE mf.id = p_id
       AND (mf.visibility = 'public'
            OR mf.owner_group_id = ANY (public.epigraph_session_groups()))
       FOR UPDATE OF mf;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'RT02: mass function not found' USING ERRCODE = 'P0002';
    END IF;

    IF v_row.owner_group_id = ANY (COALESCE(public.epigraph_writable_groups(),
                                            ARRAY[]::uuid[])) THEN
        v_arm := 'owner';
    ELSIF p_admin_client IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.oauth_clients c
             WHERE c.id = p_admin_client
               AND c.agent_id = v_principal
               AND c.status = 'active'
               AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        v_arm := 'admin';
    ELSE
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'RT03: only a writer of the mass function''s owning group, or a '
                           'live claims:admin holder, un-retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not un-retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NULL THEN
        RETURN jsonb_build_object(
            'status',           'not_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'unretracted_by',   v_principal,
            'reason',           v_reason,
            'arm',              v_arm,
            'previously_retracted_at', NULL,
            'previously_retracted_by', NULL,
            'previous_retract_reason', NULL,
            'scoped_beliefs_cleared', 0);
    END IF;

    PERFORM set_config('epigraph.mf_unretract_id', p_id::text, true);
    UPDATE public.mass_functions
       SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL
     WHERE id = p_id;
    PERFORM set_config('epigraph.mf_unretract_id', '', true);

    -- The stored folds that will include this row again: the same scopes a
    -- retraction clears.
    DELETE FROM public.ds_combined_beliefs d
     WHERE d.claim_id = v_row.claim_id AND d.frame_id = v_row.frame_id
       AND (d.scope_type = 'global'
            OR (d.scope_type = 'perspective' AND d.scope_id = v_row.perspective_id)
            OR (d.scope_type = 'community'
                AND COALESCE(d.strategy_used, '') <> 'override'
                AND d.scope_id IN (SELECT cm.community_id
                                     FROM public.community_members cm
                                    WHERE cm.perspective_id = v_row.perspective_id)));
    GET DIAGNOSTICS v_scoped = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES ('mass_functions.unretract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'unretractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'unretracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'unretracted_by',   v_principal,
        'reason',           v_reason,
        'arm',              v_arm,
        'previously_retracted_at', v_row.retracted_at,
        'previously_retracted_by', v_row.retracted_by,
        'previous_retract_reason', v_row.retract_reason,
        'scoped_beliefs_cleared', v_scoped);
END $$;

-- Migration 194's body, verbatim.
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

DROP FUNCTION IF EXISTS public.epigraph_mf_guard_grant(text, uuid[], text, uuid);
DROP FUNCTION IF EXISTS public.epigraph_mf_guard_consume(text, uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_bba_guard_owner_faults();

-- The table, back in 194's shape.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                WHERE attrelid = 'public.mass_function_purge_grants'::pg_catalog.regclass
                  AND attname = 'kind' AND NOT attisdropped) THEN
        EXECUTE pg_catalog.format(
            'DELETE FROM public.mass_function_purge_grants WHERE kind <> %L', 'purge');
    END IF;
END $$;
DELETE FROM public.mass_function_purge_grants a
 USING public.mass_function_purge_grants b
 WHERE a.mf_id = b.mf_id AND a.xact_id = b.xact_id AND a.ctid > b.ctid;
ALTER TABLE public.mass_function_purge_grants
    DROP CONSTRAINT IF EXISTS mass_function_purge_grants_pkey,
    DROP CONSTRAINT IF EXISTS mass_function_purge_grants_consumed_check,
    DROP COLUMN IF EXISTS kind,
    DROP COLUMN IF EXISTS grant_login,
    DROP COLUMN IF EXISTS granted_at,
    DROP COLUMN IF EXISTS consumed_at,
    DROP COLUMN IF EXISTS consumed_login,
    DROP COLUMN IF EXISTS consumed_row,
    DROP COLUMN IF EXISTS id;
DROP INDEX IF EXISTS public.mass_function_purge_grants_xact_idx;
ALTER TABLE public.mass_function_purge_grants
    ADD CONSTRAINT mass_function_purge_grants_pkey PRIMARY KEY (mf_id, xact_id);
COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migration 194 (H10): one row names one mass_functions id that the purge definer is about to '
    'delete in THIS transaction (xact_id). Written and cleared only by '
    'epigraph_purge_mass_functions; read only through epigraph_mf_purge_granted. The application '
    'role holds no privilege on it.';

DO $$
DECLARE
    v_owner name;
    v_super boolean;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_mf_purge_granted(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.mass_function_purge_grants TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_app';
    END IF;
    SELECT r.rolname, r.rolsuper INTO v_owner, v_super
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE c.oid = 'public.mass_functions'::pg_catalog.regclass;
    IF NOT v_super THEN
        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO %I', v_owner);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_bba_guard_owner') THEN
        EXECUTE 'REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_bba_guard_owner';
        EXECUTE 'REVOKE USAGE ON SCHEMA public FROM epigraph_bba_guard_owner';
    END IF;
END $$;

COMMIT;

-- ===================================================================
-- 274-undo.sql: take migration 274 (the retract grant that confines the
-- retracted-BBA guard's mark arm, backlog 03d444a9) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Once undone, a maintenance login can again mark a live mass
-- function retracted by a direct UPDATE, with no audit row and a
-- `retracted_by` of its choosing: 251's documented residual. The retraction
-- keeps working for its callers either way.
--
-- ORDER: undo 274 BEFORE 251 or 194. 251's undo drops
-- `epigraph_mf_guard_grant` and 194's drops the ledger, both of which 274's
-- retract definer writes through; this file puts back 184's definer, which
-- uses neither. Both of those runbooks refuse (55000, nothing changed) while
-- 274's definer is in place.
--
-- WHAT IT DOES
--   * Restores, byte for byte with `CREATE OR REPLACE` (never DROP, which
--     would drop the triggers that call the guard and reset the functions'
--     owners and ACLs), the four bodies 274 re-stated, each on its path at
--     271: 251's `epigraph_mf_guard_grant(text, uuid[], text, uuid)` and
--     `epigraph_mf_guard_consume(text, uuid, jsonb)` (`pg_catalog,
--     pg_temp`), 251's `epigraph_mass_function_retract_guard()` and 184's
--     `epigraph_retract_mass_function(uuid, text, uuid, uuid)` (`pg_catalog,
--     public, pg_temp`), and their comments.
--
-- WHAT IT LEAVES: the ledger's `kind` CHECK still admits `retract`, and every
-- `retract` row stays. The ledger is append-only and its rows are the audit
-- of the retractions made under 274; after the undo no function writes the
-- kind any more (251's grant function refuses it, 22023). 274's
-- `_sqlx_migrations` row also stays: re-introducing 274 is a NEW migration
-- (or a re-run of 274's text, whose preconditions accept the bodies this file
-- restores). Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Migration 251's body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_mf_guard_grant(
    p_kind text, p_ids uuid[], p_reason text, p_granted_by uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_n pg_catalog.int4;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('purge', 'unretract') THEN
        RAISE EXCEPTION 'a retracted-BBA grant is of kind purge or unretract; nothing was written'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.mass_function_purge_grants (mf_id, kind, granted_by, reason)
    SELECT DISTINCT u.id, p_kind, p_granted_by, p_reason
      FROM pg_catalog.unnest(p_ids) AS u(id)
     WHERE u.id IS NOT NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
COMMENT ON FUNCTION public.epigraph_mf_guard_grant(text, uuid[], text, uuid) IS
    'Migration 251: writes one ledger grant per id for this transaction, recording session_user. '
    'Runs as epigraph_bba_guard_owner and touches only the ledger.';

-- Migration 251's body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_mf_guard_consume(p_kind text, p_id uuid, p_row jsonb)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_row IS NULL OR (p_row ->> 'id') IS DISTINCT FROM p_id::pg_catalog.text THEN
        RETURN false;
    END IF;
    UPDATE public.mass_function_purge_grants g
       SET consumed_at = pg_catalog.now(), consumed_login = session_user, consumed_row = p_row
     WHERE g.id = (SELECT pg_catalog.min(c.id) FROM public.mass_function_purge_grants c
                    WHERE c.xact_id = pg_catalog.pg_current_xact_id()
                      AND c.mf_id = p_id AND c.kind = p_kind
                      AND c.consumed_at IS NULL);
    RETURN FOUND;
END $$;
COMMENT ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) IS
    'Migration 251: consumes this transaction''s oldest unconsumed grant of the kind for the id, '
    'recording the row and session_user; true when it did. The retracted-BBA guards'' only '
    'exception. Runs as epigraph_bba_guard_owner and touches only the ledger.';

-- Migration 251's body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    -- No session or frame re-writes a retracted row's assessment.
    IF TG_ARGV[0] = 'rewrite' THEN
        RAISE EXCEPTION 'RT07: mass function % is retracted; a write to its key (claim, frame, '
            'source agent, perspective) is refused until it is un-retracted; nothing was written',
            OLD.id
            USING ERRCODE = '42501', DETAIL = OLD.id::text;
    END IF;
    -- Only 184's un-retract definer (section 2b) clears a retraction.
    IF TG_ARGV[0] = 'clear' THEN
        -- 251: consume the unretract grant that definer wrote, recording the
        -- row it admits.
        IF public.epigraph_mf_guard_consume('unretract', OLD.id, pg_catalog.to_jsonb(OLD)) THEN
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

-- Migration 184's body, verbatim, on 190's path.
CREATE OR REPLACE FUNCTION public.epigraph_retract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_at timestamptz;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record as the retractor; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session retracts no mass function; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: a retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability is in the WHERE: a caller that cannot read the row locks
    -- nothing and gets the answer a random id gets.
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
                           'live claims:admin holder, retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NOT NULL THEN
        RETURN jsonb_build_object(
            'status',           'already_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'retracted_at',     v_row.retracted_at,
            'retracted_by',     v_row.retracted_by,
            'retract_reason',   v_row.retract_reason,
            'arm',              v_arm,
            'scoped_beliefs_cleared', 0);
    END IF;

    UPDATE public.mass_functions
       SET retracted_at = now(), retracted_by = v_principal, retract_reason = v_reason
     WHERE id = p_id
    RETURNING retracted_at INTO v_at;

    -- Only the stored folds that included this row: the global scope, its
    -- own perspective's, and each community counting that perspective (not
    -- a community's mass override, which folds no member row).
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
    VALUES ('mass_functions.retract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'retractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'retracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'retracted_at',     v_at,
        'retracted_by',     v_principal,
        'retract_reason',   v_reason,
        'arm',              v_arm,
        'scoped_beliefs_cleared', v_scoped);
END $$;

COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migrations 194 and 251 (274 undone; its retract grants are kept): the append-only ledger of '
    'grants that admit the delete (kind purge) or the un-retraction (kind unretract) of a '
    'retracted mass function in the transaction that wrote them (xact_id). Written only by '
    'epigraph_mf_guard_grant, consumed only by epigraph_mf_guard_consume (from the guards, with '
    'the row''s content), both owned by epigraph_bba_guard_owner, which alone holds a privilege '
    'on it. No row is deleted.';

COMMIT;

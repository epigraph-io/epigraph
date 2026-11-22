-- ===================================================================
-- 257-undo.sql: take migration 257 (the retire verb's dedicated owner role;
-- backlog 9cec11f7) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES:
--   * re-states 191's `epigraph_operator_links_retire_only` body verbatim
--     (no OLR05 arm, no clearing of the audit context), and 191's
--     `epigraph_operator_links_audit` and `epigraph_retire_operator_link`
--     bodies (no `revoked_memberships`): CREATE OR REPLACE keeps each one's
--     owner and grants;
--   * moves UPDATE (retired) on `operator_links` back from
--     `epigraph_operator_link_retirer` to `epigraph_maintenance`;
--   * re-owns `epigraph_retire_operator_link` to `epigraph_maintenance`
--     (the new owner's ACL entry becomes the maintenance role's, so it keeps
--     EXECUTE; PUBLIC and the application role stay revoked).
--
-- WHAT IT LEAVES:
--   * the role `epigraph_operator_link_retirer`. Roles are cluster-scoped and
--     another database on the cluster may still run its verb as it. Once no
--     database does, drop it as a superuser:
--       REVOKE epigraph_maintenance FROM epigraph_operator_link_retirer;
--       DROP ROLE epigraph_operator_link_retirer;
--   * every link the verb retired (a retired link is permanent, 107) and
--     every audit row (082: immutable);
--   * 257's `_sqlx_migrations` row. Re-introducing 257's control is a NEW
--     migration, never a re-run of 257.
--
-- After it, a maintenance login can again retire a link directly,
-- unserialised and with an advisory audit `via` / reason (191's limits).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_operator_links_retire_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                WHERE r.rolname = session_user AND r.rolsuper) THEN
        RETURN NEW;
    END IF;
    IF NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.operator_group_id IS DISTINCT FROM OLD.operator_group_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.retired AND NOT NEW.retired) THEN
        RAISE EXCEPTION 'OLR04: an operator link is only ever retired (retired false -> true); '
                        'a retired link is permanent and a link is never re-pointed (agent %); '
                        'nothing was changed', OLD.agent_id
            USING ERRCODE = '42501';
    END IF;
    -- ZERO write authority is a precondition of a retire on EVERY path, not
    -- only the verb's (107/122 section 7).
    IF NOT OLD.retired AND NEW.retired
       AND EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = OLD.operator_group_id
                      AND m.agent_id = OLD.agent_id
                      AND m.revoked_at IS NULL
                      AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'OLR03: agent % holds a live writer/admin membership in operator '
                        'group %, and a retired identity may hold no write authority there; '
                        'nothing was changed', OLD.agent_id, OLD.operator_group_id
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership in the same act: epigraph-operator '
                         'retire-link --revoke-membership.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_retire_only() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_operator_links_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_ctx jsonb;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.link_recorded', NEW.agent_id, true,
                jsonb_build_object('operator_id', NEW.operator_id,
                                   'operator_group_id', NEW.operator_group_id,
                                   'retired', NEW.retired,
                                   'recorded_by', session_user));
    ELSIF OLD.retired IS DISTINCT FROM NEW.retired THEN
        -- Set by `epigraph_retire_operator_link` for its own UPDATE only.
        v_ctx := NULLIF(pg_catalog.current_setting('epigraph.operator_link_retire', true),
                        '')::jsonb;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES (CASE WHEN NEW.retired THEN 'operator.link_retired'
                     ELSE 'operator.link_unretired' END,
                NEW.agent_id, true,
                pg_catalog.jsonb_build_object(
                    'operator_id', NEW.operator_id,
                    'operator_group_id', NEW.operator_group_id,
                    'retired_before', OLD.retired,
                    'retired', NEW.retired,
                    'reason', v_ctx ->> 'reason',
                    'memberships_revoked', (v_ctx ->> 'memberships_revoked')::integer,
                    'via', COALESCE(v_ctx ->> 'via', 'direct'),
                    'recorded_by', session_user));
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_retire_operator_link(
    p_agent             uuid,
    p_reason            text,
    p_revoke_membership boolean DEFAULT false)
RETURNS TABLE (outcome text, operator_id uuid, operator_group_id uuid,
               memberships_revoked integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_operator uuid;
    v_group    uuid;
    v_retired  boolean;
    v_revoked  integer := 0;
BEGIN
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'OLR02: an elevated session retires no operator link; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'OLR01: only a maintenance session retires an operator link; nothing '
                        'was changed'
            USING ERRCODE = '42501';
    END IF;
    IF p_agent IS NULL OR p_reason IS NULL OR pg_catalog.btrim(p_reason) = ''
       OR p_revoke_membership IS NULL THEN
        RAISE EXCEPTION 'epigraph_retire_operator_link: an agent and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF pg_catalog.length(p_reason) > 1000 THEN
        RAISE EXCEPTION 'epigraph_retire_operator_link: the reason is at most 1000 characters'
            USING ERRCODE = '22023';
    END IF;

    -- Every link write and every registration, one at a time (107 section 10).
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));

    SELECT l.operator_id, l.operator_group_id, l.retired
      INTO v_operator, v_group, v_retired
      FROM public.operator_links l
     WHERE l.agent_id = p_agent
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_link'::text, NULL::uuid, NULL::uuid, 0;
        RETURN;
    END IF;
    IF v_retired THEN
        RETURN QUERY SELECT 'already_retired'::text, v_operator, v_group, 0;
        RETURN;
    END IF;

    -- ZERO write authority is a precondition (122's retire, section 7): the
    -- agent's rows in the operator group, then the group row, locked first.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = p_agent
       FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')) THEN
        IF NOT p_revoke_membership THEN
            RAISE EXCEPTION 'OLR03: agent % holds a live writer/admin membership in operator '
                            'group %, and a retired identity may hold no write authority there; '
                            'nothing was changed', p_agent, v_group
                USING ERRCODE = '55000',
                      HINT = 'Revoke that membership in the same act: epigraph-operator '
                             'retire-link --revoke-membership.';
        END IF;
        UPDATE public.group_memberships m
           SET revoked_at = pg_catalog.now()
         WHERE m.group_id = v_group AND m.agent_id = p_agent
           AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin');
        GET DIAGNOSTICS v_revoked = ROW_COUNT;
    END IF;

    PERFORM pg_catalog.set_config(
        'epigraph.operator_link_retire',
        pg_catalog.jsonb_build_object('reason', p_reason,
                                      'memberships_revoked', v_revoked,
                                      'via', 'epigraph_retire_operator_link')::text,
        true);
    UPDATE public.operator_links l
       SET retired = true
     WHERE l.agent_id = p_agent AND NOT l.retired;
    PERFORM pg_catalog.set_config('epigraph.operator_link_retire', '', true);

    RETURN QUERY SELECT 'retired'::text, v_operator, v_group, v_revoked;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean) FROM PUBLIC;

GRANT UPDATE (retired) ON public.operator_links TO epigraph_maintenance;
REVOKE UPDATE (retired) ON public.operator_links FROM epigraph_operator_link_retirer;
ALTER FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean)
    OWNER TO epigraph_maintenance;
REVOKE EXECUTE ON FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean) FROM PUBLIC;

COMMIT;

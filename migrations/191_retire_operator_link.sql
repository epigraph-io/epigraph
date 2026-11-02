-- 191_retire_operator_link.sql
-- An audited, maintenance-only verb that retires an existing LIVE operator
-- link, and an audit row for every flip of `operator_links.retired` on any
-- path (backlog 4dec90c2).
--
-- ===================================================================
-- 1. WHY
--
-- 107 records an operator link as LIVE (the agent acts for its operator) or
-- RETIRED (the operator owns the agent's claims, and the agent may never act
-- for it). Every link function INSERTs a row; none ever changes one. 107's
-- `link-retired` path records a NEW retired link and refuses an agent that
-- already has a live link to the same operator ("a retire is not a
-- demotion"). So once a live link existed there was no supported way to
-- retire it: `operator_links` had no UPDATE policy, the maintenance role no
-- UPDATE grant, and 122's audit trigger `operator_links_audit` fired AFTER
-- INSERT only. Retiring a live link took a raw UPDATE on a superuser login,
-- which wrote no `security_events` row.
--
-- ===================================================================
-- 2. WHAT THIS FILE DOES
--
-- (a) `epigraph_retire_operator_link(agent, reason, revoke_membership)`,
--     SECURITY DEFINER, maintenance-only (a maintenance-role member or a
--     superuser login; EXECUTE is the maintenance role's alone). In order:
--       * refuses an ELEVATED session (OLR02, 42501), as 181's GRA03 does.
--         125 never answers "live" to a maintenance or superuser login, so
--         on today's grants this arm is unreachable; it stays so that a
--         later grant to another role cannot turn it into an elevated write;
--       * refuses any other session (OLR01, 42501);
--       * requires an agent and a non-blank reason (22004) of at most 1000
--         characters (22023);
--       * takes 107's link advisory lock, `epigraph.operator_links`, so it is
--         serialised against every link writer and registration;
--       * returns `no_link` (nothing written) when the agent has no link, and
--         `already_retired` (nothing written) when its link is retired: the
--         call is idempotent and a repeat writes no audit row;
--       * ZERO write authority is a precondition, as in 107/122's retire: a
--         live `writer` / `admin` row for the agent in the link's operator
--         group (the row 107's live link records) is refused (OLR03, 55000)
--         unless `revoke_membership` is true, in which case those rows are
--         revoked in the same transaction (rows locked first, then the group
--         row, the order every roster writer takes them);
--       * flips `retired` to true. 148's
--         `operator_links_refuse_retired_system_agent` fires on that UPDATE,
--         so a registered system agent is refused (55000) with nothing
--         written;
--       * returns `retired` with the operator, the group and the number of
--         membership rows it revoked.
--     The reason, the revoked count and the verb's name reach the audit
--     trigger through one transaction-local setting,
--     `epigraph.operator_link_retire`, set just before the UPDATE and cleared
--     right after it.
-- (b) 122's `epigraph_operator_links_audit` re-bodied (md5 precondition on
--     122's body) and its trigger re-created AFTER INSERT OR UPDATE OF
--     retired. The INSERT branch is 122's, byte for byte in what it writes.
--     An UPDATE that changes `retired` writes one `operator.link_retired`
--     (false -> true) or `operator.link_unretired` (true -> false; only a
--     superuser can) row naming the operator, the group, the before and
--     after state, the reason and revoked count when the verb passed them,
--     `via` (`epigraph_retire_operator_link`, or `direct` for any other
--     statement) and `session_user`. `via` and the reason are ADVISORY: they
--     come from a session-settable setting, so a maintenance login could set
--     it before a direct UPDATE; `recorded_by` (`session_user`) is the
--     attribution, and (c) holds a direct UPDATE to the verb's precondition
--     either way. An UPDATE that leaves `retired` as it was writes nothing.
--     The function keeps 122's `public, pg_temp` path, signature, owner and
--     ACL (185's precedent for a re-body).
-- (c) A retire-only guard, `operator_links_retire_only` (BEFORE UPDATE, an
--     INVOKER): for every login but a superuser, an UPDATE may only flip
--     `retired` from false to true. An un-retire, or a change to any other
--     column, is refused (OLR04, 42501). And the verb's precondition lives on
--     the TABLE too (122 section 1c's convention: a maintenance login's
--     direct write meets the definer's checks): a false -> true flip while
--     the agent still holds a live `writer` / `admin` row in the link's
--     operator group is refused (OLR03, 55000, the verb's HINT). Inside the
--     verb those rows are already revoked by an earlier command when
--     `revoke_membership` is true, so the verb passes. The guard reads
--     `group_memberships` as the invoker; every session that passes (d)'s
--     UPDATE policy passes `group_memberships_tenancy` by the same
--     `epigraph_definer_bypass()` arm, so no row can be hidden from it. It
--     takes no lock: a direct statement is NOT serialised against the link
--     writers by 107's advisory lock (taking it here, after the row lock,
--     would invert the verb's order and could deadlock); the verb is the
--     serialised path. A superuser stays outside the guard, as it is outside
--     every other guard here (it can disable a trigger); its un-retire is
--     audited by (b).
-- (d) The grants the verb's UPDATE needs and nothing more: UPDATE on the one
--     column `retired` for the maintenance role, and an UPDATE policy that
--     admits only a maintenance-owned frame or member
--     (`epigraph_definer_bypass()`, as 107's INSERT policy). The application
--     role still holds SELECT on the table only.
-- (e) Both event types reserved (148's RESTRICTIVE shape): the application
--     role keeps INSERT on `security_events` (077), so without this it could
--     forge a retirement record.
--
-- Convention for the new functions as 172: `SET search_path = pg_catalog,
-- pg_temp`, every public object schema-qualified, built-ins written
-- `pg_catalog.`. Owner `epigraph_maintenance`; EXECUTE revoked from PUBLIC
-- and the application role. The owner and grant blocks are role-guarded
-- like every such block since 060 and can silently no-op;
-- `tenancy_backfill.rs`'s registers report it, and `schema_contract.rs`
-- pins the catalog at head.
--
-- ===================================================================
-- 3. UNDO
--
--   DROP POLICY IF EXISTS security_events_operator_link_retire_privileged
--       ON public.security_events;
--   DROP POLICY IF EXISTS operator_links_definer_retire ON public.operator_links;
--   REVOKE UPDATE (retired) ON public.operator_links FROM epigraph_maintenance;
--   DROP TRIGGER IF EXISTS operator_links_retire_only ON public.operator_links;
--   DROP FUNCTION IF EXISTS public.epigraph_operator_links_retire_only();
--   DROP FUNCTION IF EXISTS public.epigraph_retire_operator_link(uuid, text, boolean);
--   then re-run 122's `CREATE OR REPLACE FUNCTION
--   public.epigraph_operator_links_audit` block and its `DROP TRIGGER` /
--   `CREATE TRIGGER operator_links_audit AFTER INSERT` pair verbatim.
-- Links this file's verb retired stay retired (a retired link is permanent,
-- 107), as do their audit rows (082: immutable).
-- **Applied to throwaway databases only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the audit function still carries 122's body, which (b)
-- re-states. CREATE OR REPLACE replaces a body whole, so applying this over
-- another body would silently drop that body's arm. The md5 is of `prosrc`.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_operator_links_audit()');
    IF v_found IS DISTINCT FROM 'a430b22656c42df202b0fc9cb51ef0f5' THEN
        RAISE EXCEPTION '191: public.epigraph_operator_links_audit() is not the body 191 '
                        're-states (122''s, md5 a430b22656c42df202b0fc9cb51ef0f5); found md5 %. '
                        'Another migration re-bodied it, or 122 is not applied; nothing was '
                        'changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the audit with every '
                         'delta instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- (b) THE AUDIT, ON INSERT AND ON EVERY FLIP OF `retired`
-- ===================================================================
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

DROP TRIGGER IF EXISTS operator_links_audit ON public.operator_links;
CREATE TRIGGER operator_links_audit
    AFTER INSERT OR UPDATE OF retired ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_audit();

-- ===================================================================
-- (c) A LINK IS ONLY EVER RETIRED
-- ===================================================================
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

DROP TRIGGER IF EXISTS operator_links_retire_only ON public.operator_links;
CREATE TRIGGER operator_links_retire_only
    BEFORE UPDATE ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_retire_only();

-- ===================================================================
-- (d) THE UPDATE PATH: one column, a maintenance frame only
-- ===================================================================
DROP POLICY IF EXISTS operator_links_definer_retire ON public.operator_links;
CREATE POLICY operator_links_definer_retire ON public.operator_links
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- (e) THE AUDIT ROWS ARE THE TRIGGER'S ALONE
-- ===================================================================
-- length('operator.link_retired') = 21, length('operator.link_unretired') = 23.
DROP POLICY IF EXISTS security_events_operator_link_retire_privileged ON public.security_events;
CREATE POLICY security_events_operator_link_retire_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        (lower(left(btrim(event_type), 21)) <> 'operator.link_retired'
         AND lower(left(btrim(event_type), 23)) <> 'operator.link_unretired')
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- ===================================================================
-- (a) THE VERB
-- ===================================================================
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

-- ===================================================================
-- OWNERSHIP AND GRANTS, guarded as every such block since 060.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_retire_operator_link(uuid, text, boolean) '
                'TO epigraph_maintenance';
        -- The verb runs as this role, so it holds the one column it writes.
        -- A direct write by the same role meets the same rules on the table:
        -- (c) admits only a false -> true flip of an agent with zero write
        -- authority in the operator group, and (b) audits it.
        EXECUTE 'GRANT UPDATE (retired) ON public.operator_links TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_retire_operator_link(uuid, text, boolean) FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_retire_only() '
                'FROM epigraph_app';
    END IF;
END $$;

-- 236: `epigraph_live_memberships(agent)` answers only for the session
-- principal (or a maintenance session). Backlog fad5a6c4.
--
-- ===================================================================
-- 1. WHY
--
-- `epigraph_live_memberships(uuid)` (077, re-stated by 164, 165 and 235) is
-- a SECURITY DEFINER granted to the application role. Until this file it
-- answered for ANY agent id: an application-role session could list another
-- agent's live group memberships, and since 165 the ones it holds only
-- through a role binding as well. 077 recorded that as a residual because its
-- one caller, `Viewer::resolve`, ran before any principal was stamped, so
-- there was no session subject to bind to. 165 carried it as an accepted
-- residual, and the change that added 165 named binding it to the calling
-- principal as the planned follow-up. This is that follow-up.
--
-- ===================================================================
-- 2. THE SPLIT
--
--   * `epigraph_live_memberships_unbound(agent)` (NEW): 235's body, verbatim.
--     Owned by the maintenance role, EXECUTE revoked from PUBLIC and never
--     granted to the application role. Maintenance-owned definers that must
--     ask about an agent other than the session principal call it.
--   * `epigraph_live_memberships(agent)` (RE-BODIED): the twin's rows, but
--     only when ONE of these holds, else no rows:
--       - `agent` is the session principal (`epigraph_principal_id()`);
--       - the session is a maintenance session (`epigraph_bypass()`,
--         `session_user` is a member of the maintenance role);
--       - the session user is a superuser.
--     Same signature, result, owner and application grant, so every caller's
--     SQL is unchanged. Its path becomes `pg_catalog, pg_temp` (172's form).
--
-- No arm for "the principal's operator" or "an agent the principal
-- operates": no application-role caller needs one (measured on a database at
-- head 235: the only definer bodies that call the read are the two below that
-- pass the session principal and the two team lists re-pointed in section 3),
-- and each would be another answer about an agent that is not the caller.
--
-- ===================================================================
-- 3. THE CALLERS
--
-- Definer bodies, measured from `pg_proc.prosrc` at head 235:
--   * `epigraph_publicize_claims`, `epigraph_share_claims_with_team` (215):
--     ask for `epigraph_principal_id()` itself; unchanged, they keep calling
--     the bound read.
--   * `epigraph_writable_teams(agent)` (206), `epigraph_readable_teams(agent)`
--     (234): parameterised by agent; `Viewer::resolve` calls the second on an
--     unstamped connection. Re-stated here with their one call re-pointed at
--     the twin, so each answers exactly as before. Nothing else changes in
--     either body.
-- Application callers (Rust), changed in the same PR:
--   * `GroupMembershipRepository::list_live_for_agent` (`Viewer::resolve`,
--     the unauthenticated reader's self-check) stamps `agent` as the
--     principal for its one statement (`set_config(..., true)`, gone at the
--     statement's end) before it calls the read.
--   * `AgentRepository::delegated_principal_pool` does the same with the
--     DELEGATOR, whose own memberships it reads.
--   * `agent_writes_group_conn` and `live_team_writer_groups_conn` run on a
--     transaction stamped from the caller's own viewer, whose principal is the
--     agent they ask about; unchanged.
--
-- ===================================================================
-- 4. WHAT THIS IS NOT
--
-- The principal setting is a transport, not an authority boundary: a holder
-- of the application DSN can set it, and can stamp any group set anyway. So
-- this does not stop a hostile holder of that DSN, which reads far more than
-- memberships by stamping. It removes the AMBIENT answer: an application
-- session no longer gets another agent's memberships by naming its id. A
-- caller has to stamp that agent as its own principal first, which no request
-- path does for an agent other than its caller.
--
-- `epigraph_writable_teams(agent)` and `epigraph_readable_teams(agent)` stay
-- parameterised and application-executable, as before: they answer an
-- agent's TEAM groups (with `own` / `operator`), not its full membership set
-- or its roles. Binding them is a separate change.
--
-- ===================================================================
-- 5. DEPLOY ORDER: BINARIES FIRST
--
-- A binary built before this file calls the read on an UNSTAMPED pool
-- (`Viewer::resolve`, the delegation check). On a database with 236 it gets
-- no rows: every viewer resolves to public-only and every delegated run token
-- is refused (fail-closed, but an outage). That includes any other service
-- that links `epigraph-db` at an older revision and resolves viewers on an
-- unstamped pool. Deploy every such binary at or above this file's revision
-- first; the new binaries work against 235's body as well (stamping the
-- principal changes nothing there). Then migrate.
--
-- ===================================================================
-- 6. PRECONDITION, OWNER, GRANTS
--
-- Refuses to apply over bodies other than the ones it was written from (md5
-- of `prosrc`, 165's precondition shape): 235's `epigraph_live_memberships`,
-- 206's `epigraph_writable_teams`, 234's `epigraph_readable_teams`. Owners
-- and grants of the re-stated bodies are unchanged (CREATE OR REPLACE keeps
-- them) and re-asserted below, role-guarded as every such block since 060.
--
-- ===================================================================
-- UNDO: `docs/runbooks/236-undo.sql` (re-states the three predecessor bodies,
-- then drops the twin). Roll the binaries back only AFTER the undo if they
-- predate this file.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_live     text;
    v_writable text;
    v_readable text;
BEGIN
    SELECT md5(p.prosrc) INTO v_live FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_live_memberships(uuid)');
    SELECT md5(p.prosrc) INTO v_writable FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_writable_teams(uuid)');
    SELECT md5(p.prosrc) INTO v_readable FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_readable_teams(uuid)');
    IF v_live IS DISTINCT FROM '7648baee271b2163a52c28db1b4a74b6' THEN
        RAISE EXCEPTION '236: epigraph_live_memberships(uuid) is not the body 236 re-states '
                        '(235''s, md5 7648baee271b2163a52c28db1b4a74b6); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_live, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_writable IS DISTINCT FROM 'fe6592171c20613810ef6b1ddf39c36e' THEN
        RAISE EXCEPTION '236: epigraph_writable_teams(uuid) is not the body 236 re-states '
                        '(206''s, md5 fe6592171c20613810ef6b1ddf39c36e); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_writable, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_readable IS DISTINCT FROM '7da080030db7dbaeae7f60074d59b660' THEN
        RAISE EXCEPTION '236: epigraph_readable_teams(uuid) is not the body 236 re-states '
                        '(234''s, md5 7da080030db7dbaeae7f60074d59b660); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_readable, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- The twin: 235's body, verbatim (every name in it is already
-- schema-qualified), on 172's `pg_catalog, pg_temp` path: a NEW definer does
-- not resolve through `public`. Maintenance only.
-- -------------------------------------------------------------------
CREATE FUNCTION public.epigraph_live_memberships_unbound(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.group_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(p_agent, true)))
       -- 235: a personal-group row of an agent allowlisted for the group's
       -- owner lapses with that allowance.
       AND (g.kind <> 'personal'
            OR g.created_by_agent_id = p_agent
            OR NOT EXISTS (SELECT 1 FROM public.author_binding_clients r
                            WHERE r.agent_id = p_agent
                              AND r.operator_id = g.created_by_agent_id)
            OR public.epigraph_human_of(p_agent, true) = g.created_by_agent_id)
    UNION
    SELECT d.group_id, d.role
      FROM public.epigraph_role_derived_memberships(p_agent, now()) d
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships_unbound(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- The bound read: the twin's rows for the session principal only (section 2).
-- Moved to 172's `pg_catalog, pg_temp` path with the new body (every name in
-- it is schema-qualified), so it leaves the definers that resolve through
-- `public`.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT u.group_id, u.role
      FROM public.epigraph_live_memberships_unbound(p_agent) u
     -- 236: only for the session principal, a maintenance session, or a
     -- superuser session; any other caller gets no rows.
     WHERE p_agent = public.epigraph_principal_id()
        OR public.epigraph_bypass()
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                    WHERE r.rolname = session_user AND r.rolsuper)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- 206's `epigraph_writable_teams`; delta = the twin in place of the bound read.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_writable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships_unbound(p_agent) m
         WHERE m.role IN ('writer', 'admin')
    ), h AS (
        SELECT public.epigraph_human_of(p_agent, true) AS human
    )
    SELECT g.id,
           CASE WHEN g.id IN (SELECT o.group_id FROM own o) THEN 'own' ELSE 'operator' END
      FROM public.groups g, h
     WHERE p_agent IS NOT NULL
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR (h.human IS NOT NULL AND h.human <> p_agent
                AND public.epigraph_operator_writes_group(h.human, g.id)))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- 234's `epigraph_readable_teams`; delta = the twin in place of the bound read.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_readable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships_unbound(p_agent) m
    ), h AS (
        SELECT public.epigraph_human_of(p_agent, true) AS human
    ), hm AS (
        SELECT m.group_id
          FROM h
          JOIN public.group_memberships m ON m.agent_id = h.human
         WHERE h.human IS NOT NULL AND h.human <> p_agent
           AND m.revoked_at IS NULL
           AND public.epigraph_is_human_operator(h.human)
    )
    SELECT g.id,
           CASE WHEN g.id IN (SELECT o.group_id FROM own o) THEN 'own' ELSE 'operator' END
      FROM public.groups g
     WHERE p_agent IS NOT NULL
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR g.id IN (SELECT x.group_id FROM hm x))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships_unbound(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_writable_teams(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_readable_teams(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships_unbound(uuid) '
                'TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 236 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- The bound read and the two team lists: called on the application
        -- role, as before. The twin: never.
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships_unbound(uuid) '
                'FROM epigraph_app';
    END IF;
END $$;

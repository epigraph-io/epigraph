-- 346: the team lists `epigraph_writable_teams(agent)` /
-- `epigraph_readable_teams(agent)` answer only for the session principal (the
-- writable list also for the principal's operated agent), and
-- `epigraph_is_group_admin(group)` decides on the principal's LIVE
-- membership. Backlogs 1c5edc26 and a91d957d.
--
-- ===================================================================
-- 1. WHY: THE TEAM LISTS (1c5edc26)
--
-- 236 bound `epigraph_live_memberships(agent)` to the session principal and
-- left the two team lists parameterised and application-executable (236
-- section 4: "Binding them is a separate change"). So an application session,
-- stamped or not, still listed any agent's TEAM groups (its own writer/admin
-- and reader teams, role-derived ones included, plus the ones it reaches
-- through its live human) by naming its id. This file is that separate change.
--
-- ===================================================================
-- 2. THE GATES
--
-- Both bodies are 236's, verbatim, with one uncorrelated conjunct added to the
-- outer WHERE (a one-time filter: a refused session scans nothing). Each
-- answers its rows only when ONE of these holds, and otherwise no rows:
--
--   * `agent` is the session principal (`epigraph_principal_id()`);
--   * the session is a maintenance session (`epigraph_bypass()`);
--   * the session user is a superuser;
--   * `epigraph_writable_teams` ONLY: the session principal is a live human
--     operator (`epigraph_is_human_operator`, 122) holding a live, not
--     retired, `operator_links` row for `agent` (107). This is exactly 209's
--     'operator' admission to `epigraph_set_agent_default_group`, the one
--     definer that asks the list about an agent other than the principal: an
--     operator setting its agent's default team checks the team against the
--     AGENT's list (209's VIS02). The set-default routes (REST and MCP) then
--     read the same list on the same operator-stamped transaction for their
--     response. Without this arm both would refuse every operator-set team
--     default. 236's pinned residual test named the need ("then needs an arm
--     for an agent the principal operates"). A retired link, 149's
--     author-binding allowance and a non-registered "operator" do not open it,
--     as they do not admit 209.
--
-- `epigraph_readable_teams` has no operator arm: its one caller
-- (`Viewer::resolve`, through `list_operator_readable_teams`) asks about the
-- principal it is resolving, and nothing asks it about anyone else.
--
-- The callers, measured from `pg_proc.prosrc` at head 273:
--   * definers that pass `epigraph_principal_id()` (206's and 215/242's
--     publicize / share / set-default-group bodies): unchanged, admitted by
--     the principal arm;
--   * 209's `epigraph_set_agent_default_group`: passes the target agent,
--     admitted by the principal arm ('self') or the operator arm ('operator');
--   * Rust (same change): `list_operator_readable_teams` stamps the agent it
--     resolves for its one statement (236's `list_live_for_agent` form);
--     `ClaimRepository::resolve_visibility_choice` stamps the write's author
--     inside a savepoint that is rolled back, so the caller's own stamp
--     survives; the set-default routes read on the caller-stamped transaction.
--
-- ===================================================================
-- 3. WHY: THE GROUP-ADMIN DECISION (a91d957d)
--
-- `epigraph_is_group_admin(group)` (077, never re-bodied since) asked the raw
-- table: an unrevoked `role = 'admin'` row of the principal. A row can stop
-- counting without being revoked (164: a verb-made team group's row counts
-- while its agent's human is a live human operator; 235: a personal-group row
-- of an allowlisted agent lapses with the allowance). Every viewer resolve
-- follows those rules (236's bound read), so a lapsed admin reads nothing of
-- the group, yet this function still called it an admin, and through it:
--   * 077's `group_memberships_tenancy` WITH CHECK (writes to the roster);
--   * 087/129's privatization plan policies;
--   * 181's `epigraph_mark_group_reseal_required` (GRA01).
--
-- Re-bodied over 236's bound `epigraph_live_memberships(principal)` with
-- `role = 'admin'`: the same rows `Viewer::resolve` reads, so the database's
-- admin decision and the viewer's group set cannot disagree about a lapse. A
-- role-derived membership (165) is never 'admin' (165's
-- `group_role_bindings.member_role` CHECK is reader/writer), so this admits no
-- one the raw read did not. Still no `p_agent` argument (077's reasoning: a
-- two-argument form granted to the application role is a membership oracle).
-- Moved to 172's `pg_catalog, pg_temp` path (every name qualified): the
-- register of definers resolving through `public` shrinks by one.
--
-- The privatization checks that ask about an agent OTHER than the principal
-- (the other-admin count and the caller's own admin row in
-- `InstanceAdminRepository::privatization_authority`, the dispatch-time
-- approver check `PrivatizationRepository::is_live_group_admin_conn`) cannot
-- use this function or the bound read; they move, in the same change, onto
-- 273's `epigraph_group_live_roster(group)`, which applies the same two lapse
-- rules to every member and answers on the maintenance connection both of
-- them already run on. No new definer is added.
--
-- ===================================================================
-- 4. WHAT THIS IS NOT
--
-- The principal setting is a transport, not an authority boundary (236
-- section 4): a holder of the application DSN can stamp any principal. This
-- removes the AMBIENT answer: an application session no longer gets another
-- agent's teams by naming its id.
--
-- 081's two privatization triggers (the plan guard's plurality count and the
-- approver guard) are SECURITY INVOKER bodies that still count raw unrevoked
-- admin rows. They are not re-stated here: the API and job checks above now
-- refuse a lapsed admin before either trigger is reached, and the triggers
-- remain the coarser backstop. Moving them onto the roster is a separate
-- change.
--
-- ===================================================================
-- 5. DEPLOY ORDER: BINARIES FIRST
--
-- A binary built before this file calls `epigraph_readable_teams` (every
-- viewer resolve) and `epigraph_writable_teams` (every claim write's
-- visibility resolution) on an UNSTAMPED pool. On a database with 346 it gets
-- no rows: an operated agent silently stops reading its human's teams, every
-- write that names no visibility lands private instead of in the author's
-- team, and every explicit team write is refused (fail-closed, but a silent
-- behaviour change). That includes any other service linking `epigraph-db` at
-- an older revision (bump its pin first). The new binaries work against
-- 236's bodies as well (stamping the principal changes nothing there). Then
-- migrate.
--
-- `EPIGRAPH_MIGRATE_ON_BOOT` applies every embedded migration, as
-- `epigraph-migrate` does: the first server restarted on a build that embeds
-- this file would apply it before the other binaries are upgraded. Unset it on
-- every unit for this rollout and apply this file with `epigraph-migrate` last
-- (or ship the binary change in a release before the one that embeds this
-- file).
--
-- ===================================================================
-- 6. PRECONDITION, OWNER, GRANTS
--
-- Refuses to apply over bodies other than the ones it was written from (md5 of
-- `prosrc`, 165's precondition shape): 236's `epigraph_writable_teams` and
-- `epigraph_readable_teams`, 077's `epigraph_is_group_admin`. 236's
-- `epigraph_live_memberships_unbound` is NOT changed (273 and
-- `group_live_roster.rs` pin its md5). Owners and grants of the re-stated
-- bodies are unchanged (CREATE OR REPLACE keeps them) and re-asserted below,
-- role-guarded as every such block since 060.
--
-- ===================================================================
-- UNDO: `docs/runbooks/346-undo.sql` (re-states the three predecessor bodies).
-- Roll the binaries back only AFTER the undo if they predate this file.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_writable text;
    v_readable text;
    v_admin    text;
BEGIN
    SELECT md5(p.prosrc) INTO v_writable FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_writable_teams(uuid)');
    SELECT md5(p.prosrc) INTO v_readable FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_readable_teams(uuid)');
    SELECT md5(p.prosrc) INTO v_admin FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_is_group_admin(uuid)');
    IF v_writable IS DISTINCT FROM 'd675bc199f78f07db83e1268ef9c5eaf' THEN
        RAISE EXCEPTION '346: epigraph_writable_teams(uuid) is not the body 346 re-states '
                        '(236''s, md5 d675bc199f78f07db83e1268ef9c5eaf); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_writable, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_readable IS DISTINCT FROM 'd98f6b56fa1fb3b40d831501a0a44106' THEN
        RAISE EXCEPTION '346: epigraph_readable_teams(uuid) is not the body 346 re-states '
                        '(236''s, md5 d98f6b56fa1fb3b40d831501a0a44106); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_readable, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_admin IS DISTINCT FROM 'd7cd46f92f9d8b93d7562ace0d547205' THEN
        RAISE EXCEPTION '346: epigraph_is_group_admin(uuid) is not the body 346 re-states '
                        '(077''s, md5 d7cd46f92f9d8b93d7562ace0d547205); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_admin, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- 236's `epigraph_writable_teams`; delta = the gate (section 2), operator arm
-- included.
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
       -- 346: only for the session principal, the live human operator holding
       -- a live operator link to `p_agent` (209's 'operator' admission), a
       -- maintenance session, or a superuser session; anyone else gets no rows.
       AND COALESCE(
             p_agent = public.epigraph_principal_id()
             OR public.epigraph_bypass()
             OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                         WHERE r.rolname = session_user AND r.rolsuper)
             OR (public.epigraph_is_human_operator(public.epigraph_principal_id())
                 AND EXISTS (SELECT 1 FROM public.operator_links l
                              WHERE l.agent_id = p_agent
                                AND l.operator_id = public.epigraph_principal_id()
                                AND NOT l.retired)),
             false)
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR (h.human IS NOT NULL AND h.human <> p_agent
                AND public.epigraph_operator_writes_group(h.human, g.id)))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- 236's `epigraph_readable_teams`; delta = the gate (section 2), no operator
-- arm.
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
       -- 346: only for the session principal, a maintenance session, or a
       -- superuser session; anyone else gets no rows.
       AND COALESCE(
             p_agent = public.epigraph_principal_id()
             OR public.epigraph_bypass()
             OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                         WHERE r.rolname = session_user AND r.rolsuper),
             false)
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR g.id IN (SELECT x.group_id FROM hm x))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- 077's `epigraph_is_group_admin`; delta = the principal's LIVE memberships
-- (236's bound read) in place of the raw table (section 3), on 172's path.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_is_group_admin(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT public.epigraph_principal_id() IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.epigraph_live_memberships(public.epigraph_principal_id()) m
       WHERE m.group_id = p_group
         AND m.role = 'admin')
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid) FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_writable_teams(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_readable_teams(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_is_group_admin(uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 346 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

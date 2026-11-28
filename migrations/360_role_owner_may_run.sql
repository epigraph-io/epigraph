-- 360_role_owner_may_run.sql
-- The host's owner-role question for a role's schedule: does this role have
-- a live holder, and is the identity that runs the schedule attached to it?
--
-- ===================================================================
-- 1. WHY
--
-- 166's `epigraph_role_agent_may_run(agent)` answers about an AGENT: every
-- live attachment it holds must be held by its own linked human. An agent
-- with no live attachment reads `unattached` and may run. That is the right
-- answer for an agent that belongs to no role, and the wrong one for an
-- identity that runs a ROLE'S schedule but was never attached to that role
-- (a schedule set up before the attachment, an identity the operator forgot,
-- a successor whose copy the operator detached): the role's ruling ("an
-- agent attached to a role cannot run while no human holds it") never
-- reaches it, and the schedule runs in the role's gap.
--
-- The host knows which role a schedule belongs to (the schedule's
-- `owner_role`); the database knows the attachments and the holders. This
-- file adds the question that joins them, so the host can refuse such a run
-- (the tripwire) instead of trusting that the attachment was made.
--
-- ===================================================================
-- 2. THE QUESTION
--
-- `epigraph_role_owner_may_run(p_role_id uuid, p_agent uuid) RETURNS text`,
-- exactly one of:
--   * `not_attached`: `p_agent` holds no LIVE attachment to the role. Live is
--     166's gate predicate: not detached, `valid_from <= t`, and `t <
--     valid_to` or no `valid_to`, at `clock_timestamp()`. Every row counts,
--     a succession copy (`inherited_from` set: the registration's copy, 166
--     step 5b, and the attach-time lineage follow as 195 chains it) as much
--     as a row made by name, as they do for 166's gate.
--   * `no_holder`: it is attached, and no human holds the role now (166's
--     gate's `no_holder` arm verbatim: a non-revoked assignment for which
--     123's `epigraph_live_role_assignment` answers at `clock_timestamp()`).
--   * `held`: it is attached, and some human holds the role now.
-- `not_attached` is decided FIRST: an identity outside the role learns
-- nothing about the role's holder, and the operator's remedy (attach it)
-- comes before the holder's.
-- `held` says only that the role has a holder. Whether the agent's OWN
-- linked human is that holder (166's `not_holder`) stays
-- `epigraph_role_agent_may_run`'s answer, which the host asks as before.
--
-- `p_role_id` is the role's NODE (`platform_roles.role_node_id`, the agent
-- row 123 creates for every role), the only uuid a role has. A NULL argument
-- or a uuid that is no role's node raises `22023` (nothing is answered): a
-- misconfigured or swapped call is refused, not read as `not_attached` or
-- `no_holder`. NEVER `42883`: the host reads 42883 as "this database
-- predates the question" and runs the schedule unchecked, so the body names
-- every relation and function schema-qualified (an unqualified call would
-- raise 42883 at run time on this path).
--
-- No writes: the body only reads `platform_roles`, `role_agents` and
-- `role_assignments`. It is VOLATILE only because it reads the statement's
-- clock, as 248's `epigraph_role_agent_may_run` does.
--
-- ===================================================================
-- 3. WHO MAY ASK
--
-- EXECUTE: `epigraph_identity_attestor` (the host's login) and the owner
-- `epigraph_maintenance`; revoked from PUBLIC and from `epigraph_app`. The
-- application role never needs it (epigraph-mcp asks about its own agent
-- through `epigraph_role_agent_may_run`), and an application grant would be
-- the roster oracle 248 narrowed: `agents` is world-readable, so a caller
-- could ask about every (role, agent) pair. There is no body-level caller
-- check: the ACL is the gate.
--
-- THE ATTESTOR'S GRANT, OUT OF BAND (as 166 section 4). The grant below is
-- made only when `epigraph_identity_attestor` exists when this file runs.
-- Where operations create (or re-create) the attestor after it, run with
-- 161's recipe:
--   GRANT EXECUTE ON FUNCTION public.epigraph_role_owner_may_run(uuid, uuid)
--       TO epigraph_identity_attestor;
-- Without it the host's question is denied (42501), which the host treats
-- as an unavailable answer.
--
-- OWNER. `role_agents` and `role_assignments` are FORCE RLS and admit a
-- maintenance-owned definer frame. Under any other owner both reads would
-- see no row and every identity would read `not_attached`: closed, but with
-- a reason that sends the operator to attach identities that are attached.
-- So the body checks its owner first, inline as 166's gate does (the frame's
-- `current_user` or the `session_user` must be a member of
-- `epigraph_maintenance`; skipped on a database without that role), and
-- under a wrong owner raises 166's `ROL01` naming the remedy instead of
-- answering. The host refuses the run on any code but 42883, so this changes
-- no outcome, only the reason. `tenancy_backfill verify` also reports a
-- wrong owner (registered there at 360).
--
-- PATH. 172's form: `SET search_path = pg_catalog, pg_temp`, every name
-- qualified (`definer_search_path_ratchet`).
--
-- ===================================================================
-- 4. UNDO AND DEPLOY ORDER
--
-- `docs/runbooks/360-undo.sql` drops the function. Either order: a host that
-- asks before this file is applied gets 42883 and runs the schedule as it
-- did before the question existed (logging a warning); this file changes no
-- other object, so an older host is unaffected.

SET LOCAL lock_timeout = '3s';

CREATE FUNCTION public.epigraph_role_owner_may_run(p_role_id uuid, p_agent uuid)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role text;
    v_at   timestamptz := pg_catalog.clock_timestamp();
BEGIN
    -- FAIL LOUD under a wrong owner (166's gate's check, verbatim in form):
    -- such a frame reads no `role_agents` row, and would answer
    -- `not_attached` for every identity.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance')
       AND NOT pg_catalog.pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
       AND NOT pg_catalog.pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER') THEN
        RAISE EXCEPTION 'ROL01: epigraph_role_owner_may_run runs as %, which cannot read '
                        'role_agents; refusing rather than reading every agent as not_attached',
                        current_user
            USING ERRCODE = 'ROL01',
                  HINT = 'Nothing was answered. ALTER FUNCTION '
                         'public.epigraph_role_owner_may_run(uuid, uuid) OWNER TO '
                         'epigraph_maintenance (tenancy_backfill verify reports it).';
    END IF;
    IF p_role_id IS NULL OR p_agent IS NULL THEN
        RAISE EXCEPTION 'epigraph_role_owner_may_run: the role node and the agent are required'
            USING ERRCODE = '22023';
    END IF;
    SELECT r.key INTO v_role
      FROM public.platform_roles r
     WHERE r.role_node_id = p_role_id;
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'epigraph_role_owner_may_run: % is no platform role''s node', p_role_id
            USING ERRCODE = '22023',
                  HINT = 'Pass platform_roles.role_node_id for the schedule''s owner role, '
                         'then the agent id.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.role_agents ra
                    WHERE ra.role = v_role AND ra.agent_id = p_agent
                      AND ra.detached_at IS NULL
                      AND ra.valid_from <= v_at
                      AND (ra.valid_to IS NULL OR v_at < ra.valid_to)) THEN
        RETURN 'not_attached';
    END IF;
    IF EXISTS (SELECT 1 FROM public.role_assignments x
                WHERE x.role = v_role AND x.revoked_at IS NULL
                  AND public.epigraph_live_role_assignment(
                          x.holder_person_id, v_role, v_at) IS NOT NULL) THEN
        RETURN 'held';
    END IF;
    RETURN 'no_holder';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_owner_may_run(uuid, uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_owner_may_run(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_role_owner_may_run(uuid, uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_role_owner_may_run(uuid, uuid) '
                'FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_identity_attestor') THEN
        -- The host asks before firing a schedule that names an owner role.
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_role_owner_may_run(uuid, uuid) '
                'TO epigraph_identity_attestor';
    END IF;
END $$;

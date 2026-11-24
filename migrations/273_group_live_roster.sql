-- 273: `epigraph_group_live_roster(group)`, the EXPLICIT members of ONE group
-- whose membership row still counts, answered only to a session that already
-- reads that group's roster. Backlogs 93ed2ec3 and f712db53.
--
-- ===================================================================
-- 1. WHY
--
-- A `group_memberships` row can stop counting without being revoked:
--   * 164: a row in a verb-made team group (`did:epigraph:group:`) counts
--     only while its agent's human is a live human operator;
--   * 235: a personal-group row of an agent allowlisted for the group's owner
--     counts only while that allowance still names the owner.
-- `epigraph_live_memberships` (236's bound read, the source of every resolved
-- viewer's group set) follows both rules, so a lapsed member reads nothing of
-- the group. The raw roster readers (`revoked_at IS NULL`) did not: the
-- group info route listed and counted a lapsed row, and the profile detail
-- check treated a lapsed member as a groupmate.
--
-- Asking `epigraph_live_memberships(member)` once per member does not work
-- since 236: it answers only for the session principal (backlog fad5a6c4),
-- so on the application role every other member reads as not live (the
-- reason the first attempt at this change was not merged). Undoing 236 is
-- not an option. This file adds a read of ONE group's roster instead.
--
-- ===================================================================
-- 2. THE READ
--
--   public.epigraph_group_live_roster(p_group uuid)
--     RETURNS TABLE (agent_id uuid, role text)
--
-- The unrevoked `group_memberships` rows of `p_group` that still count under
-- 164's and 235's rules, one row per member (060's `group_memberships_one_live`
-- allows one live row per (group, agent)), `role` as stored. The two rules
-- are 236's `epigraph_live_memberships_unbound` direct arm, written out with
-- the row's agent in place of the parameter (see section 5 for how the two
-- copies are kept together).
--
-- It answers ONLY when one of these holds, and otherwise returns no row:
--   * `p_group` is in the session's stamped group set
--     (`epigraph_session_groups()`);
--   * the session is a maintenance session (`epigraph_bypass()`);
--   * the session user is a superuser.
--
-- A member DERIVED from a role binding (165) holds no row and is NOT listed.
-- Listing derived members would be 165's "roster oracle" (165 section 4: the
-- derived roster stays maintenance-only), and computing them costs one
-- derivation per candidate (backlog 8377cf18). Readers that ask about the
-- CALLER (is the caller a member, with which role) use the bound
-- `epigraph_live_memberships(caller)` on a connection stamped with the
-- caller, which does count derived membership.
--
-- ===================================================================
-- 3. WHY THIS DISCLOSES NOTHING NEW
--
-- 077's `group_memberships_tenancy` USING clause admits every row of a group
-- in `epigraph_session_groups()`. So on a connection whose stamp holds
-- `p_group`, a plain `SELECT agent_id, role FROM group_memberships WHERE
-- group_id = p_group AND revoked_at IS NULL` already returns a SUPERSET of
-- this function's rows. What the function adds is the FILTER (which of those
-- rows lapsed), which needs reads the application role does not hold (164's
-- registration check, 235's allowance table), hence SECURITY DEFINER.
--
-- The gate keys on the stamp, not on the principal's membership, for that
-- reason: it is exactly the authority the table policy already accepts. The
-- stamp is a transport, not an authority boundary (236 section 4): a holder
-- of the application DSN can stamp any group, and then reads that group's
-- rows from the table directly anyway. A stamp built by `Viewer::resolve`
-- never holds a group its principal does not live-read, so a lapsed member's
-- request is answered no rows.
--
-- The gate is narrower than the table policy: 077's principal arm (a
-- session sees its own rows) and creator arm (a creator sees its group's
-- rows) do not open it.
--
-- ===================================================================
-- 4. SHAPE
--
-- 172's form: `SET search_path = pg_catalog, pg_temp` (pg_temp last, 271's
-- rule), every public name schema-qualified. Owner `epigraph_maintenance`,
-- whose definer frame `group_memberships_tenancy` admits through
-- `epigraph_definer_bypass()`; under a NON-member owner the scan is filtered
-- to the caller's own view and still filtered by the gate: fail closed.
-- EXECUTE revoked from PUBLIC, granted to `epigraph_app` (the request DSN).
-- The guarded owner and grant blocks can silently no-op; `tenancy_backfill`'s
-- registers report it.
--
-- `ROWS 20` and `COST 50`: a group's live roster is tens of rows, not the
-- default 1000 (backlog 8377cf18: inflated set-returning estimates push the
-- membership path above the JIT thresholds). The gate is uncorrelated, so it
-- is a one-time filter: a session outside the group scans nothing.
--
-- ===================================================================
-- 5. THE TWO COPIES OF THE DIRECT ARM
--
-- Precondition (165's shape): refuses to apply unless
-- `epigraph_live_memberships_unbound`'s body is still the one this file was
-- written from (236's, md5 of `prosrc` 7648baee271b2163a52c28db1b4a74b6).
-- `crates/epigraph-db/tests/group_live_roster.rs` holds the same md5 at head,
-- so a later migration that re-states the twin fails that test until it
-- re-states this function with the same delta, and the same file checks the
-- two answers agree for every lapse shape.
--
-- ===================================================================
-- 6. DEPLOY ORDER: MIGRATE FIRST
--
-- Additive: nothing calls the function before the binaries that use it. A
-- binary built with this file calls it from every read of the group roster
-- or of the profile detail rule, and gets 42883 without it:
--   * epigraph-api: `GET /api/v1/groups/:id` (member list and count),
--     `GET /api/v1/agents` and `GET /api/v1/agents/:id` (the ORCID / ROR
--     redaction, `profile_details_visible`), `GET /api/v1/agents/search`;
--   * epigraph-mcp: `find_agent` and `get_agent` (the agent-lookup card and
--     matcher).
-- So migrate BEFORE deploying the API and MCP binaries (or let
-- `EPIGRAPH_MIGRATE_ON_BOOT` apply it on the first one restarted).
--
-- ===================================================================
-- UNDO: `docs/runbooks/273-undo.sql` (drops the function). Roll the binaries
-- back FIRST: a binary built with this file fails those reads without it.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_twin text;
BEGIN
    SELECT md5(p.prosrc) INTO v_twin FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_live_memberships_unbound(uuid)');
    IF v_twin IS DISTINCT FROM '7648baee271b2163a52c28db1b4a74b6' THEN
        RAISE EXCEPTION '273: epigraph_live_memberships_unbound(uuid) is not the body 273 copies '
                        'its direct arm from (236''s, md5 7648baee271b2163a52c28db1b4a74b6); '
                        'found md5 %. Nothing was changed', COALESCE(v_twin, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Re-state epigraph_group_live_roster with the same delta as the twin '
                         'in a reconciling migration instead of this one.';
    END IF;
END $$;

CREATE FUNCTION public.epigraph_group_live_roster(p_group uuid)
RETURNS TABLE (agent_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER
ROWS 20 COST 50
SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.agent_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.group_id = p_group AND m.revoked_at IS NULL
       -- 273's gate (section 2): only a session that already reads this
       -- group's roster; uncorrelated, so a one-time filter.
       AND (p_group = ANY (public.epigraph_session_groups())
            OR public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper))
       -- 164 (236's twin, direct arm): a verb-made team group's row counts
       -- while its agent's human is a live human operator.
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(m.agent_id, true)))
       -- 235 (236's twin, direct arm): a personal-group row of an agent
       -- allowlisted for the group's owner lapses with that allowance.
       AND (g.kind <> 'personal'
            OR g.created_by_agent_id = m.agent_id
            OR NOT EXISTS (SELECT 1 FROM public.author_binding_clients r
                            WHERE r.agent_id = m.agent_id
                              AND r.operator_id = g.created_by_agent_id)
            OR public.epigraph_human_of(m.agent_id, true) = g.created_by_agent_id)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_live_roster(uuid) FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_group_live_roster(uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; '
                     'epigraph_group_live_roster stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_group_live_roster(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

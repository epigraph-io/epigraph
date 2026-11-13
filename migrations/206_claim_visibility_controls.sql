-- 206: claim visibility controls -- team by default, private and public on
-- request, and the audited acts that widen a claim later (owner request
-- 2026-11-05; spec docs/tenancy/claim-visibility-controls.md).
--
-- ===================================================================
-- 0. WHAT THIS FILE ADDS, AND WHY EACH PIECE IS A DEFINER
-- ===================================================================
--
-- Five functions. Each is SECURITY DEFINER on 172's path, `SET search_path =
-- pg_catalog, pg_temp`, with every `public` object named qualified
-- (`definer_search_path_ratchet.rs`: a new definer may not resolve through
-- `public`). Each has EXECUTE revoked from PUBLIC and granted to
-- `epigraph_app`, and is owned by `epigraph_maintenance` (section 6). That is
-- the shape of every app-callable definer since 107.
--
--   1. epigraph_writable_teams(agent)      READ  which TEAM groups an agent may
--                                                write a claim into
--   2. epigraph_default_group(agent)       READ  the agent's default team, else
--                                                its live human's
--   3. epigraph_set_default_group(group)   WRITE the session principal's default
--   4. epigraph_publicize_claims(ids, why) WRITE group -> public (team admins)
--   5. epigraph_share_claims_with_team(ids, group, why)
--                                          WRITE (group, home) -> (group, team)
--
-- The two reads are definers because they must answer the same on an UNSTAMPED
-- `epigraph_app` connection, where `group_memberships_tenancy` and
-- `groups_tenancy` hide every row. 107's `epigraph_operator_actor` and 165's
-- `epigraph_live_memberships` are definers for the same reason. They disclose
-- nothing `epigraph_live_memberships(uuid)` does not already disclose to the
-- same role.
--
-- The three writes are definers because each one meets a guard that is right
-- for every other path and is not relaxed here:
--
--   * 074 `claims_block_widening` refuses group -> public unless
--     `epigraph.allow_declassify = 'yes'`, and refuses a SEALED claim
--     unconditionally. docs/tenancy.md says that GUC is an interlock, not an
--     authorization: "the authorization for that decision has to be made in
--     the repo/route layer above it". Here it is made in the function body,
--     before the GUC is armed, and the GUC is armed transaction-locally around
--     ONE statement.
--   * 115 `<table>_owner_immutable` refuses any non-privileged change of
--     `owner_group_id`, and private -> team is exactly such a change. The body
--     runs as `epigraph_maintenance`, which the guard admits, only after the
--     body has checked the caller's authority.
--   * 072/110/120 propagation (arm (d)) copies the claim's new pair onto every
--     claim-derived row, but it never WIDENS an edge (`AND NOT (e.visibility =
--     'group' AND m.v = 'public')`). An edge between two claims that are now
--     public would stay group-only. The privatization revert answers this with
--     `recompute_boundary_meet_conn` on a maintenance connection. D9 gives
--     request processes no maintenance connection, so publicize carries the
--     same recompute in its own body (section 4).
--
-- WHO THE CALLER IS. `epigraph_principal_id()`, the session GUC that every 077
-- policy keys on. docs/tenancy.md ("The same reasoning applies to the three
-- TENANCY GUCs") records that the database does not protect it, and that the
-- control is that only `ScopedPool::acquire_as` / `begin_as` set it, from a
-- resolved `Viewer`. These functions rest on that convention exactly as the
-- whole policy set does. They never take the actor as an argument.
--
-- THE WRITE WINDOW. Each writing body switches to `public, pg_temp` (still
-- `pg_temp` last) for its write statements only, with a transaction-local
-- `set_config`, and switches back. The function-level SET restores the
-- pinned path at exit in any case. The reason is that those statements fire
-- the tables' legacy INVOKER triggers, which inherit the caller's path and
-- name their helpers unqualified: `trigger_validate_edge_refs` (001) calls
-- `validate_edge_reference(..)`. On the pinned path that call fails with
-- 42883, but only on a connection that had not already cached the
-- resolution. That was measured over HTTP, while the MCP test, on a
-- connection that had inserted an edge first, passed. Every name in these
-- bodies is still `public.`-qualified. The decisions are made before the
-- window opens.
--
-- NO SESSION STATE. A body keeps its working set in local variables and
-- arrays, never in a temporary relation. A temporary table belongs to the
-- calling SESSION, not to the definer's owner, so the caller could create one
-- of the same name first, with its own rows and triggers, and the body would
-- then read and write the caller's relation with the owner's privileges.
-- `definer_search_path_ratchet.rs` refuses any function body a definer can
-- run (the definers, and the INVOKER helpers and triggers they run as their
-- owner, such as the write window's) that creates or names one.
--
-- DECIDED ON THE ROWS IT WRITES. Each widening act first locks the claims it
-- may act on (`FOR NO KEY UPDATE`, in id order: the group-visible rows the
-- session reads), then classifies them, so an owner or visibility change
-- committed by another session before the call either finishes first (and is
-- what gets classified) or waits for this one. Its UPDATE re-checks the
-- classified owner as well, and if fewer rows move than were classified (a
-- row that was not locked, because it became readable only after the lock)
-- the call raises `VIS04` (40001) and nothing is changed.
--
-- MEMBERSHIP is always read live, through `epigraph_live_memberships` (own
-- rows, 149's human-group filter, 165's role-derived rows). Nothing is cached.

-- ===================================================================
-- 1. epigraph_writable_teams(agent)
-- ===================================================================
-- The team groups `p_agent` may write a claim into, with how it may:
--   'own'      -- p_agent itself holds a live writer/admin membership;
--   'operator' -- p_agent's LIVE human (`epigraph_human_of(p_agent, true)`, a
--                 different agent) writes the group. Owner decision D-V3
--                 (2026-11-05): an operated agent writes where its human
--                 writes. It is the same rule as the claims trigger's writer
--                 scope (`epigraph_require_writer_scope` ->
--                 `epigraph_operator_writes_group`), so the trigger and this
--                 list agree.
-- A TEAM is an active group of kind 'team' or 'community'. Personal, world and
-- seed groups are never teams. "Private" is the home group, which
-- `ClaimRepository::default_decl_for_author` resolves.
CREATE OR REPLACE FUNCTION public.epigraph_writable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships(p_agent) m
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

-- ===================================================================
-- 2. epigraph_default_group(agent)
-- ===================================================================
-- `agents.default_group_id` (062, unused until now) of the agent, else of its
-- live human. NOT validated here: the caller checks it against
-- `epigraph_writable_teams` at write time, so a default that has stopped being
-- writable (membership revoked, group suspended) is ignored rather than obeyed.
CREATE OR REPLACE FUNCTION public.epigraph_default_group(p_agent uuid)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE(
        (SELECT a.default_group_id FROM public.agents a WHERE a.id = p_agent),
        (SELECT a.default_group_id FROM public.agents a
          WHERE a.id = public.epigraph_human_of(p_agent, true) AND a.id <> p_agent))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_default_group(uuid) FROM PUBLIC;

-- ===================================================================
-- 3. epigraph_set_default_group(group)
-- ===================================================================
-- Sets the SESSION PRINCIPAL's `default_group_id`. NULL clears it. A non-NULL
-- group must be one of `epigraph_writable_teams(principal)`. One
-- `security_events` row, `agent.default_group_set`.
--
-- A definer, not an UPDATE under `agents_self_update`: 077's history (the
-- deleted `key_kind = 'derived'` arm) is a record of how a self-update policy
-- reached `default_group_id` on rows it should not, and a policy cannot check
-- the target against the principal's memberships.
CREATE OR REPLACE FUNCTION public.epigraph_set_default_group(p_group uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_prev uuid;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: setting a default team needs an authenticated principal; '
                        'nothing was changed' USING ERRCODE = '42501';
    END IF;
    IF p_group IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.epigraph_writable_teams(v_principal) t WHERE t.group_id = p_group)
    THEN
        RAISE EXCEPTION 'VIS02: group % is not a team this agent may write (writer or admin, '
                        'its own or its live human''s); nothing was changed', p_group
            USING ERRCODE = '42501';
    END IF;
    SELECT a.default_group_id INTO v_prev FROM public.agents a WHERE a.id = v_principal;
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see header
    UPDATE public.agents SET default_group_id = p_group WHERE id = v_principal;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('agent.default_group_set', v_principal, true,
            jsonb_build_object('previous', v_prev, 'default_group_id', p_group,
                               'migration', 206, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    RETURN p_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_default_group(uuid) FROM PUBLIC;

-- ===================================================================
-- 4. epigraph_publicize_claims(ids, reason): group -> public
-- ===================================================================
-- Owner decision D-V2 (2026-11-05): only a live ADMIN of the claim's owning
-- group may publicize it. That is the principal's OWN admin membership, with no
-- operator arm: publishing is a disclosure decision, and an operated agent
-- whose human is an admin does not inherit it. No second approver. Every call
-- that changes anything writes one `claim.publicized` row.
--
-- ALL OR NOTHING. Every id is classified first:
--   not_found         -- no such claim, or the session cannot read it (an
--                        unreadable claim is answered exactly like a missing
--                        one, never as "exists but forbidden");
--   already_public    -- nothing to do;
--   refused_not_admin -- readable, but the principal is not a live admin of
--                        its owning group;
--   refused_sealed    -- it has a `claim_encryption` row. 074's arm (a) refuses
--                        that with no override and stays the backstop. This is
--                        the readable answer;
--   publicize         -- to be changed.
-- If any id is not_found or refused_*, NOTHING is changed and the
-- classification is returned. Otherwise every `publicize` row becomes
-- `publicized`. The rows are locked before they are classified, and the
-- UPDATE moves only a row whose owner is still the one classified; a short
-- count raises `VIS04` (section 0, DECIDED ON THE ROWS IT WRITES).
--
-- WHAT MOVES. The claim's visibility, with its owner unchanged: the team stays
-- the owner of record, and a later privatization acts on it. Arm (d) then
-- copies 'public' onto every claim-derived row except PINNED evidence (110),
-- which stays group-visible with its pin owner. The edges incident to the
-- claims are then recomputed, widening allowed, by the privatization revert's
-- meet (`PrivatizationRepository::recompute_boundary_meet_conn`). Two public
-- epistemic endpoints give the recorded writer's group (120, D8), else world.
-- One private endpoint gives that side's group. Two different private groups
-- give owner + co-owner.
--
-- ONE DIFFERENCE FROM THE REVERT'S MEET. An edge someone DECLARED `('group',
-- G)` between endpoints that were public anyway would widen under a blind
-- recompute (120 keeps that declaration on INSERT but does not record it; the
-- revert carries the same caveat). So only edges whose tuple EQUALS the meet of
-- their endpoints before the update are recomputed. An edge already at odds
-- with its meet was declared, and is left as it was.
CREATE OR REPLACE FUNCTION public.epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)
RETURNS TABLE (claim_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_readable uuid[] := public.epigraph_session_groups();
    v_ids uuid[];
    v_cls_ids uuid[];
    v_cls_out text[];
    v_cls_own uuid[];
    v_todo uuid[];
    v_meet_edges uuid[];
    v_bad boolean;
    v_edges bigint := 0;
    v_pinned bigint := 0;
    v_owners uuid[];
    v_moved bigint := 0;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: publicize needs an authenticated principal; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'VIS03: publicize needs a non-empty reason; nothing was changed'
            USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(DISTINCT x) INTO v_ids FROM unnest(p_claim_ids) x WHERE x IS NOT NULL;
    IF v_ids IS NULL OR cardinality(v_ids) > 500 THEN
        RAISE EXCEPTION 'VIS03: publicize takes 1 to 500 claim ids; nothing was changed'
            USING ERRCODE = '22023';
    END IF;

    -- Lock what may be acted on before classifying it (header: DECIDED ON THE
    -- ROWS IT WRITES). A row a concurrent session holds is waited for, and the
    -- classification below, a new statement, then reads what it committed.
    PERFORM 1 FROM public.claims c
      WHERE c.id = ANY(v_ids) AND c.visibility::text = 'group'
        AND c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[]))
      ORDER BY c.id FOR NO KEY UPDATE;

    -- The classification, as three parallel arrays ordered by claim id (see
    -- the header: no temporary relation).
    SELECT array_agg(i.id ORDER BY i.id),
           array_agg(CASE
             WHEN c.id IS NULL
                  OR NOT (c.visibility::text = 'public'
                          OR c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[])))
               THEN 'not_found'
             WHEN c.visibility::text = 'public' THEN 'already_public'
             WHEN NOT EXISTS (SELECT 1 FROM public.epigraph_live_memberships(v_principal) m
                               WHERE m.group_id = c.owner_group_id AND m.role = 'admin')
               THEN 'refused_not_admin'
             WHEN EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = c.id)
               THEN 'refused_sealed'
             ELSE 'publicize'
           END ORDER BY i.id),
           array_agg(c.owner_group_id ORDER BY i.id)
      INTO v_cls_ids, v_cls_out, v_cls_own
      FROM unnest(v_ids) AS i(id)
      LEFT JOIN public.claims c ON c.id = i.id;

    SELECT COALESCE(bool_or(u.o NOT IN ('publicize', 'already_public')), false),
           array_agg(u.id ORDER BY u.id) FILTER (WHERE u.o = 'publicize'),
           array_agg(DISTINCT u.g) FILTER (WHERE u.o = 'publicize')
      INTO v_bad, v_todo, v_owners
      FROM unnest(v_cls_ids, v_cls_out, v_cls_own) AS u(id, o, g);
    IF v_bad OR v_todo IS NULL THEN
        RETURN QUERY SELECT u.id, u.o FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
        RETURN;
    END IF;

    -- The edges whose tuple is their endpoint meet NOW, before anything moves
    -- (section header: a declared edge is not recomputed).
    SELECT array_agg(m.id) INTO v_meet_edges
      FROM (
        SELECT e.id, e.visibility, e.owner_group_id, e.co_owner_group_id,
               COALESCE(s.v, 'public')::text AS sv,
               COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
               COALESCE(t.v, 'public')::text AS tv,
               COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg,
               CASE WHEN public.epigraph_edge_writer_scope(e.source_type, e.target_type)
                         AND EXISTS (SELECT 1 FROM public.groups wg WHERE wg.id = e.writer_group_id)
                    THEN e.writer_group_id END AS wg
          FROM public.edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
         WHERE e.source_id = ANY(v_todo) OR e.target_id = ANY(v_todo)
      ) m
     WHERE (m.visibility::text, m.owner_group_id, m.co_owner_group_id) IS NOT DISTINCT FROM (
             CASE WHEN m.sv = 'public' AND m.tv = 'public' THEN 'public' ELSE 'group' END,
             CASE WHEN m.sv = 'public' AND m.tv = 'public'
                       THEN COALESCE(m.wg, '00000000-0000-0000-0000-000000000000'::uuid)
                  WHEN m.sv = 'public' THEN m.tg
                  ELSE m.sg END,
             CASE WHEN m.sv = 'group' AND m.tv = 'group' AND m.sg <> m.tg
                       THEN m.tg ELSE NULL END);

    SELECT count(*) INTO v_pinned
      FROM public.evidence ev
      JOIN public.evidence_visibility_pins vp ON vp.evidence_id = ev.id
     WHERE ev.claim_id = ANY(v_todo);

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see header
    -- THE widening statement, and the only one the GUC is armed around.
    PERFORM set_config('epigraph.allow_declassify', 'yes', true);
    UPDATE public.claims c
       SET visibility = 'public', updated_at = now()
      FROM unnest(v_cls_ids, v_cls_out, v_cls_own) AS u(id, o, g)
     WHERE c.id = u.id AND u.o = 'publicize'
       AND c.visibility::text = 'group' AND c.owner_group_id = u.g;
    GET DIAGNOSTICS v_moved = ROW_COUNT;
    PERFORM set_config('epigraph.allow_declassify', '', true);
    IF v_moved <> cardinality(v_todo) THEN
        RAISE EXCEPTION 'VIS04: % of % claim(s) changed owner or visibility while publicize ran; '
                        'nothing was changed, retry', cardinality(v_todo) - v_moved,
                        cardinality(v_todo) USING ERRCODE = '40001';
    END IF;

    IF v_meet_edges IS NOT NULL THEN
        WITH ep AS (
          SELECT e.id,
                 COALESCE(s.v, 'public')::text AS sv,
                 COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
                 COALESCE(t.v, 'public')::text AS tv,
                 COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg,
                 CASE WHEN public.epigraph_edge_writer_scope(e.source_type, e.target_type)
                           AND EXISTS (SELECT 1 FROM public.groups wg
                                        WHERE wg.id = e.writer_group_id)
                      THEN e.writer_group_id END AS wg
            FROM public.edges e
            CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
            CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
           WHERE e.id = ANY(v_meet_edges)
           ORDER BY e.id
        ), meet AS (
          SELECT ep.id,
                 (CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                       THEN 'public' ELSE 'group' END)::varchar(16) AS v,
                 CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                           THEN COALESCE(ep.wg, '00000000-0000-0000-0000-000000000000'::uuid)
                      WHEN ep.sv = 'public' THEN ep.tg
                      ELSE ep.sg END AS g,
                 CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                           THEN ep.tg ELSE NULL END AS co
            FROM ep
        )
        UPDATE public.edges e
           SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
          FROM meet m
         WHERE m.id = e.id
           AND m.g IS NOT NULL
           AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
               IS DISTINCT FROM (m.v, m.g, m.co);
        GET DIAGNOSTICS v_edges = ROW_COUNT;
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('claim.publicized', v_principal, true,
            jsonb_build_object('claim_ids', to_jsonb(v_todo),
                               'owner_group_ids', to_jsonb(v_owners),
                               'reason', p_reason,
                               'edges_widened', v_edges,
                               'evidence_kept_private', v_pinned,
                               'migration', 206,
                               'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY
        SELECT u.id, CASE WHEN u.o = 'publicize' THEN 'publicized' ELSE u.o END
          FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) FROM PUBLIC;

-- ===================================================================
-- 5. epigraph_share_claims_with_team(ids, group, reason): private -> team
-- ===================================================================
-- Moves a PRIVATE claim, `('group', H)` where H is the caller's home group,
-- into a team the caller writes. Visibility stays 'group', so this is not a
-- widening and the declassify GUC is not armed. H is the operator's personal
-- group for an agent with an acting operator link (107), else the caller's own
-- personal group. That is the same home `default_decl_for_author` writes
-- `private` claims into.
--
-- Authority, per claim: the caller wrote it (`claims.agent_id`), or the caller
-- is a live admin of H (the human whose personal group it is, sharing what its
-- agents wrote there). The target must be one of
-- `epigraph_writable_teams(caller)`.
--
-- Classified first, all or nothing, as section 4:
--   not_found, refused_not_private (public, or owned by a group other than H),
--   refused_not_author, refused_sealed (a sealed claim's key material is bound
--   to its group), refused_not_team_writer (the target is not writable), share.
-- Arm (d) re-owns the derived rows. Pinned evidence keeps its pin owner, and
-- edges take the meet; arm (d) handles group -> group without widening. One
-- `claim.shared_with_team` row is written. Locked before classified, and a
-- short UPDATE raises `VIS04`, as section 4.
CREATE OR REPLACE FUNCTION public.epigraph_share_claims_with_team(
    p_claim_ids uuid[], p_group_id uuid, p_reason text)
RETURNS TABLE (claim_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_readable uuid[] := public.epigraph_session_groups();
    v_home uuid;
    v_home_admin boolean;
    v_team_ok boolean;
    v_ids uuid[];
    v_cls_ids uuid[];
    v_cls_out text[];
    v_bad boolean;
    v_moved bigint := 0;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: sharing with a team needs an authenticated principal; '
                        'nothing was changed' USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 OR p_group_id IS NULL THEN
        RAISE EXCEPTION 'VIS03: share_claims_with_team needs a group and a non-empty reason; '
                        'nothing was changed' USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(DISTINCT x) INTO v_ids FROM unnest(p_claim_ids) x WHERE x IS NOT NULL;
    IF v_ids IS NULL OR cardinality(v_ids) > 500 THEN
        RAISE EXCEPTION 'VIS03: share_claims_with_team takes 1 to 500 claim ids; nothing was '
                        'changed' USING ERRCODE = '22023';
    END IF;

    SELECT a.operator_group_id INTO v_home FROM public.epigraph_operator_actor(v_principal) a;
    IF v_home IS NULL THEN
        SELECT g.id INTO v_home FROM public.groups g
         WHERE g.did_key = 'did:epigraph:personal:' || v_principal::text
           AND g.kind = 'personal';
    END IF;
    v_home_admin := v_home IS NOT NULL AND EXISTS (
        SELECT 1 FROM public.epigraph_live_memberships(v_principal) m
         WHERE m.group_id = v_home AND m.role = 'admin');
    v_team_ok := p_group_id IS DISTINCT FROM v_home AND EXISTS (
        SELECT 1 FROM public.epigraph_writable_teams(v_principal) t WHERE t.group_id = p_group_id);

    -- Lock, then classify (section 4, and the header).
    PERFORM 1 FROM public.claims c
      WHERE c.id = ANY(v_ids) AND c.visibility::text = 'group'
        AND c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[]))
      ORDER BY c.id FOR NO KEY UPDATE;

    -- The classification, as two parallel arrays ordered by claim id (see the
    -- header: no temporary relation).
    SELECT array_agg(i.id ORDER BY i.id),
           array_agg(CASE
             WHEN c.id IS NULL
                  OR NOT (c.visibility::text = 'public'
                          OR c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[])))
               THEN 'not_found'
             WHEN c.visibility::text <> 'group' OR c.owner_group_id IS DISTINCT FROM v_home
               THEN 'refused_not_private'
             WHEN c.agent_id IS DISTINCT FROM v_principal AND NOT v_home_admin
               THEN 'refused_not_author'
             WHEN EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = c.id)
               THEN 'refused_sealed'
             WHEN NOT v_team_ok THEN 'refused_not_team_writer'
             ELSE 'share'
           END ORDER BY i.id)
      INTO v_cls_ids, v_cls_out
      FROM unnest(v_ids) AS i(id)
      LEFT JOIN public.claims c ON c.id = i.id;

    SELECT COALESCE(bool_or(u.o <> 'share'), false) INTO v_bad FROM unnest(v_cls_out) AS u(o);
    IF v_bad THEN
        RETURN QUERY SELECT u.id, u.o FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see header
    UPDATE public.claims c
       SET owner_group_id = p_group_id, updated_at = now()
     WHERE c.id = ANY(v_cls_ids) AND c.owner_group_id = v_home AND c.visibility::text = 'group';
    GET DIAGNOSTICS v_moved = ROW_COUNT;
    IF v_moved <> cardinality(v_cls_ids) THEN
        RAISE EXCEPTION 'VIS04: % of % claim(s) changed owner or visibility while '
                        'share_claims_with_team ran; nothing was changed, retry',
                        cardinality(v_cls_ids) - v_moved, cardinality(v_cls_ids)
            USING ERRCODE = '40001';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('claim.shared_with_team', v_principal, true,
            jsonb_build_object('claim_ids', to_jsonb(v_cls_ids), 'from_group_id', v_home,
                               'to_group_id', p_group_id, 'reason', p_reason,
                               'migration', 206, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY SELECT u.id, 'shared'::text FROM unnest(v_cls_ids) AS u(id) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) FROM PUBLIC;

-- ===================================================================
-- 6. OWNERSHIP AND GRANTS
-- ===================================================================
-- Guarded, as every such block since 060 is. Without the maintenance role the
-- bodies stay owned by the migration runner. On a superuser runner they would
-- then bypass RLS outright, which `epigraph-tenancy-backfill verify` reports
-- as for every other definer.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_writable_teams(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_default_group(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_default_group(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 206 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_default_group(uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_set_default_group(uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_share_claims_with_team('
                'uuid[], uuid, text) TO epigraph_app';
    END IF;
END $$;

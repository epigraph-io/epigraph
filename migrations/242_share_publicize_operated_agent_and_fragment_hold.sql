-- 242: share and publicize refuse an operated agent, and hold a harvester
-- fragment that a claim staying put also cites (backlog ecd842bf, fc33ef1a;
-- spec docs/tenancy/share-with-team.md, ruling R1 and section 4.6).
--
-- ===================================================================
-- 0. WHAT THIS FILE CHANGES, AND WHY ONE FILE
-- ===================================================================
--
-- It re-states 215's two widening acts, `epigraph_publicize_claims(uuid[],
-- text)` and `epigraph_share_claims_with_team(uuid[], uuid, text)`, with the
-- same signatures and the same refusals (VIS01, VIS03, VIS04). Both fixes
-- change the same two bodies, so they are one migration (215's header says
-- why two files that each `CREATE OR REPLACE` one body lose a fix). Everything
-- 206's and 215's headers say about these bodies still holds: SECURITY
-- DEFINER on 172's path, every `public` object qualified, owned by
-- `epigraph_maintenance`, EXECUTE for `epigraph_app` only; the write window;
-- no session state; locked before classified; membership read live.
--
-- ===================================================================
-- 1. AN OPERATED AGENT ACTS ON NO AUTHORITY OF ITS OWN (ecd842bf)
-- ===================================================================
--
-- THE GAP. Ruling R1 of the share-with-team spec: an operated agent (an
-- agent acting under an operator link) may not share, move or publicize on
-- its own authority, whatever memberships it holds or inherits. 206 let it,
-- and 215 closed only part of it: `epigraph_engine::visibility_act` refuses a
-- share whose moved claim the agent's own session cannot write, which stops a
-- share into a team ONLY its human writes (206's `via = 'operator'` arm). An
-- operated agent that is itself a writer of the target team, or itself an
-- admin of a claim's owning team, still shared or publicized on its own say.
--
-- THE FIX. Each act asks who the caller belongs to,
-- `epigraph_human_of(principal, false)` (122, re-stated by 149): itself for a
-- registered human operator; its operator for an agent with an operator link
-- of ANY state (a retired link confers no authority either, 107); the
-- allowlisted operator for a client-allowlisted agent (149); NULL for an
-- agent that belongs to no human. When that is another agent, every readable
-- claim of the call is classified `refused_not_human`, so the call
-- refuses as a whole and changes nothing. Its human makes the same call
-- itself. `not_found` still wins (an unreadable claim must not read as
-- "exists, forbidden").
--
-- Share's target test also stops naming the operator arm
-- (`epigraph_writable_teams` rows with `via = 'own'` only): after the gate the
-- operator arm can only ever admit an operated caller, which the gate has
-- already refused, so this changes no outcome; it says in the body what the
-- rule is.
--
-- The outcome is the spec's own name for R1's refusal (`refused_not_human`,
-- spec test 12 and the `share_preview` row), so phase P1 widens who receives
-- it without changing the API's vocabulary a second time.
--
-- WHAT IT IS NOT. It is not R1's whole human gate (every caller must satisfy
-- `epigraph_is_human_operator`): an agent that belongs to no human (no
-- operator link, no client allowance; for example a role-attached agent, 166,
-- that has neither) is still judged by its own memberships, and a human's
-- delegated run token is a transport question. Those wait on the spec's
-- phase P1.
--
-- ===================================================================
-- 2. A FRAGMENT A CLAIM THAT STAYS ALSO CITES IS HELD (fc33ef1a)
-- ===================================================================
--
-- THE GAP. Arm (d) (`epigraph_propagate_tenancy`, last re-stated in 218)
-- re-stamps every fragment a changed claim cites. 218 added one guard: when
-- the changed claims' winner is public, a fragment another group-private claim
-- still cites is left. Nothing holds a fragment on a group-to-group move: a
-- share took a fragment the moved claim cites into the team even when a claim
-- that stays in the home group also cites it, and 215's source rule then saw
-- the source's fragments "agree" and moved the source too. Nor did publicize
-- hold a group fragment whose other citer is public. The spec's table (4.6,
-- `harvester_fragments`) says such a fragment is HELD in its current tenancy
-- (`shared-fragment`), for share and publicize alike.
--
-- THE FIX. Before the claims UPDATE each act collects the fragments that a
-- moving claim cites AND a claim outside the moving set (current or not, any
-- tenancy) also cites, locks them, and records their pair. After the UPDATE
-- (arm (d) has run) and the edge re-meet, it puts each back on that pair; 173's
-- trigger carries the fragment's audit reports back with it. 215's source
-- rule then runs on the post-hold fragments, so a source with a held fragment
-- and a moved one disagrees and is held (`harvester_sources_held`). The audit
-- row counts the held fragments (`harvester_fragments_held`).
--
-- 218's arm (d) is NOT changed: `restrict-claims` and `regroup-claims` rely
-- on it moving a fragment with a moved claim and put a kept node back
-- themselves (218's header, "Moving A to another group also moves a fragment
-- B cites with it; 218 keeps that"). The hold lives in the two app acts, as
-- the tools' does in the tools.
--
-- A held fragment can be narrower than every claim that cites it (publicize
-- when every other citer is public). That costs availability, never
-- disclosure, and is the spec's rule.
--
-- ===================================================================
-- 3. PRECONDITION, OWNER, GRANTS
-- ===================================================================
--
-- The file refuses to apply over a body other than the one it was written
-- from (md5 of `prosrc`, 235's precondition shape): 215's two bodies. Another
-- migration that re-bodied either must be reconciled into a new re-statement
-- instead. Owners and grants are unchanged (CREATE OR REPLACE keeps them) and
-- re-asserted below, role-guarded.
--
-- UNDO: `docs/runbooks/242-undo.sql` (re-states 215's two bodies byte for
-- byte). **Applied to throwaway databases only, NOT to any deployed
-- database.**
-- ===================================================================
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_pub   text;
    v_share text;
BEGIN
    SELECT md5(p.prosrc) INTO v_pub FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_publicize_claims(uuid[], text)');
    SELECT md5(p.prosrc) INTO v_share FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_share_claims_with_team(uuid[], uuid, text)');
    IF v_pub IS DISTINCT FROM '6927382377fdacec2034ae623befd087' THEN
        RAISE EXCEPTION '242: epigraph_publicize_claims is not the body 242 re-states '
                        '(215''s, md5 6927382377fdacec2034ae623befd087); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_pub, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_share IS DISTINCT FROM '9f33322313e37e27f9e6386e73e144e1' THEN
        RAISE EXCEPTION '242: epigraph_share_claims_with_team is not the body 242 re-states '
                        '(215''s, md5 9f33322313e37e27f9e6386e73e144e1); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_share, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- B. epigraph_publicize_claims(ids, reason): group -> public
-- ===================================================================
-- 215 section 4, with sections 1 and 2 above.
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
    v_evidence uuid[];
    v_meet_edges uuid[];
    v_bad boolean;
    v_edges bigint := 0;
    v_ev_edges bigint := 0;
    v_sources_moved bigint := 0;
    v_sources_held bigint := 0;
    v_scoped bigint := 0;
    v_divergence bigint := 0;
    v_pinned bigint := 0;
    v_owners uuid[];
    v_moved bigint := 0;
    v_human uuid;
    v_operated boolean;
    v_hold_ids uuid[];
    v_hold_own uuid[];
    v_hold_vis text[];
    v_frags_held bigint := 0;
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

    -- Section 1: an operated agent acts on no authority of its own.
    v_human := public.epigraph_human_of(v_principal, false);
    v_operated := v_human IS NOT NULL AND v_human <> v_principal;

    -- Lock what may be acted on before classifying it (206's header: DECIDED
    -- ON THE ROWS IT WRITES).
    PERFORM 1 FROM public.claims c
      WHERE c.id = ANY(v_ids) AND c.visibility::text = 'group'
        AND c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[]))
      ORDER BY c.id FOR NO KEY UPDATE;

    SELECT array_agg(i.id ORDER BY i.id),
           array_agg(CASE
             WHEN c.id IS NULL
                  OR NOT (c.visibility::text = 'public'
                          OR c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[])))
               THEN 'not_found'
             WHEN v_operated THEN 'refused_not_human'
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

    -- The moved claims' evidence, read before the claims UPDATE moves it
    -- (section 1).
    SELECT COALESCE(array_agg(ev.id ORDER BY ev.id), ARRAY[]::uuid[]) INTO v_evidence
      FROM public.evidence ev WHERE ev.claim_id = ANY(v_todo);

    -- The edges whose tuple is their endpoint meet NOW, before anything moves:
    -- those incident to a moved claim (206) and those incident to its
    -- evidence (section 1). A declared edge is not recomputed.
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
            OR (e.source_type = 'evidence' AND e.source_id = ANY(v_evidence))
            OR (e.target_type = 'evidence' AND e.target_id = ANY(v_evidence))
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

    -- Section 2: the fragments a moved claim cites that a claim NOT moving
    -- also cites, locked, with the pair each has now (before arm (d) runs).
    SELECT array_agg(f.id ORDER BY f.id) INTO v_hold_ids
      FROM public.harvester_fragments f
     WHERE EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND p.claim_id = ANY(v_todo))
       AND EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND NOT (p.claim_id = ANY(v_todo)));
    IF v_hold_ids IS NOT NULL THEN
        PERFORM 1 FROM public.harvester_fragments f
          WHERE f.id = ANY(v_hold_ids) ORDER BY f.id FOR NO KEY UPDATE;
        SELECT array_agg(f.id ORDER BY f.id), array_agg(f.owner_group_id ORDER BY f.id),
               array_agg(f.visibility::text ORDER BY f.id)
          INTO v_hold_ids, v_hold_own, v_hold_vis
          FROM public.harvester_fragments f WHERE f.id = ANY(v_hold_ids);
    END IF;

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see 206's header
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
        ), upd AS (
          UPDATE public.edges e
             SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
            FROM meet m
           WHERE m.id = e.id
             AND m.g IS NOT NULL
             AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
                 IS DISTINCT FROM (m.v, m.g, m.co)
          RETURNING e.source_id, e.source_type, e.target_id, e.target_type
        )
        -- `evidence_edges_rewritten` counts the edges reached ONLY through a
        -- moved claim's evidence (section 1), as share's count does: an edge
        -- between a moved claim and its own evidence is a 206 edge.
        SELECT count(*),
               count(*) FILTER (WHERE (upd.source_type = 'evidence'
                                       OR upd.target_type = 'evidence')
                                  AND NOT (upd.source_id = ANY(v_todo)
                                           OR upd.target_id = ANY(v_todo)))
          INTO v_edges, v_ev_edges
          FROM upd;
    END IF;

    -- Section 2: arm (d) moved every fragment of a moved claim; a held one
    -- goes back to the pair it had (its audit reports follow it, 173), and
    -- the source rule below then sees the post-hold fragments.
    IF v_hold_ids IS NOT NULL THEN
        UPDATE public.harvester_fragments f
           SET owner_group_id = h.g, visibility = h.v
          FROM unnest(v_hold_ids, v_hold_own, v_hold_vis) AS h(id, g, v)
         WHERE f.id = h.id
           AND (f.owner_group_id, f.visibility::text) IS DISTINCT FROM (h.g, h.v);
        v_frags_held := cardinality(v_hold_ids);
    END IF;

    -- 215 section 2: a source whose fragments now agree takes their pair.
    WITH touched AS (
        SELECT DISTINCT f.source_id
          FROM public.harvester_claim_provenance p
          JOIN public.harvester_fragments f ON f.id = p.fragment_id
         WHERE p.claim_id = ANY(v_todo)
    ), agree AS (
        SELECT f.source_id,
               (array_agg(f.owner_group_id))[1] AS g,
               (array_agg(f.visibility))[1]     AS v,
               count(DISTINCT f.owner_group_id::text || '/' || f.visibility) AS n
          FROM public.harvester_fragments f
         WHERE f.source_id IN (SELECT t.source_id FROM touched t)
         GROUP BY f.source_id
    ), moved AS (
        UPDATE public.harvester_sources hs
           SET owner_group_id = a.g, visibility = a.v
          FROM agree a
         WHERE a.source_id = hs.id AND a.n = 1
           AND (hs.owner_group_id, hs.visibility) IS DISTINCT FROM (a.g, a.v)
        RETURNING hs.id
    )
    SELECT (SELECT count(*) FROM moved), (SELECT count(*) FROM agree a WHERE a.n > 1)
      INTO v_sources_moved, v_sources_held;


    -- 215 section 3: the moved claims' stored scoped folds are stale.
    DELETE FROM public.ds_combined_beliefs d WHERE d.claim_id = ANY(v_todo);
    GET DIAGNOSTICS v_scoped = ROW_COUNT;
    DELETE FROM public.ds_bayesian_divergence dv WHERE dv.claim_id = ANY(v_todo);
    GET DIAGNOSTICS v_divergence = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('claim.publicized', v_principal, true,
            jsonb_build_object('claim_ids', to_jsonb(v_todo),
                               'owner_group_ids', to_jsonb(v_owners),
                               'reason', p_reason,
                               'edges_widened', v_edges,
                               'evidence_edges_rewritten', v_ev_edges,
                               'harvester_fragments_held', v_frags_held,
                               'harvester_sources_moved', v_sources_moved,
                               'harvester_sources_held', v_sources_held,
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'evidence_kept_private', v_pinned,
                               'migration', 242,
                               'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY
        SELECT u.id, CASE WHEN u.o = 'publicize' THEN 'publicized' ELSE u.o END
          FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) FROM PUBLIC;

-- ===================================================================
-- C. epigraph_share_claims_with_team(ids, group, reason): private -> team
-- ===================================================================
-- 215 section 5, with sections 1 and 2 above.
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
    v_evidence uuid[];
    v_meet_edges uuid[];
    v_ev_edges bigint := 0;
    v_sources_moved bigint := 0;
    v_sources_held bigint := 0;
    v_scoped bigint := 0;
    v_divergence bigint := 0;
    v_human uuid;
    v_operated boolean;
    v_hold_ids uuid[];
    v_hold_own uuid[];
    v_hold_vis text[];
    v_frags_held bigint := 0;
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

    -- Section 1: an operated agent acts on no authority of its own.
    v_human := public.epigraph_human_of(v_principal, false);
    v_operated := v_human IS NOT NULL AND v_human <> v_principal;

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
        SELECT 1 FROM public.epigraph_writable_teams(v_principal) t
         WHERE t.group_id = p_group_id AND t.via = 'own');

    -- Lock, then classify (206 section 4, and its header).
    PERFORM 1 FROM public.claims c
      WHERE c.id = ANY(v_ids) AND c.visibility::text = 'group'
        AND c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[]))
      ORDER BY c.id FOR NO KEY UPDATE;

    SELECT array_agg(i.id ORDER BY i.id),
           array_agg(CASE
             WHEN c.id IS NULL
                  OR NOT (c.visibility::text = 'public'
                          OR c.owner_group_id = ANY(COALESCE(v_readable, ARRAY[]::uuid[])))
               THEN 'not_found'
             WHEN v_operated THEN 'refused_not_human'
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

    -- The moved claims' evidence, and the edges on it whose tuple is their
    -- endpoint meet, read before the claims UPDATE moves the evidence
    -- (section 1). Never both-public here, so no writer scope.
    SELECT COALESCE(array_agg(ev.id ORDER BY ev.id), ARRAY[]::uuid[]) INTO v_evidence
      FROM public.evidence ev WHERE ev.claim_id = ANY(v_cls_ids);
    SELECT array_agg(m.id) INTO v_meet_edges
      FROM (
        SELECT e.id, e.visibility, e.owner_group_id, e.co_owner_group_id,
               COALESCE(s.v, 'public')::text AS sv,
               COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
               COALESCE(t.v, 'public')::text AS tv,
               COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg
          FROM public.edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
         WHERE (e.source_type = 'evidence' AND e.source_id = ANY(v_evidence))
            OR (e.target_type = 'evidence' AND e.target_id = ANY(v_evidence))
      ) m
     WHERE NOT (m.sv = 'public' AND m.tv = 'public')
       AND (m.visibility::text, m.owner_group_id, m.co_owner_group_id) IS NOT DISTINCT FROM (
             'group',
             CASE WHEN m.sv = 'public' THEN m.tg ELSE m.sg END,
             CASE WHEN m.sv = 'group' AND m.tv = 'group' AND m.sg <> m.tg
                       THEN m.tg ELSE NULL END);

    -- Section 2: the fragments a moved claim cites that a claim NOT moving
    -- also cites, locked, with the pair each has now (before arm (d) runs).
    SELECT array_agg(f.id ORDER BY f.id) INTO v_hold_ids
      FROM public.harvester_fragments f
     WHERE EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND p.claim_id = ANY(v_cls_ids))
       AND EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND NOT (p.claim_id = ANY(v_cls_ids)));
    IF v_hold_ids IS NOT NULL THEN
        PERFORM 1 FROM public.harvester_fragments f
          WHERE f.id = ANY(v_hold_ids) ORDER BY f.id FOR NO KEY UPDATE;
        SELECT array_agg(f.id ORDER BY f.id), array_agg(f.owner_group_id ORDER BY f.id),
               array_agg(f.visibility::text ORDER BY f.id)
          INTO v_hold_ids, v_hold_own, v_hold_vis
          FROM public.harvester_fragments f WHERE f.id = ANY(v_hold_ids);
    END IF;

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see 206's header
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

    IF v_meet_edges IS NOT NULL THEN
        WITH ep AS (
          SELECT e.id,
                 COALESCE(s.v, 'public')::text AS sv,
                 COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
                 COALESCE(t.v, 'public')::text AS tv,
                 COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg
            FROM public.edges e
            CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
            CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
           WHERE e.id = ANY(v_meet_edges)
           ORDER BY e.id
        ), meet AS (
          SELECT ep.id,
                 'group'::varchar(16) AS v,
                 CASE WHEN ep.sv = 'public' THEN ep.tg ELSE ep.sg END AS g,
                 CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                           THEN ep.tg ELSE NULL END AS co
            FROM ep
           WHERE NOT (ep.sv = 'public' AND ep.tv = 'public')
        )
        UPDATE public.edges e
           SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
          FROM meet m
         WHERE m.id = e.id
           AND m.g IS NOT NULL
           AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
               IS DISTINCT FROM (m.v, m.g, m.co);
        GET DIAGNOSTICS v_ev_edges = ROW_COUNT;
    END IF;

    -- Section 2: arm (d) moved every fragment of a moved claim; a held one
    -- goes back to the pair it had (its audit reports follow it, 173), and
    -- the source rule below then sees the post-hold fragments.
    IF v_hold_ids IS NOT NULL THEN
        UPDATE public.harvester_fragments f
           SET owner_group_id = h.g, visibility = h.v
          FROM unnest(v_hold_ids, v_hold_own, v_hold_vis) AS h(id, g, v)
         WHERE f.id = h.id
           AND (f.owner_group_id, f.visibility::text) IS DISTINCT FROM (h.g, h.v);
        v_frags_held := cardinality(v_hold_ids);
    END IF;

    -- 215 section 2: a source whose fragments now agree takes their pair.
    WITH touched AS (
        SELECT DISTINCT f.source_id
          FROM public.harvester_claim_provenance p
          JOIN public.harvester_fragments f ON f.id = p.fragment_id
         WHERE p.claim_id = ANY(v_cls_ids)
    ), agree AS (
        SELECT f.source_id,
               (array_agg(f.owner_group_id))[1] AS g,
               (array_agg(f.visibility))[1]     AS v,
               count(DISTINCT f.owner_group_id::text || '/' || f.visibility) AS n
          FROM public.harvester_fragments f
         WHERE f.source_id IN (SELECT t.source_id FROM touched t)
         GROUP BY f.source_id
    ), moved AS (
        UPDATE public.harvester_sources hs
           SET owner_group_id = a.g, visibility = a.v
          FROM agree a
         WHERE a.source_id = hs.id AND a.n = 1
           AND (hs.owner_group_id, hs.visibility) IS DISTINCT FROM (a.g, a.v)
        RETURNING hs.id
    )
    SELECT (SELECT count(*) FROM moved), (SELECT count(*) FROM agree a WHERE a.n > 1)
      INTO v_sources_moved, v_sources_held;


    -- 215 section 3: the moved claims' stored scoped folds are stale.
    DELETE FROM public.ds_combined_beliefs d WHERE d.claim_id = ANY(v_cls_ids);
    GET DIAGNOSTICS v_scoped = ROW_COUNT;
    DELETE FROM public.ds_bayesian_divergence dv WHERE dv.claim_id = ANY(v_cls_ids);
    GET DIAGNOSTICS v_divergence = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('claim.shared_with_team', v_principal, true,
            jsonb_build_object('claim_ids', to_jsonb(v_cls_ids), 'from_group_id', v_home,
                               'to_group_id', p_group_id, 'reason', p_reason,
                               'evidence_edges_rewritten', v_ev_edges,
                               'harvester_fragments_held', v_frags_held,
                               'harvester_sources_moved', v_sources_moved,
                               'harvester_sources_held', v_sources_held,
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'migration', 242, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY SELECT u.id, 'shared'::text FROM unnest(v_cls_ids) AS u(id) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) FROM PUBLIC;

-- ===================================================================
-- D. OWNERSHIP AND GRANTS (as 215 section 6, for the two bodies re-stated)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 242 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_share_claims_with_team('
                'uuid[], uuid, text) TO epigraph_app';
    END IF;
END $$;

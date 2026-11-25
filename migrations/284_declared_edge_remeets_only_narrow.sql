-- 284: a declared edge is only ever NARROWED by the re-meets outside the
-- privatization: the propagation trigger, 206's publicize and share re-meets
-- and a re-point (backlog 49044d29).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- 260 recorded an edge's DECLARED tenancy (`edges.declared_owner_group_id`,
-- `declared_co_owner_group_id`: a `('group', H)` tuple 072's no-widening arm
-- kept between two public endpoints) and taught ONE re-meet to honour it,
-- the privatization's (`PrivatizationRepository::
-- recompute_boundary_meet_conn`). Its header named the rest as not changed,
-- and each still treated a declared edge as derived:
--
--   * the propagation (`epigraph_propagate_tenancy`, 258's body): a claim
--     re-tenanted into G outside the privatization re-meet (an operator
--     restrict or regroup, a share) re-owned the edge to ('group', G): G's
--     members read an edge H's author had kept from them, and H's lost it;
--   * publicize (`epigraph_publicize_claims`, 242's body): an edge whose
--     tuple equalled its meet was widened with the claim, so H's admin
--     publicizing the claim at one end of an edge DECLARED private to H made
--     the edge readable by the world;
--   * share (`epigraph_share_claims_with_team`, 242's body): an edge on a
--     moved claim's evidence that sat on its meet was re-owned to the team;
--     one declared by another group and off its meet was left on that group
--     alone, so its members read an edge naming the team's evidence;
--   * a re-point (`epigraph_edges_tenancy`, 120's body, on UPDATE OF
--     source_id, target_id; a merge or dedup re-points) onto a private
--     endpoint took the meet and dropped the declared owner.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `epigraph_edge_declared_meet(dg, dco, mv, mg, mco)`: the privatization
--      re-meet's rule as one pure function (section 1 says it in full). A
--      derived edge takes the meet; a declared one the intersection of its
--      declaration and the meet where one owner plus one co-owner expresses
--      it, the meet (declared owner kept where it can be) where it does not
--      (`unmet`), and its exact declaration when the meet is public. The
--      Rust re-meet is unchanged and computes the same rule
--      (`declared_edge_remeet.rs` pins the agreement).
--   2. `epigraph_edges_tenancy()`: after 120's meet, a re-point of a declared
--      edge takes the rule's tuple for the declaration RECORDED on the row
--      (OLD), never a value bound in the same UPDATE. 072's no-widening arm
--      still runs first, unchanged (a declared edge re-pointed onto two
--      public endpoints keeps its tuple).
--   3. `epigraph_propagate_tenancy()`: 258's body with the edges statement's
--      meet passed through the rule. It still writes only where the MEET is
--      `group` (120's conjunct) and never widens; every other arm is 258's
--      byte for byte (the `derived` literal, the three CASE expressions).
--   4. `epigraph_publicize_claims`: its re-meet also takes every DECLARED
--      edge incident to a moved claim or its evidence (on or off its meet)
--      and computes it through the rule, so a declared edge goes back on its
--      declaration instead of public. The audit row reports
--      `declared_edges_held` (declared edges kept off their meet, or unmet)
--      and `migration: 284`.
--   5. `epigraph_share_claims_with_team`: the same for its evidence re-meet
--      (the moved claims' own edges are re-met by the propagation, item 3).
--      Audit: `declared_evidence_edges_held`, `migration: 284`.
--   6. A one-time repair (section 7) of the exposure the old re-meets left:
--      every declared edge whose tuple is not the rule's for its endpoints
--      now takes the rule's owner and, as co-owner, the one other group the
--      rule's tuple and its current tuple require together (so no session
--      gains it), or is left and counted when that takes three groups.
--      Counts are RAISEd as a NOTICE.
--
-- NOT changed: 260's recording trigger and owner guard; the Rust
-- privatization re-meet; the operator CLI's models of the cascade
-- (`restrict-claims`, `regroup-claims`), which predict an edge on a moved
-- claim as its meet and hold a claim whose declared edge that meet would
-- widen (fail-closed, as before; with this file the trigger only narrows
-- such an edge, so a hold there is now conservative).
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser (section 7 refuses
-- otherwise). No binary depends on it (the new audit keys are additive), so
-- it may go before or after any binary. Measure first:
-- `SELECT count(*) FROM edges WHERE declared_owner_group_id IS NOT NULL`
-- (section 7 reads those rows and their endpoints once, under a 3 s lock
-- timeout per statement; a lock-timeout failure means re-run).
--
-- Re-stating shared bodies: the GUARD refuses (55000) unless all four still
-- hold the bodies this file was written from (md5 of `prosrc`). A sibling
-- migration that re-bodied one of them first must be reconciled into a
-- re-statement of the MERGED body.
--
-- ORDER OF UNDOS: run `284-undo.sql` BEFORE `258-undo.sql`, `242-undo.sql`
-- or `260-undo.sql`. 258's refuses over 284's propagation body; 242's has no
-- guard and would silently put 242's publicize and share back; 260's drops
-- the two columns these four bodies read, after which every claim
-- re-tenant and edge re-point fails (42703).
--
-- Undo: `docs/runbooks/284-undo.sql` re-states the four predecessor bodies
-- byte for byte (CREATE OR REPLACE keeps owner and ACL) and drops the rule.
-- The edges section 7 narrowed STAY narrowed (fail-closed).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD: re-state only the bodies this file was written from
-- ===================================================================
-- md5(prosrc) of 120's `epigraph_edges_tenancy`, 258's
-- `epigraph_propagate_tenancy` and 242's `epigraph_publicize_claims` and
-- `epigraph_share_claims_with_team` (258's literal is the one
-- `docs/runbooks/258-undo.sql` accepts as 258's). A migration that re-bodied
-- one of them before this file would be silently reverted here: refuse.
DO $$
DECLARE v_edges text; v_prop text; v_pub text; v_share text;
BEGIN
    SELECT md5(p.prosrc) INTO v_edges FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_edges_tenancy()');
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_propagate_tenancy()');
    SELECT md5(p.prosrc) INTO v_pub FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_publicize_claims(uuid[], text)');
    SELECT md5(p.prosrc) INTO v_share FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_share_claims_with_team(uuid[], uuid, text)');
    IF (v_edges, v_prop, v_pub, v_share) IS DISTINCT FROM
       ('af64f98db26f2a6b27f2c1d2c2c7d91f', '9fff86ca2a363b9d14e645296888f61f',
        '5dcea7946212bc1700f7e78cc127324a', '59bdaddd95a6410a5d72fa2ef01ba50c') THEN
        RAISE EXCEPTION '284: epigraph_edges_tenancy (prosrc md5 %), epigraph_propagate_tenancy '
                        '(%), epigraph_publicize_claims (%) or epigraph_share_claims_with_team '
                        '(%) is not the body 284 re-states (120''s, 258''s, 242''s, 242''s). '
                        'Another migration re-bodied it; nothing was changed',
                        COALESCE(v_edges, '(absent)'), COALESCE(v_prop, '(absent)'),
                        COALESCE(v_pub, '(absent)'), COALESCE(v_share, '(absent)')
              USING ERRCODE = '55000',
                    HINT = 'Re-state the MERGED body in a later migration instead.';
    END IF;
END $$;

-- ===================================================================
-- 1. THE RULE: epigraph_edge_declared_meet
-- ===================================================================
-- The privatization re-meet's rule (`PrivatizationRepository::
-- recompute_boundary_meet_conn`, 260), as one function every SQL re-meet
-- calls. Inputs: an edge's declaration (`p_dg`, `p_dco`; `p_dg` NULL for a
-- derived edge) and its endpoints' meet (`p_mv`, `p_mg`, `p_mco`). Output:
-- the tuple the edge takes, and whether the declaration could not be fully
-- honoured (`unmet`).
--
--   * derived: the meet, as given;
--   * declared, meet `public`: the declaration exactly, co-owner included;
--   * declared, meet `group`, at most one group besides the declared owner
--     among (declared co-owner, meet owner, meet co-owner): the
--     intersection, (declared owner, co that group);
--   * more (`unmet`): the meet bounds it. A one-group meet G gives
--     (declared owner, co G); a two-group meet naming the declared owner
--     gives (declared owner, co the other); one not naming it gives the meet.
--
-- So a declared edge is never readable by a session that cannot read its
-- endpoints' meet, and, where one owner plus one co-owner can say so, never
-- by one that cannot read its declaration. Pure (reads no table): IMMUTABLE,
-- SECURITY INVOKER, on 172's path.
CREATE OR REPLACE FUNCTION public.epigraph_edge_declared_meet(
    p_dg uuid, p_dco uuid, p_mv character varying, p_mg uuid, p_mco uuid)
RETURNS TABLE (v character varying(16), g uuid, co uuid, unmet boolean)
LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN p_dg IS NULL THEN p_mv
                ELSE 'group' END::character varying(16),
           CASE WHEN p_dg IS NULL THEN p_mg
                WHEN pg_catalog.cardinality(x.others) <= 1 THEN p_dg
                WHEN p_mco IS NULL OR p_dg = p_mco THEN p_dg
                ELSE p_mg END,
           CASE WHEN p_dg IS NULL THEN p_mco
                WHEN pg_catalog.cardinality(x.others) = 0 THEN NULL
                WHEN pg_catalog.cardinality(x.others) = 1 THEN x.others[1]
                WHEN p_mco IS NULL OR p_dg = p_mco THEN p_mg
                ELSE p_mco END,
           (p_dg IS NOT NULL AND pg_catalog.cardinality(x.others) > 1)
      FROM (SELECT COALESCE(pg_catalog.array_agg(DISTINCT u.o)
                              FILTER (WHERE u.o IS NOT NULL AND u.o <> p_dg),
                            '{}'::uuid[]) AS others
              FROM pg_catalog.unnest(CASE WHEN p_mv = 'group'
                                          THEN ARRAY[p_dco, p_mg, p_mco]
                                          ELSE ARRAY[p_dco] END) AS u(o)) x
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edge_declared_meet(
    uuid, uuid, character varying, uuid, uuid) FROM PUBLIC;

-- ===================================================================
-- 2. A RE-POINT: 120's epigraph_edges_tenancy plus the declared step
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
        dg uuid; dv varchar(16); dco uuid;
BEGIN
    SELECT g, v INTO sg, sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type);
    SELECT g, v INTO tg, tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type);

    -- 120: the author record, from the SESSION, never from the caller.
    IF TG_OP = 'INSERT' THEN
        NEW.writer_group_id := CASE WHEN public.epigraph_principal_id() IS NOT NULL
                                    THEN public.epigraph_writer_group() END;
    END IF;

    -- No-widening. Explicitly declared private, endpoints both public: the meet
    -- would WIDEN it. Keep the declaration, co-ownership included.
    IF NEW.visibility = 'group'
       AND NEW.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       AND NOT (sv = 'group' OR tv = 'group') THEN
        RETURN NEW;
    END IF;

    IF sv = 'public' AND tv = 'public' THEN
        NEW.visibility := 'public';
        NEW.co_owner_group_id := NULL;
        IF TG_OP = 'UPDATE' AND OLD.visibility = 'public' THEN
            -- (u) a re-point keeps the owner it had.
            NEW.owner_group_id := OLD.owner_group_id;
        ELSIF public.epigraph_edge_writer_scope(NEW.source_type, NEW.target_type) THEN
            -- (i) D8: the writer owns it; world when there is no writer.
            NEW.owner_group_id := COALESCE(NEW.writer_group_id,
                                           '00000000-0000-0000-0000-000000000000'::uuid);
        ELSE
            -- A structural edge (an agent, paper, workflow ... endpoint): as before.
            NEW.owner_group_id := '00000000-0000-0000-0000-000000000000'::uuid;
        END IF;
    ELSIF sv = 'public' THEN
        NEW.owner_group_id := tg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSIF tv = 'public' THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSIF sg = tg THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSE
        -- Expressible now. The edge is owned by BOTH groups and, under the
        -- INTERSECTION read fragment, visible to neither group alone.
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := tg;
    END IF;

    -- 284: a re-point of a DECLARED edge only narrows it. The declaration is
    -- the row's RECORD (OLD; 260's trigger, which fires after this one, puts
    -- back any value the UPDATE bound), and the tuple is the meet just
    -- computed intersected with it, the privatization re-meet's rule
    -- (`epigraph_edge_declared_meet`). An INSERT has no record yet: 260's
    -- trigger records the declaration from the no-widening arm above.
    IF TG_OP = 'UPDATE' AND OLD.declared_owner_group_id IS NOT NULL THEN
        SELECT d.g, d.v, d.co INTO dg, dv, dco
          FROM public.epigraph_edge_declared_meet(OLD.declared_owner_group_id,
                                                  OLD.declared_co_owner_group_id,
                                                  NEW.visibility, NEW.owner_group_id,
                                                  NEW.co_owner_group_id) d;
        NEW.owner_group_id := dg;
        NEW.visibility := dv;
        NEW.co_owner_group_id := dco;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_tenancy() FROM PUBLIC;

-- ===================================================================
-- 3. A RE-TENANT: 258's epigraph_propagate_tenancy, the edges statement through the rule
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint; pin_skip text;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
        writer_tables text[] := ARRAY['evidence','mass_functions','reasoning_traces'];
BEGIN
    -- The firing gate. MUST stay ahead of the assertion below.
    IF NOT EXISTS (
        SELECT 1 FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.owner_group_id, ch.visibility)
               IS DISTINCT FROM (p.owner_group_id, p.visibility))
    THEN RETURN NULL; END IF;

    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: propagation requires a maintenance-role '
                        'owner; refusing to run RLS-filtered' USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY derived LOOP
        -- 110: a PINNED evidence row is left to the statement after the loop.
        -- (An IF, not a conditional expression: `tenancy_triggers.rs` counts
        -- this body's conditional expressions to pin the edges meet at three.)
        IF t = 'evidence' THEN
            pin_skip := ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
                        ' WHERE vp.evidence_id = d.id)';
        ELSE
            pin_skip := '';
        END IF;
        -- 114: a WRITER-OWNED row is left to the statement after the loop.
        IF t = ANY (writer_tables) THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        -- 168 (R-CH1): an OUTSIDER's challenge is the challenger's, and it
        -- never follows the claim, so it is not in `writer_tables` and the
        -- narrowing statement after the loop does not re-own it either.
        IF t = 'challenges' THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip;
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- 110: PINNED evidence. Never widened, owner never changed.
    SELECT count(*) INTO expected
      FROM public.evidence d
      JOIN changed ch ON ch.id = d.claim_id
      JOIN public.evidence_visibility_pins vp ON vp.evidence_id = d.id
     WHERE d.visibility IS DISTINCT FROM 'group'::character varying(16);
    IF expected > 0 THEN
        UPDATE public.evidence d
           SET visibility = 'group'::character varying(16)
          FROM changed ch, public.evidence_visibility_pins vp
         WHERE ch.id = d.claim_id
           AND vp.evidence_id = d.id
           AND d.visibility IS DISTINCT FROM 'group'::character varying(16);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to pinned evidence updated % '
                            'of % rows (RLS filtered?)', actual, expected;
        END IF;
    END IF;
    -- 114: WRITER-OWNED rows. While the claim stays public they are left
    -- alone: their owner is the writer's whoever the claim moves to, and their
    -- visibility is already the claim's (or narrower, for pinned evidence).
    -- When the claim NARROWS to non-public they become the claim's: owner and
    -- visibility follow the claim and the flag is cleared (review finding W5).
    -- Keeping the writer as owner there would leave rows about a private claim
    -- readable by the writer's group and hidden from the claim's own owner,
    -- which is sequestering evidence from the one party who now holds the
    -- claim; privatization's seal already encrypts every evidence row of the
    -- claim with the claim group's key, the writer's included. Pinned evidence
    -- is re-owned too (its visibility is 'group' either way, set above).
    -- Issued only when a count finds a row to change.
    FOREACH t IN ARRAY writer_tables LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE d.writer_owned
               AND ch.visibility IS DISTINCT FROM ''public''', t)
          INTO expected;
        IF expected > 0 THEN
            EXECUTE format(
              'UPDATE %I d SET owner_group_id = ch.owner_group_id,
                               visibility     = ch.visibility,
                               writer_owned   = false
                 FROM changed ch
                WHERE ch.id = d.claim_id
                  AND d.writer_owned
                  AND ch.visibility IS DISTINCT FROM ''public''', t);
            GET DIAGNOSTICS actual = ROW_COUNT;
            IF actual <> expected THEN
                RAISE EXCEPTION 'epigraph tenancy: propagation to writer-owned % updated % '
                                'of % rows (RLS filtered?)', t, actual, expected;
            END IF;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    -- 218: a fragment of a changed claim takes the MOST RESTRICTIVE of the
    -- CHANGED claims that cite it (group before public, a real owner before a
    -- sentinel, then the lowest owner id); it never moves to a claim this
    -- statement did not change. When that winner is public, a group fragment
    -- that another group-private claim still cites is left as it is (owner
    -- and visibility): publicizing one citer no longer makes the fragment
    -- public, and does not hand it to the other citer's group either.
    UPDATE public.harvester_fragments f
       SET owner_group_id = w.owner_group_id, visibility = w.visibility
      FROM (SELECT DISTINCT ON (p.fragment_id)
                   p.fragment_id, ch.owner_group_id, ch.visibility
              FROM public.harvester_claim_provenance p
              JOIN changed ch ON ch.id = p.claim_id
             ORDER BY p.fragment_id,
                      (ch.visibility = 'group') DESC,
                      (ch.owner_group_id IN (
                         '00000000-0000-0000-0000-000000000000'::uuid,
                         '00000000-0000-0000-0000-00000000dead'::uuid)) ASC,
                      ch.owner_group_id ASC) w
     WHERE f.id = w.fragment_id
       AND NOT (w.visibility = 'public'
                AND f.visibility = 'group'
                AND EXISTS (SELECT 1
                              FROM public.harvester_claim_provenance p2
                              JOIN public.claims c2 ON c2.id = p2.claim_id
                             WHERE p2.fragment_id = f.id
                               AND c2.visibility = 'group'))
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (w.owner_group_id, w.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
    -- 219: a `workflow` endpoint is met with its OWN row (183's columns), as
    -- `epigraph_node_tenancy` now meets it.
    -- 246: so is a `paper` endpoint (246's columns).
    -- 258: so is a `frame`, `context`, `perspective` or `community` endpoint
    -- (062's columns on the four registries).
    -- 284: a DECLARED edge (260's record) only narrows: `mm` is the meet, and
    -- `epigraph_edge_declared_meet` gives a declared edge the meet intersected
    -- with its declaration (the privatization re-meet's rule) and a derived
    -- edge the meet itself. `m.v` stays the MEET's visibility, so the
    -- statement still writes only where the meet is `group`.
    UPDATE public.edges e
       SET owner_group_id    = m.g,
           visibility        = m.v,
           co_owner_group_id = m.co
      FROM (
        SELECT mm.id, d.g, mm.v, d.co
          FROM (
        SELECT DISTINCT e2.id, e2.dg, e2.dco,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN s.v = 'public' THEN t.g
                    WHEN t.v = 'public' THEN s.g
                    ELSE s.g END AS g,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN 'public'::character varying(16)
                    ELSE 'group'::character varying(16) END AS v,
               CASE WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g
                         THEN t.g
                    ELSE NULL END AS co
          FROM (SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type,
                       x.declared_owner_group_id AS dg, x.declared_co_owner_group_id AS dco
                  FROM public.edges x
                  JOIN changed ch ON x.source_id = ch.id AND x.source_type = 'claim'
                UNION
                SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type,
                       x.declared_owner_group_id AS dg, x.declared_co_owner_group_id AS dco
                  FROM public.edges x
                  JOIN changed ch ON x.target_id = ch.id AND x.target_type = 'claim') e2
          LEFT JOIN public.claims   sc ON e2.source_type = 'claim'    AND sc.id = e2.source_id
          LEFT JOIN public.evidence se ON e2.source_type = 'evidence' AND se.id = e2.source_id
          LEFT JOIN public.workflows sw ON e2.source_type = 'workflow' AND sw.id = e2.source_id
          LEFT JOIN public.papers    sa ON e2.source_type = 'paper'    AND sa.id = e2.source_id
          LEFT JOIN public.frames       sf ON e2.source_type = 'frame'       AND sf.id = e2.source_id
          LEFT JOIN public.contexts     sx ON e2.source_type = 'context'     AND sx.id = e2.source_id
          LEFT JOIN public.perspectives sp ON e2.source_type = 'perspective' AND sp.id = e2.source_id
          LEFT JOIN public.communities  sm ON e2.source_type = 'community'   AND sm.id = e2.source_id
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          LEFT JOIN public.workflows tw ON e2.target_type = 'workflow' AND tw.id = e2.target_id
          LEFT JOIN public.papers    ta ON e2.target_type = 'paper'    AND ta.id = e2.target_id
          LEFT JOIN public.frames       tf ON e2.target_type = 'frame'       AND tf.id = e2.target_id
          LEFT JOIN public.contexts     tx ON e2.target_type = 'context'     AND tx.id = e2.target_id
          LEFT JOIN public.perspectives tp ON e2.target_type = 'perspective' AND tp.id = e2.target_id
          LEFT JOIN public.communities  tm ON e2.target_type = 'community'   AND tm.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id, sw.owner_group_id,
                            sa.owner_group_id, sf.owner_group_id, sx.owner_group_id, sp.owner_group_id,
                            sm.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility, sw.visibility,
                            sa.visibility, sf.visibility, sx.visibility, sp.visibility, sm.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id, tw.owner_group_id,
                            ta.owner_group_id, tf.owner_group_id, tx.owner_group_id, tp.owner_group_id,
                            tm.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility, tw.visibility,
                            ta.visibility, tf.visibility, tx.visibility, tp.visibility, tm.visibility,
                            'public'::character varying(16)) AS v) t
          ) mm
          CROSS JOIN LATERAL public.epigraph_edge_declared_meet(mm.dg, mm.dco, mm.v, mm.g, mm.co) d
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND m.v = 'group'
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;

-- ===================================================================
-- 4. PUBLICIZE: 242's epigraph_publicize_claims, its re-meet through the rule
-- ===================================================================
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
    v_frags_held bigint := 0;
    v_decl_held bigint := 0;
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
    -- evidence (section 1). 284: and every DECLARED edge incident to them
    -- (260's record), on or off its meet; it is recomputed below by the
    -- privatization re-meet's rule, never widened to the meet.
    SELECT array_agg(m.id) INTO v_meet_edges
      FROM (
        SELECT e.id, e.visibility, e.owner_group_id, e.co_owner_group_id,
               e.declared_owner_group_id AS dg,
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
     WHERE m.dg IS NOT NULL
        OR (m.visibility::text, m.owner_group_id, m.co_owner_group_id) IS NOT DISTINCT FROM (
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
                 e.declared_owner_group_id AS dg, e.declared_co_owner_group_id AS dco,
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
          SELECT ep.id, ep.dg, ep.dco,
                 (CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                       THEN 'public' ELSE 'group' END)::varchar(16) AS v,
                 CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                           THEN COALESCE(ep.wg, '00000000-0000-0000-0000-000000000000'::uuid)
                      WHEN ep.sv = 'public' THEN ep.tg
                      ELSE ep.sg END AS g,
                 CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                           THEN ep.tg ELSE NULL END AS co
            FROM ep
        ), decided AS (
          -- 284: a derived edge takes the meet; a DECLARED one the meet
          -- intersected with its declaration (`epigraph_edge_declared_meet`,
          -- the privatization re-meet's rule): its exact declaration when
          -- the meet is public, so publicize never widens it.
          SELECT m.id, m.dg, m.v AS mv, m.g AS mg, m.co AS mco,
                 d.v, d.g, d.co, d.unmet
            FROM meet m
            CROSS JOIN LATERAL public.epigraph_edge_declared_meet(m.dg, m.dco, m.v, m.g, m.co) d
        ), held AS (
          -- The declared edges kept off their meet (or `unmet`), for the
          -- audit row.
          SELECT count(*) AS n FROM decided h
           WHERE h.dg IS NOT NULL
             AND (h.unmet OR (h.v, h.g, h.co) IS DISTINCT FROM (h.mv, h.mg, h.mco))
        ), upd AS (
          UPDATE public.edges e
             SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
            FROM decided m
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
                                           OR upd.target_id = ANY(v_todo))),
               (SELECT h.n FROM held h)
          INTO v_edges, v_ev_edges, v_decl_held
          FROM upd;
    END IF;

    -- Section 2: arm (d) made public every fragment of a moved claim except
    -- one a group claim still cites (218's guard), which keeps its pair. That
    -- is publicize's hold; count it for the audit row. Every moved claim is
    -- public now, so a fragment of one that is still `group` was held.
    SELECT count(*) INTO v_frags_held
      FROM public.harvester_fragments f
     WHERE f.visibility::text = 'group'
       AND EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND p.claim_id = ANY(v_todo));

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
                               'declared_edges_held', v_decl_held,
                               'evidence_edges_rewritten', v_ev_edges,
                               'harvester_fragments_held', v_frags_held,
                               'harvester_sources_moved', v_sources_moved,
                               'harvester_sources_held', v_sources_held,
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'evidence_kept_private', v_pinned,
                               'migration', 284,
                               'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY
        SELECT u.id, CASE WHEN u.o = 'publicize' THEN 'publicized' ELSE u.o END
          FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) FROM PUBLIC;

-- ===================================================================
-- 5. SHARE: 242's epigraph_share_claims_with_team, its evidence re-meet through the rule
-- ===================================================================
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
    v_decl_held bigint := 0;
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
    -- (section 1). Never both-public here, so no writer scope. 284: and every
    -- DECLARED edge on it (260's record), on or off its meet; it is
    -- recomputed below by the privatization re-meet's rule, so it is never
    -- re-owned to the team. (The moved claims' own edges are re-met by the
    -- propagation, which applies the same rule since 284.)
    SELECT COALESCE(array_agg(ev.id ORDER BY ev.id), ARRAY[]::uuid[]) INTO v_evidence
      FROM public.evidence ev WHERE ev.claim_id = ANY(v_cls_ids);
    SELECT array_agg(m.id) INTO v_meet_edges
      FROM (
        SELECT e.id, e.visibility, e.owner_group_id, e.co_owner_group_id,
               e.declared_owner_group_id AS dg,
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
     WHERE m.dg IS NOT NULL
        OR (NOT (m.sv = 'public' AND m.tv = 'public')
            AND (m.visibility::text, m.owner_group_id, m.co_owner_group_id) IS NOT DISTINCT FROM (
             'group',
             CASE WHEN m.sv = 'public' THEN m.tg ELSE m.sg END,
             CASE WHEN m.sv = 'group' AND m.tv = 'group' AND m.sg <> m.tg
                       THEN m.tg ELSE NULL END));

    -- Section 2: the fragments a moved claim cites that a claim NOT moving,
    -- and not already the target team's, also cites; locked, with the pair
    -- each has now (before arm (d) runs). A co-citer already in the team
    -- takes nothing from anyone when the fragment joins it.
    SELECT array_agg(f.id ORDER BY f.id) INTO v_hold_ids
      FROM public.harvester_fragments f
     WHERE EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                    WHERE p.fragment_id = f.id AND p.claim_id = ANY(v_cls_ids))
       AND EXISTS (SELECT 1 FROM public.harvester_claim_provenance p
                     JOIN public.claims c2 ON c2.id = p.claim_id
                    WHERE p.fragment_id = f.id AND NOT (p.claim_id = ANY(v_cls_ids))
                      AND (c2.visibility::text, c2.owner_group_id)
                          IS DISTINCT FROM ('group', p_group_id));
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
                 e.declared_owner_group_id AS dg, e.declared_co_owner_group_id AS dco,
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
          SELECT ep.id, ep.dg, ep.dco,
                 'group'::varchar(16) AS v,
                 CASE WHEN ep.sv = 'public' THEN ep.tg ELSE ep.sg END AS g,
                 CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                           THEN ep.tg ELSE NULL END AS co
            FROM ep
           WHERE NOT (ep.sv = 'public' AND ep.tv = 'public')
        ), decided AS (
          -- 284: a derived edge takes the meet; a DECLARED one the meet
          -- intersected with its declaration (`epigraph_edge_declared_meet`,
          -- the privatization re-meet's rule), never the team alone.
          SELECT m.id, m.dg, m.v AS mv, m.g AS mg, m.co AS mco,
                 d.v, d.g, d.co, d.unmet
            FROM meet m
            CROSS JOIN LATERAL public.epigraph_edge_declared_meet(m.dg, m.dco, m.v, m.g, m.co) d
        ), upd AS (
          UPDATE public.edges e
             SET visibility = m.v, owner_group_id = m.g, co_owner_group_id = m.co
            FROM decided m
           WHERE m.id = e.id
             AND m.g IS NOT NULL
             AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
                 IS DISTINCT FROM (m.v, m.g, m.co)
          RETURNING e.id
        )
        -- The declared edges kept off their meet (or `unmet`), for the audit
        -- row.
        SELECT (SELECT count(*) FROM upd),
               (SELECT count(*) FROM decided h
                 WHERE h.dg IS NOT NULL
                   AND (h.unmet OR (h.v, h.g, h.co) IS DISTINCT FROM (h.mv, h.mg, h.mco)))
          INTO v_ev_edges, v_decl_held;
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
        -- Only the fragments arm (d) actually moved, and this put back.
        GET DIAGNOSTICS v_frags_held = ROW_COUNT;
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
                               'declared_evidence_edges_held', v_decl_held,
                               'harvester_fragments_held', v_frags_held,
                               'harvester_sources_moved', v_sources_moved,
                               'harvester_sources_held', v_sources_held,
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'migration', 284, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY SELECT u.id, 'shared'::text FROM unnest(v_cls_ids) AS u(id) ORDER BY u.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) FROM PUBLIC;

-- ===================================================================
-- 6. OWNERSHIP AND GRANTS (CREATE OR REPLACE keeps them; re-asserted)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_edge_declared_meet(uuid, uuid, character varying, '
                'uuid, uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_edges_tenancy() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_share_claims_with_team(uuid[], uuid, text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 284 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_publicize_claims(uuid[], text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_share_claims_with_team('
                'uuid[], uuid, text) TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 7. THE ONE-TIME REPAIR: declared edges the old re-meets re-owned or widened
-- ===================================================================
-- Between 260 and this file the three re-meets above treated a declared edge
-- as derived, and its record survived each of them (260's trigger keeps it
-- across a re-point; nothing else writes it). So an exposed edge is
-- recognisable: a declared edge whose tuple is not the rule's for its
-- endpoints' meet NOW. The repair never lets anyone read an edge they cannot
-- read now: each one takes the rule's owner and, as co-owner, the one other
-- group that the rule's tuple and its CURRENT tuple require together, if
-- there is at most one. So an edge the propagation or share re-owned to the
-- meet G goes to (declared owner, co G); one publicize widened to the world
-- goes back on its declaration; one left on G after its endpoint went public
-- again by a path that does not re-meet goes to (declared owner, co G). One
-- that would need three groups is left as it is and counted, for the
-- privatization revert or an operator.
--
-- It reads `edges` and every endpoint table under FORCEd row security, so it
-- refuses unless this session reads every row (260's guard). An edge with a
-- dangling endpoint is skipped and counted (`edges_validate_refs` fires on
-- every UPDATE of `edges` and would abort the migration). The UPDATE names
-- no source or target column, so neither tenancy trigger fires; the owner
-- guard admits this privileged session.
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '284: run as the maintenance role or a superuser; the repair must '
                        'read every group''s edges and endpoints'
              USING ERRCODE = '42501';
    END IF;
END $$;

DO $$
DECLARE v_fixed bigint; v_wider bigint; v_dangling bigint; v_unmet bigint;
BEGIN
    WITH ep AS (
        SELECT e.id, e.source_id, e.source_type, e.target_id, e.target_type,
               e.visibility AS cv, e.owner_group_id AS cg, e.co_owner_group_id AS cco,
               e.declared_owner_group_id AS dg, e.declared_co_owner_group_id AS dco,
               COALESCE(s.v, 'public')::text AS sv,
               COALESCE(s.g, '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
               COALESCE(t.v, 'public')::text AS tv,
               COALESCE(t.g, '00000000-0000-0000-0000-000000000000'::uuid) AS tg
          FROM public.edges e
          LEFT JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s ON true
          LEFT JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t ON true
         WHERE e.declared_owner_group_id IS NOT NULL
    ), meet AS (
        SELECT ep.*,
               (CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                     THEN 'public' ELSE 'group' END)::varchar(16) AS mv,
               CASE WHEN ep.sv = 'public' AND ep.tv = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN ep.sv = 'public' THEN ep.tg
                    ELSE ep.sg END AS mg,
               CASE WHEN ep.sv = 'group' AND ep.tv = 'group' AND ep.sg <> ep.tg
                         THEN ep.tg ELSE NULL END AS mco
          FROM ep
    ), rule AS (
        SELECT m.id, m.source_id, m.source_type, m.target_id, m.target_type,
               m.cv, m.cg, m.cco, d.g, d.unmet,
               -- The groups the rule's tuple and the current one require
               -- together, besides the rule's owner.
               ARRAY(SELECT DISTINCT x
                       FROM pg_catalog.unnest(ARRAY[d.co,
                                                    CASE WHEN m.cv = 'group' THEN m.cg END,
                                                    CASE WHEN m.cv = 'group' THEN m.cco END]) x
                      WHERE x IS NOT NULL AND x <> d.g) AS others
          FROM meet m
          CROSS JOIN LATERAL public.epigraph_edge_declared_meet(m.dg, m.dco, m.mv, m.mg, m.mco) d
         WHERE (m.cv, m.cg, m.cco) IS DISTINCT FROM (d.v, d.g, d.co)
    ), cand AS (
        SELECT r.id, r.g, r.others[1] AS co, r.unmet,
               pg_catalog.cardinality(r.others) <= 1 AS fits,
               (public.validate_edge_reference(r.source_id, r.source_type)
                AND public.validate_edge_reference(r.target_id, r.target_type)) AS refs_ok
          FROM rule r
    ), upd AS (
        UPDATE public.edges e
           SET visibility = 'group', owner_group_id = c.g, co_owner_group_id = c.co
          FROM cand c
         WHERE e.id = c.id AND c.fits AND c.refs_ok
           AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
               IS DISTINCT FROM ('group'::character varying(16), c.g, c.co)
        RETURNING e.id
    )
    SELECT (SELECT count(*) FROM upd),
           (SELECT count(*) FROM cand c WHERE NOT c.fits),
           (SELECT count(*) FROM cand c WHERE c.fits AND NOT c.refs_ok),
           (SELECT count(*) FROM cand c WHERE c.fits AND c.refs_ok AND c.unmet)
      INTO v_fixed, v_wider, v_dangling, v_unmet;
    RAISE NOTICE '284: narrowed % declared edge(s) (% of them unmet); left % that would need '
                 'three groups; skipped % with a dangling endpoint',
                 v_fixed, v_unmet, v_wider, v_dangling;
END $$;

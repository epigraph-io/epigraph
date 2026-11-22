-- 258: a frame, context, perspective or community endpoint contributes its
-- own tenancy to an edge's meet (backlog a07c25c0).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 062 gave the four instance-wide registries (`frames`,
-- `contexts`, `perspectives`, `communities`) their own tenancy columns
-- (`owner_group_id`, `visibility`), and 077's registry policy reads them:
-- a group-private registry row is readable by its group's members only.
-- `epigraph_node_tenancy` (070, re-stated by 219) still answered
-- ('public', world) for all four, and the propagation (`epigraph_propagate_
-- tenancy`, 219's body) read only claims, evidence and workflows. An edge's
-- tenancy is the MEET of its endpoints (070, 072, 120), so an edge between a
-- public claim and a GROUP-PRIVATE frame, context, perspective or community
-- took its tenancy from the claim alone:
--
--   * it was ('public', world): a non-member listing the claim's edges read
--     the private registry row's id and its relationship to the claim;
--   * an edge between a claim private to group A and a registry row private
--     to group B was ('group', A) alone, never co-owned, so A's members read
--     an edge naming B's private row;
--   * edge ownership and retract authority were decided without the private
--     endpoint's group.
--
-- Mitigation that keeps this latent rather than live: every first-party
-- writer of the four tables declares the row instance-wide,
-- ('public', world) (`TenancyDecl::instance_wide()` in the frame, context,
-- perspective and community repositories). A group-private registry row
-- arises only from a legacy re-stamp (071's ownership shim, retired by 084)
-- or a direct write by a group writer (077's registry WITH CHECK admits a
-- row owned by any group the session writes).
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `epigraph_node_tenancy(uuid, text)` gains `frame`, `context`,
--      `perspective` and `community` arms that read the row's
--      `(owner_group_id, visibility)`. Same signature, LANGUAGE, volatility,
--      SECURITY DEFINER and search_path, so CREATE OR REPLACE keeps 070's
--      owner (`epigraph_maintenance`) and its revoked ACL; the definer reads
--      the four tables through 077's `epigraph_definer_bypass()` arm, so the
--      read is never RLS-filtered. Every caller follows: the write-time stamp
--      (`epigraph_edges_tenancy`, 120), 206's and 215's publicize and share
--      re-meets, the privatization boundary re-meet and the operator CLI's
--      models of the cascade (which already read these rows from their own
--      tables, `regroup::node_types`).
--   2. `epigraph_propagate_tenancy()` (219's body) meets those endpoints with
--      their own rows too: one LEFT JOIN per table per side and its column in
--      each COALESCE. Nothing else in the body changes (the `derived`
--      literal, the three CASE expressions and every guard are 219's byte for
--      byte), so a claim's re-tenanting re-meets an edge onto a private frame
--      with the frame's row, not with ('public', world).
--   3. A one-time re-meet of every edge with a NON-PUBLIC frame, context,
--      perspective or community endpoint, under the propagation's rules: the
--      edge takes the meet only when the meet is `group`, never widens, and is
--      written only when its (owner, visibility, co-owner) triple differs. An
--      edge that is already group-private also keeps every group it requires
--      (section 4 says why); one that would then need three groups is held,
--      and one whose other endpoint no longer exists is skipped (a write
--      would trip `edges_validate_refs` and abort the migration). Counts by
--      relationship and transition, and the held and skipped counts, are
--      RAISEd as a NOTICE: they are the measurement of what this changed.
--
-- NOT changed:
--   * re-tenanting a registry row does not, by itself, re-meet its edges
--     (there is no propagation trigger on the four tables, as there is none
--     on `workflows`, backlog 67befd57). No first-party path re-tenants a
--     registry row; a direct re-stamp is repaired by
--     `epigraph-tenancy-backfill run --entity registry-edges` (dry run
--     first), and `verify` fails while any such edge is off its meet.
--   * reasoning traces (`trace` endpoints) are still met as public.
--   * `epigraph_edges_tenancy`, `epigraph_edge_writer_scope` and every
--     policy. An edge between two PUBLIC endpoints stays ('public', world).
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser (section 4 refuses otherwise:
-- an RLS-filtered re-meet would see no private registry row and re-meet
-- nothing). No binary depends on it. Run the `epigraph-tenancy-backfill`
-- built with it AFTER the migration: its `verify` now fails on an edge with a
-- non-public registry endpoint that is off its meet, held or skipped as
-- dangling (section 4). New edges written after
-- 258 from a public claim to a group-private registry row are ('group',
-- that row's group), so the writer must write that group (fail-closed).
--
-- Undo: `docs/runbooks/258-undo.sql` re-states 219's two bodies (CREATE OR
-- REPLACE, never DROP: a DROP resets the ACL) and refuses unless both still
-- hold 258's bodies. The edges section 4 narrowed STAY narrowed
-- (fail-closed); the NOTICE lists how many there were.
--
-- Re-stating a shared body: 219 re-stated `epigraph_node_tenancy` and
-- `epigraph_propagate_tenancy` last on main. The GUARD below refuses to
-- apply unless both functions still hold exactly 219's bodies (md5 of
-- `prosrc`), so a re-statement applied before this file fails it loudly
-- instead of being silently reverted. The migration that lands second must
-- re-state the MERGED body and make its own undo restore the merged
-- predecessor.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD: re-state only the bodies this file was written against (219's)
-- ===================================================================
-- The literals are md5(prosrc) of 219's bodies (the same literals
-- `docs/runbooks/219-undo.sql` accepts as 219's; pinned by
-- `epigraph-db/tests/registry_endpoint_tenancy_undo.rs` and by every suite
-- that migrates to head, which a wrong literal would fail).
DO $$
DECLARE v_node text; v_prop text;
BEGIN
    SELECT md5(p.prosrc) INTO v_node FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure;
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_propagate_tenancy()'::regprocedure;
    IF v_node IS DISTINCT FROM 'd08bf867256ced915ba54f65cf620de7'
       OR v_prop IS DISTINCT FROM 'd48f242f2756ae9679d97d111dfda925' THEN
        RAISE EXCEPTION '258: epigraph_node_tenancy (prosrc md5 %) or epigraph_propagate_tenancy '
                        '(prosrc md5 %) is not the body 258 builds on (219''s). A migration '
                        'before 258 re-stated it; re-stating it here would revert that change. '
                        'Re-state the MERGED body in the later migration',
                        v_node, v_prop
              USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 1. THE ORACLE: 219's body plus the four registry arms
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_node_tenancy(p_id uuid, p_type text)
RETURNS TABLE (g uuid, v character varying(16))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_type = 'claim' THEN
        RETURN QUERY SELECT c.owner_group_id, c.visibility FROM public.claims c WHERE c.id = p_id;
    ELSIF p_type = 'evidence' THEN
        RETURN QUERY SELECT e.owner_group_id, e.visibility FROM public.evidence e WHERE e.id = p_id;
    ELSIF p_type = 'workflow' THEN
        -- 219: a plan's row carries its tenancy since 183.
        RETURN QUERY SELECT w.owner_group_id, w.visibility FROM public.workflows w WHERE w.id = p_id;
    ELSIF p_type = 'frame' THEN
        -- 258: the four registries carry their tenancy since 062.
        RETURN QUERY SELECT f.owner_group_id, f.visibility FROM public.frames f WHERE f.id = p_id;
    ELSIF p_type = 'context' THEN
        RETURN QUERY SELECT x.owner_group_id, x.visibility FROM public.contexts x WHERE x.id = p_id;
    ELSIF p_type = 'perspective' THEN
        RETURN QUERY SELECT p.owner_group_id, p.visibility FROM public.perspectives p WHERE p.id = p_id;
    ELSIF p_type = 'community' THEN
        RETURN QUERY SELECT m.owner_group_id, m.visibility FROM public.communities m WHERE m.id = p_id;
    END IF;
    -- An edge pointing at an agent/paper/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

-- ===================================================================
-- 2. ARM (d): 219's epigraph_propagate_tenancy plus the registry joins
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
    -- 258: so is a `frame`, `context`, `perspective` or `community` endpoint
    -- (062's columns on the four registries).
    UPDATE public.edges e
       SET owner_group_id    = m.g,
           visibility        = m.v,
           co_owner_group_id = m.co
      FROM (
        SELECT DISTINCT e2.id,
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
          FROM (SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.source_id = ch.id AND x.source_type = 'claim'
                UNION
                SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.target_id = ch.id AND x.target_type = 'claim') e2
          LEFT JOIN public.claims   sc ON e2.source_type = 'claim'    AND sc.id = e2.source_id
          LEFT JOIN public.evidence se ON e2.source_type = 'evidence' AND se.id = e2.source_id
          LEFT JOIN public.workflows sw ON e2.source_type = 'workflow' AND sw.id = e2.source_id
          LEFT JOIN public.frames       sf ON e2.source_type = 'frame'       AND sf.id = e2.source_id
          LEFT JOIN public.contexts     sx ON e2.source_type = 'context'     AND sx.id = e2.source_id
          LEFT JOIN public.perspectives sp ON e2.source_type = 'perspective' AND sp.id = e2.source_id
          LEFT JOIN public.communities  sm ON e2.source_type = 'community'   AND sm.id = e2.source_id
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          LEFT JOIN public.workflows tw ON e2.target_type = 'workflow' AND tw.id = e2.target_id
          LEFT JOIN public.frames       tf ON e2.target_type = 'frame'       AND tf.id = e2.target_id
          LEFT JOIN public.contexts     tx ON e2.target_type = 'context'     AND tx.id = e2.target_id
          LEFT JOIN public.perspectives tp ON e2.target_type = 'perspective' AND tp.id = e2.target_id
          LEFT JOIN public.communities  tm ON e2.target_type = 'community'   AND tm.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id, sw.owner_group_id,
                            sf.owner_group_id, sx.owner_group_id, sp.owner_group_id,
                            sm.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility, sw.visibility,
                            sf.visibility, sx.visibility, sp.visibility, sm.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id, tw.owner_group_id,
                            tf.owner_group_id, tx.owner_group_id, tp.owner_group_id,
                            tm.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility, tw.visibility,
                            tf.visibility, tx.visibility, tp.visibility, tm.visibility,
                            'public'::character varying(16)) AS v) t
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
-- 3. OWNERSHIP (CREATE OR REPLACE keeps it; re-set regardless, as 219 does)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 4. THE ONE-TIME RE-MEET OF EDGES WITH A GROUP-PRIVATE REGISTRY ENDPOINT
-- ===================================================================
-- It reads the four registries, `claims`, `evidence`, `workflows` and
-- `edges`, all under FORCEd row security, so refuse unless this session
-- reads every row (219's guard).
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '258: run as the maintenance role or a superuser; the re-meet must '
                        'read every group''s registry rows and edges';
    END IF;
END $$;

-- Driven from the non-public registry rows by equi-joins (source side, target
-- side, per table), 122's shape, so it never scans `edges` for a type. An
-- edge whose registry endpoints are all public has the meet the cascade
-- already gave it.
--
-- The rule is the propagation's (section 2): the edge takes the meet only
-- when the meet is `group`, never widens, and is written only when its
-- (owner, visibility, co-owner) triple differs. One addition, because this
-- re-meets rows the old oracle stamped: an edge that is ALREADY group-private
-- keeps every group it requires. A legacy edge declared ('group', G) between
-- a public claim and a frame private to H would otherwise go to ('group', H)
-- alone, handing G's edge to H's members; it becomes (H, co-owner G),
-- readable only by a member of both. An edge whose meet and current tuple
-- need three groups is HELD (left as it is) and counted;
-- `epigraph-tenancy-backfill verify` fails on it, for an operator to decide.
-- `epigraph-tenancy-backfill run --entity registry-edges` applies the same
-- rule later.
--
-- An edge whose other endpoint no longer exists (a deleted agent, task,
-- claim, ...) is SKIPPED and counted, never written: an UPDATE of `edges`
-- fires `edges_validate_refs` on every row it writes, and one dangling
-- endpoint would abort this migration and the api's boot with it (175's
-- header; 260 skips the same way). `epigraph-tenancy-backfill verify` fails on
-- such an edge, for an operator to repair or delete.
DO $$
DECLARE v_summary text; v_total bigint; v_held bigint; v_dangling bigint;
BEGIN
    WITH reg_edges AS (
        SELECT x.id FROM public.edges x
          JOIN public.frames r ON x.source_type = 'frame' AND x.source_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.frames r ON x.target_type = 'frame' AND x.target_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.contexts r ON x.source_type = 'context' AND x.source_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.contexts r ON x.target_type = 'context' AND x.target_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.perspectives r ON x.source_type = 'perspective' AND x.source_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.perspectives r ON x.target_type = 'perspective' AND x.target_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.communities r ON x.source_type = 'community' AND x.source_id = r.id
         WHERE r.visibility <> 'public'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.communities r ON x.target_type = 'community' AND x.target_id = r.id
         WHERE r.visibility <> 'public'
    ), m AS (
        SELECT e2.id, e2.relationship,
               e2.source_id, e2.source_type, e2.target_id, e2.target_type,
               e2.visibility AS old_v, e2.owner_group_id AS old_g,
               e2.co_owner_group_id AS old_co,
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
          FROM reg_edges k
          JOIN public.edges e2 ON e2.id = k.id
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.source_id, e2.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.target_id, e2.target_type) t
    ), n AS (
        -- The groups the edge requires besides its owner: the meet's co-owner
        -- and, for an edge already group-private, the groups it requires now.
        SELECT m.*,
               ARRAY(SELECT DISTINCT x
                       FROM unnest(ARRAY[m.co,
                                         CASE WHEN m.old_v = 'group' THEN m.old_g END,
                                         CASE WHEN m.old_v = 'group' THEN m.old_co END]) x
                      WHERE x IS NOT NULL AND x <> m.g) AS others
          FROM m
         WHERE m.v = 'group'
    ), d AS (
        SELECT n.id, n.relationship, n.g, n.v, n.others[1] AS co,
               cardinality(n.others) > 1 AS held,
               (public.validate_edge_reference(n.source_id, n.source_type)
                AND public.validate_edge_reference(n.target_id, n.target_type)) AS refs_ok,
               CASE WHEN n.old_v = 'public' THEN 'public to group'
                    WHEN n.others[1] IS NOT NULL AND n.old_co IS NULL THEN 'group to co-owned'
                    WHEN n.old_g IS DISTINCT FROM n.g THEN 'group to another group'
                    ELSE 'co-owner changed' END AS transition
          FROM n
         WHERE (n.old_g, n.old_v, n.old_co) IS DISTINCT FROM (n.g, n.v, n.others[1])
    ), upd AS (
        UPDATE public.edges e
           SET owner_group_id    = d.g,
               visibility        = d.v,
               co_owner_group_id = d.co
          FROM d
         WHERE e.id = d.id
           AND NOT d.held
           AND d.refs_ok
        RETURNING d.relationship, d.transition
    ), counts AS (
        SELECT relationship, transition, count(*) AS n FROM upd GROUP BY 1, 2
    )
    SELECT COALESCE((SELECT sum(n) FROM counts), 0),
           COALESCE((SELECT string_agg(format('%s %s: %s', relationship, transition, n), '; '
                                       ORDER BY relationship, transition) FROM counts), 'none'),
           (SELECT count(*) FROM d WHERE d.held AND d.refs_ok),
           (SELECT count(*) FROM d WHERE NOT d.refs_ok)
      INTO v_total, v_summary, v_held, v_dangling;
    RAISE NOTICE '258: re-met % edge(s) with a non-public frame, context, perspective or '
                 'community endpoint (%); % held (they need three groups); % skipped with a '
                 'dangling endpoint (see `epigraph-tenancy-backfill verify`)',
                 v_total, v_summary, v_held, v_dangling;
END $$;

-- 219: a workflow endpoint contributes its own tenancy to an edge's meet
-- (backlog 630af617, item 3).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 183 gave `workflows` rows a tenancy (`owner_group_id`,
-- `visibility`) and row security, and left `epigraph_node_tenancy` (070)
-- unchanged: for every endpoint type but `claim` and `evidence` it answers
-- ('public', world). An edge's tenancy is the MEET of its endpoints (070,
-- 072, 120), so an edge with a group-private WORKFLOW endpoint took its
-- tenancy from the other endpoint alone:
--
--   * `variant_of` between two generations of a group lineage, and the
--     `AUTHORED` edge from the author agent, were ('public', world);
--   * an `executes` edge from a group plan to a PUBLIC claim (a step reused
--     from a public generation, a shared level-3 operation atom) was public;
--   * 206's publicize re-meets an incident edge with widening allowed, so a
--     group plan's `executes` edge onto a claim being publicized went public.
--
-- Each of these is readable by a caller who cannot read the plan, and names
-- it: a non-member listing the edges into a public generation saw the private
-- generation that descends from it, and listing the edges into a public step
-- saw every private plan that executes it.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `epigraph_node_tenancy(uuid, text)` gains a `workflow` arm that reads
--      `workflows.(owner_group_id, visibility)`. Same signature, LANGUAGE,
--      volatility, SECURITY DEFINER and search_path, so CREATE OR REPLACE
--      keeps 070's owner (`epigraph_maintenance`) and its revoked ACL. The
--      definer reads `workflows` through 183's `epigraph_definer_bypass()`
--      arm, so the read is never RLS-filtered. Every caller of the oracle
--      follows: the write-time stamp (`epigraph_edges_tenancy`, 120), 206's
--      publicize and share re-meet, 115's `epigraph_session_writes_node`
--      (called with 'claim' only), the privatization boundary re-meet, and the
--      operator CLI's models of the cascade.
--   2. `epigraph_propagate_tenancy()` (168's body) meets a workflow endpoint
--      with its own row too. 122 inlined the endpoint reads as LEFT JOINs on
--      `claims` and `evidence`; this adds the same LEFT JOIN on `workflows`
--      for each side and its column to each COALESCE. Nothing else in the body
--      changes (the `derived` literal, the three CASE expressions and every
--      guard are byte for byte 168's), so a claim's re-tenanting re-meets an
--      `executes` edge with its plan's row, not with ('public', world).
--   3. A one-time re-meet of every edge with a GROUP-PRIVATE workflow
--      endpoint, under the propagation's rules exactly: the edge takes the
--      meet only when the meet is `group`, never widens, and is written only
--      when its (owner, visibility, co-owner) triple differs. Counts by
--      relationship and transition are RAISEd as a NOTICE: they are the
--      measurement of what this changed.
--   4. `epigraph_step_lineage_has_hidden_executor(uuid)`, a boolean definer
--      for the `evolve_step` authority gates (section 5). They found the
--      workflows executing a step's lineage through `executes` edges read
--      under the caller's row security; after item 1 a group plan's edge onto
--      a public step is hidden from a non-member, who would then be admitted
--      to supersede a step that plan runs. The gates refuse when this answers
--      true.
--
-- A group workflow whose other endpoint is private to ANOTHER group now gets
-- a CO-OWNED edge (072's intersection: readable only by a member of both).
-- That is the meet's rule for every cross-group edge, and it is fail-closed:
-- the edge names a plan the other group's members cannot read and a claim
-- the plan's members cannot read.
--
-- NOT changed:
--   * re-tenanting a `workflows` row does not, by itself, re-meet that row's
--     edges (there is no propagation trigger on `workflows`). The acts that
--     re-tenant one re-meet its edges themselves: the privatization batch
--     (`PrivatizationRepository::restrict_plan_workflows_conn` and
--     `restore_plan_workflows_conn`) and `epigraph-cli reown-workflows`.
--   * the other endpoint types that carry their own tenancy (frames,
--     contexts, perspectives, communities, reasoning traces) are still met as
--     public; `epigraph-cli regroup-claims` reads them from their own rows.
--   * `epigraph_edges_tenancy`, `epigraph_edge_writer_scope` and every policy.
--     An edge between two PUBLIC endpoints where one is a workflow stays
--     ('public', world), a structural edge, as 120 decided.
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser (section 4 refuses otherwise:
-- an RLS-filtered backfill would see no private workflow and re-meet
-- nothing). Deploy order: migrate BEFORE rolling out a binary built with it
-- (its `evolve_step` gates call section 5's definer; that binary also re-meets
-- a privatized plan's workflow edges). An older binary on a 219 database
-- keeps working but its `evolve_step` gate misses a hidden plan's edge, so
-- roll the binary out promptly. New edges written after 219 from a group plan
-- to a public claim are ('group', plan group), so the writer must write that
-- group, which every plan write path already requires.
--
-- Undo (roll every 219 binary back first): `docs/runbooks/219-undo.sql`
-- re-states 070's `epigraph_node_tenancy` and 168's
-- `epigraph_propagate_tenancy` (CREATE OR REPLACE, never DROP: a DROP resets
-- the ACL) and DROPs section 5's definer (nothing in SQL names it); it
-- refuses unless both functions still hold 219's bodies. The edges
-- section 4 narrowed STAY narrowed (fail-closed); the NOTICE lists how many
-- there were.
--
-- Re-stating a shared body: on main nothing re-states
-- `epigraph_node_tenancy` after 070 or `epigraph_propagate_tenancy` after 168,
-- but another change in flight re-states the propagation too. Whichever of
-- two such migrations applies LATER would silently put back the earlier one's
-- body without the other's change. So the GUARD below refuses to apply
-- unless both functions still hold exactly the bodies this file builds on
-- (070's and 168's, by the md5 of `prosrc`): a re-statement applied before
-- this file fails it loudly instead. The migration that lands second must
-- take the higher number, re-state the MERGED body, and make its own undo
-- restore the merged predecessor. The undo runbook carries the same guard
-- against this file's bodies.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD: re-state only the bodies this file was written against
-- ===================================================================
-- Sections 1 and 2 re-state 070's and 168's bodies plus the workflow arm and
-- joins. Over any other body they would silently revert whatever re-stated it
-- after 070 / 168, so refuse (see "Re-stating a shared body" above). The
-- literals are md5(prosrc) of the bodies in 070_tenancy_triggers.sql and
-- 168_outsider_owned_challenges.sql (pinned by
-- `epigraph-db/tests/workflow_endpoint_tenancy_undo.rs`, and by every suite
-- that migrates to head, which a wrong literal would fail).
DO $$
DECLARE v_node text; v_prop text;
BEGIN
    SELECT md5(p.prosrc) INTO v_node FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure;
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_propagate_tenancy()'::regprocedure;
    IF v_node IS DISTINCT FROM '8e97895802b7dbb334f92b3c5a4d884a'
       OR v_prop IS DISTINCT FROM '763b53778fcd779f1f968d38af58b3d7' THEN
        RAISE EXCEPTION '219: epigraph_node_tenancy (prosrc md5 %) or epigraph_propagate_tenancy '
                        '(prosrc md5 %) is not the body 219 builds on (070''s and 168''s). '
                        'A migration before 219 re-stated it; re-stating it here would revert '
                        'that change. Re-state the MERGED body in the later migration',
                        v_node, v_prop
              USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 1. THE ORACLE: 070's body plus the workflow arm
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
    END IF;
    -- An edge pointing at a frame/agent/paper/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

-- ===================================================================
-- 2. ARM (d): 168's epigraph_propagate_tenancy plus the workflow joins
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
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
    -- 219: a `workflow` endpoint is met with its OWN row (183's columns), as
    -- `epigraph_node_tenancy` now meets it.
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
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          LEFT JOIN public.workflows tw ON e2.target_type = 'workflow' AND tw.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id, sw.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility, sw.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id, tw.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility, tw.visibility,
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
-- 3. OWNERSHIP (CREATE OR REPLACE keeps it; re-set regardless, as 168 does)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 4. THE ONE-TIME RE-MEET OF EDGES WITH A GROUP-PRIVATE WORKFLOW ENDPOINT
-- ===================================================================
-- It reads `workflows`, `claims`, `evidence` and `edges`, all under FORCEd row
-- security, so refuse unless this session reads every row (183's guard).
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '219: run as the maintenance role or a superuser; the re-meet must '
                        'read every group''s workflows and edges';
    END IF;
END $$;

-- Driven from the group-private workflow rows by two equi-joins (source side,
-- target side), 122's shape, so it never scans `edges` for a type. An edge
-- whose workflow endpoints are all public has the meet the cascade already
-- gave it. The WHERE is the propagation's (section 2) exactly.
DO $$
DECLARE v_summary text; v_total bigint;
BEGIN
    WITH wf_edges AS (
        SELECT x.id FROM public.edges x
          JOIN public.workflows w ON x.source_type = 'workflow' AND x.source_id = w.id
         WHERE w.visibility = 'group'
        UNION
        SELECT x.id FROM public.edges x
          JOIN public.workflows w ON x.target_type = 'workflow' AND x.target_id = w.id
         WHERE w.visibility = 'group'
    ), m AS (
        SELECT e2.id, e2.relationship,
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
          FROM wf_edges k
          JOIN public.edges e2 ON e2.id = k.id
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.source_id, e2.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.target_id, e2.target_type) t
    ), upd AS (
        UPDATE public.edges e
           SET owner_group_id    = m.g,
               visibility        = m.v,
               co_owner_group_id = m.co
          FROM m
         WHERE e.id = m.id
           AND m.g IS NOT NULL
           AND m.v = 'group'
           AND NOT (e.visibility = 'group' AND m.v = 'public')
           AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
               IS DISTINCT FROM (m.g, m.v, m.co)
        RETURNING m.relationship,
                  CASE WHEN m.old_v = 'public' THEN 'public to group'
                       WHEN m.co IS NOT NULL AND m.old_co IS NULL THEN 'group to co-owned'
                       WHEN m.old_g IS DISTINCT FROM m.g THEN 'group to another group'
                       ELSE 'co-owner changed' END AS transition
    ), counts AS (
        SELECT relationship, transition, count(*) AS n FROM upd GROUP BY 1, 2
    )
    SELECT COALESCE(sum(n), 0),
           COALESCE(string_agg(format('%s %s: %s', relationship, transition, n), '; '
                               ORDER BY relationship, transition), 'none')
      INTO v_total, v_summary
      FROM counts;
    RAISE NOTICE '219: re-met % edge(s) with a group-private workflow endpoint (%)',
                 v_total, v_summary;
END $$;

-- ===================================================================
-- 5. THE EVOLVE_STEP GATE: does a workflow the session cannot read execute
--    this step's lineage?
-- ===================================================================
-- `evolve_step` (REST and MCP) requires workflow authority over EVERY
-- workflow that executes the parent's step lineage, and found them through
-- `WorkflowRepository::workflows_executing_step_lineage`, under the caller's
-- row security. Before 219 a group plan's `executes` edge onto a public step
-- was public, so a caller outside the plan's group still found the plan, and
-- its authority check refused (answered as a missing parent). After section 1
-- that edge is the plan's group's, the caller no longer finds it, and would
-- be admitted to supersede a step a private plan runs.
--
-- So the gate also asks this definer, which reads the edges and the lineage
-- members unfiltered and answers ONE BOOLEAN: true when some workflow
-- executing the lineage (retracted `executes` edges included, as the
-- repository read counts them) is a row the session cannot read: not
-- public, and not owned by a group in `epigraph_session_groups()`, or no row
-- at all. It never returns an id, so it names no hidden plan; the gate then
-- refuses exactly as it refuses a missing parent. A privileged session
-- (`epigraph_bypass()`) reads every row, so it is never true there. NOT
-- 183's `workflows_read` USING clause verbatim: its `epigraph_definer_bypass()`
-- arm is always true inside this maintenance-owned body.
--
-- 172's form: `pg_catalog, pg_temp`, every public name qualified. Owned by
-- `epigraph_maintenance`, EXECUTE revoked from PUBLIC and granted to
-- `epigraph_app` (the gate runs on the request DSN).
CREATE OR REPLACE FUNCTION public.epigraph_step_lineage_has_hidden_executor(p_claim uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT NOT public.epigraph_bypass()
       AND EXISTS (
           SELECT 1
             FROM public.edges e
             LEFT JOIN public.workflows w ON w.id = e.source_id
            WHERE e.relationship = 'executes'
              AND e.source_type = 'workflow' AND e.target_type = 'claim'
              AND (e.target_id = p_claim
                   OR e.target_id IN (
                       SELECT m.id FROM public.claims m
                         JOIN public.claims p ON p.step_lineage_id = m.step_lineage_id
                        WHERE p.id = p_claim))
              AND (w.id IS NULL
                   OR NOT (w.visibility = 'public'
                           OR w.owner_group_id = ANY (public.epigraph_session_groups()))))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_step_lineage_has_hidden_executor(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_step_lineage_has_hidden_executor(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_step_lineage_has_hidden_executor(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

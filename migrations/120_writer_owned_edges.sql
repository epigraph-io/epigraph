-- 120: an edge between two public claims is owned by its writer (batch W12b,
-- operator decision D8).
--
-- ===================================================================
-- 0. WHAT THIS FILE CHANGES
-- ===================================================================
--
-- Until this file an edge's owner was ALWAYS the meet of its endpoints
-- (070/072): an edge between two public endpoints was `('public', world)`,
-- owned by the memberless world group, whoever wrote it. 115 then licensed the
-- writer of the edge's SOURCE node to delete such an edge, and 117 made UPDATE
-- owner-scoped, so on the application role a world-owned edge could be
-- retracted by nobody (UPDATE) and deleted by whoever writes its source
-- (DELETE). Neither rule names the edge's author, because the schema recorded
-- none.
--
-- D8: "An edge between two public claims is owned by its author's group and
-- stays public ... The owner arm covers patch/retract/delete; 115's
-- source-writer DELETE arm is removed. Legacy world-owned public-public edges
-- stay admin-only unless re-owned to their recorded signer by a maintenance
-- step. Replaces the endpoint-MEET owner for public-public edges only; mixed or
-- private endpoints keep the meet (visibility must never widen)."
--
-- So:
--   (1) `edges.writer_group_id` records the writing session's group
--       (114's `epigraph_writer_group()`) on every INSERT, whatever the caller
--       bound. It is the author record the schema lacked. It is never
--       recomputed, a non-privileged session cannot change it, and only the
--       privatization REVERT reads it (section 5).
--   (2) `epigraph_edges_tenancy()` owns an edge by its writer's group when both
--       endpoints are PUBLIC and both are epistemic nodes in the D8 sense
--       (`epigraph_edge_writer_scope`, section 2). Every other public-meet edge
--       (an agent, paper, workflow, trace ... endpoint: AUTHORED, processed_by,
--       executes) stays `('public', world)` and administrative, as before. A
--       re-point of a public edge keeps the owner it had (arm (u)). Mixed and
--       private endpoints keep 072's meet, byte for byte.
--   (3) `epigraph_propagate_tenancy()` re-meets an edge only when its new meet
--       is non-public: a public-to-public owner change of an endpoint (the
--       operator re-own, an administrative re-own) no longer rewrites public
--       edges, and a narrowing still takes the meet.
--   (4) `edges_delete_owner` loses 115's source-writer arm (D1's consequence
--       and D8): a non-privileged DELETE is strictly owner or co-owner scoped.
--   (5) `edges_owner_immutable` also watches `writer_group_id`.
--   (6) `epigraph_record_cascade_deferral` accepts cause `edge_retract` (D1
--       names edge-keyed BBA deletes as an administrative cascade): when an
--       edge's owner retracts or deletes it, other writers' BBAs keyed on it are
--       removed by the maintenance replay, not by the owner.
--   (7) `epigraph_reown_legacy_edges_to_signer` is D8's maintenance step for
--       legacy world-owned edges. The migration does NOT run it.
--
-- WHAT STAYS:
--   * 072's first arm (an explicit `('group', G)` declaration between two
--     non-group endpoints is kept, co-owner included) is UNCHANGED and runs
--     first, so no declaration is ever widened.
--   * 077's `edges_tenancy` WITH CHECK world arm (`visibility = 'public' AND
--     owner_group_id = world`) is KEPT: a principal-less INSERT (a maintenance
--     login, a backfill) and an edge outside the D8 scope still land as
--     `('public', world)`, administrative. 077's comment on that arm ("EVERY
--     edge between two public claims arrives at the policy world-owned") no
--     longer describes every public-public edge: after this file a stamped
--     writer's edge between two public claims arrives owned by the writer's
--     group, and the arm admits only the principal-less and out-of-scope ones.
--   * 117's `edges_update_owner` and `edges_repoint_unsign` are unchanged. They
--     now admit the writer's patch, retract and re-point, and nobody else's.
--   * `epigraph_session_writes_node` stays (117's deferral definer and
--     `claims_supersedes_guard` use it). 115's file is not edited.
--
-- ARM (i) APPLIES TO PRIVILEGED SESSIONS THAT CARRY A PRINCIPAL. A deliberate
-- difference from 114 section 2(b), which leaves privileged sessions'
-- claim-derived rows claim-owned. An edge has no parent claim to follow: its
-- only non-writer owner is the memberless world group. A stamped transaction on
-- a privileged DSN therefore records its principal's group like any other
-- stamped writer; otherwise every edge written while a deployment still serves
-- on a privileged DSN would join the administrative legacy set with no author
-- to recover it from. A privileged session with NO principal (a maintenance
-- login, a backfill) gets world.
--
-- LEGACY EDGES. Edges written before this file carry no attributable author
-- (`signer_id`, where set, is a bulk attestation key rather than an author), so
-- they stay world-owned and administrative: patch, retract and delete of one is
-- refused to every application session and runs through the maintenance path.
-- `epigraph_reown_legacy_edges_to_signer` re-owns a legacy edge only to a
-- signer that resolves to an operator or personal group, and only for signers
-- the operator has not excluded.
--
-- PRIVATIZATION. Apply is unchanged: an edge with a private endpoint takes the
-- meet, and a writer-owned edge narrows to it. The revert
-- (`PrivatizationRepository::recompute_boundary_meet_conn`) reads
-- `writer_group_id` and the same scope predicate, so apply then revert restores
-- a writer-owned edge exactly and still restores a legacy or out-of-scope edge
-- to `('public', world)`.
--
-- LOCKS. `ALTER TABLE edges ADD COLUMN` without a default is catalog-only but
-- takes ACCESS EXCLUSIVE on a hot, large table, and the policy and trigger DDL
-- below lock it too. `lock_timeout` bounds the wait; a lock-timeout failure
-- means re-run (in a maintenance window), never force.
--
-- DEPLOY ORDER: apply 120 only once the per-caller HTTP identity is serving, so
-- that no request unit stamps edges as a shared principal; see the batch
-- runbook. Apply 120 BEFORE any binary built with it serves.
--
-- Undo (roll the binaries back first; export `(id, writer_group_id)` of the
-- non-NULL rows before dropping the column):
--   * as a maintenance login, restamp writer-owned public edges
--     (`visibility = 'public' AND owner_group_id <> world`) to world;
--   * CREATE OR REPLACE, from their files' text: 072's
--     `epigraph_edges_tenancy`, 114's `epigraph_propagate_tenancy`, 117's
--     `epigraph_record_cascade_deferral`;
--   * DROP TRIGGER `edges_owner_immutable` and re-create it with 115's watch
--     list (`owner_group_id, co_owner_group_id`);
--   * re-create 115's `edges_delete_owner` WITH its source-writer arm only if
--     D8 itself is reversed;
--   * DROP FUNCTION `epigraph_reown_legacy_edges_to_signer(integer, uuid[])`
--     and `epigraph_edge_writer_scope(text, text)` (after the trigger no longer
--     names the latter), then DROP COLUMN `writer_group_id`.
--   Never DROP FUNCTION a body that a policy or trigger still names.
-- Checked before claiming: no `origin/*` ref and no local worktree carries a
-- `120`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE AUTHOR RECORD
-- ===================================================================
-- Nullable, no default (catalog-only on a large table), and NO foreign key: a
-- recorded author must not become a new obstacle to deleting a group.
ALTER TABLE public.edges ADD COLUMN IF NOT EXISTS writer_group_id uuid;

COMMENT ON COLUMN public.edges.writer_group_id IS
    'Migration 120: the writing session''s group (epigraph_writer_group()) at INSERT, '
    'set by epigraph_edges_tenancy() whatever the caller bound; NULL when the session '
    'carried no principal or the principal had no writable group. Never recomputed; '
    'immutable to a non-privileged session (edges_owner_immutable). Read only by the '
    'privatization revert, to restore a writer-owned edge exactly.';

-- ===================================================================
-- 2. THE D8 SCOPE
-- ===================================================================
-- "An edge between two public CLAIMS". Both endpoints must be tenancy-bearing
-- epistemic nodes: `claim` or `evidence`, the two types `epigraph_node_tenancy`
-- gives real tenancy. A registered non-claim SOURCE whose owner writes claims'
-- provenance in-process on its own stamped transaction (`synthesis`) is in
-- scope as a source only; `epigraph_node_tenancy` counts it as public.
-- Referenced by exactly: the tenancy trigger (section 3), the privatization
-- revert (Rust), the legacy re-own (section 8), and the tests.
CREATE OR REPLACE FUNCTION public.epigraph_edge_writer_scope(src_type text, tgt_type text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog AS $$
    SELECT COALESCE(src_type IN ('claim', 'evidence', 'synthesis')
                    AND tgt_type IN ('claim', 'evidence'), false)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edge_writer_scope(text, text) FROM PUBLIC;

-- ===================================================================
-- 3. THE WRITE-TIME STAMP (072's body plus the writer)
-- ===================================================================
-- Same signature, owner, SECURITY DEFINER, search_path and trigger
-- (`edges_tenancy BEFORE INSERT OR UPDATE OF source_id, target_id`).
--
-- Order matters:
--   * the writer is recorded FIRST, so a declared edge keeps its author record
--     too;
--   * 072's no-widening arm runs next, unchanged;
--   * a both-public meet then takes (u), (i) or world;
--   * anything else is 072's four meet arms, byte for byte.
--
-- (u) A re-point of a public edge keeps its owner: 117's administrative
--     cascade re-points other writers' edges on a principal-less maintenance
--     connection, and the writer keeps its edge; a legacy world edge stays
--     world.
-- (i) Effectively INSERT-only. An OLD group edge re-pointed onto public
--     endpoints is caught by the unchanged no-widening arm and stays group,
--     co-owner kept; an OLD public edge takes (u).
CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
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
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_tenancy() FROM PUBLIC;

-- ===================================================================
-- 4. PROPAGATION: 114's body, the edges statement only where the meet narrows
-- ===================================================================
-- 114's body BYTE FOR BYTE (the `derived text[]` literal included:
-- `crates/epigraph-cli/src/operator/tables.rs::parse_derived_array` reads it),
-- except the final `UPDATE public.edges`, which gains one conjunct,
-- `AND m.v = 'group'`. So a public-to-public owner change of an endpoint (the
-- operator re-own and its reverse, an administrative re-own) never touches a
-- public edge: a writer-owned edge stays the writer's and a world edge stays
-- world. A narrowing (privatization; any claim going non-public) still takes
-- the meet, and the writer loses the edge, which is 114's W5 rule for
-- writer-owned derived rows. 070's no-widening guard is left in place.
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
    -- BOTH endpoints (072's header; unchanged since).
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
          FROM public.edges e2
          JOIN changed ch
            ON ((e2.source_id = ch.id AND e2.source_type = 'claim')
             OR (e2.target_id = ch.id AND e2.target_type = 'claim'))
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.source_id, e2.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.target_id, e2.target_type) t
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
-- 5. DELETE ON edges: OWNER AND CO-OWNER ONLY
-- ===================================================================
-- 115's source-writer arm ("the edge nobody owns ... its source's writer may
-- remove it") is gone: the source's writer is not the edge's author, and the
-- one application path that relied on the arm (the workflow step rewire) now
-- refuses a rewire it cannot complete. A legacy world edge is deletable only by
-- a privileged session.
DROP POLICY IF EXISTS edges_delete_owner ON public.edges;
CREATE POLICY edges_delete_owner ON public.edges AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR co_owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- ===================================================================
-- 6. THE AUTHOR RECORD IS IMMUTABLE TO THE APPLICATION
-- ===================================================================
-- 115's trigger, with `writer_group_id` added to its column list and its WHEN.
-- A non-privileged UPDATE that names it and changes it is refused (42501) by
-- 115's `epigraph_owner_immutable_guard`.
DROP TRIGGER IF EXISTS edges_owner_immutable ON public.edges;
CREATE TRIGGER edges_owner_immutable
    BEFORE UPDATE OF owner_group_id, co_owner_group_id, writer_group_id
    ON public.edges
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
          OR OLD.co_owner_group_id IS DISTINCT FROM NEW.co_owner_group_id
          OR OLD.writer_group_id IS DISTINCT FROM NEW.writer_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

-- ===================================================================
-- 7. THE DEFERRAL DEFINER GAINS `edge_retract`
-- ===================================================================
-- 117's body, with one cause added. Same signature, so 117's owner and ACL are
-- preserved.
--
--   edge_retract : the subject is an EDGE the session owns or co-owns (the
--                  retract or delete act's own authority), read before any
--                  DELETE of the row; an edge-factor perspective
--                  (`perspectives.id = edge`, `perspective_type = 'edge'`)
--                  exists; and the edge is OUT OF FORCE (`valid_to <= now()`):
--                  an edge in force, or one retracted into the future, records
--                  nothing. An act that deletes the row closes its window
--                  first, in the same transaction. No object. The optional
--                  sources are the claims whose OWN edge-keyed BBAs the act
--                  deleted: the caller cannot re-derive a belief cache it does
--                  not own, so the replay re-derives them. The replay is
--                  STATE-DERIVED: it removes the edge-keyed BBAs only while the
--                  edge is absent or out of force, and a source only asks it to
--                  re-derive a claim's belief from the rows the claim has, so a
--                  stale or forged deferral does nothing state does not
--                  justify.
CREATE OR REPLACE FUNCTION public.epigraph_record_cascade_deferral(
    p_cause text, p_agent_id uuid, p_subject uuid, p_object uuid, p_sources uuid[],
    p_oauth jsonb, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    -- session_user, not current_user: inside this frame current_user is the
    -- owner (epigraph_maintenance).
    v_priv boolean := public.epigraph_bypass()
        OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls FROM pg_catalog.pg_roles r
                      WHERE r.rolname = session_user), false);
    v_principal uuid := public.epigraph_principal_id();
    v_sources uuid[] := COALESCE(p_sources, ARRAY[]::uuid[]);
    v_agent uuid;
    v_ok boolean;
    v_oauth jsonb;
    v_status text;
    v_trigger jsonb;
    v_id uuid := gen_random_uuid();
BEGIN
    IF p_cause IS NULL OR p_cause NOT IN ('supersede', 'dedup', 'consolidate', 'match_retire',
                                          'edge_retract') THEN
        RAISE EXCEPTION 'CX01: unknown cascade cause %; no deferral was recorded', p_cause
            USING ERRCODE = '22023';
    END IF;
    IF p_subject IS NULL
       OR (p_cause IN ('supersede', 'dedup')) <> (p_object IS NOT NULL)
       OR (p_cause = 'edge_retract' AND p_object IS NOT NULL)
       OR (p_cause <> 'edge_retract'
           AND (p_cause = 'consolidate') <> (cardinality(v_sources) > 0)) THEN
        RAISE EXCEPTION 'CX01: a % deferral names a subject%; no deferral was recorded', p_cause,
            CASE p_cause WHEN 'supersede' THEN ' and an object, and no sources'
                         WHEN 'dedup' THEN ' and an object, and no sources'
                         WHEN 'consolidate' THEN ' and its sources, and no object'
                         WHEN 'edge_retract' THEN ', optional claim sources, and no object'
                         ELSE ', and no object or sources' END
            USING ERRCODE = '22023';
    END IF;

    IF v_priv THEN
        v_agent := COALESCE(p_agent_id, v_principal);
    ELSIF v_principal IS NULL OR p_agent_id IS DISTINCT FROM v_principal THEN
        RAISE EXCEPTION 'CX02: a deferral is attributed to the session principal, and this '
            'session''s principal (%) is not the one named (%); no deferral was recorded',
            v_principal, p_agent_id
            USING ERRCODE = '42501';
    ELSE
        v_agent := v_principal;
    END IF;

    IF p_cause = 'supersede' THEN
        v_ok := EXISTS (SELECT 1 FROM public.claims o JOIN public.claims n ON n.id = p_object
                         WHERE o.id = p_subject AND NOT COALESCE(o.is_current, true)
                           AND n.supersedes = o.id)
            AND (v_priv OR (public.epigraph_session_writes_node(p_subject, 'claim')
                            AND public.epigraph_session_writes_node(p_object, 'claim')));
    ELSIF p_cause = 'dedup' THEN
        v_ok := EXISTS (SELECT 1 FROM public.claims d
                         WHERE d.id = p_subject AND d.supersedes = p_object
                           AND NOT COALESCE(d.is_current, true))
            AND (v_priv OR (public.epigraph_session_writes_node(p_subject, 'claim')
                            AND EXISTS (SELECT 1 FROM public.claims k
                                         WHERE k.id = p_object
                                           AND (k.visibility::text = 'public'
                                                OR public.epigraph_session_writes_node(k.id, 'claim')))));
    ELSIF p_cause = 'consolidate' THEN
        v_ok := (SELECT count(DISTINCT s) FROM unnest(v_sources) s) = cardinality(v_sources)
            AND (SELECT count(*) FROM public.claims s
                  WHERE s.id = ANY (v_sources) AND s.supersedes = p_subject
                    AND NOT COALESCE(s.is_current, true)) = cardinality(v_sources)
            AND (v_priv OR NOT EXISTS (
                    SELECT 1 FROM unnest(v_sources) s
                     WHERE NOT public.epigraph_session_writes_node(s, 'claim')));
    ELSIF p_cause = 'edge_retract' THEN
        -- The edge is out of force (a retract, or a row the act closed before
        -- deleting it: `withdraw_edge_bbas_conn` sets `valid_to = now()` first),
        -- so no deferral names an edge in force. The sources are the claims
        -- whose own edge-keyed BBAs the act deleted (distinct, at most 1000).
        -- They are not checked against `claims` here: under row security this
        -- frame may not see a claim the caller's BBA lived on, and refusing
        -- would roll back an honest retract. A source only asks the replay to
        -- re-derive that claim's belief from the rows it has (an unknown id
        -- re-derives nothing), so a wrong one changes nothing that state does
        -- not justify.
        v_ok := cardinality(v_sources) <= 1000
            AND (SELECT count(DISTINCT s) FROM unnest(v_sources) s) = cardinality(v_sources)
            AND EXISTS (SELECT 1 FROM public.edges e
                         WHERE e.id = p_subject
                           AND e.valid_to <= now()
                           AND (v_priv
                                OR e.owner_group_id = ANY (public.epigraph_writable_groups())
                                OR e.co_owner_group_id = ANY (public.epigraph_writable_groups())))
            AND EXISTS (SELECT 1 FROM public.perspectives p
                         WHERE p.id = p_subject AND p.perspective_type = 'edge');
    ELSE
        SELECT mc.status INTO v_status FROM public.match_candidates mc WHERE mc.id = p_subject;
        v_ok := v_status IS NOT NULL;
    END IF;
    IF NOT COALESCE(v_ok, false) THEN
        RAISE EXCEPTION 'CX03: the % act on % is not recorded as one this session made; a '
            'deferral names only a committed act of its own session; no deferral was recorded',
            p_cause, p_subject
            USING ERRCODE = '42501';
    END IF;

    IF p_oauth IS NULL OR jsonb_typeof(p_oauth) = 'null' THEN
        v_oauth := 'null'::jsonb;
    ELSIF jsonb_typeof(p_oauth) <> 'object'
          OR EXISTS (SELECT 1 FROM jsonb_object_keys(p_oauth) k
                      WHERE k NOT IN ('client_id', 'owner_id', 'agent_id')) THEN
        RAISE EXCEPTION 'CX01: the OAuth principal must be an object of client_id, owner_id and '
            'agent_id; no deferral was recorded'
            USING ERRCODE = '22023';
    ELSE
        v_oauth := jsonb_build_object('client_id', (p_oauth->>'client_id')::uuid,
                                      'owner_id',  (p_oauth->>'owner_id')::uuid,
                                      'agent_id',  (p_oauth->>'agent_id')::uuid);
    END IF;

    v_trigger := jsonb_build_object('agent_id', v_agent, 'oauth', v_oauth,
                                    'subject_id', p_subject, 'object_id', p_object);
    IF p_cause = 'consolidate'
       OR (p_cause = 'edge_retract' AND cardinality(v_sources) > 0) THEN
        v_trigger := v_trigger || jsonb_build_object('sources', to_jsonb(v_sources));
    ELSIF p_cause = 'match_retire' THEN
        v_trigger := v_trigger || jsonb_build_object('candidate_status', v_status);
    END IF;
    INSERT INTO public.security_events (id, event_type, agent_id, success, details)
    VALUES (v_id, 'cascade.deferred', v_agent, false,
            jsonb_build_object('cause', p_cause, 'trigger', v_trigger, 'migration', 117,
                               'reason', p_reason, 'session_user', session_user::text,
                               'recorded_by', 'epigraph_record_cascade_deferral'));
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_record_cascade_deferral(
    text, uuid, uuid, uuid, uuid[], jsonb, text) FROM PUBLIC;

-- ===================================================================
-- 8. LEGACY WORLD-OWNED EDGES: RE-OWN TO THEIR RECORDED SIGNER (D8)
-- ===================================================================
-- MAINTENANCE ONLY (EXECUTE granted to `epigraph_maintenance` alone) and NOT
-- run by this migration. A candidate is a public, world-owned, signed edge in
-- the D8 scope whose recomputed endpoint meet is still public, and whose signer
-- is not in `p_exclude_signers`. Its target group is the signer's operator's
-- personal group (`epigraph_operator_of_author`, retired links included,
-- ordered as 114's legacy BBA re-own), else the signer's own personal group;
-- a signer with neither is skipped. It sets `owner_group_id` AND
-- `writer_group_id`, so a later privatization revert restores it exactly.
--
-- `p_exclude_signers` is MANDATORY (a NULL array raises): a signature is an
-- attribution only when the signing key belongs to an author, and a bulk
-- attestation key does not. The operator passes every non-author signing key
-- the deployment holds; the empty array is an explicit "none".
--
-- Bounded by `p_limit` (NULL means all), idempotent, and one `security_events`
-- row (`edges.legacy_signer_reown`) per call that changed anything.
CREATE OR REPLACE FUNCTION public.epigraph_reown_legacy_edges_to_signer(
    p_limit integer, p_exclude_signers uuid[])
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_n bigint;
BEGIN
    IF p_exclude_signers IS NULL THEN
        RAISE EXCEPTION 'RLE01: p_exclude_signers is mandatory; pass every non-author signing '
            'key (an empty array only when there is none); nothing was re-owned'
            USING ERRCODE = '22004';
    END IF;
    WITH base AS (
        SELECT e.id,
               COALESCE(
                 (SELECT o.operator_group_id
                    FROM public.epigraph_operator_of_author(e.signer_id) o
                   ORDER BY o.retired, o.operator_id LIMIT 1),
                 (SELECT g.id FROM public.groups g
                   WHERE g.did_key = 'did:epigraph:personal:' || e.signer_id::text
                     AND g.kind = 'personal'
                     AND g.created_by_agent_id = e.signer_id)) AS w
          FROM public.edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
         WHERE e.visibility = 'public'
           AND e.owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid
           AND e.signer_id IS NOT NULL
           AND e.signer_id <> ALL (p_exclude_signers)
           AND public.epigraph_edge_writer_scope(e.source_type, e.target_type)
           AND s.v = 'public' AND t.v = 'public'
    ), cand AS (
        SELECT b.id, b.w FROM base b
         WHERE b.w IS NOT NULL
         ORDER BY b.id
         LIMIT p_limit
    )
    UPDATE public.edges e
       SET owner_group_id = cand.w, writer_group_id = cand.w
      FROM cand
     WHERE e.id = cand.id;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('edges.legacy_signer_reown', NULL, true,
                jsonb_build_object('rows', v_n, 'limit', p_limit,
                                   'excluded_signers', cardinality(p_exclude_signers),
                                   'migration', 120));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reown_legacy_edges_to_signer(integer, uuid[]) FROM PUBLIC;

-- ===================================================================
-- 9. OWNERSHIP AND GRANTS
-- ===================================================================
-- CREATE OR REPLACE preserves an existing function's owner and ACL; the
-- re-own is repeated anyway, for 072's stated reason (a cluster whose
-- migration role could not create the maintenance role leaves the bodies
-- app-owned, and `epigraph-tenancy-backfill verify` is the loud check).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_edge_writer_scope(text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_edges_tenancy() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_cascade_deferral('
                'text, uuid, uuid, uuid, uuid[], jsonb, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_reown_legacy_edges_to_signer(integer, uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_edge_writer_scope(text, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_reown_legacy_edges_to_signer('
                'integer, uuid[]) TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 120 function '
                     'bodies stay app-owned. Run `epigraph-tenancy-backfill verify` before '
                     'deploying.';
    END IF;
END $$;

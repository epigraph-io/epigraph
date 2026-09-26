-- 115: DELETE is owner-scoped on every tier-A table (batch W9).
--
-- ===================================================================
-- 0. WHAT THIS FILE CHANGES
-- ===================================================================
--
-- 077's `<table>_tenancy` policies are FOR ALL, and their USING clause is the
-- READ predicate: `visibility = 'public' OR owner_group_id = ANY (session
-- groups)`. For SELECT that is right. For DELETE it means that the rows a
-- session may remove are the rows it may READ, so a public row is removable by
-- any application session whatever group owns it. Migration 114 makes "a row a
-- writer attached to a public claim is the writer's" a stated property; this
-- file makes DELETE agree with it.
--
-- The rule, one sentence: a non-privileged session deletes a tier-A row only
-- when the row's owning group is in its WRITABLE set (for `edges`, the owner or
-- the co-owner; plus the one bespoke arm of section 2). Everything that used to
-- rely on reading a row as licence to delete it now goes through one of three
-- audited or trigger-bound definers (sections 3-5).
--
-- HOW: one RESTRICTIVE, FOR DELETE policy per table, `<table>_delete_owner`.
-- A restrictive policy is AND-ed with the permissive ones, so the existing
-- `<table>_tenancy` policies keep deciding SELECT / INSERT / UPDATE exactly as
-- before, and for DELETE both must admit the row. That also means a permissive
-- policy added to one of these tables by anything other than this series
-- cannot widen DELETE past this rule. A refused row is filtered, not an error:
-- `DELETE ... WHERE id = <someone else's row>` reports 0 rows, as it already
-- does for a row the session cannot read.
--
-- The privileged sessions are unchanged: `epigraph_bypass()` (a maintenance
-- login, or a superuser session) and `epigraph_definer_bypass()` (a definer
-- body owned by `epigraph_maintenance`) are the first two disjuncts of every
-- policy here, as in 077.
--
-- UPDATE of `owner_group_id` IS changed here, because the DELETE rule depends
-- on it: a session that could move a row into its own group with an UPDATE
-- could then delete it as that group's writer. 077's UPDATE admits exactly
-- that (USING = the read predicate, WITH CHECK = the writable set), so section
-- 7 makes `owner_group_id` (and `edges.co_owner_group_id`) immutable to every
-- non-privileged session on every table below, as 114 already did for
-- `evidence`, `mass_functions` and `reasoning_traces`. The rest of 077's
-- UPDATE side (the other columns, and the world arm on `edges` and the four
-- registries) is a separate item; section 3 states the one place this file's
-- admission leans on it.
--
-- ===================================================================
-- 1. THE TABLE SET
-- ===================================================================
--
-- Every relation in `public` carrying BOTH tenancy columns (`owner_group_id`,
-- `visibility`) and a permissive policy whose USING admits `visibility =
-- 'public'`: 062's tier-A array minus `recall_events`, i.e. the two roots
-- (`claims`, `evidence`), the claim-derived tables, `harvester_fragments`, the
-- four instance-wide registries (`frames`, `contexts`, `perspectives`,
-- `communities`) and `edges`. `recall_events` is keyed on the querying
-- principal (077 section 4) and admits no public arm. Measured on a database at
-- head: exactly 24 relations match, and
-- `epigraph-db/tests/owner_scoped_delete.rs::every_public_admitting_table_has_a_restrictive_delete_policy`
-- is the ratchet that fails when a 25th appears without one.
--
-- The four registries are world-owned by design, and the world group is
-- memberless, so NO application session deletes a registry row after this
-- file; no application code path does (the grep is in the test file's
-- header). A group-owned registry row is deletable by its group's writers.
--
-- Cascades that are not a policy question: a foreign key `ON DELETE CASCADE`
-- (every claim-derived table's `claim_id`) is a referential action, and
-- PostgreSQL runs it without consulting row security, so an owner deleting its
-- own claim still removes every row that hangs off it, other writers' included.
-- The `<node>_cascade_edges` triggers are row DELETEs issued by a trigger body
-- and DO consult policies; section 5 handles them.
--
-- ===================================================================
-- 2. THE `edges` RULE
-- ===================================================================
--
-- An edge is deletable by a writer of its owner OR of its co-owner (072's
-- intersection is a read rule; either co-owning party may remove the edge),
-- and, for the one shape nobody owns -- an edge between two PUBLIC endpoints,
-- which 070's trigger stamps `('public', world)` whatever the writer declared
-- -- by a session that can WRITE the edge's SOURCE node
-- (`epigraph_session_writes_node`). The source is the asserting end: "A
-- supports B" is A's author's assertion, and the edge-factor BBA it wires is
-- attributed to A's author. Without this arm a world-owned edge would be
-- undeletable by every application session, including the workflow step
-- rewire (`workflow_steps.rs`), which removes the `step_follows` edge between
-- two public step claims its own system agent owns.
--
-- `epigraph_session_writes_node(id, type)` answers ONE question: is this
-- node's owning group in the CALLER's writable set. It is bound to the caller
-- (it reads the session's own writable GUC), returns false for a node that
-- does not exist or has no tenancy of its own (070's `('public', world)`
-- fallback, and the world group is never writable), and so reveals nothing
-- the caller could not already derive from its own writable set. It does NOT
-- expose `epigraph_node_tenancy`, which stays revoked from the application.
--
-- ===================================================================
-- 3. THE CASCADE DEFINER FOR EDGE-KEYED BBAs
-- ===================================================================
--
-- An edge-factor BBA is a `mass_functions` row keyed `perspective_id = <edge
-- id>`, stored on the edge's target and attributed to the edge SOURCE's
-- author. Three code paths invalidate such rows as a consequence of something
-- the caller did to the EDGE, and the rows are routinely owned by somebody
-- else (the writer who wired the edge, or the claim's group):
--   * `ClaimRepository::mark_duplicate_with_repair_conn` retracts the
--     duplicate's colliding edges and drops their BBAs;
--   * `epigraph_engine::retraction_cascade` invalidates the BBAs of edges a
--     supersede or a dedup just re-sourced, and re-derives them;
--   * `MatchCandidateRepo::retire` retracts a promoted matcher edge and drops
--     its derived rows.
-- Each now calls `epigraph_cascade_delete_edge_bbas(edge_ids, cause)` for a
-- non-privileged session (a privileged one runs the plain statement it always
-- ran). The definer considers only rows the session can READ (public, or owned
-- by one of its groups) -- a row it cannot see is left alone, as the invoker
-- statement always left it -- and admits a row by exactly one of:
--   (owner)          its owner is in the session's writable set: the ordinary
--                    rule, so one call handles a mixed set;
--   (retracted_edge) its edge is retracted (`valid_to` set and past): the row is
--                    the derived record of a withdrawn assertion (MemTX I2,
--                    "retracting a belief leaves no orphaned derived record").
--                    Needs no principal: the match-candidate retirement runs on
--                    an unstamped connection. Its trust basis is the edge
--                    retraction itself, i.e. 077's UPDATE rule for `edges`
--                    (section 0);
--   (source_writer)  the edge's source is a claim S, and the session can write
--                    S, or can write a RETIRED duplicate d of S
--                    (`d.supersedes = S`, `NOT d.is_current`) whose author is
--                    the row's attributed source agent. The first shape is the
--                    supersede cascade (the edge now leaves the replacement,
--                    which the superseder wrote); the second is the dedup
--                    cascade (the edge now leaves the canonical, and the stale
--                    BBA was frozen from the duplicate the session retired).
-- If ANY readable candidate row is admitted by none of these, the call raises
-- 42501 (CD02) and deletes nothing, so a refusal reaches the caller as an
-- error -- `CascadeReport::errors` for the retraction cascade -- instead of
-- reading as "this edge carried no BBA". A call that deleted anything appends
-- one `security_events` row (`event_type = 'derived.cascade_bba_delete'`,
-- `agent_id` = the session principal, which may be NULL for the retirement),
-- with the cause, the edge ids, the per-arm counts and the owners of the
-- removed rows.
--
-- Two properties of these arms, stated so nobody reads more into them:
--   * `source_writer` is a STANDING capability of the source's writer, not one
--     scoped to a cascade event: it does not require that the edge was just
--     re-sourced, nor that the row sits on the edge's target. The writer of S
--     may invalidate edge-keyed BBAs of any edge sourced at S at any time: the
--     definer is executable by the application role, and the application
--     itself calls it only from the three cascade paths, over edges they
--     select. That matches the attribution rule (the edge-factor BBA is the
--     source author's assertion), not a cascade binding.
--   * `p_cause` is CALLER-ASSERTED. It is checked against a three-value list
--     and recorded in the audit row, but nothing verifies that the named event
--     happened; read the audit's `cause` as what the caller said, and its
--     `arms` as what licensed each row.
-- The whole-call refusal is fail-closed on purpose, and it has a cost: a
-- readable BBA on the same edge that no arm admits (for instance one a third
-- party stored under that edge's perspective, attributed to another agent)
-- makes the legitimate actor's call refuse too, and the stale rows it meant to
-- invalidate stay combined until a privileged recompute. Skipping the
-- unadmitted rows per edge was rejected: it would make "some of this edge's
-- BBAs were not yours" indistinguishable from "done".
--
-- WHY NOT "deleted in this transaction": the retraction cascade runs AFTER the
-- supersede / dedup transaction committed (it is best-effort by design, see
-- the module doc), so there is no transaction to bind to; every arm above is a
-- predicate over the database state at call time, not over a caller-supplied
-- list.
--
-- ===================================================================
-- 4. THE DEDUP COLLISION, INSIDE THE DEDUP MOVE
-- ===================================================================
--
-- `mark_duplicate_with_repair_conn` pre-deletes a canonical-side row that has
-- the same (claim, frame, source agent, perspective) key as a row about to move
-- in from the duplicate, so the move does not trip the unique index. That
-- DELETE stays a plain statement: for a privileged session it is what it was,
-- and for any other session this file scopes it to the rows the session owns.
-- It is NOT routed through a definer, because the only licence a definer could
-- check is "the duplicate carries a row with the same key", and the duplicate
-- is the session's own claim: it could plant that row itself and so delete
-- any writer's BBA on any canonical it marks a duplicate of.
--
-- A collision the plain DELETE could not clear (the canonical's row belongs to
-- somebody else) is resolved the other way round, inside 114's
-- `epigraph_dedup_move_bbas`, which already verifies the dedup context (the
-- session writes the duplicate, the duplicate supersedes the canonical, the
-- edge now targets the canonical): the DUPLICATE's copy is dropped and the
-- canonical keeps its own. Both rows carry the same edge, frame and source
-- agent; only the moment their masses were frozen differs. The drop is counted
-- in the move's `dedup_bba_move` audit row. Redefined here (CREATE OR REPLACE,
-- same signature); 114 is not edited.
--
-- ===================================================================
-- 5. NODE-DELETE EDGE CASCADE
-- ===================================================================
--
-- `claims_cascade_edges`, `evidence_cascade_edges` and `traces_cascade_edges`
-- ran 001's `cascade_delete_edges()`, a SECURITY INVOKER body, so the edges it
-- removes are subject to the deleting session's policies. With section 2 in
-- place an owner deleting its own public claim could not remove a world-owned
-- edge from somebody else's claim to it, and the edge would be left pointing at
-- a row that no longer exists. Those three triggers now run
-- `epigraph_cascade_delete_node_edges()`, the same statement in a definer owned
-- by `epigraph_maintenance`. A trigger function cannot be called from SQL, and
-- a BEFORE DELETE row trigger fires only for a row the DELETE's own policies
-- already admitted, so the definer adds no capability beyond "deleting a node
-- you may delete removes the edges that point at it". The other tables that
-- use `cascade_delete_edges()` (agents, papers, analyses, tasks, events,
-- workflows, experiments) are not tier-A rows and keep 001's body.
--
-- ===================================================================
-- 6. GRANTS AND OWNERSHIP
-- ===================================================================
--
-- The three definers and the helper are owned by `epigraph_maintenance` (so
-- `epigraph_definer_bypass()` holds inside them), EXECUTE revoked from PUBLIC.
-- `epigraph_session_writes_node` is granted to `epigraph_app` and
-- `epigraph_maintenance`, because a policy names it (077 correction (1): a
-- function a policy calls must be executable by every role the policy
-- filters); the cascade definer to `epigraph_app` and `epigraph_maintenance`;
-- the trigger body to nobody.
--
-- `epigraph_maintenance` gains DELETE on `mass_functions` and `edges` -- the two
-- tables these definers delete from as their owner. 070 granted the role
-- SELECT / INSERT / UPDATE only; this is the narrowest grant under which the
-- bodies work, and a maintenance login already bypasses every policy here.
--
-- ===================================================================
-- 7. OWNER IMMUTABILITY (`epigraph_owner_immutable_guard`)
-- ===================================================================
--
-- A BEFORE UPDATE OF `owner_group_id` row trigger, `<table>_owner_immutable`,
-- on each of the 21 tables of section 1 that 114's `<table>_writer_owner_guard`
-- does not already cover (on `edges` it also watches `co_owner_group_id`). It
-- refuses (42501) a change of the owner from any session that is not
-- privileged in 114's sense (`epigraph_session_is_privileged_writer()`: a
-- superuser or BYPASSRLS role, a maintenance login, or a body running as the
-- maintenance role). A WITH CHECK cannot see the OLD row, so this has to be a
-- trigger. `UPDATE OF` fires only when the statement's SET list names the
-- column, so the tenancy triggers that restamp an owner from the row's parent
-- or endpoints (074, 070/072) are unaffected, and the propagation, privatization,
-- backfill and operator re-own paths all run as the maintenance role. No
-- application path re-owns one of these rows.
--
-- ===================================================================
-- 8. THE GROUP-KEYED SEALED-CONTENT TABLES
-- ===================================================================
--
-- The same shape outside tier A: `claim_encryption`, `evidence_encryption`,
-- `edge_encryption`, `claim_version_encryption` and `group_key_epochs` carry
-- a `group_id` instead of the tenancy columns, and their 077 policies are FOR
-- ALL with USING = the READ set (`epigraph_session_groups()`) and WITH CHECK =
-- the writable set. So a `reader` member of a group could DELETE the group's
-- ciphertext rows, and a sealed row has no plaintext to restore from. Each
-- gets a RESTRICTIVE, FOR DELETE policy `<table>_delete_writer`: the row's
-- group must be in the session's WRITABLE set (on `group_key_epochs` also the
-- group's creator, which that table's 077 policy admits for provisioning).
-- The application's own deletes on these tables are the privatization /
-- unseal paths, which run as the maintenance role and are unchanged. `groups`
-- keeps its delete-blocking trigger, and `group_memberships` grants the
-- application no DELETE. `owner_scoped_delete.rs`'s catalog ratchet fails
-- when a table whose permissive DELETE-covering policy admits on the read
-- set has no restrictive DELETE policy and is not on its short allow-list.
--
-- DEPLOY ORDER: apply 115 BEFORE any binary built with it serves: the repo
-- layer calls `epigraph_cascade_delete_edge_bbas` for every non-privileged
-- cascade. A binary built without 115 against a database at 115 runs its old
-- plain statements, which the policies then scope to owned rows.
--
-- Undo: DROP the 24 `<table>_delete_owner` policies, the five
-- `<table>_delete_writer` policies and the 21 `<table>_owner_immutable`
-- triggers; point the three
-- `<node>_cascade_edges` triggers back at `cascade_delete_edges('<type>')`;
-- restore 114's body of `epigraph_dedup_move_bbas`; DROP the four new
-- functions; REVOKE DELETE ON mass_functions, edges FROM epigraph_maintenance.
-- Checked before claiming: no `origin/*` ref carries a `115`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 2a. THE CALLER-BOUND WRITABILITY HELPER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_session_writes_node(p_id uuid, p_type text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(
        (SELECT t.g FROM public.epigraph_node_tenancy(p_id, p_type) t LIMIT 1)
            = ANY (public.epigraph_writable_groups()),
        false)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_session_writes_node(uuid, text) FROM PUBLIC;

-- ===================================================================
-- 1. RESTRICTIVE DELETE ON THE 23 SINGLE-OWNER TABLES
-- ===================================================================
DO $$
DECLARE t text;
        owned text[] := ARRAY[
          'claims','evidence',
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments',
          'frames','contexts','perspectives','communities'];
BEGIN
    FOREACH t IN ARRAY owned LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_delete_owner', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR DELETE TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_delete_owner', t);
    END LOOP;
END $$;

-- ===================================================================
-- 2b. RESTRICTIVE DELETE ON edges
-- ===================================================================
DROP POLICY IF EXISTS edges_delete_owner ON public.edges;
CREATE POLICY edges_delete_owner ON public.edges AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR co_owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        -- The edge nobody owns: both endpoints public (070 stamps it world).
        -- Its source's writer may remove it. See section 2.
        OR (visibility = 'public'
            AND owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid
            AND public.epigraph_session_writes_node(source_id, source_type::text)));

-- ===================================================================
-- 3. THE CASCADE DEFINER FOR EDGE-KEYED BBAs
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_cascade_delete_edge_bbas(
    p_edge_ids uuid[], p_cause text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := COALESCE(public.epigraph_writable_groups(), ARRAY[]::uuid[]);
        v_g uuid[] := COALESCE(public.epigraph_session_groups(), ARRAY[]::uuid[]);
        v_total bigint; v_refused bigint; v_n bigint; v_ids uuid[];
        v_arms jsonb; v_owners jsonb;
BEGIN
    IF p_cause IS NULL OR p_cause NOT IN ('dedup_retracted_edge', 'retraction_cascade',
                                          'match_candidate_retire') THEN
        RAISE EXCEPTION 'CD01: unknown cascade cause %; nothing was deleted', p_cause
            USING ERRCODE = '22023';
    END IF;
    IF p_edge_ids IS NULL OR cardinality(p_edge_ids) = 0 THEN
        RETURN 0;
    END IF;
    -- A privileged SESSION (maintenance login or superuser; `session_user`,
    -- which a definer frame does not change) is the plain statement.
    IF public.epigraph_bypass() THEN
        DELETE FROM public.mass_functions WHERE perspective_id = ANY (p_edge_ids);
        GET DIAGNOSTICS v_n = ROW_COUNT;
        RETURN v_n;
    END IF;

    -- Classify every candidate the SESSION can read, locked so the verdict and
    -- the delete see the same rows. (No temp table: one created inside a
    -- definer frame is reachable by the caller's session, which could plant a
    -- same-named relation carrying its own trigger.)
    WITH cand AS (
        SELECT mf.id, mf.owner_group_id,
               CASE
                 WHEN mf.owner_group_id = ANY (v_w) THEN 'owner'
                 WHEN e.id IS NOT NULL AND e.valid_to IS NOT NULL AND e.valid_to <= now()
                      THEN 'retracted_edge'
                 WHEN e.id IS NOT NULL AND e.source_type = 'claim'
                      AND EXISTS (
                          SELECT 1 FROM public.claims d
                           WHERE d.owner_group_id = ANY (v_w)
                             AND (d.id = e.source_id
                                  OR (d.supersedes = e.source_id
                                      AND NOT d.is_current
                                      AND d.agent_id IS NOT DISTINCT FROM mf.source_agent_id)))
                      THEN 'source_writer'
                 ELSE NULL
               END AS arm
          FROM public.mass_functions mf
          LEFT JOIN public.edges e ON e.id = mf.perspective_id
         WHERE mf.perspective_id = ANY (p_edge_ids)
           AND (mf.visibility = 'public' OR mf.owner_group_id = ANY (v_g))
           FOR UPDATE OF mf
    )
    SELECT count(*),
           count(*) FILTER (WHERE arm IS NULL),
           COALESCE(array_agg(id), ARRAY[]::uuid[]),
           jsonb_build_object(
               'owner',          count(*) FILTER (WHERE arm = 'owner'),
               'retracted_edge', count(*) FILTER (WHERE arm = 'retracted_edge'),
               'source_writer',  count(*) FILTER (WHERE arm = 'source_writer')),
           COALESCE(to_jsonb(array_agg(DISTINCT owner_group_id)), '[]'::jsonb)
      INTO v_total, v_refused, v_ids, v_arms, v_owners
      FROM cand;
    IF v_refused > 0 THEN
        RAISE EXCEPTION 'CD02: % of % edge-keyed mass function(s) for these edges are not '
            'this session''s to delete (cause %); nothing was deleted',
            v_refused, v_total, p_cause
            USING ERRCODE = '42501';
    END IF;
    IF v_total = 0 THEN
        RETURN 0;
    END IF;

    DELETE FROM public.mass_functions mf WHERE mf.id = ANY (v_ids);
    GET DIAGNOSTICS v_n = ROW_COUNT;

    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('derived.cascade_bba_delete', v_principal, true,
                jsonb_build_object(
                    'cause',              p_cause,
                    'edge_ids',           to_jsonb(p_edge_ids),
                    'deleted',            v_n,
                    'arms',               v_arms,
                    'owner_group_ids',    v_owners,
                    'writable_group_ids', to_jsonb(v_w),
                    'migration',          115));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_cascade_delete_edge_bbas(uuid[], text) FROM PUBLIC;

-- ===================================================================
-- 4. THE DEDUP MOVE, WITH THE RESIDUAL-COLLISION DROP
-- ===================================================================
-- 114's body; the only change is the `v_dropped` statement ahead of the move
-- and its count in the audit row. See section 4 of the header.
CREATE OR REPLACE FUNCTION public.epigraph_dedup_move_bbas(
    p_dup uuid, p_canonical uuid, p_perspectives uuid[])
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := public.epigraph_writable_groups();
        v_dup_owner uuid; v_dup_sup uuid;
        v_c_owner uuid; v_c_vis character varying(16);
        v_c_writable boolean; v_n bigint; v_dropped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'FA01: a non-owner write to a claim''s aggregate needs a session '
            'principal (epigraph.principal_id) to attribute it to; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    SELECT c.owner_group_id, c.supersedes INTO v_dup_owner, v_dup_sup
      FROM public.claims c WHERE c.id = p_dup;
    IF NOT FOUND OR NOT (v_dup_owner = ANY (v_w)) OR v_dup_sup IS DISTINCT FROM p_canonical THEN
        RAISE EXCEPTION 'FA08: claim % is not a duplicate of % that this session may move '
            'BBAs from; nothing was written', p_dup, p_canonical USING ERRCODE = '42501';
    END IF;
    SELECT c.owner_group_id, c.visibility INTO v_c_owner, v_c_vis
      FROM public.claims c WHERE c.id = p_canonical;
    IF NOT FOUND OR NOT (v_c_vis = 'public'
                         OR v_c_owner = ANY (public.epigraph_session_groups())) THEN
        RAISE EXCEPTION 'FA02: claim % not found', p_canonical USING ERRCODE = 'P0002';
    END IF;
    v_c_writable := v_c_owner = ANY (v_w);
    IF NOT v_c_writable AND v_c_vis IS DISTINCT FROM 'public' THEN
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'FA04: a non-owner may attach only to a PUBLIC claim';
    END IF;

    -- 115: a collision the caller's owner-scoped pre-delete could not clear
    -- keeps the CANONICAL's row; the duplicate's copy (same edge, frame and
    -- source agent) is dropped instead of moved.
    DELETE FROM public.mass_functions d
     WHERE d.claim_id = p_dup
       AND d.perspective_id = ANY (p_perspectives)
       AND EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = d.perspective_id
                      AND e.target_id = p_canonical AND e.target_type = 'claim')
       AND EXISTS (SELECT 1 FROM public.mass_functions c
                    WHERE c.claim_id = p_canonical
                      AND c.perspective_id = d.perspective_id
                      AND c.frame_id = d.frame_id
                      AND c.source_agent_id IS NOT DISTINCT FROM d.source_agent_id);
    GET DIAGNOSTICS v_dropped = ROW_COUNT;

    UPDATE public.mass_functions mf
       SET claim_id       = p_canonical,
           owner_group_id = CASE
                              WHEN NOT v_c_writable THEN mf.owner_group_id
                              WHEN v_c_vis = 'public' AND mf.writer_owned THEN mf.owner_group_id
                              ELSE v_c_owner END,
           visibility     = v_c_vis,
           writer_owned   = CASE
                              WHEN v_c_vis IS DISTINCT FROM 'public' THEN false
                              WHEN NOT v_c_writable THEN true
                              ELSE mf.writer_owned END
     WHERE mf.claim_id = p_dup
       AND mf.perspective_id = ANY (p_perspectives)
       AND EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = mf.perspective_id
                      AND e.target_id = p_canonical AND e.target_type = 'claim');
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF (v_n > 0 OR v_dropped > 0) AND NOT v_c_writable THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_canonical, v_c_owner, 'dedup_bba_move',
            jsonb_build_object('from_claim_id', p_dup),
            jsonb_build_object('moved', v_n, 'dropped_duplicate_copies', v_dropped));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) FROM PUBLIC;

-- ===================================================================
-- 5. NODE-DELETE EDGE CASCADE FOR THE THREE TIER-A NODE TABLES
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_cascade_delete_node_edges() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- 001's `cascade_delete_edges()` statement, as the maintenance owner.
    DELETE FROM public.edges
     WHERE (source_id = OLD.id AND source_type = TG_ARGV[0])
        OR (target_id = OLD.id AND target_type = TG_ARGV[0]);
    RETURN OLD;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_cascade_delete_node_edges() FROM PUBLIC;

DROP TRIGGER IF EXISTS claims_cascade_edges ON public.claims;
CREATE TRIGGER claims_cascade_edges BEFORE DELETE ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_cascade_delete_node_edges('claim');
DROP TRIGGER IF EXISTS evidence_cascade_edges ON public.evidence;
CREATE TRIGGER evidence_cascade_edges BEFORE DELETE ON public.evidence
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_cascade_delete_node_edges('evidence');
DROP TRIGGER IF EXISTS traces_cascade_edges ON public.reasoning_traces;
CREATE TRIGGER traces_cascade_edges BEFORE DELETE ON public.reasoning_traces
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_cascade_delete_node_edges('trace');

-- ===================================================================
-- 7. OWNER IMMUTABILITY
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_owner_immutable_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: an UPDATE of % changes owner_group_id or '
                    'co_owner_group_id; only a maintenance session re-owns a row',
                    TG_TABLE_NAME
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_owner_immutable_guard() FROM PUBLIC;

DO $$
DECLARE t text;
        guarded text[] := ARRAY[
          'claims',
          'triples','entity_mentions','claim_versions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments',
          'frames','contexts','perspectives','communities'];
BEGIN
    FOREACH t IN ARRAY guarded LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', t || '_owner_immutable', t);
        EXECUTE format(
          'CREATE TRIGGER %I BEFORE UPDATE OF owner_group_id ON public.%I
             FOR EACH ROW
             WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
             EXECUTE FUNCTION public.epigraph_owner_immutable_guard()',
          t || '_owner_immutable', t);
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS edges_owner_immutable ON public.edges;
CREATE TRIGGER edges_owner_immutable BEFORE UPDATE OF owner_group_id, co_owner_group_id
    ON public.edges
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
          OR OLD.co_owner_group_id IS DISTINCT FROM NEW.co_owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

-- ===================================================================
-- 8. RESTRICTIVE DELETE ON THE GROUP-KEYED SEALED-CONTENT TABLES
-- ===================================================================
DO $$
DECLARE t text;
        sealed text[] := ARRAY['claim_encryption','evidence_encryption','edge_encryption',
                               'claim_version_encryption'];
BEGIN
    FOREACH t IN ARRAY sealed LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_delete_writer', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR DELETE TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_delete_writer', t);
    END LOOP;
END $$;

DROP POLICY IF EXISTS group_key_epochs_delete_writer ON public.group_key_epochs;
CREATE POLICY group_key_epochs_delete_writer ON public.group_key_epochs
    AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR public.epigraph_is_group_creator(group_id));

-- ===================================================================
-- 6. OWNERSHIP AND GRANTS
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_session_writes_node(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_cascade_delete_edge_bbas(uuid[], text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_cascade_delete_node_edges() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_owner_immutable_guard() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT DELETE ON public.mass_functions, public.edges TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_session_writes_node(uuid, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_cascade_delete_edge_bbas(uuid[], text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_session_writes_node(uuid, text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_cascade_delete_edge_bbas(uuid[], text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'TO epigraph_app';
    END IF;
END $$;

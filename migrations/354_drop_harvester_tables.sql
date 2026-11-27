-- 354: drop the five harvester tables (backlog a6e3dba2, c7752f07).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `harvester_sources`, `harvester_fragments`, `harvester_audit_reports`,
-- `harvester_claim_provenance` and `harvester_enriched_concepts` (001) were
-- written by the Python harvester. Its in-repo crate and gRPC proto are gone,
-- no code in this repository writes any of them, and the application role
-- holds no INSERT on three of them (118 section 6). The operator decided
-- (2026-11-27, backlog c7752f07 option (b)) to drop them, after a read-only
-- check of the deployed database found every one of the five with no live
-- row and no insert, update or delete since its statistics were reset: no
-- external writer. 089, 115, 173, 215, 218, 242, 284 and 347 kept them under
-- tenancy; every one of those arms goes with them.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. GUARDS (nothing changes on a refusal):
--      a. the four shared bodies it re-states are the ones it was written
--         from (md5 of `prosrc`; 55000), as 284's guard;
--      b. the session reads every row (a superuser, BYPASSRLS, or the
--         maintenance role, 173's three admissions; 42501). The five tables
--         are FORCEd, so any other session, their owner included, would count
--         only public rows and its own groups' and pass guard (c) over rows it
--         cannot see;
--      c. all five tables are EMPTY (55000). This file archives nothing: a
--         database that holds a harvester row needs a decision first.
--   2. Re-states, without their harvester arms, every surviving function whose
--      body names one of the five tables (a catalog grep of `prosrc` after
--      the drop finds none):
--      * `epigraph_propagate_tenancy()` (284's body): drops
--        `harvester_claim_provenance` from `derived[]` and arm (d), the
--        fragment statement (089, ranked by 218). Every other arm is 284's
--        byte for byte;
--      * `epigraph_publicize_claims` and `epigraph_share_claims_with_team`
--        (284's bodies): drop 242's fragment hold and 215's source rule, and
--        the three audit keys they reported (`harvester_fragments_held`,
--        `harvester_sources_moved`, `harvester_sources_held`); the audit row's
--        `migration` is 354. Everything else is 284's byte for byte;
--      * `epigraph_record_elevated_access` (127's body): drops the
--        `harvester_fragments` arm of its owner-group list.
--      CREATE OR REPLACE keeps each function's owner and ACL; each keeps its
--      pinned `search_path`.
--   3. DROP TABLE (RESTRICT, no CASCADE, foreign-key order): provenance,
--      audit reports, fragments, sources, concepts. That removes their
--      columns, constraints, indexes, triggers, policies and grants. Nothing
--      outside the five references them (measured: no foreign key, view,
--      policy or `tenancy_exempt` row), so RESTRICT refuses anything
--      unexpected instead of removing it.
--   4. Drops the three trigger functions only these tables ran:
--      `epigraph_inherit_fragment_tenancy_stmt()` (089, 218),
--      `epigraph_audit_report_inherit_tenancy()` and
--      `epigraph_fragment_audit_reports_follow()` (173). The shared trigger
--      bodies they also used (`epigraph_owner_immutable_guard`,
--      `epigraph_root_require_tenancy`, `epigraph_derived_require_tenancy`,
--      `epigraph_inherit_tenancy_stmt`, `epigraph_role_agent_write_check`)
--      stay.
--
-- NOT CHANGED: `docs/runbooks/079-undo.sql` and the other historical
-- runbooks still name these tables; they describe the files they undo.
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as a superuser (or a login that owns the five tables and is a member
-- of `epigraph_maintenance`): DROP TABLE needs the tables' owner, the
-- re-statements need the functions' owner, and guard (b) needs a session
-- that reads every row.
--
-- Measure first: `SELECT count(*) FROM <each table>` as a superuser (guard
-- (c) refuses on any row).
--
-- Binary: the API binary of this change no longer requires the 070, 074,
-- 089 and 173 harvester triggers, and no longer names the tables in its seal
-- or its FORCE list, so it boots before and after this file. An OLDER binary
-- refuses to boot on a migrated database (it requires
-- `harvester_claim_provenance_inherit_tenancy`, 070's tier), and its seal
-- fails (42P01). Deploy the binary with this file (`epigraph-migrate` as the
-- unit's ExecStartPre does). The operator CLI of this change refuses a
-- database below 354 (its cascade model finds a table in
-- `epigraph_propagate_tenancy`'s list it no longer attributes).
--
-- Undo: `docs/runbooks/354-undo.sql` (roll the binary back first) recreates
-- the five tables EMPTY in their 347 shape and re-states the four bodies
-- and the three trigger functions this file replaced or dropped.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD (a): re-state only the bodies this file was written from
-- ===================================================================
-- md5(prosrc) of 284's `epigraph_propagate_tenancy`,
-- `epigraph_publicize_claims` and `epigraph_share_claims_with_team`, and
-- 127's `epigraph_record_elevated_access`. A migration that re-bodied one of
-- them before this file would be silently reverted here: refuse.
DO $$
DECLARE v_prop text; v_pub text; v_share text; v_elev text;
BEGIN
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_propagate_tenancy()');
    SELECT md5(p.prosrc) INTO v_pub FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_publicize_claims(uuid[], text)');
    SELECT md5(p.prosrc) INTO v_share FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_share_claims_with_team(uuid[], uuid, text)');
    SELECT md5(p.prosrc) INTO v_elev FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure(
               'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])');
    IF (v_prop, v_pub, v_share, v_elev) IS DISTINCT FROM
       ('3f149d9aaf288162fadd609f4bc6ddaf', 'cf74273d3e1a889e30b1adc13e846ba3',
        '303bd7afda24bd28b2b8ae4187d7849f', '5d05a3c17f9a0cbf75e24e2a9f4859d6') THEN
        RAISE EXCEPTION '354: epigraph_propagate_tenancy (prosrc md5 %), '
                        'epigraph_publicize_claims (%), epigraph_share_claims_with_team (%) '
                        'or epigraph_record_elevated_access (%) is not the body 354 re-states '
                        '(284''s, 284''s, 284''s, 127''s). Another migration re-bodied it; '
                        'nothing was changed',
                        COALESCE(v_prop, '(absent)'), COALESCE(v_pub, '(absent)'),
                        COALESCE(v_share, '(absent)'), COALESCE(v_elev, '(absent)')
              USING ERRCODE = '55000',
                    HINT = 'Re-state the MERGED body in a later migration instead.';
    END IF;
END $$;

-- ===================================================================
-- GUARDS (b) and (c): a session that reads every row finds none
-- ===================================================================
-- (b) is 173's three admissions, inlined: `epigraph_definer_bypass()` is not
-- executable by PUBLIC, so calling it here would turn the refusal into a
-- 42501 of another kind.
DO $$
DECLARE reads_all boolean; t text; n bigint; nonempty text[] := ARRAY[]::text[];
BEGIN
    SELECT r.rolsuper OR r.rolbypassrls INTO reads_all
      FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
    reads_all := COALESCE(reads_all, false)
        OR public.epigraph_bypass()
        OR COALESCE((SELECT pg_catalog.pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
                      WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                                     WHERE rolname = 'epigraph_maintenance')), false);
    IF NOT reads_all THEN
        RAISE EXCEPTION '354: role % cannot read every harvester row (not a superuser, no '
                        'BYPASSRLS, not a member of epigraph_maintenance); the five tables '
                        'are FORCEd, so the emptiness check below could pass over rows it '
                        'cannot see. Nothing was changed. Run as a superuser.', current_user
            USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY ARRAY['harvester_claim_provenance', 'harvester_audit_reports',
                             'harvester_fragments', 'harvester_sources',
                             'harvester_enriched_concepts'] LOOP
        EXECUTE format('SELECT count(*) FROM public.%I', t) INTO n;
        IF n > 0 THEN
            nonempty := nonempty || format('%s (%s)', t, n);
        END IF;
    END LOOP;
    IF cardinality(nonempty) > 0 THEN
        RAISE EXCEPTION '354: harvester table(s) hold rows: %. This file drops the tables '
                        'and archives nothing; decide what happens to those rows first. '
                        'Nothing was changed.', array_to_string(nonempty, ', ')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 2. THE SHARED BODIES, WITHOUT THEIR HARVESTER ARMS
-- ===================================================================
-- 284's propagation: `harvester_claim_provenance` leaves `derived[]`
-- (`epigraph-cli`'s operator parses that literal) and the fragment statement
-- of arm (d) goes; the rest is 284's byte for byte.
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint; pin_skip text;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'evidence',
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
    -- 354: the fragment arm (089, 218) went with the tables it wrote.
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

-- 284's publicize: 242's fragment count and 215's source rule go, with their
-- three audit keys; the audit row records `migration: 354`.
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
    v_scoped bigint := 0;
    v_divergence bigint := 0;
    v_pinned bigint := 0;
    v_owners uuid[];
    v_moved bigint := 0;
    v_human uuid;
    v_operated boolean;
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
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'evidence_kept_private', v_pinned,
                               'migration', 354,
                               'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY
        SELECT u.id, CASE WHEN u.o = 'publicize' THEN 'publicized' ELSE u.o END
          FROM unnest(v_cls_ids, v_cls_out) AS u(id, o) ORDER BY u.id;
END $$;

-- 284's share: 242's fragment hold (capture before the move, restore after)
-- and 215's source rule go, with their three audit keys; the audit row
-- records `migration: 354`.
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
    v_scoped bigint := 0;
    v_divergence bigint := 0;
    v_human uuid;
    v_operated boolean;
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
                               'scoped_beliefs_cleared', v_scoped,
                               'divergence_rows_cleared', v_divergence,
                               'migration', 354, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);

    RETURN QUERY SELECT u.id, 'shared'::text FROM unnest(v_cls_ids) AS u(id) ORDER BY u.id;
END $$;

-- 127's recorder: the `harvester_fragments` arm of its owner-group list goes.
CREATE OR REPLACE FUNCTION public.epigraph_record_elevated_access(
    p_surface text, p_args jsonb, p_row_count integer, p_candidate_ids uuid[])
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_session public.elevation_sessions%ROWTYPE;
    v_ids     uuid[];
    v_mine    uuid[];
    v_groups  uuid[];
    v_id      uuid;
BEGIN
    IF NOT public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'ELV07: this connection is not elevated; only an elevated request '
                        'is recorded, by the process that serves it'
            USING ERRCODE = 'ELV07';
    END IF;
    -- `epigraph_is_elevated()` has validated the setting's shape and found
    -- this session live.
    SELECT s.* INTO STRICT v_session
      FROM public.elevation_sessions s
     WHERE s.id = current_setting('epigraph.elevation_id')::uuid;

    v_ids := ARRAY(SELECT DISTINCT x FROM unnest(COALESCE(p_candidate_ids, ARRAY[]::uuid[])) x
                    WHERE x IS NOT NULL);
    v_mine := ARRAY(SELECT m.group_id FROM public.group_memberships m
                     WHERE m.agent_id = v_session.person_agent_id AND m.revoked_at IS NULL);

    WITH owned (g, foreign_row) AS (
        -- The owner-group tables an elevated session reads (126 list 3a),
        -- keyed by a uuid `id`: private and not the elevator's group.
                  SELECT owner_group_id, visibility <> 'public' FROM public.challenges
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.claim_clusters
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public'
                    FROM public.claim_signature_revocations WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.claim_versions
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.claims
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.contexts
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public'
                    FROM public.ds_bayesian_divergence WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.ds_combined_beliefs
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.entity_mentions
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.evidence
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.frames
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.mass_functions
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.perspectives
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.reasoning_traces
                   WHERE id = ANY (v_ids)
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.triples
                   WHERE id = ANY (v_ids)
        -- An edge is private to its owner AND its co-owner (072): either
        -- group the elevator is not in is a subject.
        UNION ALL SELECT g, e.visibility <> 'public'
                    FROM public.edges e
                    CROSS JOIN LATERAL unnest(ARRAY[e.owner_group_id, e.co_owner_group_id]) g
                   WHERE e.id = ANY (v_ids) AND g IS NOT NULL
        -- A group, and a membership in one.
        UNION ALL SELECT id, true FROM public.groups WHERE id = ANY (v_ids)
        UNION ALL SELECT group_id, agent_id IS DISTINCT FROM v_session.person_agent_id
                    FROM public.group_memberships WHERE id = ANY (v_ids)
    )
    SELECT COALESCE(array_agg(DISTINCT g ORDER BY g), ARRAY[]::uuid[]) INTO v_groups
      FROM owned
     WHERE foreign_row AND g IS NOT NULL AND NOT (g = ANY (v_mine));
    -- Another agent's recall event (the agent-less ones included), by its
    -- owner group WHATEVER that group is: its policy admits only the row's own
    -- agent, so the elevator could not read it even in a group it shares.
    v_groups := ARRAY(SELECT DISTINCT g FROM unnest(v_groups || ARRAY(
                    SELECT r.owner_group_id FROM public.recall_events r
                     WHERE r.id = ANY (v_ids)
                       AND r.agent_id IS DISTINCT FROM v_session.person_agent_id
                       AND r.owner_group_id IS NOT NULL)) g ORDER BY g);

    INSERT INTO public.elevated_access (elevation_id, person_agent_id, assignment_id, reason,
                                        surface, args, row_count, owner_group_ids)
    VALUES (v_session.id, v_session.person_agent_id, v_session.assignment_id, v_session.reason,
            p_surface, COALESCE(p_args, '{}'::jsonb), p_row_count, v_groups)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;

-- ===================================================================
-- 3. THE TABLES, IN FOREIGN-KEY ORDER (RESTRICT: nothing else names them)
-- ===================================================================
DROP TABLE public.harvester_claim_provenance;
DROP TABLE public.harvester_audit_reports;
DROP TABLE public.harvester_fragments;
DROP TABLE public.harvester_sources;
DROP TABLE public.harvester_enriched_concepts;

-- ===================================================================
-- 4. THE TRIGGER FUNCTIONS ONLY THESE TABLES RAN
-- ===================================================================
DROP FUNCTION public.epigraph_inherit_fragment_tenancy_stmt();
DROP FUNCTION public.epigraph_audit_report_inherit_tenancy();
DROP FUNCTION public.epigraph_fragment_audit_reports_follow();

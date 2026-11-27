-- ===================================================================
-- 354-undo.sql: take migration 354 (the five harvester tables dropped;
-- backlog a6e3dba2, c7752f07) back out, in ONE transaction, as a superuser
-- on the migration DSN.
--
-- ROLL THE BINARY BACK FIRST: a binary built with 354 no longer blanks
-- harvester fragment text in a seal, so it must not serve a database where
-- the harvester tables exist and hold rows. The pre-354 binary requires the
-- harvester tenancy triggers this file recreates.
--
-- WHAT IT DOES:
--   * REFUSES (55000, nothing changed) unless each of the four bodies 354
--     re-stated is 354's or already the one before it (a later migration
--     that re-bodied one would otherwise be silently reverted), and the five
--     tables are all absent or all present;
--   * re-creates the three trigger functions 354 dropped (089/218's
--     `epigraph_inherit_fragment_tenancy_stmt`, 173's
--     `epigraph_audit_report_inherit_tenancy` and
--     `epigraph_fragment_audit_reports_follow`), owned by
--     `epigraph_maintenance` with EXECUTE revoked from PUBLIC, as they were;
--   * re-states 284's `epigraph_propagate_tenancy`,
--     `epigraph_publicize_claims` and `epigraph_share_claims_with_team` and
--     127's `epigraph_record_elevated_access` byte for byte (CREATE OR REPLACE
--     keeps owner and ACL);
--   * re-creates the five tables EMPTY in the shape they had after 347:
--     columns, constraints, indexes, triggers, ENABLE + FORCE row security,
--     policies, grants and table comments.
--   * re-seeds the two `tenancy_backfill_progress` rows 354 deleted, as 062
--     seeded them (not complete; the row is observability only).
--
-- WHAT IT LEAVES:
--   * no rows: 354 refused to run while any table held one, so there is
--     nothing to restore;
--   * the tables owned by the login that runs this file (001 created them as
--     the migrating login), with the grants a fresh migrate gives them. The
--     exact-match test (harvester_tables_dropped.rs) proves the shape on a
--     fresh database only; a deployed database whose tables had another owner
--     or extra grants comes back without them, and nothing reports it. So
--     BEFORE applying 354, record each table's owner and ACL (`\dp
--     public.harvester_*`, or `SELECT relname, pg_get_userbyid(relowner),
--     relacl FROM pg_class WHERE relname LIKE 'harvester\_%'`), and after
--     this file compare against that record and re-apply any difference;
--   * 354's `_sqlx_migrations` row. Dropping the tables again is a NEW
--     migration, never a re-run of 354.
--
-- Idempotent: a second run changes nothing (every statement is CREATE OR
-- REPLACE, IF NOT EXISTS, or DROP ... IF EXISTS followed by its CREATE).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE v_prop text; v_pub text; v_share text; v_elev text; n int;
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
    -- Each body is 354's (first run) or the one before 354 (a second run).
    IF v_prop IS DISTINCT FROM '27cbfcdef05f5ef4f9e6930dcb081918'
       AND v_prop IS DISTINCT FROM '3f149d9aaf288162fadd609f4bc6ddaf'
    OR v_pub IS DISTINCT FROM '6be48ddb5a73273f97868cac91d1dfc1'
       AND v_pub IS DISTINCT FROM 'cf74273d3e1a889e30b1adc13e846ba3'
    OR v_share IS DISTINCT FROM '442935f9779c1ab905d1e5618384fabc'
       AND v_share IS DISTINCT FROM '303bd7afda24bd28b2b8ae4187d7849f'
    OR v_elev IS DISTINCT FROM 'a386b90a382ba00cac564b04748398d8'
       AND v_elev IS DISTINCT FROM '5d05a3c17f9a0cbf75e24e2a9f4859d6' THEN
        RAISE EXCEPTION '354-undo: epigraph_propagate_tenancy (prosrc md5 %), '
                        'epigraph_publicize_claims (%), epigraph_share_claims_with_team (%) '
                        'or epigraph_record_elevated_access (%) is neither 354''s body nor '
                        'the one 354 replaced. A later migration re-bodied it; restoring '
                        'here would revert that. Nothing was changed.',
                        COALESCE(v_prop, '(absent)'), COALESCE(v_pub, '(absent)'),
                        COALESCE(v_share, '(absent)'), COALESCE(v_elev, '(absent)')
            USING ERRCODE = '55000';
    END IF;
    SELECT count(*) INTO n FROM unnest(ARRAY[
             'harvester_sources', 'harvester_fragments', 'harvester_audit_reports',
             'harvester_claim_provenance', 'harvester_enriched_concepts']) t
     WHERE to_regclass('public.' || t) IS NOT NULL;
    IF n NOT IN (0, 5) THEN
        RAISE EXCEPTION '354-undo: % of the five harvester tables exist; expected none '
                        '(354 applied) or all five (already undone). Nothing was changed.', n
            USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 1. THE THREE TRIGGER FUNCTIONS 354 DROPPED
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_inherit_fragment_tenancy_stmt()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
    -- `session_user`, not `current_user`: inside this definer the latter is
    -- the maintenance owner. Only a session that could itself write a
    -- sentinel-owned fragment stamps one (115 section 9).
    IF NOT public.epigraph_bypass() THEN
        RETURN NULL;
    END IF;
    -- 218: the MOST RESTRICTIVE citing claim wins (group before public, a
    -- real owner before the seed sentinel, then the lowest owner id), ranked
    -- over THIS statement's rows only (`newprov`), as 115 stamped from them:
    -- a link an earlier, unstamped session wrote never decides the fragment.
    -- The ingest path is trusted to name any citing claim (finding F-089-F,
    -- accepted): a stamp only ever moves a sentinel-owned, hence public,
    -- fragment to public or group, never to something more readable.
    UPDATE public.harvester_fragments f
       SET owner_group_id = w.owner_group_id,
           visibility     = w.visibility
      FROM (SELECT DISTINCT ON (n.fragment_id)
                   n.fragment_id, c.owner_group_id, c.visibility
              FROM newprov n
              JOIN public.claims c ON c.id = n.claim_id
             WHERE c.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
             ORDER BY n.fragment_id,
                      (c.visibility = 'group') DESC,
                      (c.owner_group_id = '00000000-0000-0000-0000-00000000dead'::uuid) ASC,
                      c.owner_group_id ASC) w
     WHERE f.id = w.fragment_id
       AND f.owner_group_id IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid)
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (w.owner_group_id, w.visibility);
    RETURN NULL;
END $$;
ALTER FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() OWNER TO epigraph_maintenance;
REVOKE ALL ON FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() FROM PUBLIC, epigraph_app;

CREATE OR REPLACE FUNCTION public.epigraph_audit_report_inherit_tenancy()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    SELECT f.owner_group_id, f.visibility INTO g, v
      FROM public.harvester_fragments f WHERE f.id = NEW.fragment_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph tenancy: harvester_audit_reports.fragment_id=% references '
                        'a nonexistent fragment', NEW.fragment_id
            USING ERRCODE = '23503';
    END IF;
    NEW.owner_group_id := g;
    NEW.visibility     := v;
    RETURN NEW;
END $$;
ALTER FUNCTION public.epigraph_audit_report_inherit_tenancy() OWNER TO epigraph_maintenance;
REVOKE ALL ON FUNCTION public.epigraph_audit_report_inherit_tenancy() FROM PUBLIC, epigraph_app;

CREATE OR REPLACE FUNCTION public.epigraph_fragment_audit_reports_follow()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
BEGIN
    UPDATE public.harvester_audit_reports r
       SET owner_group_id = NEW.owner_group_id,
           visibility     = NEW.visibility
     WHERE r.fragment_id = NEW.id
       AND (r.owner_group_id, r.visibility)
           IS DISTINCT FROM (NEW.owner_group_id, NEW.visibility);
    RETURN NULL;
END $$;
ALTER FUNCTION public.epigraph_fragment_audit_reports_follow() OWNER TO epigraph_maintenance;
REVOKE ALL ON FUNCTION public.epigraph_fragment_audit_reports_follow() FROM PUBLIC, epigraph_app;

-- ===================================================================
-- 2. THE FOUR BODIES 354 RE-STATED, AS THEY WERE (284's three, 127's one)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $$
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

CREATE OR REPLACE FUNCTION public.epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)
 RETURNS TABLE(claim_id uuid, outcome text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
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

CREATE OR REPLACE FUNCTION public.epigraph_share_claims_with_team(p_claim_ids uuid[], p_group_id uuid, p_reason text)
 RETURNS TABLE(claim_id uuid, outcome text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
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

CREATE OR REPLACE FUNCTION public.epigraph_record_elevated_access(p_surface text, p_args jsonb, p_row_count integer, p_candidate_ids uuid[])
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $$
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
        UNION ALL SELECT owner_group_id, visibility <> 'public' FROM public.harvester_fragments
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
-- 3. THE TABLES, EMPTY, IN THEIR 347 SHAPE (parents first)
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.harvester_sources (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    content_hash bytea NOT NULL,
    filename text,
    mime_type text,
    file_size bigint,
    modality text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    owner_group_id uuid NOT NULL,
    visibility character varying(16) NOT NULL,
    CONSTRAINT harvester_sources_file_size_positive CHECK (((file_size IS NULL) OR (file_size >= 0))),
    CONSTRAINT harvester_sources_group_needs_real_group CHECK ((((visibility)::text <> 'group'::text) OR (owner_group_id <> ALL (ARRAY['00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-00000000dead'::uuid])))),
    CONSTRAINT harvester_sources_modality_check CHECK ((modality = ANY (ARRAY['text'::text, 'pdf'::text, 'audio'::text]))),
    CONSTRAINT harvester_sources_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT harvester_sources_visibility_check CHECK (visibility IN ('public', 'group')),
    CONSTRAINT harvester_sources_content_hash_key UNIQUE (content_hash),
    CONSTRAINT harvester_sources_pkey PRIMARY KEY (id),
    CONSTRAINT harvester_sources_owner_group_fkey FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS public.harvester_fragments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    content_hash bytea NOT NULL,
    content_text text NOT NULL,
    context_window text,
    char_offset_start bigint,
    char_offset_end bigint,
    page_number integer,
    section_title text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_group_id uuid NOT NULL,
    visibility character varying(16) NOT NULL,
    CONSTRAINT harvester_fragments_group_needs_real_group CHECK ((((visibility)::text <> 'group'::text) OR (owner_group_id <> ALL (ARRAY['00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-00000000dead'::uuid])))),
    CONSTRAINT harvester_fragments_offsets_valid CHECK (((char_offset_start IS NULL) OR (char_offset_end IS NULL) OR (char_offset_end >= char_offset_start))),
    CONSTRAINT harvester_fragments_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT harvester_fragments_visibility_check CHECK (visibility IN ('public', 'group')),
    CONSTRAINT harvester_fragments_pkey PRIMARY KEY (id),
    CONSTRAINT harvester_fragments_owner_group_fkey FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT harvester_fragments_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.harvester_sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.harvester_audit_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    fragment_id uuid NOT NULL,
    extraction_id uuid NOT NULL,
    skeptic_passed boolean,
    hallucinations_detected integer DEFAULT 0,
    skeptic_findings jsonb,
    logician_passed boolean,
    contradictions_found integer DEFAULT 0,
    logician_findings jsonb,
    variance_passed boolean,
    similarity_score double precision,
    variance_report jsonb,
    final_confidence double precision,
    passed_audit boolean,
    attempts integer DEFAULT 1,
    model_used text,
    token_usage jsonb,
    processing_time_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_group_id uuid NOT NULL,
    visibility character varying(16) NOT NULL,
    CONSTRAINT harvester_audit_attempts_positive CHECK ((attempts >= 1)),
    CONSTRAINT harvester_audit_confidence_bounds CHECK (((final_confidence IS NULL) OR ((final_confidence >= (0.0)::double precision) AND (final_confidence <= (1.0)::double precision)))),
    CONSTRAINT harvester_audit_reports_group_needs_real_group CHECK ((((visibility)::text <> 'group'::text) OR (owner_group_id <> ALL (ARRAY['00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-00000000dead'::uuid])))),
    CONSTRAINT harvester_audit_reports_visibility_check CHECK (visibility IN ('public', 'group')),
    CONSTRAINT harvester_audit_similarity_bounds CHECK (((similarity_score IS NULL) OR ((similarity_score >= (0.0)::double precision) AND (similarity_score <= (1.0)::double precision)))),
    CONSTRAINT harvester_audit_reports_pkey PRIMARY KEY (id),
    CONSTRAINT harvester_audit_reports_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE,
    CONSTRAINT harvester_audit_reports_owner_group_fkey FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS public.harvester_claim_provenance (
    claim_id uuid NOT NULL,
    fragment_id uuid NOT NULL,
    audit_report_id uuid,
    extraction_confidence double precision,
    owner_group_id uuid NOT NULL,
    visibility character varying(16) NOT NULL,
    CONSTRAINT harvester_claim_provenance_group_needs_real_group CHECK ((((visibility)::text <> 'group'::text) OR (owner_group_id <> ALL (ARRAY['00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-00000000dead'::uuid])))),
    CONSTRAINT harvester_claim_provenance_visibility_check CHECK (visibility IN ('public', 'group')),
    CONSTRAINT harvester_provenance_confidence_bounds CHECK (((extraction_confidence IS NULL) OR ((extraction_confidence >= (0.0)::double precision) AND (extraction_confidence <= (1.0)::double precision)))),
    CONSTRAINT harvester_claim_provenance_pkey PRIMARY KEY (claim_id, fragment_id),
    CONSTRAINT harvester_claim_provenance_audit_report_id_fkey FOREIGN KEY (audit_report_id) REFERENCES public.harvester_audit_reports(id) ON DELETE SET NULL,
    CONSTRAINT harvester_claim_provenance_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE,
    CONSTRAINT harvester_claim_provenance_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE,
    CONSTRAINT harvester_claim_provenance_owner_group_fkey FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS public.harvester_enriched_concepts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    concept_name text NOT NULL,
    canonical_name text,
    latent_definition text,
    source_model text,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_group_id uuid NOT NULL,
    visibility character varying(16) NOT NULL,
    CONSTRAINT harvester_enriched_concepts_group_needs_real_group CHECK ((((visibility)::text <> 'group'::text) OR (owner_group_id <> ALL (ARRAY['00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-00000000dead'::uuid])))),
    CONSTRAINT harvester_enriched_concepts_visibility_check CHECK (visibility IN ('public', 'group')),
    CONSTRAINT harvester_enriched_concepts_pkey PRIMARY KEY (id),
    CONSTRAINT harvester_enriched_concepts_owner_group_fkey FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT
);

COMMENT ON TABLE public.harvester_audit_reports IS 'Council of Critics audit results per fragment extraction';
COMMENT ON TABLE public.harvester_claim_provenance IS 'Links extracted claims to source fragments and audit trails';
COMMENT ON TABLE public.harvester_enriched_concepts IS 'Concepts enriched with latent knowledge and embeddings';
COMMENT ON TABLE public.harvester_fragments IS 'Text fragments chunked from source documents';
COMMENT ON TABLE public.harvester_sources IS 'Source documents submitted for harvester extraction';

-- ===================================================================
-- 4. INDEXES
-- ===================================================================
CREATE INDEX IF NOT EXISTS idx_harvester_audit_fragment ON public.harvester_audit_reports USING btree (fragment_id);
CREATE INDEX IF NOT EXISTS idx_harvester_audit_passed ON public.harvester_audit_reports USING btree (passed_audit) WHERE (passed_audit IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_harvester_concepts_embedding ON public.harvester_enriched_concepts USING hnsw (embedding public.vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_harvester_concepts_name ON public.harvester_enriched_concepts USING btree (concept_name);
CREATE INDEX IF NOT EXISTS idx_harvester_fragments_source ON public.harvester_fragments USING btree (source_id);
CREATE INDEX IF NOT EXISTS idx_harvester_fragments_status ON public.harvester_fragments USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));
CREATE INDEX IF NOT EXISTS idx_harvester_provenance_claim ON public.harvester_claim_provenance USING btree (claim_id);
CREATE INDEX IF NOT EXISTS idx_harvester_provenance_fragment ON public.harvester_claim_provenance USING btree (fragment_id);
CREATE INDEX IF NOT EXISTS idx_harvester_sources_hash ON public.harvester_sources USING btree (content_hash);
CREATE INDEX IF NOT EXISTS idx_harvester_sources_status ON public.harvester_sources USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));

-- ===================================================================
-- 5. TRIGGERS (070, 074, 089, 115, 166, 173, 347)
-- ===================================================================
CREATE OR REPLACE TRIGGER harvester_audit_reports_inherit_tenancy BEFORE INSERT ON public.harvester_audit_reports FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_report_inherit_tenancy();
CREATE OR REPLACE TRIGGER harvester_audit_reports_owner_immutable BEFORE UPDATE OF owner_group_id ON public.harvester_audit_reports FOR EACH ROW WHEN ((old.owner_group_id IS DISTINCT FROM new.owner_group_id)) EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
CREATE OR REPLACE TRIGGER harvester_claim_provenance_fragment_inherit_tenancy AFTER INSERT ON public.harvester_claim_provenance REFERENCING NEW TABLE AS newprov FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_inherit_fragment_tenancy_stmt();
CREATE OR REPLACE TRIGGER harvester_claim_provenance_inherit_tenancy AFTER INSERT ON public.harvester_claim_provenance REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_inherit_tenancy_stmt();
CREATE OR REPLACE TRIGGER harvester_claim_provenance_owner_immutable BEFORE UPDATE OF owner_group_id ON public.harvester_claim_provenance FOR EACH ROW WHEN ((old.owner_group_id IS DISTINCT FROM new.owner_group_id)) EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
CREATE OR REPLACE TRIGGER harvester_claim_provenance_require_tenancy BEFORE INSERT ON public.harvester_claim_provenance FOR EACH ROW EXECUTE FUNCTION public.epigraph_derived_require_tenancy();
CREATE OR REPLACE TRIGGER harvester_enriched_concepts_owner_immutable BEFORE UPDATE OF owner_group_id ON public.harvester_enriched_concepts FOR EACH ROW WHEN ((old.owner_group_id IS DISTINCT FROM new.owner_group_id)) EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
CREATE OR REPLACE TRIGGER harvester_enriched_concepts_require_tenancy BEFORE INSERT ON public.harvester_enriched_concepts FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();
CREATE OR REPLACE TRIGGER harvester_fragments_audit_reports_inherit_tenancy AFTER UPDATE OF owner_group_id, visibility ON public.harvester_fragments FOR EACH ROW WHEN (((old.owner_group_id IS DISTINCT FROM new.owner_group_id) OR ((old.visibility)::text IS DISTINCT FROM (new.visibility)::text))) EXECUTE FUNCTION public.epigraph_fragment_audit_reports_follow();
CREATE OR REPLACE TRIGGER harvester_fragments_owner_immutable BEFORE UPDATE OF owner_group_id ON public.harvester_fragments FOR EACH ROW WHEN ((old.owner_group_id IS DISTINCT FROM new.owner_group_id)) EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
CREATE OR REPLACE TRIGGER harvester_fragments_require_tenancy BEFORE INSERT ON public.harvester_fragments FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();
CREATE OR REPLACE TRIGGER harvester_sources_owner_immutable BEFORE UPDATE OF owner_group_id ON public.harvester_sources FOR EACH ROW WHEN ((old.owner_group_id IS DISTINCT FROM new.owner_group_id)) EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
CREATE OR REPLACE TRIGGER harvester_sources_require_tenancy BEFORE INSERT ON public.harvester_sources FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();
CREATE OR REPLACE TRIGGER role_agent_write_check BEFORE INSERT OR DELETE OR UPDATE OR TRUNCATE ON public.harvester_claim_provenance FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_role_agent_write_check();
CREATE OR REPLACE TRIGGER role_agent_write_check BEFORE INSERT OR DELETE OR UPDATE OR TRUNCATE ON public.harvester_fragments FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_role_agent_write_check();

-- ===================================================================
-- 6. ROW SECURITY (077, 079, 115, 126, 173, 347)
-- ===================================================================
ALTER TABLE public.harvester_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_fragments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_fragments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_audit_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_audit_reports FORCE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_claim_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_claim_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_enriched_concepts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_enriched_concepts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS harvester_audit_reports_delete_owner ON public.harvester_audit_reports;
CREATE POLICY harvester_audit_reports_delete_owner ON public.harvester_audit_reports AS RESTRICTIVE FOR DELETE USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_audit_reports_tenancy ON public.harvester_audit_reports;
CREATE POLICY harvester_audit_reports_tenancy ON public.harvester_audit_reports USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR ((visibility)::text = 'public'::text) OR (owner_group_id = ANY (( SELECT public.epigraph_session_groups() AS epigraph_session_groups)::uuid[])))) WITH CHECK ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_claim_provenance_delete_owner ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_delete_owner ON public.harvester_claim_provenance AS RESTRICTIVE FOR DELETE USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_delete ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_elevated_no_delete ON public.harvester_claim_provenance AS RESTRICTIVE FOR DELETE TO epigraph_app USING ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_insert ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_elevated_no_insert ON public.harvester_claim_provenance AS RESTRICTIVE FOR INSERT TO epigraph_app WITH CHECK ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_update ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_elevated_no_update ON public.harvester_claim_provenance AS RESTRICTIVE FOR UPDATE TO epigraph_app USING ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_claim_provenance_elevated_read ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_elevated_read ON public.harvester_claim_provenance FOR SELECT TO epigraph_app USING (( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated));
DROP POLICY IF EXISTS harvester_claim_provenance_tenancy ON public.harvester_claim_provenance;
CREATE POLICY harvester_claim_provenance_tenancy ON public.harvester_claim_provenance USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR ((visibility)::text = 'public'::text) OR (owner_group_id = ANY (( SELECT public.epigraph_session_groups() AS epigraph_session_groups)::uuid[])))) WITH CHECK ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_enriched_concepts_delete_owner ON public.harvester_enriched_concepts;
CREATE POLICY harvester_enriched_concepts_delete_owner ON public.harvester_enriched_concepts AS RESTRICTIVE FOR DELETE USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_enriched_concepts_tenancy ON public.harvester_enriched_concepts;
CREATE POLICY harvester_enriched_concepts_tenancy ON public.harvester_enriched_concepts USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR ((visibility)::text = 'public'::text) OR (owner_group_id = ANY (( SELECT public.epigraph_session_groups() AS epigraph_session_groups)::uuid[])))) WITH CHECK ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_fragments_delete_owner ON public.harvester_fragments;
CREATE POLICY harvester_fragments_delete_owner ON public.harvester_fragments AS RESTRICTIVE FOR DELETE USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_fragments_elevated_no_delete ON public.harvester_fragments;
CREATE POLICY harvester_fragments_elevated_no_delete ON public.harvester_fragments AS RESTRICTIVE FOR DELETE TO epigraph_app USING ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_fragments_elevated_no_insert ON public.harvester_fragments;
CREATE POLICY harvester_fragments_elevated_no_insert ON public.harvester_fragments AS RESTRICTIVE FOR INSERT TO epigraph_app WITH CHECK ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_fragments_elevated_no_update ON public.harvester_fragments;
CREATE POLICY harvester_fragments_elevated_no_update ON public.harvester_fragments AS RESTRICTIVE FOR UPDATE TO epigraph_app USING ((NOT ( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated)));
DROP POLICY IF EXISTS harvester_fragments_elevated_read ON public.harvester_fragments;
CREATE POLICY harvester_fragments_elevated_read ON public.harvester_fragments FOR SELECT TO epigraph_app USING (( SELECT public.epigraph_is_elevated() AS epigraph_is_elevated));
DROP POLICY IF EXISTS harvester_fragments_tenancy ON public.harvester_fragments;
CREATE POLICY harvester_fragments_tenancy ON public.harvester_fragments USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR ((visibility)::text = 'public'::text) OR (owner_group_id = ANY (( SELECT public.epigraph_session_groups() AS epigraph_session_groups)::uuid[])))) WITH CHECK ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_sources_delete_owner ON public.harvester_sources;
CREATE POLICY harvester_sources_delete_owner ON public.harvester_sources AS RESTRICTIVE FOR DELETE USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));
DROP POLICY IF EXISTS harvester_sources_tenancy ON public.harvester_sources;
CREATE POLICY harvester_sources_tenancy ON public.harvester_sources USING ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR ((visibility)::text = 'public'::text) OR (owner_group_id = ANY (( SELECT public.epigraph_session_groups() AS epigraph_session_groups)::uuid[])))) WITH CHECK ((( SELECT public.epigraph_bypass() AS epigraph_bypass) OR ( SELECT public.epigraph_definer_bypass() AS epigraph_definer_bypass) OR (owner_group_id = ANY (( SELECT public.epigraph_writable_groups() AS epigraph_writable_groups)::uuid[]))));

-- ===================================================================
-- 7. GRANTS (118 section 6, as they stood before 354)
-- ===================================================================
-- Revoke first: a default privilege (ALTER DEFAULT PRIVILEGES) of the login
-- running this file would otherwise give a role more than it held before 354.
REVOKE ALL ON TABLE public.harvester_sources FROM PUBLIC, epigraph_app, epigraph_maintenance;
REVOKE ALL ON TABLE public.harvester_fragments FROM PUBLIC, epigraph_app, epigraph_maintenance;
REVOKE ALL ON TABLE public.harvester_audit_reports FROM PUBLIC, epigraph_app, epigraph_maintenance;
REVOKE ALL ON TABLE public.harvester_claim_provenance FROM PUBLIC, epigraph_app, epigraph_maintenance;
REVOKE ALL ON TABLE public.harvester_enriched_concepts FROM PUBLIC, epigraph_app, epigraph_maintenance;
GRANT SELECT,INSERT,UPDATE ON TABLE public.harvester_audit_reports TO epigraph_maintenance;
GRANT SELECT ON TABLE public.harvester_audit_reports TO epigraph_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.harvester_claim_provenance TO epigraph_maintenance;
GRANT SELECT,INSERT,DELETE ON TABLE public.harvester_claim_provenance TO epigraph_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.harvester_enriched_concepts TO epigraph_maintenance;
GRANT SELECT ON TABLE public.harvester_enriched_concepts TO epigraph_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.harvester_fragments TO epigraph_maintenance;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.harvester_fragments TO epigraph_app;
GRANT SELECT,INSERT,UPDATE ON TABLE public.harvester_sources TO epigraph_maintenance;
GRANT SELECT ON TABLE public.harvester_sources TO epigraph_app;

-- ===================================================================
-- 8. THE BACKFILL PROGRESS ROWS 354 DELETED, AS 062 SEEDED THEM
-- ===================================================================
INSERT INTO public.tenancy_backfill_progress (entity)
VALUES ('harvester_claim_provenance'), ('harvester_fragments')
ON CONFLICT (entity) DO NOTHING;

COMMIT;

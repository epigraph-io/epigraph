-- ===================================================================
-- 215-undo.sql: take migration 215 (share and publicize carry evidence-
-- endpoint edges, harvester sources and the stale scoped folds) back out, in
-- ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: no binary needs rolling back for this file alone. A 215 binary
-- calls the same two functions with the same signatures, and refolds the
-- moved claims' cached belief in Rust (`epigraph_engine::visibility_act`),
-- which works on either body. Rolling the binary back too re-opens backlog
-- 31285392's cached-belief leak; this undo re-opens 3b505b5c and the scoped
-- half of 31285392.
--
-- WHAT IT DOES:
--   * re-states 206's `epigraph_publicize_claims(uuid[], text)` and
--     `epigraph_share_claims_with_team(uuid[], uuid, text)` bodies byte for
--     byte (215 re-states both); `CREATE OR REPLACE` keeps their owner and
--     grants;
--   * revokes the DELETE on `ds_bayesian_divergence` that 215 granted
--     `epigraph_maintenance` (070 granted it SELECT, INSERT and UPDATE only;
--     nothing between 070 and 215 grants DELETE on it).
--
-- WHAT IT LEAVES:
--   * every row as 215 left it: edges on moved evidence stay re-met,
--     harvester sources stay with their fragments, and the deleted scoped
--     folds stay deleted (the next belief computation that stores one writes
--     it again);
--   * the `security_events` rows 215 wrote (`claim.publicized`,
--     `claim.shared_with_team` with `migration` 215);
--   * 215's `_sqlx_migrations` row.
-- Re-introducing any of it is a NEW migration, never a re-run of 215.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

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

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'REVOKE DELETE ON public.ds_bayesian_divergence FROM epigraph_maintenance';
    END IF;
END $$;

COMMIT;

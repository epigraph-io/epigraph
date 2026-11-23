-- ===================================================================
-- 267-undo.sql: take migration 267 (edge, evidence and assessment BBAs keyed
-- on `mass_functions.slot_kind` / `slot_id` instead of a `perspectives` row)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES:
--   * drops `perspectives_not_bba_slot`, then re-creates one slot row of
--     `perspectives` per distinct slot still held by a BBA: id = `slot_id`,
--     `perspective_type` `edge` (name `edge_factor`) for an edge slot and
--     `evidence` (name `evidence_grounded`) for an evidence or assessment
--     slot, `owner_agent_id` = the `source_agent_id` of the slot's earliest
--     BBA (every write path stamped the BBA's source agent as the slot row's
--     owner), public over the world group (the instance-wide declaration
--     the writers used);
--   * moves every slot row back onto `perspective_id` and drops the slot
--     columns, `mass_functions_unique_per_key`, `mass_functions_slot_shape`
--     and `idx_mass_functions_slot`; re-adds 034's
--     `mass_functions_unique_per_perspective`;
--   * re-states the three predecessor bodies verbatim (194's
--     `epigraph_cascade_delete_edge_bbas`, 115's `epigraph_dedup_move_bbas`,
--     120's `epigraph_record_cascade_deferral`; CREATE OR REPLACE keeps owner
--     and grants) and drops `epigraph_edge_bbas_keyed(uuid)`.
--
-- WHAT IT LEAVES:
--   * the slot rows' original `created_at` (re-created rows carry now()) and
--     any slot row 267 deleted whose BBAs are gone since (nothing keyed on it
--     needs it);
--   * 267's `_sqlx_migrations` row. Re-introducing the slot is a NEW
--     migration, never a re-run of 267.
--
-- Roll the binary back FIRST: a 267 binary writes slot rows, which this file
-- would then move onto perspectives that the old binary expects.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.perspectives DROP CONSTRAINT IF EXISTS perspectives_not_bba_slot;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'mass_functions'
                  AND column_name = 'slot_id') THEN
        INSERT INTO public.perspectives (id, name, owner_agent_id, perspective_type,
                                         visibility, owner_group_id)
        SELECT DISTINCT ON (mf.slot_id)
               mf.slot_id,
               CASE WHEN mf.slot_kind = 'edge' THEN 'edge_factor' ELSE 'evidence_grounded' END,
               mf.source_agent_id,
               CASE WHEN mf.slot_kind = 'edge' THEN 'edge' ELSE 'evidence' END,
               'public',
               '00000000-0000-0000-0000-000000000000'::uuid
          FROM public.mass_functions mf
         WHERE mf.slot_id IS NOT NULL
         ORDER BY mf.slot_id, mf.created_at, mf.id
        ON CONFLICT (id) DO NOTHING;

        ALTER TABLE public.mass_functions DROP CONSTRAINT IF EXISTS mass_functions_unique_per_key;
        ALTER TABLE public.mass_functions DROP CONSTRAINT IF EXISTS mass_functions_slot_shape;
        DROP INDEX IF EXISTS public.idx_mass_functions_slot;

        UPDATE public.mass_functions
           SET perspective_id = slot_id
         WHERE slot_id IS NOT NULL;

        ALTER TABLE public.mass_functions DROP COLUMN slot_kind, DROP COLUMN slot_id;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.mass_functions'::regclass
                      AND conname = 'mass_functions_unique_per_perspective') THEN
        ALTER TABLE public.mass_functions
            ADD CONSTRAINT mass_functions_unique_per_perspective
                UNIQUE NULLS NOT DISTINCT (claim_id, frame_id, source_agent_id, perspective_id);
    END IF;
END $$;

DROP FUNCTION IF EXISTS public.epigraph_edge_bbas_keyed(uuid);

-- epigraph_cascade_delete_edge_bbas: the predecessor body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_cascade_delete_edge_bbas(p_edge_ids uuid[], p_cause text)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := COALESCE(public.epigraph_writable_groups(), ARRAY[]::uuid[]);
        v_g uuid[] := COALESCE(public.epigraph_session_groups(), ARRAY[]::uuid[]);
        v_total bigint; v_refused bigint; v_n bigint; v_ids uuid[];
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
    -- which a definer frame does not change) is the plain statement. This is
    -- where the application's administrative cascade lands.
    IF public.epigraph_bypass() THEN
        -- 194: a retracted row is kept (H10; rulings R-79 / R-103).
        DELETE FROM public.mass_functions WHERE perspective_id = ANY (p_edge_ids)
            AND retracted_at IS NULL;
        GET DIAGNOSTICS v_n = ROW_COUNT;
        RETURN v_n;
    END IF;

    -- Any other session: its OWN rows only. Every candidate it can read is
    -- classified, locked so the verdict and the delete see the same rows.
    SELECT count(*),
           count(*) FILTER (WHERE NOT (mf.owner_group_id = ANY (v_w))),
           COALESCE(array_agg(mf.id), ARRAY[]::uuid[])
      INTO v_total, v_refused, v_ids
      FROM (SELECT m.id, m.owner_group_id
              FROM public.mass_functions m
             WHERE m.perspective_id = ANY (p_edge_ids)
               -- 194: a retracted row is neither deleted nor counted toward CD02.
               AND m.retracted_at IS NULL
               AND (m.visibility = 'public' OR m.owner_group_id = ANY (v_g))
               FOR UPDATE) mf;
    IF v_refused > 0 THEN
        RAISE EXCEPTION 'CD02: % of % edge-keyed mass function(s) for these edges are not '
            'this session''s to delete (cause %); another writer''s rows are removed only '
            'by the administrative cascade on the maintenance connection; nothing was deleted',
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
                    'arms',               jsonb_build_object('owner', v_n),
                    'writable_group_ids', to_jsonb(v_w),
                    'migration',          117));
    END IF;
    RETURN v_n;
END $function$;

-- epigraph_dedup_move_bbas: the predecessor body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_dedup_move_bbas(p_dup uuid, p_canonical uuid, p_perspectives uuid[])
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
END $function$;

-- epigraph_record_cascade_deferral: the predecessor body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_record_cascade_deferral(p_cause text, p_agent_id uuid, p_subject uuid, p_object uuid, p_sources uuid[], p_oauth jsonb, p_reason text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
       OR (p_cause = 'edge_retract'
           AND (p_object IS NOT NULL OR cardinality(v_sources) > 0))
       OR (p_cause <> 'edge_retract'
           AND (p_cause = 'consolidate') <> (cardinality(v_sources) > 0)) THEN
        RAISE EXCEPTION 'CX01: a % deferral names a subject%; no deferral was recorded', p_cause,
            CASE p_cause WHEN 'supersede' THEN ' and an object, and no sources'
                         WHEN 'dedup' THEN ' and an object, and no sources'
                         WHEN 'consolidate' THEN ' and its sources, and no object'
                         WHEN 'edge_retract' THEN
                             ', and no object or sources (the database derives them)'
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
        -- so no deferral names an edge in force.
        v_ok := EXISTS (SELECT 1 FROM public.edges e
                         WHERE e.id = p_subject
                           AND e.valid_to <= now()
                           AND (v_priv
                                OR e.owner_group_id = ANY (public.epigraph_writable_groups())
                                OR e.co_owner_group_id = ANY (public.epigraph_writable_groups())))
            AND EXISTS (SELECT 1 FROM public.perspectives p
                         WHERE p.id = p_subject AND p.perspective_type = 'edge');
        -- The sources are STATE, never the caller's word: the claims of the
        -- session's OWN BBA rows keyed on the edge (the rows the act deletes
        -- right after this call). A caller naming another writer's claims
        -- would otherwise make the privileged replay rewrite or clear their
        -- belief caches.
        IF COALESCE(v_ok, false) THEN
            v_sources := ARRAY(SELECT DISTINCT m.claim_id FROM public.mass_functions m
                                WHERE m.perspective_id = p_subject
                                  AND m.owner_group_id
                                      = ANY (public.epigraph_writable_groups())
                                ORDER BY m.claim_id);
        END IF;
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
END $function$;

COMMIT;

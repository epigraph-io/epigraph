-- 267: key edge, evidence and assessment BBAs on a typed slot of their own
-- (`mass_functions.slot_kind`, `mass_functions.slot_id`), not on a row of
-- `perspectives` (backlog 1777638e, the residual of 63bb3d2e).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- `perspectives` is the table of viewpoints (an agent's or a group's lens).
-- Until this file it was also a keying device: `mass_functions` is unique per
-- (claim, frame, source agent, perspective) and `perspective_id` is a foreign
-- key to `perspectives`, so every BBA that needed a key of its own wrote a
-- pseudo-perspective row first:
--
--   * the edge factor (`perspective_type = 'edge'`, name `edge_factor`, id =
--     the edge's id), one per epistemic edge;
--   * the DS evidence auto-wire (`'evidence'`, `evidence_grounded`, id = the
--     evidence row's id), one per evidence row;
--   * `/claims/:id/assess` (`'evidence'`, `evidence_grounded`, id = the
--     owner's derived assessment slot), one per owner.
--
-- Every perspective read had to filter those rows out (e305a895, 63bb3d2e),
-- and a reader that forgot treated an edge as a viewpoint. After this file a
-- BBA has at most ONE of: a genuine perspective (`perspective_id`), or a slot
-- (`slot_kind`, `slot_id`). No `perspectives` row is typed `edge` or
-- `evidence`, and a CHECK keeps it so.
--
-- ===================================================================
-- 2. WHAT IT DOES (one transaction)
-- ===================================================================
--
--   (0) PRECONDITIONS: the three definers it re-states are the bodies it was
--       written from (md5 of `prosrc`); refused 55000 otherwise.
--   (1) `mass_functions.slot_kind text` and `mass_functions.slot_id uuid`,
--       both nullable, no foreign key (an edge-slot row never had a key to
--       `edges`, and an `ON DELETE` action would bypass 194's retracted-row
--       delete guard or collapse two keys into one under NULLS NOT DISTINCT).
--   (2) CLASSIFIES every row whose `perspective_id` names a slot row, FAIL
--       CLOSED (55000, nothing changed) on any row it cannot place:
--         edge       the perspective is typed `edge`, or the row is an
--                    `edge_factor` row and its perspective's id is an edge's
--                    id (the keying the cascades use: `ensure_edge_perspective`
--                    kept an existing row's type);
--         assessment typed `evidence`, `combination_method = 'discount'`
--                    (the assess route's label);
--         evidence   typed `evidence`, or the row is an `auto_wire` row and
--                    its perspective's id is an evidence row's id. A row on an
--                    evidence-typed perspective with a label other than
--                    `auto_wire` (the DS auto-wire's) or `discount` is refused
--                    (A1 below);
--       refuses (A2) when a `community_members` row names a slot row (the
--       DELETE in (4) would cascade it away), and (A3) when a row it did not
--       classify is keyed on an edge's id or on a perspective named
--       `edge_factor` / `evidence_grounded` (the slot writers' names).
--   (3) MOVES each classified row: `slot_kind`/`slot_id` = (kind, old
--       `perspective_id`), `perspective_id` = NULL. The unique key is
--       rebuilt around it: `mass_functions_unique_per_perspective` is dropped
--       (moved rows would collide on it) and
--       `mass_functions_unique_per_key UNIQUE NULLS NOT DISTINCT (claim_id,
--       frame_id, source_agent_id, perspective_id, slot_kind, slot_id)` added,
--       with `mass_functions_slot_shape` (kind and id together; a known kind;
--       never both a slot and a perspective) and a partial index on the slot.
--   (4) DELETES the slot rows of `perspectives`: every row typed `edge` or
--       `evidence`, and every row (2) moved BBAs off, then adds
--       `perspectives_not_bba_slot CHECK (perspective_type IS NULL OR
--       perspective_type NOT IN ('edge', 'evidence'))`.
--   (5) RE-STATES three definers whose bodies keyed an edge's BBAs on
--       `perspective_id` (owners and grants unchanged; CREATE OR REPLACE keeps
--       them): 194's `epigraph_cascade_delete_edge_bbas`, 115's
--       `epigraph_dedup_move_bbas` and 120's `epigraph_record_cascade_deferral`
--       (its `edge_retract` arm now asks whether a BBA is keyed on the edge's
--       slot, where it asked whether the edge's slot perspective existed).
--   (6) ADDS `public.epigraph_edge_bbas_keyed(uuid) RETURNS boolean`, STABLE
--       SECURITY DEFINER, owner `epigraph_maintenance`, 172's form
--       (`search_path = pg_catalog, pg_temp`, every name qualified): whether a
--       BBA (any writer's) is keyed on the edge's slot, answered only to a
--       session that writes the edge (owner or co-owner group writable, or a
--       maintenance session); false otherwise. The edge-withdraw path asked
--       the same question of the public `perspectives` row, which every
--       session could read; a BBA row is readable only under its claim's
--       tenancy, so the question moves into a definer. EXECUTE revoked from
--       PUBLIC, granted to `epigraph_app` and `epigraph_maintenance`.
--
-- ===================================================================
-- 3. WHAT IT LEAVES
-- ===================================================================
--
--   * A deleted slot row's `owner_agent_id` and `created_at`. The owner is
--     the moved BBA's `source_agent_id` on every write path (the edge's
--     signer, the evidence writer, the assessment's owner); the undo rebuilds
--     the rows from it.
--   * `ds_combined_beliefs` rows scoped to a slot id as a perspective (none
--     is written by any path; a lens read of a slot id now answers not
--     found).
--   * The writers: a binary older than this file writes a slot perspective
--     first and is refused by the CHECK (23514), so deploy the binary with
--     the migration (README entry 267, deploy order).
--
-- ===================================================================
-- UNDO: `docs/runbooks/267-undo.sql`.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- (0) PRECONDITIONS
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_cascade text;
    v_move    text;
    v_defer   text;
BEGIN
    SELECT md5(p.prosrc) INTO v_cascade FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_cascade_delete_edge_bbas(uuid[], text)');
    SELECT md5(p.prosrc) INTO v_move FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_dedup_move_bbas(uuid, uuid, uuid[])');
    SELECT md5(p.prosrc) INTO v_defer FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure(
         'public.epigraph_record_cascade_deferral(text, uuid, uuid, uuid, uuid[], jsonb, text)');
    IF v_cascade IS DISTINCT FROM '8a49dd788a4076f53e05fe6fe0436139' THEN
        RAISE EXCEPTION '267: epigraph_cascade_delete_edge_bbas is not the body 267 re-states '
                        '(194''s, md5 8a49dd788a4076f53e05fe6fe0436139); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_cascade, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_move IS DISTINCT FROM 'a6b705c1dc915d20e7d1e8d61990f6ae' THEN
        RAISE EXCEPTION '267: epigraph_dedup_move_bbas is not the body 267 re-states '
                        '(115''s, md5 a6b705c1dc915d20e7d1e8d61990f6ae); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_move, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_defer IS DISTINCT FROM '90f2455bc72c9ae79d38df4a221d04f0' THEN
        RAISE EXCEPTION '267: epigraph_record_cascade_deferral is not the body 267 re-states '
                        '(120''s, md5 90f2455bc72c9ae79d38df4a221d04f0); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_defer, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- (1) THE SLOT COLUMNS
-- -------------------------------------------------------------------
ALTER TABLE public.mass_functions
    ADD COLUMN slot_kind text NULL,
    ADD COLUMN slot_id uuid NULL;

COMMENT ON COLUMN public.mass_functions.slot_kind IS
    'What keys this BBA besides (claim, frame, source agent) when it is not a '
    'perspective''s: ''edge'' (slot_id = the edge''s id; the edge factor), '
    '''evidence'' (slot_id = the evidence row''s id; the DS evidence auto-wire) '
    'or ''assessment'' (slot_id = the owner''s derived assessment slot; '
    '/claims/:id/assess). NULL for every other row. Never set together with '
    'perspective_id. Migration 267.';
COMMENT ON COLUMN public.mass_functions.slot_id IS
    'The id the slot_kind names (no foreign key: see migration 267). NULL '
    'exactly when slot_kind is NULL.';

-- -------------------------------------------------------------------
-- (2) CLASSIFY, FAIL CLOSED
-- -------------------------------------------------------------------
CREATE TEMPORARY TABLE t267_slot ON COMMIT DROP AS
SELECT mf.id AS mf_id,
       mf.perspective_id AS slot_id,
       CASE
           WHEN p.perspective_type = 'edge' OR mf.combination_method = 'edge_factor'
               THEN 'edge'
           WHEN p.perspective_type = 'evidence' AND mf.combination_method = 'discount'
               THEN 'assessment'
           ELSE 'evidence'
       END AS kind,
       mf.combination_method AS method
  FROM public.mass_functions mf
  JOIN public.perspectives p ON p.id = mf.perspective_id
 WHERE p.perspective_type IN ('edge', 'evidence')
    OR (mf.combination_method = 'edge_factor'
        AND EXISTS (SELECT 1 FROM public.edges e WHERE e.id = mf.perspective_id))
    OR (mf.combination_method = 'auto_wire'
        AND EXISTS (SELECT 1 FROM public.evidence v WHERE v.id = mf.perspective_id));

DO $$
DECLARE
    v_bad    bigint;
    v_labels text;
    v_comm   bigint;
BEGIN
    -- (A1) an evidence slot carries the auto-wire's label; anything else is a
    -- row no known writer produced, and it is not guessed at.
    SELECT count(*), string_agg(DISTINCT COALESCE(t.method, '(NULL)'), ', ')
      INTO v_bad, v_labels
      FROM t267_slot t
     WHERE t.kind = 'evidence' AND t.method IS DISTINCT FROM 'auto_wire';
    -- (A3) a row left on its perspective that still looks like a slot row.
    IF v_bad = 0 THEN
        SELECT count(*), string_agg(DISTINCT COALESCE(mf.combination_method, '(NULL)'), ', ')
          INTO v_bad, v_labels
          FROM public.mass_functions mf
          JOIN public.perspectives p ON p.id = mf.perspective_id
         WHERE NOT EXISTS (SELECT 1 FROM t267_slot t WHERE t.mf_id = mf.id)
           AND (p.name IN ('edge_factor', 'evidence_grounded')
                OR EXISTS (SELECT 1 FROM public.edges e WHERE e.id = mf.perspective_id));
    END IF;
    IF v_bad > 0 THEN
        RAISE EXCEPTION '267: % mass function(s) keyed on a slot-shaped perspective cannot be '
                        'classified (combination_method %); nothing was changed',
                        v_bad, v_labels
            USING ERRCODE = '55000',
                  HINT = 'Classify those rows by hand (README entry 267 lists the measuring '
                         'query) before applying 267.';
    END IF;
    -- (A2) the DELETE below would cascade a community membership away.
    SELECT count(*) INTO v_comm
      FROM public.community_members cm
      JOIN public.perspectives p ON p.id = cm.perspective_id
     WHERE p.perspective_type IN ('edge', 'evidence')
        OR p.id IN (SELECT t.slot_id FROM t267_slot t);
    IF v_comm > 0 THEN
        RAISE EXCEPTION '267: % community membership(s) name a BBA slot perspective; deleting '
                        'the slot rows would remove them; nothing was changed', v_comm
            USING ERRCODE = '55000';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- (3) MOVE, AND THE KEY
-- -------------------------------------------------------------------
ALTER TABLE public.mass_functions
    DROP CONSTRAINT mass_functions_unique_per_perspective;

UPDATE public.mass_functions mf
   SET slot_kind = t.kind,
       slot_id = t.slot_id,
       perspective_id = NULL
  FROM t267_slot t
 WHERE mf.id = t.mf_id;

ALTER TABLE public.mass_functions
    ADD CONSTRAINT mass_functions_unique_per_key
        UNIQUE NULLS NOT DISTINCT
        (claim_id, frame_id, source_agent_id, perspective_id, slot_kind, slot_id),
    ADD CONSTRAINT mass_functions_slot_shape CHECK (
        (slot_kind IS NULL) = (slot_id IS NULL)
        AND (slot_kind IS NULL OR slot_kind IN ('edge', 'evidence', 'assessment'))
        AND (slot_kind IS NULL OR perspective_id IS NULL));

CREATE INDEX idx_mass_functions_slot
    ON public.mass_functions (slot_id, slot_kind)
    WHERE slot_id IS NOT NULL;

-- -------------------------------------------------------------------
-- (4) THE SLOT ROWS OF `perspectives` GO, AND STAY GONE
-- -------------------------------------------------------------------
DELETE FROM public.perspectives p
 WHERE p.perspective_type IN ('edge', 'evidence')
    OR p.id IN (SELECT t.slot_id FROM t267_slot t);

DO $$
DECLARE v_left bigint;
BEGIN
    SELECT count(*) INTO v_left FROM public.mass_functions mf
      JOIN public.perspectives p ON p.id = mf.perspective_id
     WHERE p.perspective_type IN ('edge', 'evidence');
    IF v_left > 0 THEN
        RAISE EXCEPTION '267: % mass function(s) still keyed on a slot perspective; nothing was '
                        'changed', v_left USING ERRCODE = '55000';
    END IF;
END $$;

ALTER TABLE public.perspectives
    ADD CONSTRAINT perspectives_not_bba_slot CHECK (
        perspective_type IS NULL OR perspective_type NOT IN ('edge', 'evidence'));

-- -------------------------------------------------------------------
-- (5) THE THREE DEFINERS THAT KEYED AN EDGE'S BBAS ON perspective_id
-- -------------------------------------------------------------------

-- epigraph_cascade_delete_edge_bbas: the predecessor body; delta = the edge slot (marked 267).
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
        -- 267: an edge-keyed row is keyed by its slot, never a perspective.
        DELETE FROM public.mass_functions WHERE slot_kind = 'edge' AND slot_id = ANY (p_edge_ids)
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
             WHERE m.slot_kind = 'edge' AND m.slot_id = ANY (p_edge_ids)
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

-- epigraph_dedup_move_bbas: the predecessor body; delta = the edge slot (marked 267).
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
       -- 267: `p_perspectives` names EDGE ids, matched on the edge slot.
       AND d.slot_kind = 'edge' AND d.slot_id = ANY (p_perspectives)
       AND EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = d.slot_id
                      AND e.target_id = p_canonical AND e.target_type = 'claim')
       AND EXISTS (SELECT 1 FROM public.mass_functions c
                    WHERE c.claim_id = p_canonical
                      AND c.slot_kind = 'edge' AND c.slot_id = d.slot_id
                      AND c.perspective_id IS NULL
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
       AND mf.slot_kind = 'edge' AND mf.slot_id = ANY (p_perspectives)
       AND EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = mf.slot_id
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

-- epigraph_record_cascade_deferral: the predecessor body; delta = the edge slot (marked 267).
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
            -- 267: the edge carries a BBA keyed on its slot (any writer's,
            -- retracted or live; this frame reads past row security).
            AND EXISTS (SELECT 1 FROM public.mass_functions m
                         WHERE m.slot_kind = 'edge' AND m.slot_id = p_subject);
        -- The sources are STATE, never the caller's word: the claims of the
        -- session's OWN BBA rows keyed on the edge (the rows the act deletes
        -- right after this call). A caller naming another writer's claims
        -- would otherwise make the privileged replay rewrite or clear their
        -- belief caches.
        IF COALESCE(v_ok, false) THEN
            v_sources := ARRAY(SELECT DISTINCT m.claim_id FROM public.mass_functions m
                                WHERE m.slot_kind = 'edge' AND m.slot_id = p_subject
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

-- -------------------------------------------------------------------
-- (6) WHETHER A BBA IS KEYED ON AN EDGE, FOR THE EDGE'S WRITER
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_edge_bbas_keyed(p_edge uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.id = p_edge
                          AND (e.owner_group_id = ANY (public.epigraph_writable_groups())
                               OR e.co_owner_group_id
                                  = ANY (public.epigraph_writable_groups()))))
       AND EXISTS (SELECT 1 FROM public.mass_functions m
                    WHERE m.slot_kind = 'edge' AND m.slot_id = p_edge);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edge_bbas_keyed(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_edge_bbas_keyed(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_edge_bbas_keyed(uuid) TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 267 function '
                     'body stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_edge_bbas_keyed(uuid) TO epigraph_app';
    END IF;
END $$;

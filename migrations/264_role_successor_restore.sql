-- 264_role_successor_restore.sql
-- One audited maintenance verb restores a role's running successor when its
-- detached root identity is attached by name again.
--
-- ===================================================================
-- 1. WHY (backlog 9073f0a5)
--
-- 166's `role_agents` follows an attachment down the identity lineage: each
-- registered successor of an attached identity gets a succession COPY
-- (`inherited_from`) over the window. 179's attached mode makes such a copy
-- a GRANT (`epigraph_role_derived_memberships`): a copy counts only while
-- every row on its `inherited_from` chain is live. 195 made a detach sticky
-- per identity and made the attach-time follow chain its copies.
--
-- So when the operator detaches a role's root identity A, the running
-- successor B (whose copy chains to A's row) loses the group, as intended.
-- But attaching A by name AGAIN does not give it back. A's new row's follow
-- copies only into the GAPS B's own un-detached rows leave, and B's old copy,
-- chained to A's DETACHED row, still covers the window. B stays out (179's
-- membership: not a member, an armed write stamped with the group is refused
-- OPL02) until someone finds that stale copy, detaches it and attaches B by
-- name: the manual two-step restore docs/tenancy.md documented. 195 found
-- two paths where that manual restore re-admitted an identity the operator
-- had cut off, so doing it by hand is error-prone.
--
-- The plain re-attach cannot be taught to do it under 195's rules: the only
-- way to retire B's stale copy is a detach, and a detach is sticky (no copy
-- admits B afterwards). So the restore stays an attachment made BY NAME,
-- exactly as the documented procedure makes it, but in ONE audited act that
-- first decides whether B may have it.
--
-- ===================================================================
-- 2. THE VERB
--
-- `epigraph_restore_role_successor(role, root, successor, valid_to, reason)`
-- RETURNS TABLE (out_step, out_agent_id, out_attachment_id). Maintenance
-- only; one transaction; a refusal writes nothing.
--
--   (1) THE ROOT. When `root` holds a live row made by name for the role, it
--       is kept (`root_already_attached`; a `valid_to` other than NULL or
--       that row's end is refused 22023). Otherwise `root` is attached by
--       name now, until `valid_to` (`root_attached`), and 166's follow copies
--       into its successors' gaps as for any attach; but only when `root`
--       has EVER held a row made by name for the role (any state), else
--       ROL04, nothing written. An identity that only ever held copies is a
--       middle identity: re-attaching it by name would undo its own sticky
--       detach, or step around the detach of the root above it.
--   (2) NOTHING TO DO. A successor that already holds a live row made by name
--       is reported `successor_already_attached`; one whose copies covering
--       the window all chain through LIVE rows (the root's follow just filled
--       its gap, or it was never cut off) is reported `successor_unchanged`.
--       Neither writes anything for the successor.
--   (3) WHO MAY BE RESTORED (refused ROL04 otherwise, nothing written). The
--       attachment made by name skips 179's folder rule and ends 195's walk
--       up the lineage, so the verb gives one only where a copy written
--       FRESH from the root's row would admit the successor:
--         * the successor runs in exactly one group folder, and the root runs
--           in it (179's folder rule: a shared successor or one in another
--           folder is never restored);
--         * the successor holds no detached row for the role (195: a detach
--           of the successor itself is sticky; attach it by name with
--           `epigraph_attach_agent_to_role` if that is meant);
--         * every un-detached row of the successor that overlaps the new
--           window is a COPY whose `inherited_from` chain passes through a
--           row of the root (else it was not cut off by the root's detach);
--           a future row made by name there is refused too;
--         * every row of such a chain BELOW the root's row is live now (a
--           detached or lapsed middle copy is that identity's own detach,
--           which the restore does not undo);
--         * walking up `agent_succession` from the successor and from the
--           agent of each copy below the root's row, through parents that
--           hold no live row made by name (195's walk; the root's row ends
--           it), reaches no identity but the root that holds a detached row
--           for the role (a second, detached parent keeps the successor out,
--           as 195 rules).
--   (4) THE ACT. Every such overlapping row of the successor is detached
--       (`copy_detached`, the gap copies (1) may have written included, as
--       166's guard refuses an overlap), and the successor is attached by
--       name from now until the root row's end (`successor_attached`).
--       Successors registered from it later chain through that row. A
--       registered descendant of the successor whose own copy still chains
--       through a dead row is reported `descendant_still_out` (not changed:
--       restore it with its own call if it runs).
--   (5) THE AUDIT. Each attach and detach writes 166's own security event.
--       A restore writes one more, `platform.role_successor_restored`, naming
--       the role, the root and its row, the successor and its new row, the
--       detached rows, the descendants left out, the reason and the login.
--
-- WHAT IT LEAVES AS IT WAS: the derivation, the registration and the follow
-- (no body is re-stated, so this file does not depend on, or conflict with,
-- any later re-statement of them); the plain attach and detach verbs; the
-- consequence 195 documents for any row made by name: the restored
-- successor is no longer cut off by a later detach of the root alone (detach
-- the successor too, as 195's "what cuts a job off" says).
--
-- Locks: 107's `operator_links` advisory lock, then 166's `role_agents` one,
-- in the order 166's insert guard takes them, BEFORE the first read, so a
-- registration or another attach cannot land between the decision and the
-- act. READ COMMITTED only (ROL04 otherwise): under an older snapshot the
-- reads after the locks would miss a row committed while waiting for them.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/264-undo.sql` drops the function. Roll back first any
-- `epigraph-operator` that carries `restore-role-successor` (it calls the
-- function; without it the command fails 42883 and writes nothing). Rows the
-- verb wrote stay as written (`role_agents` is append-only): detach one with
-- `epigraph_detach_agent_from_role` if it is to go.
--
-- DEPLOY: no binary needs it; the operator CLI's new command needs it.
-- Migrate first, then deploy the CLI.

SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF to_regclass('public.role_agents') IS NULL
       OR to_regclass('public.agent_succession') IS NULL
       OR to_regprocedure('public.epigraph_role_derived_memberships(uuid, timestamptz)') IS NULL
    THEN
        RAISE EXCEPTION '264: role_agents, agent_succession or the role derivation is absent; '
                        'apply 161, 166 and 179 first (nothing was changed)'
            USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_restore_role_successor(
    p_role text, p_root uuid, p_successor uuid, p_valid_to timestamptz, p_reason text)
RETURNS TABLE (out_step text, out_agent_id uuid, out_attachment_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_now        timestamptz := pg_catalog.now();
    v_root_row   uuid;
    v_root_to    timestamptz;
    v_root_new   boolean := false;
    v_found      uuid;
    v_folder     text;
    v_folders    bigint;
    v_row        record;
    v_pos        integer;
    v_bad        uuid;
    v_row_stale  boolean;
    v_below      uuid[];
    v_judged     uuid[] := ARRAY[p_successor];
    v_replace    uuid[] := '{}';
    v_stale      uuid[] := '{}';
    v_blocker    uuid;
    v_new        uuid;
    v_out        uuid[] := '{}';
BEGIN
    IF p_role IS NULL OR p_root IS NULL OR p_successor IS NULL OR p_reason IS NULL
       OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_restore_role_successor: the role, the root, the successor '
                        'and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF p_root = p_successor THEN
        RAISE EXCEPTION 'epigraph_restore_role_successor: the successor is the root itself'
            USING ERRCODE = '22023',
                  HINT = 'Attach it by name with epigraph_attach_agent_to_role.';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'ROL04: a restore runs only under READ COMMITTED (this transaction is '
                        '%): an older snapshot would miss a row committed since',
                        current_setting('transaction_isolation')
            USING ERRCODE = 'ROL04',
                  HINT = 'Nothing was written.';
    END IF;

    -- 166's insert guard's locks, in its order, before the first read.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.role_agents'));

    -- (1) The root: its live row made by name, or a new one (166's follow
    -- then copies into its successors' gaps, as for any attach).
    SELECT r.id, r.valid_to INTO v_root_row, v_root_to
      FROM public.role_agents r
     WHERE r.agent_id = p_root AND r.role = p_role
       AND r.inherited_from IS NULL AND r.detached_at IS NULL
       AND r.valid_from <= v_now AND (r.valid_to IS NULL OR v_now < r.valid_to)
     ORDER BY r.valid_from DESC
     LIMIT 1;
    IF v_root_row IS NOT NULL THEN
        IF p_valid_to IS NOT NULL AND p_valid_to IS DISTINCT FROM v_root_to THEN
            RAISE EXCEPTION 'epigraph_restore_role_successor: % already holds a live row made by '
                            'name for % (%), ending %; valid_to % would not apply',
                            p_root, p_role, v_root_row, COALESCE(v_root_to::text, 'never'),
                            p_valid_to
                USING ERRCODE = '22023',
                      HINT = 'Pass NULL (the successor ends with that row) or that row''s end.';
        END IF;
        out_step := 'root_already_attached';
    ELSE
        -- Only an identity the operator once attached BY NAME is a root this
        -- verb re-attaches. An identity that only ever held succession copies
        -- (a middle identity, its own detach sticky under 195) is not: naming
        -- it would undo that detach, or step around the real root's detach.
        IF NOT EXISTS (SELECT 1 FROM public.role_agents n
                        WHERE n.agent_id = p_root AND n.role = p_role
                          AND n.inherited_from IS NULL) THEN
            RAISE EXCEPTION 'ROL04: % was never attached by name to %, so it is not a root this '
                            'verb re-attaches: attaching it now would undo its own detach or step '
                            'around the detach of the root it descends from', p_root, p_role
                USING ERRCODE = 'ROL04',
                      HINT = 'Nothing was written. Name the identity the operator attached by '
                             'name, or attach this one with epigraph_attach_agent_to_role if '
                             'that is meant.';
        END IF;
        INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason)
        VALUES (p_role, p_root, v_now, p_valid_to, p_reason)
        RETURNING id INTO v_root_row;
        v_root_to := p_valid_to;
        v_root_new := true;
        out_step := 'root_attached';
    END IF;
    out_agent_id := p_root;
    out_attachment_id := v_root_row;
    RETURN NEXT;

    -- (2) Already attached by name: nothing to restore.
    SELECT r.id INTO v_found
      FROM public.role_agents r
     WHERE r.agent_id = p_successor AND r.role = p_role
       AND r.inherited_from IS NULL AND r.detached_at IS NULL
       AND r.valid_from <= v_now AND (r.valid_to IS NULL OR v_now < r.valid_to)
     LIMIT 1;
    IF v_found IS NOT NULL THEN
        out_step := 'successor_already_attached';
        out_agent_id := p_successor;
        out_attachment_id := v_found;
        RETURN NEXT;
        RETURN;
    END IF;

    -- (3) Who may be restored. 179's folder rule, against the root.
    SELECT min(s.group_folder), count(DISTINCT s.group_folder) INTO v_folder, v_folders
      FROM public.agent_prompt_snapshots s
     WHERE s.agent_id = p_successor;
    IF v_folders <> 1
       OR NOT EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                       WHERE s.agent_id = p_root AND s.group_folder = v_folder) THEN
        RAISE EXCEPTION 'ROL04: % runs in % group folder(s) and must run in exactly one that % '
                        'runs in: a copy of %''s row would admit it nowhere, so it is not '
                        'restored', p_successor, v_folders, p_root, p_root
            USING ERRCODE = 'ROL04',
                  HINT = 'Nothing was written. Attach it by name with '
                         'epigraph_attach_agent_to_role if it is meant to be a member anyway.';
    END IF;
    -- 195: a detach of the successor itself is sticky.
    IF EXISTS (SELECT 1 FROM public.role_agents d
                WHERE d.agent_id = p_successor AND d.role = p_role
                  AND d.detached_at IS NOT NULL) THEN
        RAISE EXCEPTION 'ROL04: % holds a detached row for %: a detach of the identity itself is '
                        'sticky, and restoring its root does not undo it', p_successor, p_role
            USING ERRCODE = 'ROL04',
                  HINT = 'Nothing was written. Attach it by name with '
                         'epigraph_attach_agent_to_role if it is meant to be a member again.';
    END IF;
    -- Every un-detached row of the successor that overlaps the new window
    -- must be a copy whose chain passes through a row of the root, every row
    -- below that one live now. The agents of the copies below the root's row
    -- are judged by the lineage walk next.
    FOR v_row IN
        SELECT r.id, r.inherited_from
          FROM public.role_agents r
         WHERE r.agent_id = p_successor AND r.role = p_role AND r.detached_at IS NULL
           AND (r.valid_to IS NULL OR r.valid_to > v_now)
           AND (v_root_to IS NULL OR r.valid_from < v_root_to)
         ORDER BY r.valid_from, r.id
    LOOP
        IF v_row.inherited_from IS NULL THEN
            RAISE EXCEPTION 'ROL04: % already holds row % made by name for %, not live yet; '
                            'it is not replaced', p_successor, v_row.id, p_role
                USING ERRCODE = 'ROL04',
                      HINT = 'Nothing was written.';
        END IF;
        WITH RECURSIVE rs_chain (id, agent_id, inherited_from, live, depth) AS (
            SELECT h.id, h.agent_id, h.inherited_from,
                   h.detached_at IS NULL AND h.valid_from <= v_now
                       AND (h.valid_to IS NULL OR v_now < h.valid_to),
                   0
              FROM public.role_agents h
             WHERE h.id = v_row.id
            UNION ALL
            SELECT h.id, h.agent_id, h.inherited_from,
                   h.detached_at IS NULL AND h.valid_from <= v_now
                       AND (h.valid_to IS NULL OR v_now < h.valid_to),
                   c.depth + 1
              FROM public.role_agents h
              JOIN rs_chain c ON h.id = c.inherited_from
        ),
        rs_root (pos) AS (
            SELECT min(c.depth) FROM rs_chain c WHERE c.agent_id = p_root
        )
        SELECT rr.pos,
               (SELECT c.agent_id FROM rs_chain c
                 WHERE c.depth < rr.pos AND NOT c.live ORDER BY c.depth LIMIT 1),
               EXISTS (SELECT 1 FROM rs_chain c WHERE c.depth >= rr.pos AND NOT c.live),
               ARRAY(SELECT c.agent_id FROM rs_chain c
                      WHERE c.depth > 0 AND c.depth < rr.pos ORDER BY c.depth)
          INTO v_pos, v_bad, v_row_stale, v_below
          FROM rs_root rr;
        IF v_pos IS NULL THEN
            RAISE EXCEPTION 'ROL04: %''s attachment % to % was not copied through any row of %; '
                            'restoring % does not decide it', p_successor, v_row.id, p_role,
                            p_root, p_root
                USING ERRCODE = 'ROL04',
                      HINT = 'Nothing was written. Name the root the copy came from.';
        END IF;
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'ROL04: %''s attachment % to % is copied through a row of % that is '
                            'detached or not live, below %: that identity''s own detach is not '
                            'undone by restoring %', p_successor, v_row.id, p_role, v_bad,
                            p_root, p_root
                USING ERRCODE = 'ROL04',
                      HINT = 'Nothing was written.';
        END IF;
        v_replace := v_replace || v_row.id;
        v_judged := v_judged || v_below;
        IF v_row_stale THEN
            v_stale := v_stale || v_row.id;
        END IF;
    END LOOP;
    IF cardinality(v_replace) = 0 THEN
        RAISE EXCEPTION 'ROL04: % holds no attachment to % copied through %: it was not cut off '
                        'by a detach of %', p_successor, p_role, p_root, p_root
            USING ERRCODE = 'ROL04',
                  HINT = 'Nothing was written. Attach it by name with '
                         'epigraph_attach_agent_to_role if it is meant to be a member.';
    END IF;
    IF cardinality(v_stale) = 0 THEN
        -- Every covering copy already chains through live rows (e.g. the
        -- root's follow just filled its gap): nothing to restore.
        out_step := 'successor_unchanged';
        out_agent_id := p_successor;
        out_attachment_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    -- 195's walk up `agent_succession`, through parents with no live row
    -- made by name (the root's row ends it): no identity reached but the
    -- root may hold a detached row for the role.
    WITH RECURSIVE rs_up (agent_id) AS (
        SELECT j FROM unnest(v_judged) AS j
        UNION
        SELECT s.parent_agent_id
          FROM rs_up u
          JOIN public.agent_succession s ON s.child_agent_id = u.agent_id
         WHERE NOT EXISTS (
                   SELECT 1 FROM public.role_agents dr
                    WHERE dr.agent_id = s.parent_agent_id AND dr.role = p_role
                      AND dr.inherited_from IS NULL AND dr.detached_at IS NULL
                      AND dr.valid_from <= v_now
                      AND (dr.valid_to IS NULL OR v_now < dr.valid_to))
    )
    SELECT u.agent_id INTO v_blocker
      FROM rs_up u
     WHERE u.agent_id <> p_root
       AND EXISTS (SELECT 1 FROM public.role_agents dd
                    WHERE dd.agent_id = u.agent_id AND dd.role = p_role
                      AND dd.detached_at IS NOT NULL)
     ORDER BY u.agent_id
     LIMIT 1;
    IF v_blocker IS NOT NULL THEN
        RAISE EXCEPTION 'ROL04: % descends from %, which holds a detached row for % and no live '
                        'row made by name: that detach cuts % off, and restoring % does not '
                        'undo it', p_successor, v_blocker, p_role, p_successor, p_root
            USING ERRCODE = 'ROL04',
                  HINT = 'Nothing was written.';
    END IF;

    -- (4) The act: retire the covering rows, attach the successor by name.
    UPDATE public.role_agents r
       SET detached_at = pg_catalog.now(), detached_by = session_user,
           detach_reason = 'replaced by an attachment made by name '
                           '(epigraph_restore_role_successor): ' || p_reason
     WHERE r.id = ANY (v_replace);
    FOR v_found IN SELECT x FROM unnest(v_replace) AS x LOOP
        out_step := 'copy_detached';
        out_agent_id := p_successor;
        out_attachment_id := v_found;
        RETURN NEXT;
    END LOOP;
    INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason)
    VALUES (p_role, p_successor, v_now, v_root_to, p_reason)
    RETURNING id INTO v_new;
    out_step := 'successor_attached';
    out_agent_id := p_successor;
    out_attachment_id := v_new;
    RETURN NEXT;

    -- Registered descendants of the successor whose live copy still chains
    -- through a row that is not live: reported, not changed.
    FOR v_found IN
        WITH RECURSIVE rs_down (agent_id) AS (
            SELECT s.child_agent_id FROM public.agent_succession s
             WHERE s.parent_agent_id = p_successor
            UNION
            SELECT s.child_agent_id
              FROM rs_down d
              JOIN public.agent_succession s ON s.parent_agent_id = d.agent_id
        )
        SELECT d.agent_id
          FROM rs_down d
         WHERE d.agent_id <> p_successor AND d.agent_id <> p_root
           AND EXISTS (
                   SELECT 1 FROM public.role_agents c
                    WHERE c.agent_id = d.agent_id AND c.role = p_role
                      AND c.inherited_from IS NOT NULL AND c.detached_at IS NULL
                      AND c.valid_from <= v_now AND (c.valid_to IS NULL OR v_now < c.valid_to)
                      AND EXISTS (
                              WITH RECURSIVE rs_up2 (id, inherited_from, live) AS (
                                  SELECT h.id, h.inherited_from,
                                         h.detached_at IS NULL AND h.valid_from <= v_now
                                             AND (h.valid_to IS NULL OR v_now < h.valid_to)
                                    FROM public.role_agents h WHERE h.id = c.inherited_from
                                  UNION ALL
                                  SELECT h.id, h.inherited_from,
                                         h.detached_at IS NULL AND h.valid_from <= v_now
                                             AND (h.valid_to IS NULL OR v_now < h.valid_to)
                                    FROM public.role_agents h
                                    JOIN rs_up2 x ON h.id = x.inherited_from
                              )
                              SELECT 1 FROM rs_up2 x WHERE NOT x.live))
           AND NOT EXISTS (
                   SELECT 1 FROM public.role_agents n
                    WHERE n.agent_id = d.agent_id AND n.role = p_role
                      AND n.inherited_from IS NULL AND n.detached_at IS NULL
                      AND n.valid_from <= v_now AND (n.valid_to IS NULL OR v_now < n.valid_to))
         ORDER BY d.agent_id
    LOOP
        v_out := v_out || v_found;
        out_step := 'descendant_still_out';
        out_agent_id := v_found;
        out_attachment_id := NULL;
        RETURN NEXT;
    END LOOP;

    -- (5) One audit row for the act, beside 166's per-row events.
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.role_successor_restored', p_successor, true,
            jsonb_build_object('role', p_role,
                               'root', p_root,
                               'root_attachment', v_root_row,
                               'root_attached_now', v_root_new,
                               'successor', p_successor,
                               'successor_attachment', v_new,
                               'detached', to_jsonb(v_replace),
                               'stale', to_jsonb(v_stale),
                               'descendants_still_out', to_jsonb(v_out),
                               'reason', p_reason,
                               'recorded_by', session_user));
    RETURN;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_restore_role_successor(text, uuid, uuid, timestamptz, text) FROM PUBLIC;

-- Owner and grants, guarded as every such block since 060 is. The owner is
-- load-bearing: `role_agents`, `agent_succession` and
-- `agent_prompt_snapshots` are FORCEd, so under a non-member owner every
-- read here is filtered to nothing (the folder check refuses every
-- successor: loud) and the writes are refused by the policies (loud).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_restore_role_successor(text, uuid, uuid, '
                'timestamptz, text) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_restore_role_successor(text, uuid, '
                'uuid, timestamptz, text) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_restore_role_successor(text, uuid, '
                'uuid, timestamptz, text) FROM epigraph_app';
    END IF;
END $$;

-- 117: the retraction cascade is an administrative act, and UPDATE of an edge
-- or a registry row is owner-scoped (batch W10).
--
-- ===================================================================
-- 0. WHAT THIS FILE CHANGES
-- ===================================================================
--
-- Two rules, stated once:
--
--   (1) A non-privileged session UPDATEs an `edges` row only when the edge's
--       owner or co-owner is in its WRITABLE set, and an instance-wide
--       registry row (`frames`, `contexts`, `perspectives`, `communities`)
--       only when the row's owner is. Both the row it starts from (USING) and
--       the row it leaves behind (WITH CHECK) must pass.
--   (2) The cascade that follows a supersede, a dedup or a match-candidate
--       retirement -- invalidating edge-keyed BBAs, and re-pointing or
--       retracting edges and rows other writers own -- runs on the server's
--       privileged maintenance connection, not with the caller's authority.
--       So the cascade definer 115 added no longer needs, and no longer has,
--       any arm that admits a row the session does not own.
--
-- ===================================================================
-- 1. WHY UPDATE, AND WHY THESE FIVE TABLES
-- ===================================================================
--
-- 077's `<table>_tenancy` policies are FOR ALL, with USING = the READ
-- predicate (`visibility = 'public'` admits) and WITH CHECK = the writable set.
-- On nineteen of the tier-A tables that WITH CHECK, plus 115's owner
-- immutability, already refuses a non-owner's UPDATE of a public row: the
-- owner cannot change, so the new row fails the writable check. Two shapes
-- escape that, and they are exactly the five tables below:
--
--   * `edges` and the four registries carry a WORLD arm in their WITH CHECK
--     (`visibility = 'public' AND owner_group_id = <world>`). The world group
--     is memberless, so that arm names a row nobody owns, and any application
--     session could rewrite such a row: retract an edge between two public
--     claims, rewrite its properties, or rewrite a shared frame's or
--     perspective's properties.
--   * `edges` has a BEFORE trigger that RESTAMPS the owner from the endpoints
--     (070/072's `edges_tenancy`, `BEFORE INSERT OR UPDATE OF source_id,
--     target_id`). So an UPDATE that names only `source_id` / `target_id`
--     re-owns the edge without naming `owner_group_id`, and 115's
--     `edges_owner_immutable` guard (UPDATE OF the owner columns) never fires.
--     Re-pointing a world edge's source at a claim the session writes made
--     the edge the session's to delete through 115's source-writer DELETE arm.
--
-- The enumeration is from the catalog, not from this list: every relation in
-- `public` with both tenancy columns, whose UPDATE-covering permissive policy
-- admits the world group in its WITH CHECK, or which carries a BEFORE UPDATE
-- trigger that assigns `NEW.owner_group_id`. Measured on a database at 115: exactly
-- these five, and only `edges` has the restamp. The ratchets are
-- `owner_scoped_update.rs::every_world_admitting_table_has_a_restrictive_update_policy`
-- and `...::no_other_table_restamps_its_owner_on_update`.
--
-- HOW: one RESTRICTIVE, FOR UPDATE policy per table, `<table>_update_owner`,
-- AND-ed with the permissive `<table>_tenancy`, as 115 did for DELETE. Its
-- USING makes a row the session does not own invisible to its UPDATE (0 rows,
-- not an error); its WITH CHECK refuses (42501) an UPDATE whose NEW row --
-- after `edges_tenancy` has restamped it -- the session would not own. So the
-- restamp can no longer be driven by a non-owner: the old row must already be
-- the session's.
--
-- WHAT THIS DOES NOT CHANGE: 077's INSERT arm (a new edge between two public
-- endpoints still arrives world-owned, and is still admitted), and 115's
-- `edges_delete_owner`, whose source-writer arm still lets the writer of a
-- world edge's SOURCE delete it. That leaves one stated asymmetry: such a
-- writer may DELETE its world edge but may not retract or re-point it. The
-- retraction, the property patch and the re-point of an edge nobody owns are
-- privileged operations after this file.
--
-- THE CO-OWNER ARM, precisely. 077's permissive WITH CHECK on `edges` names
-- only the OWNER, so a co-owner's in-place UPDATE (a relabel, a retraction)
-- was refused before this file and still is. The co-owner arm here matters
-- for one shape: a co-owner re-points the edge off the owner's endpoint, and
-- the restamp leaves the edge wholly in the co-owner's group, which then
-- passes both WITH CHECKs. That is an edit by a party that could already
-- DELETE the edge (115), so it is admitted, as rule (1) above says.
-- `owner_scoped_update.rs::the_owner_and_the_co_owner_still_update_their_edges`
-- pins both halves.
--
-- ===================================================================
-- 2. THE CASCADE, ON THE MAINTENANCE CONNECTION
-- ===================================================================
--
-- 115 let a non-privileged session invalidate another writer's edge-keyed BBA
-- through two arms of `epigraph_cascade_delete_edge_bbas`: `retracted_edge`
-- (the BBA's edge is retracted) and `source_writer` (the session writes the
-- edge's source, or a retired duplicate of it). The first was licensed by the
-- very UPDATE rule section 1 closes; the second let the writer of a claim
-- remove other writers' rows at any time.
--
-- Both are removed. The application now splits each of the three flows into
-- the caller's own act and an administrative cascade:
--   * supersede: the caller retires its claim and inserts the replacement on
--     its own stamped transaction; migrating the edges onto the replacement
--     and invalidating the BBAs frozen from the retired claim's interval run on
--     the maintenance connection;
--   * dedup: the caller marks its duplicate on its own stamped transaction;
--     retracting colliding edges, re-pointing every other edge onto the
--     canonical claim, moving and dropping their BBAs, and re-deriving them
--     run on the maintenance connection;
--   * match-candidate retirement: the caller flips the candidate to `stale`;
--     retracting the matcher edge and removing its derived rows run on the
--     maintenance connection.
-- Every administrative cascade writes one `security_events` row naming the
-- triggering principal, the cause and what it touched. A server with no
-- maintenance connection configured still commits the caller's act, reports
-- the cascade as deferred, and writes a `security_events` row saying so.
--
-- 114's `epigraph_dedup_move_bbas` moved OTHER writers' BBAs onto the
-- canonical on the deduplicating session's authority. Nothing non-privileged
-- calls it after this batch (the move is part of the administrative repair,
-- which runs the statement directly and keeps 114's writer-owned outcome), so
-- EXECUTE on it is revoked from the application role: a non-privileged call
-- is refused (42501). The maintenance role keeps it.
--
-- The definer stays, reduced to the owner arm: for a non-privileged session it
-- deletes the edge-keyed BBAs the session owns, and refuses the whole call
-- (CD02, 42501) when a readable one is not the session's. So a non-privileged
-- caller of the old arms is refused, loudly, instead of silently removing
-- less. A privileged session keeps the plain statement. The body is replaced
-- with CREATE OR REPLACE and the same signature, so 115's owner
-- (`epigraph_maintenance`) and ACL are preserved; 115 is not edited.
--
-- DEPLOY ORDER: apply 117 BEFORE any binary built with it serves, and set the
-- maintenance DSN on every server process first: a binary built with 117 runs
-- each cascade on that connection and defers it when there is none. A binary
-- built without 117 against a database at 117 keeps working for its own rows;
-- its non-privileged cascades of other writers' rows are refused (CD02) and
-- reported in the cascade's errors, as they were for an unstamped session
-- under 115.
--
-- Undo: DROP the five `<table>_update_owner` policies; restore 115's body of
-- `epigraph_cascade_delete_edge_bbas` with CREATE OR REPLACE (never DROP: a
-- DROP resets the ACL); GRANT EXECUTE ON `epigraph_dedup_move_bbas(uuid, uuid,
-- uuid[])` TO epigraph_app. Checked before claiming: no `origin/*` ref carries
-- a `117`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1a. RESTRICTIVE UPDATE ON edges
-- ===================================================================
DROP POLICY IF EXISTS edges_update_owner ON public.edges;
CREATE POLICY edges_update_owner ON public.edges AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR co_owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR co_owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- ===================================================================
-- 1b. RESTRICTIVE UPDATE ON THE FOUR REGISTRIES
-- ===================================================================
DO $$
DECLARE t text;
        registry text[] := ARRAY['frames','contexts','perspectives','communities'];
BEGIN
    FOREACH t IN ARRAY registry LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_update_owner', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR UPDATE TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_update_owner', t);
    END LOOP;
END $$;

-- ===================================================================
-- 2. THE CASCADE DEFINER, OWNER ARM ONLY
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
        DELETE FROM public.mass_functions WHERE perspective_id = ANY (p_edge_ids);
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
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_cascade_delete_edge_bbas(uuid[], text) FROM PUBLIC;

-- ===================================================================
-- 3. THE DEDUP MOVE DEFINER IS NO LONGER THE APPLICATION'S
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'FROM epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 4. THE MAINTENANCE ROLE'S GRANTS FOR THE RETIREMENT CASCADE
-- ===================================================================
-- The match-candidate retirement cascade deletes the retracted matcher edge's
-- `factors` and `bp_messages`. 070 granted `epigraph_maintenance` SELECT /
-- INSERT / UPDATE only, so on a maintenance login that is not a superuser the
-- cascade would stop at its first DELETE. The narrowest grant under which it
-- runs, as 115 did for `mass_functions` and `edges`.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.factors, public.bp_messages TO epigraph_maintenance';
    END IF;
END $$;

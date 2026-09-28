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
--   (3) The `security_events` rows that drive that cascade's replay are the
--       server's: a non-privileged session writes no `cascade.*` row itself,
--       and records a deferral only through a definer that checks the act is
--       one the session made (section 6).
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
-- world edge's SOURCE delete it. That arm is a non-owner DELETE, and whether
-- it survives the rule that a non-privileged DELETE is owner/co-owner scoped
-- is an OPEN operator decision, not settled here: the workflow step rewire
-- (`workflow_steps.rs`) deletes world `step_follows` edges through it on the
-- application role, and removing it would move every world-edge delete onto
-- the administrative connection. Until that decision, such a writer may
-- DELETE a world edge from its source but may not retract or re-point it. The
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
-- pins both halves. A re-point must not keep the ORIGINAL writer's signature,
-- though: the signed content named the old endpoints, so an edge re-pointed
-- in place would carry an attribution its signer never made. Section 5 clears
-- `signature`, `signer_id` and `content_hash` whenever a non-privileged
-- session changes an edge's endpoints.
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
--   * match-candidate retirement: administrative end to end. The flip to
--     `stale`, retracting the matcher edge and removing its derived rows run
--     together on the maintenance connection (a later migration refuses the
--     flip on a non-privileged session, so the flip cannot be the caller's).
-- Every administrative cascade writes one `security_events` row naming the
-- triggering principal, the cause and what it touched. A server with no
-- maintenance connection configured still commits the caller's act, reports
-- the cascade as deferred, and writes a `security_events` row saying so. A
-- retirement has no act of the caller's to commit: its deferral is the whole
-- request, the candidate is left as it was, and the replay carries the
-- request out while the candidate still has the status the deferral recorded.
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
-- Undo: DROP the five `<table>_update_owner` policies; DROP TRIGGER
-- `edges_repoint_unsign` and its function; restore 115's body of
-- `epigraph_cascade_delete_edge_bbas` with CREATE OR REPLACE (never DROP: a
-- DROP resets the ACL); GRANT EXECUTE ON `epigraph_dedup_move_bbas(uuid, uuid,
-- uuid[])` TO epigraph_app; DROP POLICY `security_events_cascade_privileged`,
-- DROP TRIGGER `claims_supersedes_guard` and its function, and DROP FUNCTION
-- `epigraph_record_cascade_deferral` (new here, so a DROP resets nothing). A
-- binary built with section 6 needs the function; roll the binary back first.
-- Checked before claiming: no `origin/*` ref carries a `117`.

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

-- ===================================================================
-- 5. A NON-PRIVILEGED RE-POINT UNSIGNS THE EDGE
-- ===================================================================
-- An edge's `signature` / `signer_id` / `content_hash` attest the edge as its
-- signer wrote it, endpoints included. The owner and the co-owner may re-point
-- an edge (section 1a), but the re-pointed edge is no longer what was signed,
-- so a non-privileged session that changes an endpoint leaves an unsigned edge
-- rather than one that keeps another writer's attribution. A privileged
-- session (the administrative cascade that migrates a superseded or duplicate
-- claim's edges, a backfill) keeps the columns: it records where an
-- assertion moved, and the audit row says so.
CREATE OR REPLACE FUNCTION public.epigraph_edges_repoint_unsign()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF (NEW.source_id, NEW.source_type, NEW.target_id, NEW.target_type)
           IS DISTINCT FROM (OLD.source_id, OLD.source_type, OLD.target_id, OLD.target_type)
       AND (OLD.signature IS NOT NULL OR OLD.signer_id IS NOT NULL
            OR OLD.content_hash IS NOT NULL)
       AND NOT public.epigraph_session_is_privileged_writer() THEN
        NEW.signature := NULL;
        NEW.signer_id := NULL;
        NEW.content_hash := NULL;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS edges_repoint_unsign ON public.edges;
CREATE TRIGGER edges_repoint_unsign
    BEFORE UPDATE OF source_id, source_type, target_id, target_type ON public.edges
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_edges_repoint_unsign();

-- ===================================================================
-- 6. THE CASCADE AUDIT ROWS ARE THE SERVER'S, NOT THE SESSION'S
-- ===================================================================
-- The replay (`replay_deferred_cascades`) runs a repair with administrative
-- authority for every `cascade.deferred` / `cascade.admin_failed` row that no
-- later `cascade.admin_applied` / `cascade.retired` row answers. So those rows
-- are instructions to a privileged process, and 077's `security_events_append`
-- is not a strong enough gate for them: it admits any row whose `agent_id`
-- column is NULL or the session principal, with any `details` and any
-- `created_at`. Three rules close that:
--
--   (a) A non-privileged session writes NO `cascade.*` row directly (a
--       RESTRICTIVE INSERT policy, AND-ed with 077's permissive one). That
--       covers the answering rows too: a `cascade.admin_applied` row would
--       otherwise silence a genuine deferral. The privileged arms are 077's:
--       the maintenance session, and a body running as the maintenance role.
--       Every maintenance-owned definer that inserts into `security_events`
--       names a fixed event type that is not `cascade.*` (114's two, 115's and
--       section 2's `derived.cascade_bba_delete`), except the one below.
--   (b) A deferral is written only by `epigraph_record_cascade_deferral`, a
--       definer that derives the row from committed state and the session:
--       `agent_id` is the session principal (a named principal that differs
--       is refused), `created_at` is the default, `details` is built here, and
--       the act must be one this session could have made:
--         supersede    : the retired subject and its successor, both written by
--                        the session (the supersede act's own authority);
--         dedup        : the retired duplicate, written by the session, onto a
--                        canonical that is public or written by the session
--                        (114's attach rule, FA04, as the act checks it);
--         consolidate  : every retired source, written by the session;
--         match_retire : the candidate exists; its current status is
--                        recorded in the trigger (`candidate_status`) and is
--                        the replay's precondition. The deferral is a REQUEST
--                        to retire, which the operator's replay carries out.
--                        `match_candidates` carries no tenancy, so the
--                        database holds no finer authority for requesting a
--                        retirement than the ability to call this definer;
--                        the request paths gate it on the `claims:admin`
--                        scope, and a non-privileged session that calls the
--                        definer directly can enqueue a request the replay
--                        will run. That is no wider than what the table grant
--                        allowed before the flip to `stale` was reserved to
--                        privileged sessions, and every request is an
--                        attributed row the operator can read before
--                        replaying (and retire with the replay's --retire).
--       A privileged session is not held to the authority half (it may write
--       any row under (a) anyway) but is to the state half. The OAuth part of
--       the trigger is the server's report of the request, recorded as given;
--       `agent_id` is the attribution the database vouches for.
--   (c) A non-privileged UPDATE that sets `claims.supersedes` to a claim the
--       session neither writes nor sees as public is refused (FA04). The
--       dedup act checks this too, but an UPDATE of `supersedes` issued
--       outside the act had no guard, and 074's check runs on INSERT only.
--       074's other INSERT rule (a public successor of a group-private claim)
--       is about the tenancy an INSERT inherits; an UPDATE inherits nothing,
--       so it is not repeated here.
DROP POLICY IF EXISTS security_events_cascade_privileged ON public.security_events;
CREATE POLICY security_events_cascade_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        left(event_type, 8) <> 'cascade.'
        OR (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

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
    IF p_cause IS NULL OR p_cause NOT IN ('supersede', 'dedup', 'consolidate', 'match_retire') THEN
        RAISE EXCEPTION 'CX01: unknown cascade cause %; no deferral was recorded', p_cause
            USING ERRCODE = '22023';
    END IF;
    IF p_subject IS NULL
       OR (p_cause IN ('supersede', 'dedup')) <> (p_object IS NOT NULL)
       OR (p_cause = 'consolidate') <> (cardinality(v_sources) > 0) THEN
        RAISE EXCEPTION 'CX01: a % deferral names a subject%; no deferral was recorded', p_cause,
            CASE p_cause WHEN 'supersede' THEN ' and an object, and no sources'
                         WHEN 'dedup' THEN ' and an object, and no sources'
                         WHEN 'consolidate' THEN ' and its sources, and no object'
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
    IF p_cause = 'consolidate' THEN
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

CREATE OR REPLACE FUNCTION public.epigraph_claims_supersedes_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.supersedes IS NULL OR NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes
       OR public.epigraph_session_is_privileged_writer() THEN
        RETURN NEW;
    END IF;
    -- Read as the invoker: a claim the session cannot read is refused like a
    -- private one, and the message names nothing the session could not see.
    IF NOT EXISTS (SELECT 1 FROM public.claims k
                    WHERE k.id = NEW.supersedes
                      AND (k.visibility::text = 'public'
                           OR public.epigraph_session_writes_node(k.id, 'claim'))) THEN
        RAISE EXCEPTION 'FA04: claim % may not name % in supersedes: it is not public and this '
            'session cannot write it; a non-owner may attach only to a PUBLIC claim; nothing was '
            'written', NEW.id, NEW.supersedes
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS claims_supersedes_guard ON public.claims;
CREATE TRIGGER claims_supersedes_guard
    BEFORE UPDATE OF supersedes ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_supersedes_guard();

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_record_cascade_deferral('
                'text, uuid, uuid, uuid, uuid[], jsonb, text) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_record_cascade_deferral('
                'text, uuid, uuid, uuid, uuid[], jsonb, text) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_record_cascade_deferral('
                'text, uuid, uuid, uuid, uuid[], jsonb, text) TO epigraph_app';
    END IF;
END $$;

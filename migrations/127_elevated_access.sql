-- Migration 127: the ELEVATED-ACCESS LOG. Every request served to an elevated
-- viewer is recorded, fail-closed, in a row the owners of the rows it read can
-- see (elevation plan EL-8, DESIGN 6.6).
--
-- ===================================================================
-- 1. THE MODEL
--
-- An elevated session (migration 125) reads every row of an armed table
-- (migration 126). That is a custodian looking at other people's private
-- rows, so each elevated request leaves one `elevated_access` row behind:
-- which session (and so which person, which role assignment, which reason),
-- which surface (an API route or an MCP tool), the request's ids and filters
-- (never content), how many rows the response carried, and the OWNER GROUPS
-- of the private rows it named that the elevator could not have read
-- unelevated.
--
-- THE SERVING PROCESS RECORDS, BEFORE IT ANSWERS. The API's response layer
-- and the MCP tool-call wrapper buffer an elevated response, collect every id
-- it names, and call `epigraph_record_elevated_access` on a connection stamped
-- with the same elevation, BEFORE the response leaves. If the call fails the
-- response is withheld (fail-closed). Only a build that does this declares
-- the recorder on its connections (`epigraph.access_recorder`, migration
-- 125's second key); a connection that does not declare it is never elevated.
--
-- THE DATABASE ATTRIBUTES, NOT THE CALLER. The caller hands over the ids it
-- found; the definer itself decides which of them name a private row the
-- elevator could not read unelevated, and whose group owns it, by each
-- table's own tenancy rule:
--   * the owner-group tables an elevated session reads (126 list 3a, those
--     keyed by a uuid `id`): private (`visibility <> 'public'`) and owned by a
--     group the elevator is not a live member of; an edge also by its
--     co-owner group;
--   * `recall_events`: any row of another agent (its policy admits only the
--     row's own agent), the agent-less rows included, attributed to its
--     `owner_group_id`;
--   * `groups` and `group_memberships`: a group the elevator is not a member
--     of (attributed to that group), and another agent's membership in one.
-- `agents` is readable by every session (its policy is `true`), and papers
-- and workflows carry no tenancy, so they never contribute. An AGGREGATE
-- answer names no row, so it is logged with an empty group list: the log says
-- that an elevated count ran, not whose rows it counted.
--
-- ATTRIBUTION IS BY ID, SO IT CAN OVER-REPORT. The definer cannot tell an id
-- the response READ from an id it merely MENTIONED: a group id carried as a
-- field of a public row (its `owner_group_id`) attributes that group, and the
-- memberless world group can be named the same way (no admin reads it). An
-- error that names a private row's id (a "not found") attributes the row's
-- group too. Each errs toward telling the subject more, never less.
--
-- WHO SEES A ROW. The subject: a live ADMIN member of a group the row names
-- ("an elevated session read rows of your group G at T, for reason R"; the
-- session's reason is copied onto the row, because the subject cannot read
-- `elevation_sessions`). A writer or reader member does not. Holders of a
-- `reads_audit` role, an elevated session and the maintenance role read every
-- row through `epigraph_elevated_access_audit` (123's
-- `epigraph_platform_audit` pattern), not through a policy arm.
--
-- APPEND-ONLY. Inserted by the recorder definer only (or a privileged
-- session); never updated, never deleted (ELV03 for both, whoever asks).
--
-- ===================================================================
-- 2. THE GATE STAYS CLOSED
--
-- Migration 125 ships `epigraph_elevated_access_ready()` answering false, so
-- NO session is live until one migration of the stack opens it. This file
-- installs the recorder, which is ONE of the conditions that opening waits on
-- (125's header, "OPENING IT WAITS ON MORE THAN THE RECORDER"):
--   (1) operator-hidden (pinned) evidence: SETTLED by the operator, as an
--       INTERIM ruling ("for now"): an elevated session that reads claims MAY
--       read their evidence, pinned rows included, so no hide predicate is
--       added to 126's `evidence_elevated_read`. What the ruling requires is
--       here: `evidence` is in the attribution set, so an elevated read of a
--       pinned row is recorded against its owning group (the hiding
--       operator's), whose admin reads the log row. A later ruling may
--       restore hiding (a per-row definer predicate in the read arm; a plain
--       `NOT EXISTS (pin)` would be a no-op, since the application role
--       reads no pin);
--   (2) the API refusing elevated non-GET requests: NOT built yet;
--   (3) `recall_events` in the attribution set: here.
-- (2) is unmet, so this file does NOT replace the gate: after it, exactly as
-- before it, no session is live on any database. The opening moves to the
-- stack's last migration (the elevation plan's EL-8, binding).
--
-- ===================================================================
-- 3. REFUSALS
--
--   ELV03  not the append-only shape: a row is born from its live session
--          (person, assignment and reason copied from it, stamped now by the
--          inserting login) and never changes or goes away.
--   ELV07  the recorder was called on a connection that is not elevated: the
--          application cannot forge a log row for a session it does not hold.
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/127-undo.sql`, BEFORE 126-undo. Roll back first every binary
-- that records (docs/deploy.md).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE TABLE
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.elevated_access (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    elevation_id     uuid NOT NULL REFERENCES public.elevation_sessions(id) ON DELETE RESTRICT,
    person_agent_id  uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    assignment_id    uuid NOT NULL REFERENCES public.role_assignments(id) ON DELETE RESTRICT,
    -- The session's reason, copied: the subject reads this row, never the
    -- session.
    reason           text NOT NULL,
    -- `GET /api/v1/claims/:id`, `mcp:get_claim`, ...
    surface          text NOT NULL CONSTRAINT elevated_access_surface
                         CHECK (length(btrim(surface)) BETWEEN 1 AND 512),
    -- The request's ids and filters (path, query, id-shaped body fields),
    -- never content; bounded.
    args             jsonb NOT NULL CONSTRAINT elevated_access_args
                         CHECK (jsonb_typeof(args) = 'object'
                                AND pg_column_size(args) <= 32768),
    -- How many rows the response carried (the serving process counts them).
    row_count        integer NOT NULL CONSTRAINT elevated_access_row_count
                         CHECK (row_count >= 0),
    -- The groups whose private rows the response named (the definer decides).
    owner_group_ids  uuid[] NOT NULL DEFAULT ARRAY[]::uuid[]
                         CONSTRAINT elevated_access_groups_present
                         CHECK (array_position(owner_group_ids, NULL) IS NULL),
    recorded_by      text NOT NULL DEFAULT session_user,
    created_at       timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON public.elevated_access FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_elevated_access_elevation
    ON public.elevated_access (elevation_id);
CREATE INDEX IF NOT EXISTS idx_elevated_access_created
    ON public.elevated_access (created_at);
-- The subject's read: `owner_group_ids && <the reader's admin groups>`.
CREATE INDEX IF NOT EXISTS idx_elevated_access_owner_groups
    ON public.elevated_access USING gin (owner_group_ids);

-- ===================================================================
-- 2. THE GUARDS
-- ===================================================================

-- BEFORE INSERT: ELV03. The row is born from a session that exists, carrying
-- that session's person, assignment and reason, stamped now by the login that
-- inserts it.
CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.elevation_sessions s
                    WHERE s.id = NEW.elevation_id
                      AND s.person_agent_id = NEW.person_agent_id
                      AND s.assignment_id = NEW.assignment_id
                      AND s.reason = NEW.reason) THEN
        RAISE EXCEPTION 'ELV03: an elevated-access row names its session''s own person, '
                        'assignment and reason (session %)', NEW.elevation_id
            USING ERRCODE = 'ELV03';
    END IF;
    IF NEW.created_at IS DISTINCT FROM now() OR NEW.recorded_by IS DISTINCT FROM session_user THEN
        RAISE EXCEPTION 'ELV03: an elevated-access row is stamped now, by the login that '
                        'inserts it'
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevated_access_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevated_access_guard_insert ON public.elevated_access;
CREATE TRIGGER elevated_access_guard_insert
    BEFORE INSERT ON public.elevated_access
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevated_access_guard_insert();

-- BEFORE UPDATE OR DELETE: ELV03, whoever asks (the maintenance role and a
-- superuser included). The log is the subject's record; nothing edits it.
CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_guard_change()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'ELV03: the elevated-access log is append-only (% of row %)',
                    TG_OP, OLD.id
        USING ERRCODE = 'ELV03';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevated_access_guard_change() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevated_access_guard_change ON public.elevated_access;
CREATE TRIGGER elevated_access_guard_change
    BEFORE UPDATE OR DELETE ON public.elevated_access
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevated_access_guard_change();

-- ===================================================================
-- 3. WHO SEES A ROW
-- ===================================================================

-- The groups the SESSION PRINCIPAL is a live admin member of. Principal-bound
-- and argument-free (077's `epigraph_is_group_admin` reasoning): it answers
-- only for the caller, so it is no membership oracle. Read by the subject
-- policy below, once per statement.
CREATE OR REPLACE FUNCTION public.epigraph_admin_group_ids()
RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(array_agg(m.group_id), ARRAY[]::uuid[])
      FROM public.group_memberships m
     WHERE public.epigraph_principal_id() IS NOT NULL
       AND m.agent_id = public.epigraph_principal_id()
       AND m.role = 'admin'
       AND m.revoked_at IS NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_group_ids() FROM PUBLIC;

ALTER TABLE public.elevated_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.elevated_access FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS elevated_access_subject_read ON public.elevated_access;
CREATE POLICY elevated_access_subject_read ON public.elevated_access
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass())
           OR owner_group_ids && (SELECT public.epigraph_admin_group_ids()));
DROP POLICY IF EXISTS elevated_access_definer_insert ON public.elevated_access;
CREATE POLICY elevated_access_definer_insert ON public.elevated_access
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
-- No UPDATE and no DELETE policy: under FORCE nobody changes or removes a row
-- (and the guard above refuses even a privileged login).

-- ===================================================================
-- 4. THE RECORDER
-- ===================================================================

-- Record one elevated request: `p_surface` (route or tool), `p_args` (its ids
-- and filters), `p_row_count` (rows the response carried) and
-- `p_candidate_ids` (every id the response named). Refused (ELV07) unless
-- THIS connection is elevated (`epigraph_is_elevated()`, migration 125: a
-- live session of the stamped principal and family, on a connection that
-- declares the recorder). The session, person, assignment and reason come
-- from the session row, never from the caller; the owner groups are decided
-- here (header, section 1). Returns the row's id.
CREATE OR REPLACE FUNCTION public.epigraph_record_elevated_access(
    p_surface text, p_args jsonb, p_row_count integer, p_candidate_ids uuid[])
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
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
REVOKE EXECUTE ON FUNCTION public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])
    FROM PUBLIC;

-- The whole log (newest first, at most `p_limit`, capped at 1000, since
-- `p_since`), for a session that holds a role which `reads_audit` NOW, as its
-- own principal; for an ELEVATED session; or for a privileged session.
-- Anyone else gets no rows (their own group's rows they read through the
-- table's policy).
CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_audit(
    p_since timestamptz, p_limit integer)
RETURNS SETOF public.elevated_access
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT a.*
      FROM public.elevated_access a
     WHERE a.created_at >= COALESCE(p_since, '-infinity'::timestamptz)
       AND (public.epigraph_bypass()
            OR public.epigraph_is_elevated()
            OR EXISTS (SELECT 1 FROM public.platform_roles r
                        WHERE r.reads_audit
                          AND public.epigraph_holds_role(public.epigraph_principal_id(),
                                                         r.key, now())))
     ORDER BY a.created_at DESC, a.id
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 100), 1), 1000)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevated_access_audit(timestamptz, integer)
    FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- 077's default privileges hand the application role DML on every new table:
-- taken back here, leaving SELECT (which the policy narrows to the subject's
-- rows). Every function is owned by the maintenance role, so its frame passes
-- `epigraph_definer_bypass()`. The application role may EXECUTE the recorder
-- (refused unless elevated), the audit reader (empty unless entitled) and the
-- principal-bound admin-group helper the policy reads.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_elevated_access_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevated_access_guard_change() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_group_ids() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_elevated_access(text, jsonb, integer, '
                'uuid[]) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevated_access_audit(timestamptz, integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT ON public.elevated_access TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_admin_group_ids(), '
                'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]), '
                'public.epigraph_elevated_access_audit(timestamptz, integer) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.elevated_access FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.elevated_access TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_admin_group_ids(), '
                'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]), '
                'public.epigraph_elevated_access_audit(timestamptz, integer) TO epigraph_app';
    END IF;
END $$;

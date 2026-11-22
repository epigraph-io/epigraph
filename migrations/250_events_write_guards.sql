-- Migration 250: two `events` write guards, both on the provenance record.
--   1. The maintenance role prunes telemetry only through a type-restricted
--      definer and loses its table-wide DELETE and UPDATE on `events`
--      (backlog 062d7767).
--   2. A `claim.assessed` row is refused unless it records a slot write made
--      in the same transaction, or comes from a maintenance session (backlog
--      a278f16d).
--
-- ===================================================================
-- 1. TELEMETRY-ONLY PRUNE (backlog 062d7767)
-- ===================================================================
--
-- WHY. 186 granted `epigraph_maintenance` DELETE on `events` so the retention
-- job `prune_recall_events` could prune telemetry on a NOSUPERUSER maintenance
-- login, and 070 had granted it UPDATE. 189 closed `events` to the
-- application role and, deliberately, left the maintenance role alone (its
-- header names a telemetry-only definer as the follow-up). So any session
-- acting as `epigraph_maintenance` (timers, scripts, operator logins on the
-- maintenance DSN) could delete or rewrite any `events` row, provenance events
-- such as `claim.created` included; the type and age filters were the job's,
-- in Rust. UPDATE alone was enough to defeat a type filter: re-type a
-- provenance row to `tool.invoked` and the prune deletes it.
--
-- WHAT IT DOES.
--   * `epigraph_prunable_event_types()`: the allowlist, `{tool.invoked}`. It
--     must equal `epigraph_db::PRUNABLE_EVENT_TYPES` (pinned by
--     `events_telemetry_prune_definer.rs::the_definers_type_list_is_prunable_event_types`).
--     IMMUTABLE, SQL, invoker; EXECUTE stays with PUBLIC (a constant). The
--     dry-run count (`RecallEventRepository::count_prunable_events`) reads it,
--     so the count and the delete cannot disagree.
--   * `epigraph_prune_telemetry_events(retention_days)`: SECURITY DEFINER.
--     Deletes `events` rows whose `event_type` is EXACTLY one of the allowlist
--     and whose `created_at` is older than `retention_days` (floored at 1, as
--     the Rust caller already did); returns the count. It takes no type
--     argument, so no caller widens the allowlist. It refuses a NULL window
--     (22004) and a session `epigraph_bypass()` does not admit (42501), as a
--     second gate behind the grant. EXECUTE is revoked from PUBLIC and granted
--     to `epigraph_maintenance` only.
--   * `REVOKE DELETE, UPDATE, TRUNCATE ON public.events FROM
--     epigraph_maintenance`. The role keeps SELECT and INSERT (070). TRUNCATE
--     was never granted (070 grants SELECT / INSERT / UPDATE, 186 DELETE) and
--     is revoked as defence in depth, as 189 did for the application role.
--
-- THE OWNER. The definer must hold DELETE on `events` while the maintenance
-- role no longer does, so it cannot be owned by `epigraph_maintenance` (the
-- owner of every other definer since 070): its own DELETE would go with the
-- revoke, and every maintenance login inherits that role's privileges. It is
-- owned by the owner of `public.events` instead (re-owned explicitly below,
-- read from `pg_class.relowner`), which holds every privilege on the table
-- already, so the definer grants its callers nothing the table owner could
-- not do, and only on the fixed type list. The migration refuses (42501) if
-- that owner is `epigraph_maintenance` or a member of it, which would leave
-- maintenance logins holding the DELETE this file takes away. A dedicated
-- NOLOGIN owner role that no login is a member of is the open question
-- 194's header records (OD-9) and is not decided here.
--
-- THE PATH. `SET search_path = pg_catalog, public, pg_temp`, not 172's
-- `pg_catalog, pg_temp`: each deleted row fires 024's `events_cascade_edges`,
-- 001's SECURITY INVOKER `cascade_delete_edges`, whose body says
-- `DELETE FROM edges` unqualified and carries no path of its own. It runs on
-- the definer's path, and on `pg_catalog, pg_temp` it fails with 42P01. The
-- definer's own body names everything qualified. Registered in
-- `definer_search_path_ratchet.rs::PUBLIC_PATH_REGISTER` for that reason.
-- The cascade runs as the definer's owner; `edges` policies admit it through
-- `epigraph_bypass()` (the session is a maintenance login) or the owner's own
-- bypass. A telemetry row is never an edge endpoint in practice; the cascade
-- is kept, not skipped.
--
-- EVERY WRITER OF `events`, RE-ENUMERATED (crates/*/src, scripts/ and the
-- sibling repositories that share the database):
--   * INSERT: `EventRepository::insert` / `insert_on` / `publish_or_log_conn`.
--     Unchanged.
--   * DELETE: `RecallEventRepository::prune_telemetry_events`, which now calls
--     the definer.
--   * UPDATE: `AgentRepository::delete`'s `actor_id` detach. It already
--     refused on the application role (189); after this it refuses on a
--     maintenance login too (42501). Its only callers are test fixtures on
--     the superuser pool. An operator who must delete an agent with events
--     does it on the migration (owner) DSN.
--   No other writer exists; no migration-defined function writes `events`.
--
-- RESIDUAL. The owner of `events` (the migration login) can still do anything
-- to the table, as before. A maintenance session can still INSERT any event.
--
-- DEPLOY ORDER (coupled, both ways): after this file the shipped binary's
-- `DELETE FROM events` gets 42501, and the new binary calls the definer, which
-- exists only after this file. Apply this migration and deploy the binary that
-- calls `epigraph_prune_telemetry_events` before the next `prune_recall_events`
-- run. Out of order the job exits non-zero having deleted nothing from
-- `events` (its `recall_events` prune runs first and is unaffected); no data
-- is lost either way.
--
-- ===================================================================
-- 2. `claim.assessed` IS RESERVED IN THE DATABASE (backlog a278f16d)
-- ===================================================================
--
-- WHY. `claim.assessed` is the assess route's durable writer record
-- (`POST /api/v1/claims/:id/assess`): the writer of masses a later call
-- replaces is read as the `actor_id` of the previous record with the same
-- `mass_function_id`. `EventRepository::RESERVED_EVENT_TYPES` refused the type
-- on the two caller-typed publish surfaces (REST `POST /api/v1/events`, MCP
-- `publish_event`), but nothing in the database did, so any session holding an
-- application DSN (agent containers hold one) could INSERT a record naming a
-- real slot row's `mass_function_id` and be credited, by that rule, as the
-- writer of its masses.
--
-- WHAT IT DOES. A BEFORE INSERT OR UPDATE row trigger on `events`,
-- `events_assessment_guard`, runs `epigraph_events_assessment_guard()` for
-- any row whose lower-cased type contains `claim.assessed` (the trigger's
-- WHEN clause, so every other event pays nothing beyond that test). The body:
--   * admits a row whose type, trimmed and lower-cased, is not exactly
--     `claim.assessed` (e.g. `claim.assessed.v2` is another type);
--   * admits any session `epigraph_bypass()` admits (maintenance logins, the
--     migration / superuser DSN): repair and backfill stay possible;
--   * refuses (42501) any spelling other than the exact `claim.assessed`
--     (padded or re-cased), as the API layer does;
--   * otherwise requires the payload to name, as uuids, `mass_function_id`,
--     `claim_id`, `frame_id`, `owner_agent_id` and `assessed_by`, the row's
--     `actor_id` to equal `assessed_by`, and a `mass_functions` row with that
--     id, claim, frame and `source_agent_id = owner_agent_id` whose `xmin` is
--     THIS transaction: the slot write the record describes must have been
--     made in the same transaction, which is exactly what the assess route
--     does (slot upsert and record in one `slot_tx`; the upsert's
--     ON CONFLICT DO UPDATE writes a new row version, so a replacement counts).
--     Anything else is refused with 42501, never 22P02.
--
-- WHY A VALIDATING TRIGGER, NOT A DEFINER THE ROUTE CALLS. The fix sketch
-- named "the assess path's definer". A definer the application role may call
-- with a caller-built payload would admit the same forgery the table did; what
-- closes it is the binding to the slot row written in the same transaction,
-- and a trigger enforces that on every path, the shipped route included. It
-- also needs no binary change: the shipped route already writes the record
-- this way, so the migration may be applied before or after the binary.
--
-- THE BODY. SECURITY DEFINER owned by `epigraph_maintenance` on 172's path
-- (`pg_catalog, pg_temp`, every public name qualified), so its read of
-- `mass_functions` is not filtered by row security (`epigraph_definer_bypass()`
-- admits the owner), and `epigraph_bypass()` still reads `session_user`, the
-- caller. EXECUTE revoked from PUBLIC (a trigger function is not checked at
-- fire time). The `xmin` comparison is against the top-level transaction id,
-- so the slot write must not be inside a SAVEPOINT; the route takes none.
--
-- RESIDUAL. A session that can write the slot row itself (row security admits
-- the owner's writers) can still record a false `assessed_by` for its own
-- write: the database binds the record to a write, not to an identity it
-- cannot authenticate (the tenancy GUCs are session-settable). Rows written
-- before this migration are not checked: a `claim.assessed` row older than the
-- reservation may have been filed by a caller. Classifying them is an
-- operator data-repair step (README entry for 250 has the query); this file
-- changes no row.
--
-- DEPLOY ORDER for section 2: none against the binaries.
--
-- UNDO: docs/runbooks/250-undo.sql (both sections).
-- Checked before claiming: slot 250 was assigned to this batch; no origin
-- branch carries a `250`.

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_prunable_event_types()
RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT ARRAY['tool.invoked']::text[]
$$;

CREATE OR REPLACE FUNCTION public.epigraph_prune_telemetry_events(p_retention_days integer)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    IF p_retention_days IS NULL THEN
        RAISE EXCEPTION 'epigraph_prune_telemetry_events: retention_days is required'
            USING ERRCODE = '22004';
    END IF;
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'epigraph_prune_telemetry_events: a maintenance session only'
            USING ERRCODE = '42501';
    END IF;
    DELETE FROM public.events e
     WHERE e.event_type = ANY (public.epigraph_prunable_event_types())
       AND e.created_at < pg_catalog.now()
             - pg_catalog.make_interval(days => GREATEST(p_retention_days, 1));
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_prune_telemetry_events(integer) FROM PUBLIC;

DO $$
DECLARE
    events_owner name;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(c.relowner) INTO events_owner
      FROM pg_catalog.pg_class c
     WHERE c.oid = 'public.events'::regclass;
    EXECUTE format('ALTER FUNCTION public.epigraph_prune_telemetry_events(integer) OWNER TO %I',
                   events_owner);

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        IF events_owner = 'epigraph_maintenance'
           OR (NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = events_owner)
               AND pg_catalog.pg_has_role(events_owner, 'epigraph_maintenance', 'MEMBER')) THEN
            RAISE EXCEPTION 'migration 250: the owner of public.events (%) is, or is a member '
                            'of, epigraph_maintenance, so the prune definer would leave every '
                            'maintenance login its DELETE on events', events_owner
                USING ERRCODE = '42501';
        END IF;
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_prune_telemetry_events(integer) '
                'TO epigraph_maintenance';
        EXECUTE 'REVOKE DELETE, UPDATE, TRUNCATE ON public.events FROM epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- Section 2: the `claim.assessed` guard.
-- ===================================================================

CREATE OR REPLACE FUNCTION public.epigraph_events_assessment_guard()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_uuid constant text :=
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
    c_keys constant text[] :=
        ARRAY['mass_function_id', 'claim_id', 'frame_id', 'owner_agent_id', 'assessed_by'];
    k text;
    v_mf uuid;
    v_by uuid;
    v_found boolean;
BEGIN
    IF pg_catalog.lower(pg_catalog.regexp_replace(NEW.event_type,
                                                  '^[[:space:]]+|[[:space:]]+$', '', 'g'))
       IS DISTINCT FROM 'claim.assessed' THEN
        RETURN NEW;
    END IF;
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    IF NEW.event_type <> 'claim.assessed' THEN
        RAISE EXCEPTION 'event type % is a spelling of the reserved claim.assessed', NEW.event_type
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.jsonb_typeof(NEW.payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'claim.assessed is reserved for the assess path: no payload object'
            USING ERRCODE = '42501';
    END IF;
    FOREACH k IN ARRAY c_keys LOOP
        IF NOT COALESCE((NEW.payload ->> k) ~ c_uuid, false) THEN
            RAISE EXCEPTION 'claim.assessed is reserved for the assess path: payload % is not a uuid', k
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
    v_mf := (NEW.payload ->> 'mass_function_id')::uuid;
    v_by := (NEW.payload ->> 'assessed_by')::uuid;
    IF NEW.actor_id IS DISTINCT FROM v_by THEN
        RAISE EXCEPTION 'claim.assessed is reserved for the assess path: actor_id is not assessed_by'
            USING ERRCODE = '42501';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM public.mass_functions mf
         WHERE mf.id = v_mf
           AND mf.claim_id = (NEW.payload ->> 'claim_id')::uuid
           AND mf.frame_id = (NEW.payload ->> 'frame_id')::uuid
           AND mf.source_agent_id = (NEW.payload ->> 'owner_agent_id')::uuid
           AND mf.xmin::text
               = (pg_catalog.pg_current_xact_id()::text::numeric % 4294967296)::text
    ) INTO v_found;
    IF NOT v_found THEN
        RAISE EXCEPTION 'claim.assessed is reserved for the assess path: mass function % was not '
                        'written for this claim, frame and owner in this transaction', v_mf
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_events_assessment_guard() FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_events_assessment_guard() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

DROP TRIGGER IF EXISTS events_assessment_guard ON public.events;
CREATE TRIGGER events_assessment_guard
    BEFORE INSERT OR UPDATE ON public.events
    FOR EACH ROW
    WHEN (pg_catalog.strpos(pg_catalog.lower(NEW.event_type), 'claim.assessed') > 0)
    EXECUTE FUNCTION public.epigraph_events_assessment_guard();

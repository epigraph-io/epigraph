-- Migration 250: `events` guards. The maintenance role prunes telemetry only
-- through a type-restricted definer and loses its table-wide DELETE and UPDATE
-- on `events` (section 1, backlog 062d7767).
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
-- UNDO: docs/runbooks/250-undo.sql.
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

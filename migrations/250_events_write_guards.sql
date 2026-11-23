-- Migration 250: two `events` write guards, both on the provenance record.
--   1. The maintenance role prunes telemetry only through a type-restricted
--      definer and loses its table-wide DELETE and UPDATE on `events`
--      (backlog 062d7767).
--   2. A `claim.assessed` row is refused unless it records a write of a slot
--      row's masses made in the same transaction, or comes from a maintenance
--      session (backlog a278f16d).
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
-- WHAT IT DOES.
--   * `mass_function_masses_writes (mass_function_id, written_xact xid8)`: per
--     mass function, the top-level transaction that last wrote its masses.
--     Written only by the SECURITY DEFINER trigger function
--     `epigraph_mass_function_masses_written()`, which two AFTER row triggers
--     on `mass_functions` run: `mass_functions_masses_written_ins` on every
--     INSERT and `mass_functions_masses_written_upd` on an UPDATE `WHEN
--     (OLD.masses IS DISTINCT FROM NEW.masses)` (jsonb equality). It upserts
--     `pg_current_xact_id()` for the row. The application role holds no
--     privilege on the table (SELECT included), so no caller sets a stamp;
--     the maintenance role holds SELECT / INSERT / UPDATE (the two definers
--     it owns need them). No FK and no row per existing mass function: a
--     missing row matches no transaction, a stale row (its mass function
--     deleted) names a transaction that is over, and xid8 values are never
--     reused, so neither can match a later transaction.
--   * `epigraph_event_type_norm(text)`: the type as `is_reserved_type` reads
--     it: Unicode whitespace trimmed at both ends (the White_Space set Rust's
--     `str::trim` strips, NBSP and the U+2000 block included), lower-cased.
--     IMMUTABLE; the guard and the README's classification query both use it.
--   * The BEFORE INSERT OR UPDATE row trigger `events_assessment_guard` on
--     `events` runs `epigraph_events_assessment_guard()` for any row whose
--     lower-cased type contains `claim.assessed` (its WHEN clause, so every
--     other event pays nothing beyond that test). The body:
--       - admits a row whose normalised type is not exactly `claim.assessed`
--         (e.g. `claim.assessed.v2` is another type);
--       - admits any session `epigraph_bypass()` admits (maintenance logins,
--         the migration / superuser DSN): repair and backfill stay possible;
--       - refuses (42501) any spelling other than the exact `claim.assessed`
--         (padded, Unicode-padded or re-cased), as the API layer does;
--       - otherwise requires the payload to name, as uuids,
--         `mass_function_id`, `claim_id`, `frame_id`, `owner_agent_id` and
--         `assessed_by`, the row's `actor_id` to equal `assessed_by`, a
--         `mass_functions` row with that id, claim, frame and
--         `source_agent_id = owner_agent_id`, and a `mass_function_masses_writes`
--         row for it whose `written_xact` EQUALS `pg_current_xact_id()` (xid8
--         equality): this transaction wrote that row's masses. That is exactly
--         what the assess route does (slot upsert and record in one `slot_tx`).
--     Anything else is refused with 42501, never 22P02.
--
-- WHY xid8, AND WHY ONLY A MASSES WRITE COUNTS, NOT `xmin`. An earlier draft
-- compared `mf.xmin` with the current xid modulo 2^32. `xmin` is the raw
-- 32-bit xid (freezing keeps it), so after an epoch wrap an OLD row whose
-- xmin equals the current xid modulo 2^32 would satisfy the bind; and a row
-- written under a SAVEPOINT carries the subtransaction's xid, so a genuine
-- write there was refused. `pg_current_xact_id()` is the 64-bit, epoch-aware
-- id of the TOP-level transaction, also inside a subtransaction (a write
-- rolled back to its savepoint takes its stamp with it). And `xmin` changes
-- on ANY update: a stranger's stamped session (the tenancy GUCs are
-- session-settable, so an application-DSN holder can stamp itself into the
-- row's writable group) could run `UPDATE mass_functions SET masses = masses`
-- on someone else's row and then file a record naming it. The stamp moves
-- only when the masses change, so a no-op or tenancy-only update (unretract,
-- the 114/115 BBA moves, the reown sweep) credits no one. A transaction-local
-- GUC marker was rejected (the attacker's session can set it), as was a write
-- counter bumped by every upsert (the trigger cannot tell the route's upsert
-- from the stranger's no-op one).
--
-- WHY A SIDE TABLE, NOT A COLUMN ON `mass_functions`. A stamp column would
-- change every `mass_functions` row image (`to_jsonb(mf.*)`), which the
-- restore tools store and compare byte for byte: the K10 sweep's undo
-- re-inserts a row from its image and its re-run probe reads "already
-- restored" only when the live row equals the image, so a restored row whose
-- stamp is the restore's transaction would read as superseded. The side
-- table keeps the row shape, and "no caller sets the stamp" is a privilege
-- (no grant), not a trigger that overrides what a statement supplied.
--
-- RE-ASSESSING IDENTICAL MASSES. A call whose upsert writes exactly the masses
-- the slot already holds changes no masses, so its record would be refused.
-- The route (`assess_claim`) therefore asks, under the slot lock and before
-- the upsert, whether the slot already holds those masses
-- (`MassFunctionRepository::slot_holds_masses`, which locks the row), and
-- files no record when it does: the slot's writer record stays the one that
-- wrote those masses.
--
-- WHY A VALIDATING TRIGGER, NOT A DEFINER THE ROUTE CALLS. The fix sketch
-- named "the assess path's definer". A definer the application role may call
-- with a caller-built payload would admit the same forgery the table did; what
-- closes it is the binding to the masses written in the same transaction, and
-- a trigger enforces that on every path, the shipped route included.
--
-- THE BODIES. Both SECURITY DEFINER, owned by `epigraph_maintenance` (as 194's
-- purge-grant definers are), on 172's path (`pg_catalog, pg_temp`, every
-- public name qualified), so the guard's read of `mass_functions` is not
-- filtered by row security (`epigraph_definer_bypass()` admits the owner),
-- and `epigraph_bypass()` still reads `session_user`, the caller. EXECUTE
-- revoked from PUBLIC (a trigger function is not checked at fire time).
--
-- EVERY WRITER OF `mass_functions.masses`, RE-ENUMERATED (crates/*/src and
-- every migration function body), each stamped as a write of the masses:
--   * INSERT: the slot upsert (`MassFunctionRepository::store_with_perspective`,
--     whose ON CONFLICT DO UPDATE is stamped only when the masses differ),
--     plain inserts (dekg and the other ingestion paths), the K10 sweep's
--     undo (`k10_retro::RESTORE_ROW_SQL`) and the dedup revert's restore
--     (`ClaimRepository`, `jsonb_populate_recordset`), both re-inserting a
--     deleted row by id on the maintenance connection;
--   * UPDATE: `edge_rewire::restore_edge_rows` (a compare-and-swap that puts
--     a rewired edge factor's masses back), on its operator connection.
--   No migration-defined function sets `masses`; the other UPDATE writers
--   (114/115 BBA moves, 184 retract / unretract, the dedup repair's moves,
--   `backfill_evidence_type`, backfill_factors) change tenancy or bookkeeping
--   columns only and are not stamped. None of the restore paths files a
--   `claim.assessed` record, so being stamped changes nothing for them.
--
-- RESIDUAL. The database binds the record to a write of the masses, not to an
-- identity it cannot authenticate: because the tenancy GUCs are
-- session-settable, any application-DSN holder can genuinely rewrite a slot
-- row's masses (or write them away and back in one transaction) and then
-- holds a TRUE record of that write, naming itself or any `assessed_by` equal
-- to its `actor_id`. Closing that needs an unforgeable session identity, not
-- an events guard. Each masses write now costs one upsert into the side
-- table; the side table keeps one row per mass function ever written after
-- this migration (rows of deleted mass functions are not removed). Rows of
-- `events` written before this migration are not checked: a `claim.assessed`
-- row older than the reservation may have been filed by a caller. Classifying
-- them is an operator data-repair step (README entry for 250 has the
-- procedure); this file changes no `events` row.
--
-- DEPLOY ORDER for section 2 (one way): deploy the binary whose
-- `assess_claim` skips the record for identical masses BEFORE or WITH this
-- migration. That binary runs on either side of it (its check is a plain
-- jsonb comparison). The shipped binary on top of this migration answers 500
-- to a re-assessment with identical masses (its slot transaction rolls back;
-- no data changes); every other call works.
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

-- The type as `EventRepository::is_reserved_type` reads it: the White_Space
-- characters Rust's `str::trim` strips (U+0009..U+000D, U+0020, U+0085,
-- U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F, U+205F, U+3000),
-- trimmed at both ends, then lower-cased.
CREATE OR REPLACE FUNCTION public.epigraph_event_type_norm(p_type text)
RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.lower(pg_catalog.regexp_replace(
        p_type,
        '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+'
        '|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$',
        '', 'g'))
$$;

CREATE TABLE IF NOT EXISTS public.mass_function_masses_writes (
    mass_function_id uuid PRIMARY KEY,
    written_xact     xid8 NOT NULL
);
COMMENT ON TABLE public.mass_function_masses_writes IS
    'Migration 250 (backlog a278f16d): per mass_functions id, the top-level transaction (xid8) '
    'that last wrote its masses. Written only by epigraph_mass_function_masses_written (AFTER '
    'INSERT, and AFTER UPDATE when masses change); read by epigraph_events_assessment_guard. '
    'The application role holds no privilege on it.';

REVOKE ALL ON public.mass_function_masses_writes FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.mass_function_masses_writes FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.mass_function_masses_writes '
                'TO epigraph_maintenance';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_mass_function_masses_written()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.mass_function_masses_writes AS w (mass_function_id, written_xact)
    VALUES (NEW.id, pg_catalog.pg_current_xact_id())
    ON CONFLICT (mass_function_id) DO UPDATE
       SET written_xact = EXCLUDED.written_xact
     WHERE w.written_xact IS DISTINCT FROM EXCLUDED.written_xact;
    RETURN NULL;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_mass_function_masses_written() FROM PUBLIC;

DROP TRIGGER IF EXISTS mass_functions_masses_written_ins ON public.mass_functions;
CREATE TRIGGER mass_functions_masses_written_ins
    AFTER INSERT ON public.mass_functions
    FOR EACH ROW
    EXECUTE FUNCTION public.epigraph_mass_function_masses_written();

DROP TRIGGER IF EXISTS mass_functions_masses_written_upd ON public.mass_functions;
CREATE TRIGGER mass_functions_masses_written_upd
    AFTER UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.masses IS DISTINCT FROM NEW.masses)
    EXECUTE FUNCTION public.epigraph_mass_function_masses_written();

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
    IF public.epigraph_event_type_norm(NEW.event_type) IS DISTINCT FROM 'claim.assessed' THEN
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
           AND EXISTS (SELECT 1 FROM public.mass_function_masses_writes w
                        WHERE w.mass_function_id = mf.id
                          AND w.written_xact = pg_catalog.pg_current_xact_id())
    ) INTO v_found;
    IF NOT v_found THEN
        RAISE EXCEPTION 'claim.assessed is reserved for the assess path: this transaction wrote '
                        'no masses of mass function % for this claim, frame and owner', v_mf
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_events_assessment_guard() FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_events_assessment_guard() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_mass_function_masses_written() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

DROP TRIGGER IF EXISTS events_assessment_guard ON public.events;
CREATE TRIGGER events_assessment_guard
    BEFORE INSERT OR UPDATE ON public.events
    FOR EACH ROW
    WHEN (pg_catalog.strpos(pg_catalog.lower(NEW.event_type), 'claim.assessed') > 0)
    EXECUTE FUNCTION public.epigraph_events_assessment_guard();

-- Migration 189: `events` is append-only for the application role (backlog
-- 796c55aa). `epigraph_app` loses UPDATE, DELETE and TRUNCATE on
-- `public.events`; it keeps SELECT and INSERT.
--
-- WHY. `events` has no row security, and the application role held every
-- table privilege on it (README: SELECT / INSERT / UPDATE / DELETE on all
-- tables), allowlisted as OPERATIONAL in
-- `app_role_table_lockdown.rs::ALLOWLIST`. So any session on the application
-- role could delete or rewrite provenance events (`claim.created`,
-- `edge.added`, ...), not only telemetry. Each delete also fires 024's
-- `events_cascade_edges` (001's SECURITY INVOKER `cascade_delete_edges`),
-- which deletes the edges naming the event in the same statement. Events are
-- an append-only record; nothing on the request path changes or removes one.
--
-- EVERY WRITER, ENUMERATED (crates/*/src at the base, plus scripts/ and the
-- sibling repositories that share the database: none writes `events` there):
--   * INSERT: `EventRepository::insert` and `::publish_or_log_conn` (the event
--     bus, best-effort publishes). Kept. The sequence `events_graph_version_seq`
--     is untouched.
--   * DELETE: `RecallEventRepository::prune_telemetry_events`, called only by
--     `prune_recall_events` on `epigraph_cli::MaintenancePool` (a maintenance
--     login; it refuses an application session). Unaffected by this file. Its
--     maintenance DELETE is a separate grant (open PR #729, migration 186);
--     this file neither depends on nor duplicates it.
--   * UPDATE: `AgentRepository::delete` detaches `events.actor_id` before
--     deleting an agent. `agents` has row security and no DELETE policy, so on
--     the application role that call already deleted nothing; it now fails at
--     the detach with 42501 instead. Its only callers are privileged test
--     fixtures. No statement on the app path reads `events` FOR UPDATE / FOR
--     SHARE or upserts it with ON CONFLICT DO UPDATE.
--   * No migration-defined function or trigger writes `events`.
--
-- WHAT IS UNCHANGED. Row security (still none on `events`); the maintenance
-- role's grants (070: SELECT / INSERT / UPDATE); the triggers
-- (`events_cascade_edges`, 166's `role_agent_write_check`); and the
-- `events_actor_id_fkey` referential check, which runs as the table owner.
-- No column-level grant on `events` exists, so the table-level REVOKE leaves
-- the application role no UPDATE path.
--
-- DEPLOY ORDER: none against other migrations or the binaries. No shipped
-- request-path statement needs the revoked privileges. Independent of 186
-- (either order, with or without it).
--
-- UNDO:
--   GRANT UPDATE, DELETE, TRUNCATE ON public.events TO epigraph_app;
--   (and re-add ("events", OPERATIONAL) to app_role_table_lockdown.rs.)
-- Checked before claiming: no `origin/main` migration, open PR or origin
-- branch carries a `189`.

SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.events FROM epigraph_app';
    END IF;
END $$;

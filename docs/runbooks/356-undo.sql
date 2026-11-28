-- ===================================================================
-- 356-undo.sql: take migration 356 (the declared agent scopes record, its
-- arming flag and its two maintenance verbs) back out, in ONE transaction, on
-- the migration (superuser) DSN.
--
-- READ FIRST: no binary and no write door reads anything 356 adds, so nothing
-- needs rolling back first. A later migration that reads `agent_scopes` or
-- `agent_scope_arming` (an enforcing door) must be undone BEFORE this.
-- Undoing 356 DISCARDS every declared scope row; `security_events` keeps the
-- `platform.agent_scope_granted` / `platform.agent_scope_revoked` rows (it is
-- immutable, 082), which are the record of what was declared. Export the
-- table first if the rows are to be re-granted after a re-apply:
--   \copy (SELECT * FROM agent_scopes) TO 'agent_scopes.csv' CSV HEADER
--
-- WHAT IT DOES: drops both tables (their triggers, policies and indexes go
-- with them), then the four functions.
--
-- WHAT IT LEAVES: 356's `_sqlx_migrations` row; delete it as well if 356 is
-- to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 356;
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TABLE IF EXISTS public.agent_scopes;
DROP TABLE IF EXISTS public.agent_scope_arming;

DROP FUNCTION IF EXISTS public.epigraph_agent_scope_grant(
    uuid, uuid, text, text, timestamptz, timestamptz, uuid);
DROP FUNCTION IF EXISTS public.epigraph_agent_scope_revoke(uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_agent_scopes_audit();
DROP FUNCTION IF EXISTS public.epigraph_agent_scopes_guard();

COMMIT;

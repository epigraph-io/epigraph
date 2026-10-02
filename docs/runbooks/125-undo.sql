-- ===================================================================
-- 125-undo.sql: take migration 125 (elevation tickets, elevation sessions,
-- `epigraph_is_elevated()`) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Roll back every binary that calls a 125 function BEFORE this
-- runs (docs/deploy.md): any epigraph-api that serves the elevation ceremony
-- or the elevate grant, and every binary that stamps the elevation GUCs or
-- resolves an elevated viewer. A row policy that reads
-- `epigraph_is_elevated()` (a later migration) must be undone first: this
-- script refuses while any policy still names it.
--
-- WHAT IT DOES
--   1. Refuses if a policy still reads `epigraph_is_elevated()`; lists (NOTICE)
--      how many tickets and sessions it drops, live sessions included.
--   2. Drops the three end triggers on 123's / 122's / 118's tables (their
--      tables stay exactly as those migrations left them), both tables, and
--      every 125 function.
--
-- WHAT IT LEAVES: the `platform.elevat*` rows in `security_events` (history),
-- and 125's `_sqlx_migrations` row. Re-introducing elevation is a NEW
-- migration, never a re-run of 125.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_policies bigint := 0;
    v_tickets  bigint := 0;
    v_sessions bigint := 0;
    v_live     bigint := 0;
BEGIN
    SELECT count(*) INTO v_policies FROM pg_policies
     WHERE coalesce(qual, '') || coalesce(with_check, '') LIKE '%epigraph_is_elevated%';
    IF v_policies > 0 THEN
        RAISE EXCEPTION '125-undo: % row polic(y/ies) still read epigraph_is_elevated(); undo '
                        'the elevated read arms first', v_policies;
    END IF;
    IF to_regclass('public.elevation_sessions') IS NOT NULL THEN
        SELECT count(*), count(*) FILTER (WHERE ended_at IS NULL AND now() < expires_at)
          INTO v_sessions, v_live FROM public.elevation_sessions;
    END IF;
    IF to_regclass('public.elevation_tickets') IS NOT NULL THEN
        SELECT count(*) INTO v_tickets FROM public.elevation_tickets;
    END IF;
    RAISE NOTICE '125-undo: dropping % ticket(s) and % session(s) (% live)',
                 v_tickets, v_sessions, v_live;
END $$;

DROP TRIGGER IF EXISTS role_assignments_end_elevations ON public.role_assignments;
DROP TRIGGER IF EXISTS human_operators_end_elevations ON public.human_operators;
DROP TRIGGER IF EXISTS refresh_tokens_end_elevations ON public.refresh_tokens;

-- The tables reference each other; both go in one statement.
DROP TABLE IF EXISTS public.elevation_sessions, public.elevation_tickets;

DROP FUNCTION IF EXISTS public.epigraph_is_elevated();
DROP FUNCTION IF EXISTS public.epigraph_end_elevation(uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_elevation_live(uuid, uuid);
DROP FUNCTION IF EXISTS public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid);
DROP FUNCTION IF EXISTS public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_ticket(uuid);
DROP FUNCTION IF EXISTS public.epigraph_set_elevation_ticket_challenge(uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_ticket_for_ceremony(uuid);
DROP FUNCTION IF EXISTS public.epigraph_create_elevation_ticket(uuid, uuid, text, text, bytea);
DROP FUNCTION IF EXISTS public.epigraph_end_expired_elevations(uuid, uuid);
DROP FUNCTION IF EXISTS public.epigraph_end_elevations_on_family_reuse();
DROP FUNCTION IF EXISTS public.epigraph_end_elevations_on_operator_revoke();
DROP FUNCTION IF EXISTS public.epigraph_end_elevations_on_assignment_revoke();
DROP FUNCTION IF EXISTS public.epigraph_elevation_sessions_audit();
DROP FUNCTION IF EXISTS public.epigraph_elevation_tickets_audit();
DROP FUNCTION IF EXISTS public.epigraph_elevation_sessions_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_elevation_sessions_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_elevation_tickets_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_elevation_tickets_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_family_of_person_is_live(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.epigraph_live_elevating_assignment(uuid, timestamptz);

COMMIT;

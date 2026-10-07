-- ===================================================================
-- 124-undo.sql: take migration 124 (a registered human's passkeys and their
-- enrollment tickets) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Roll back every binary that calls a 124 function BEFORE this
-- runs (docs/deploy.md, "Passkeys (migration 124)"): epigraph-operator
-- (passkey-enroll, list-passkeys, revoke-passkey), any epigraph-api that
-- serves the enrollment ceremony, and epigraph-tenancy-backfill (its verify
-- lists the 124 definers; presence-gated, so an older verify is fine). A new
-- binary left serving after this script fails every such call with 42883 or
-- 42P01.
--
-- WHAT IT DOES
--   1. Lists, for the operator (NOTICE), how many passkeys and enrollment
--      tickets it is about to DROP, live ones included. Nothing else in the
--      schema references either table yet, so this is the whole of their
--      data; a human whose passkey is dropped enrolls again after a re-apply.
--   2. Drops both tables (their triggers and policies with them) and every
--      124 function.
--
-- WHAT IT LEAVES: the `platform.passkey_*` rows in `security_events`
-- (history; that table is append-only on every role), and 124's
-- `_sqlx_migrations` row. Re-introducing passkeys is a NEW migration, never a
-- re-run of 124.
--
-- `person_authenticators.rs::the_rollback_returns_the_catalog_to_123` pins
-- that a database taken 123 -> 124 -> this script has 123's catalog.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- 1. What is about to go.
DO $$
DECLARE
    v_keys    bigint := 0;
    v_live    bigint := 0;
    v_tickets bigint := 0;
BEGIN
    IF to_regclass('public.person_authenticators') IS NOT NULL THEN
        SELECT count(*), count(*) FILTER (WHERE revoked_at IS NULL)
          INTO v_keys, v_live FROM public.person_authenticators;
    END IF;
    IF to_regclass('public.passkey_enrollments') IS NOT NULL THEN
        SELECT count(*) INTO v_tickets FROM public.passkey_enrollments;
    END IF;
    RAISE NOTICE '124-undo: dropping % passkey(s) (% live) and % enrollment ticket(s)',
                 v_keys, v_live, v_tickets;
END $$;

-- 2. The tables (each carries its own triggers and policies), then the
--    functions. The two tables reference each other, so both go in one
--    statement.
DROP TABLE IF EXISTS public.person_authenticators, public.passkey_enrollments;

DROP FUNCTION IF EXISTS public.epigraph_create_passkey_enrollment(uuid, text, text);
DROP FUNCTION IF EXISTS public.epigraph_enrollment_for_ceremony(uuid);
DROP FUNCTION IF EXISTS public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_complete_passkey_enrollment(
    uuid, bytea, jsonb, uuid, text, boolean, boolean);
DROP FUNCTION IF EXISTS public.epigraph_revoke_passkey(uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_passkey_enrollments_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_passkey_enrollments_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_passkey_enrollments_audit();
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_audit();

COMMIT;

-- ===================================================================
-- VERIFY. Expect 0 rows from each.
--
--   SELECT relname FROM pg_class
--    WHERE relnamespace = 'public'::regnamespace
--      AND relname IN ('person_authenticators', 'passkey_enrollments');
--   SELECT proname FROM pg_proc
--    WHERE pronamespace = 'public'::regnamespace
--      AND (proname LIKE '%passkey%' OR proname LIKE '%person_authenticators%'
--           OR proname = 'epigraph_enrollment_for_ceremony');
-- ===================================================================

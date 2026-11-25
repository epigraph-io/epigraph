-- ===================================================================
-- 312-undo.sql: take migration 312 (an agent client's owner is named at
-- approval) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: roll the API back to a build WITHOUT 312 before running this.
-- A binary built with 312 registers an agent client with no owner, which
-- 001's CHECK (restored here) refuses: every agent registration would be a
-- 500. The operator CLI of 312 calls the four-argument approval (42883 once
-- it is gone).
--
-- WHAT IT DOES: drops the four-argument
-- `epigraph_oauth_client_approve(uuid, text[], uuid, uuid)` and restores
-- 001's `agents_must_have_owner` (every agent client has an owner, whatever
-- its status).
--
-- REFUSES (55000, nothing changed) while any agent client has no owner (the
-- rows 312's registration wrote and nobody approved): 001's CHECK cannot be
-- restored over them. List them with
--   SELECT id, client_id, client_name, status, created_at FROM oauth_clients
--    WHERE client_type = 'agent' AND owner_id IS NULL;
-- and give each an owner first (or delete one that was never approved: a
-- pending client never held a token). Revoking does not help: 001's CHECK
-- holds for every status.
--
-- WHAT IT LEAVES: every owner 312's approval wrote, and every
-- `oauth.client_approved` row (`security_events` is append-only). 118's
-- three-argument approval was never changed by 312 and is untouched. 312's
-- `_sqlx_migrations` row stays; delete it as well if 312 is to be re-applied
-- by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 312;
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_n bigint;
BEGIN
    SELECT count(*) INTO v_n FROM public.oauth_clients
     WHERE client_type = 'agent' AND owner_id IS NULL;
    IF v_n > 0 THEN
        RAISE EXCEPTION '312-undo: % agent client(s) have no owner; 001''s CHECK cannot be '
                        'restored over them. Nothing was changed', v_n
            USING ERRCODE = '55000',
                  HINT = 'Give each an owner (or delete a never-approved one), then run this again.';
    END IF;
END $$;

DROP FUNCTION IF EXISTS public.epigraph_oauth_client_approve(uuid, text[], uuid, uuid);

ALTER TABLE public.oauth_clients DROP CONSTRAINT IF EXISTS agents_must_have_owner;
ALTER TABLE public.oauth_clients ADD CONSTRAINT agents_must_have_owner
    CHECK (((client_type)::text <> 'agent'::text) OR (owner_id IS NOT NULL));

COMMIT;

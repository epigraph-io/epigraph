-- ===================================================================
-- 348-undo.sql: take migration 348 (an agent client's owner is named at
-- approval) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: roll the API back to a build WITHOUT 348 before running this.
-- A binary built with 348 registers an agent client with no owner, which
-- 001's CHECK (restored here) refuses: every agent registration would be a
-- 500. The operator CLI of 348 calls the four-argument approval (42883 once
-- it is gone).
--
-- WHAT IT DOES: drops the four-argument
-- `epigraph_oauth_client_approve(uuid, text[], uuid, uuid)` and restores
-- 001's `agents_must_have_owner` (every agent client has an owner, whatever
-- its status).
--
-- REFUSES (55000, nothing changed) while any agent client has no owner (the
-- rows 348's registration wrote and nobody approved, and the pending rows
-- 348 itself cleared): 001's CHECK cannot be restored over them. A cleared
-- row's previous owner is in its 348 security event:
--   SELECT details->>'oauth_client_id', details->>'previous_owner_id'
--     FROM security_events WHERE event_type = 'oauth.client_owner_cleared';
-- List the ownerless rows with
--   SELECT id, client_id, client_name, status, created_at FROM oauth_clients
--    WHERE client_type = 'agent' AND owner_id IS NULL;
-- and give each an owner first (or delete one that was never approved: a
-- pending client never held a token). Revoking does not help: 001's CHECK
-- holds for every status.
--
-- WHAT IT LEAVES: every owner 348's approval wrote, and every
-- `oauth.client_approved` row (`security_events` is append-only). 118's
-- three-argument approval was never changed by 348 and is untouched. 348's
-- `_sqlx_migrations` row stays; delete it as well if 348 is to be re-applied
-- by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 348;
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
        RAISE EXCEPTION '348-undo: % agent client(s) have no owner; 001''s CHECK cannot be '
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

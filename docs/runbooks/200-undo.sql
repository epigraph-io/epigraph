-- ===================================================================
-- 200-undo.sql: take migration 200 (the anchored passkey path's reader, the
-- act-confirmer insert guard and the anchored-revoke cascade) back out, in
-- ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Turn `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY` off (or
-- roll back to a binary without it) on every API unit BEFORE this runs
-- (docs/deploy.md section 10); a unit left serving with it on answers every
-- enrollment challenge with an error (42883).
--
-- WHAT IT DOES: drops 200's two triggers, then its three functions.
--
-- WHAT IT LEAVES: every enrollment, act and passkey (no table is touched),
-- including a passkey registered on the anchored path, which stays live
-- (`epigraph-operator revoke-passkey` removes one; after this undo, revoking
-- its anchor no longer revokes it), and 200's `_sqlx_migrations` row.
-- Re-introducing them is a NEW migration, never a re-run of 200. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS person_authenticators_guard_insert_act_confirmer
    ON public.person_authenticators;
DROP TRIGGER IF EXISTS person_authenticators_revoke_anchored ON public.person_authenticators;
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_guard_act_confirmer();
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_revoke_anchored();
DROP FUNCTION IF EXISTS public.epigraph_enrollment_anchor(uuid);

COMMIT;

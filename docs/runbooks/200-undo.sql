-- ===================================================================
-- 200-undo.sql: take migration 200 (the anchored passkey path's reader, the
-- act-confirmer insert guard, the anchored-revoke cascade, the compromised
-- revoke and the revoke audit's `mode`) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST. Turn `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY` off (or
-- roll back to a binary without it) on every API unit BEFORE this runs
-- (docs/deploy.md section 10); a unit left serving with it on answers every
-- enrollment challenge with an error (42883). Roll back `epigraph-operator`
-- to a build without `revoke-passkey --compromised` (it would get 42883).
--
-- WHAT IT DOES: drops 200's two triggers, then its four functions, and
-- restores 124's body of `epigraph_person_authenticators_audit()` (revoke
-- audit rows written from then on carry no `mode`; rows written before keep
-- theirs). Owner and grants of the audit function are unchanged by either.
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
DROP FUNCTION IF EXISTS public.epigraph_revoke_passkey_compromised(uuid, text);

-- 124's body, byte for byte (CREATE OR REPLACE keeps owner and grants).
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE public.passkey_enrollments
           SET consumed_at = now(), authenticator_id = NEW.id
         WHERE id = NEW.enrollment_id AND consumed_at IS NULL;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        IF v_rows <> 1 THEN
            RAISE EXCEPTION 'ELV04: enrollment % was not consumed by passkey %',
                            NEW.enrollment_id, NEW.id
                USING ERRCODE = 'ELV04';
        END IF;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.passkey_registered', NEW.person_agent_id, true,
                jsonb_build_object('authenticator_id', NEW.id, 'person', NEW.person_agent_id,
                                   'enrollment_id', NEW.enrollment_id,
                                   'credential_id', encode(NEW.credential_id, 'hex'),
                                   'aaguid', NEW.aaguid,
                                   'attestation_format', NEW.attestation_format,
                                   'user_verified', NEW.user_verified,
                                   'backup_eligible', NEW.backup_eligible,
                                   'label', NEW.label, 'recorded_by', session_user));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.passkey_revoked', NEW.person_agent_id, true,
                jsonb_build_object('authenticator_id', NEW.id, 'person', NEW.person_agent_id,
                                   'credential_id', encode(NEW.credential_id, 'hex'),
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoked_reason', NEW.revoked_reason));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_audit() FROM PUBLIC;

COMMIT;

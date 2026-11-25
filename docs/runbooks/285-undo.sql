-- ===================================================================
-- 285-undo.sql: take migration 285 (an anchored passkey's recorded anchor,
-- the ceremony readers' `anchor_authenticator_id`, and the standing-refusal
-- audit definer) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- READ FIRST: roll the API back to a build WITHOUT 285 before running this.
-- A binary built with 285 selects `anchor_authenticator_id` from
-- `epigraph_passkeys_for_ticket` / `epigraph_passkeys_for_act` (42703 once
-- it is gone: every elevation and admin-act assertion fails) and calls
-- `epigraph_record_passkey_standing_refusal` (42883).
--
-- WHAT IT DOES: drops 285's two triggers and their function, the audit
-- definer, and the column (with its foreign key and two CHECKs, so every
-- recorded anchor is lost), and restores 125's `epigraph_passkeys_for_ticket`
-- and 130's `epigraph_passkeys_for_act`, verbatim, with their owner and
-- grants.
--
-- WHAT IT LEAVES: every passkey row, and every `platform.passkey_standing_refused`
-- row already written (`security_events` is append-only). After it, an
-- anchored `none` passkey asserts again whatever its anchor's standing (the
-- defect 285 closed). 285's `_sqlx_migrations` row stays; delete it as well
-- if 285 is to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 285;
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS person_authenticators_record_anchor ON public.person_authenticators;
DROP TRIGGER IF EXISTS person_authenticators_keep_anchor ON public.person_authenticators;
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_anchor();
DROP FUNCTION IF EXISTS public.epigraph_record_passkey_standing_refusal(text, uuid, uuid, text,
                                                                       text);

-- 125's reader, verbatim.
DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_ticket(uuid);
CREATE FUNCTION public.epigraph_passkeys_for_ticket(p_ticket uuid)
RETURNS TABLE (authenticator_id uuid, credential_id bytea, passkey jsonb, sign_count bigint,
               backup_eligible boolean, attestation_format text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT a.id, a.credential_id, a.passkey, a.sign_count, a.backup_eligible,
           a.attestation_format
      FROM public.elevation_tickets t
      JOIN public.person_authenticators a ON a.person_agent_id = t.person_agent_id
     WHERE t.id = p_ticket
       AND t.outcome IS NULL
       AND now() < t.expires_at
       AND a.revoked_at IS NULL
     ORDER BY a.created_at, a.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid) FROM PUBLIC;

-- 130's reader, verbatim.
DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_act(uuid);
CREATE FUNCTION public.epigraph_passkeys_for_act(p_act uuid)
RETURNS TABLE (authenticator_id uuid, credential_id bytea, passkey jsonb, sign_count bigint,
               backup_eligible boolean, attestation_format text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT k.id, k.credential_id, k.passkey, k.sign_count, k.backup_eligible,
           k.attestation_format
      FROM public.pending_admin_acts a
      JOIN public.person_authenticators k ON k.person_agent_id = a.proposed_by
     WHERE a.id = p_act
       AND a.outcome IS NULL
       AND now() < a.expires_at
       AND k.revoked_at IS NULL
     ORDER BY k.created_at, k.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkeys_for_act(uuid) FROM PUBLIC;

ALTER TABLE public.person_authenticators DROP COLUMN IF EXISTS anchor_authenticator_id;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_ticket(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_act(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_passkeys_for_act(uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_passkeys_for_act(uuid) TO epigraph_app';
    END IF;
END $$;
COMMIT;

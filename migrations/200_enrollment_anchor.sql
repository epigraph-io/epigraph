-- 200: the anchored passkey path's reader. One application-callable SECURITY
-- DEFINER, `epigraph_enrollment_anchor(enrollment)`, returns what the API
-- needs to decide whether a LATER passkey may be registered without
-- attestation: the enrollment's `passkey.register` act and the passkey that
-- confirmed it.
--
-- ===================================================================
-- 1. WHY
--
-- A person's later passkey is enrolled on a confirmed `passkey.register`
-- admin act (130): `epigraph-operator passkey-enroll --act <id>` opens the
-- enrollment `created_via = 'confirmed_act'` with its `act_id`, and the act
-- records the passkey that confirmed it (`pending_admin_acts.authenticator_id`,
-- with the assertion's evidence and the ceremony state that holds the act's
-- nonce). Nothing new needs recording.
--
-- With `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY` on, the API may
-- register such a later passkey WITHOUT attestation (a synced passkey, a
-- password manager's) when the confirming passkey is the same person's, live
-- and hardware-attested. The enrollment page runs on the unauthenticated
-- request DSN, which reads none of these rows: `pending_admin_acts` and
-- `person_authenticators` admit only a privileged session or a definer frame,
-- and 130's act readers answer only while an act is LIVE (unasserted), which a
-- consumed act never is again. Hence this reader, keyed by the enrollment id
-- (the ceremony's capability), like 124's `epigraph_enrollment_for_ceremony`.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_enrollment_anchor(uuid)`: SECURITY DEFINER, STABLE, owned
-- by `epigraph_maintenance` (whose frame passes the tables' definer-bypass
-- policies), with 172's pinned path `pg_catalog, pg_temp` and every relation
-- and built-in schema-qualified. One row only for a LIVE enrollment
-- (unconsumed, unexpired) opened on an act (`created_via = 'confirmed_act'`)
-- whose confirming passkey exists; otherwise no row, and the API then runs the
-- attested ceremony as before. It decides nothing: the API's
-- `epigraph_passkey::Passkeys::check_anchor` requires the act to be a
-- confirmed `passkey.register` act, the passkey to be the enrollment person's,
-- live and hardware-attested, and RE-VERIFIES the recorded assertion against
-- the passkey's stored key and the act's own challenge (the database cannot
-- verify a signature, so a confirmation recorded with fabricated evidence
-- anchors nothing).
--
-- WHAT IT REVEALS, to a holder of the request DSN and a live enrollment id:
-- the act's kind, outcome, args digest, ceremony state and assertion
-- evidence, and the confirming passkey's id, credential id, stored
-- credential (a PUBLIC key), AAGUID, attestation format, backup-eligible flag
-- and whether it is revoked. Authentication records of the person the
-- enrollment registers a passkey for, no secret among them; it enumerates
-- nothing.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the enrollment
-- page) and `epigraph_maintenance`, role-guarded as every such block since
-- 060 is. REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- (`DEFERRED_DEFINER_FUNCTIONS` at 200, and its grant register): under a
-- non-bypassing owner its reads are row-security filtered and it answers no
-- row, silently, so every anchored enrollment would fall back to the attested
-- ceremony.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary that reads it serves with the anchored setting on:
-- without it every enrollment challenge errors (42883) once the setting is on.
-- With the setting off (the default) no binary calls it.
--
-- UNDO: `docs/runbooks/200-undo.sql`, only after rolling back every binary
-- that calls the function or turning the setting off.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_enrollment_anchor(p_enrollment uuid)
RETURNS TABLE (act_id uuid, act_kind text, act_outcome text, args_digest bytea,
               act_challenge_state jsonb, assertion_evidence jsonb,
               enrollment_person uuid, anchor_id uuid, anchor_person uuid,
               anchor_credential_id bytea, anchor_passkey jsonb, anchor_aaguid uuid,
               anchor_attestation_format text, anchor_backup_eligible boolean,
               anchor_revoked boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.id, a.kind, a.outcome, a.args_digest, a.challenge_state, a.assertion_evidence,
           en.person_agent_id, k.id, k.person_agent_id, k.credential_id, k.passkey, k.aaguid,
           k.attestation_format, k.backup_eligible, k.revoked_at IS NOT NULL
      FROM public.passkey_enrollments en
      JOIN public.pending_admin_acts a ON a.id = en.act_id
      JOIN public.person_authenticators k ON k.id = a.authenticator_id
     WHERE en.id = p_enrollment
       AND en.created_via = 'confirmed_act'
       AND en.consumed_at IS NULL
       AND pg_catalog.now() < en.expires_at
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

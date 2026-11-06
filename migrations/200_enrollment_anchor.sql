-- 200: the anchored passkey path. One application-callable SECURITY DEFINER
-- reader, `epigraph_enrollment_anchor(enrollment)`, returns what the API needs
-- to decide whether a LATER passkey may be registered without attestation (the
-- enrollment's `passkey.register` act, the passkey that confirmed it, and that
-- passkey's lineage); two triggers on `person_authenticators` keep the
-- decision true while the passkey is recorded and afterwards.
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
-- and hardware-attested under the API's CURRENT configuration, and so is
-- every passkey that authorized it. The enrollment page runs on the
-- unauthenticated request DSN, which reads none of these rows:
-- `pending_admin_acts` and `person_authenticators` admit only a privileged
-- session or a definer frame, and 130's act readers answer only while an act
-- is LIVE (unasserted), which a consumed act never is again. Hence this
-- reader, keyed by the enrollment id (the ceremony's capability), like 124's
-- `epigraph_enrollment_for_ceremony`.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- (a) `public.epigraph_enrollment_anchor(uuid)`: SECURITY DEFINER, STABLE,
-- owned by `epigraph_maintenance` (whose frame passes the tables'
-- definer-bypass policies), with 172's pinned path `pg_catalog, pg_temp` and
-- every relation and built-in schema-qualified. One row only for a LIVE
-- enrollment (unconsumed, unexpired) opened on an act (`created_via =
-- 'confirmed_act'`) whose confirming passkey exists; otherwise no row, and
-- the API then runs the attested ceremony as before. It decides nothing: the
-- API's `epigraph_passkey::Passkeys::check_anchor` requires the act to be a
-- confirmed `passkey.register` act, the passkey to be the enrollment person's
-- and live, RE-VERIFIES the passkey's stored attestation chain (and every
-- lineage passkey's) against the roots the API trusts now, and RE-VERIFIES
-- the recorded assertion against the passkey's stored key and the act's own
-- challenge (the database cannot verify a signature, so a confirmation
-- recorded with fabricated evidence anchors nothing).
--
-- THE LINEAGE (`anchor_lineage`, `anchor_lineage_complete`): the passkeys
-- that authorized the anchor, nearest first. A passkey enrolled on an act was
-- authorized by the passkey that confirmed that act; a passkey enrolled by
-- the maintenance DSN (the person's first) by nobody. The reader walks that
-- chain up from the anchor, at most 32 steps, and reports whether it reached
-- a maintenance-enrolled passkey. The API refuses an anchor whose lineage is
-- incomplete or holds a passkey that is not hardware-attested: a synced
-- passkey that confirmed the act a phone was enrolled on would otherwise
-- anchor further synced passkeys through that phone.
--
-- (b) `epigraph_person_authenticators_guard_act_confirmer()`, BEFORE INSERT
-- (after 124's guard, which locks the enrollment: triggers fire in name
-- order): a passkey enrolled on an act is recorded only while the passkey
-- that confirmed the act is LIVE, read under `FOR SHARE`. It closes the
-- window between the API's read of the anchor and the completion: a revoke
-- that committed first is seen (refused, ELV04), and one that comes later
-- waits for this insert to commit and then reaches it through (c). It
-- applies to every act enrollment, anchored or attested, as 130's
-- `epigraph_consume_admin_act` already refuses to OPEN one whose confirming
-- passkey is revoked.
--
-- (c) `epigraph_person_authenticators_revoke_anchored()`, AFTER UPDATE OF
-- `revoked_at`: revoking a passkey revokes, in the same transaction, every
-- live UNATTESTED (`none`) passkey enrolled on an act it confirmed: on an
-- armed database exactly the passkeys it anchored, which hold only through
-- it. Same stamp (`now()`, the revoking login), the reason `anchor <id>
-- revoked: <reason>`, through 124's update guard and audit. An attested
-- passkey enrolled on such an act stands on its own attestation and is left
-- live. (On a database that served the software policy, every `none` passkey
-- enrolled on the revoked passkey's acts goes too.)
--
-- WHAT THE READER REVEALS, to a holder of the request DSN and a live
-- enrollment id: the act's kind, outcome, args digest, ceremony state and
-- assertion evidence (clientDataJSON, authenticatorData, signature), and, for
-- the confirming passkey and every passkey on its lineage, the id, the
-- stored credential, AAGUID, attestation format and backup-eligible flag
-- (and for the confirming one its credential id and whether it is revoked).
-- A stored credential is the library's whole record: the PUBLIC key and, for
-- an attested passkey, its attestation certificate chain, which identifies
-- the device model and, for an Android key, carries per-device certificates.
-- Authentication records of the person the enrollment registers a passkey
-- for, no secret among them, but device identifiers; it enumerates nothing.
--
-- EXECUTE: the reader revoked from PUBLIC and granted to `epigraph_app` (the
-- enrollment page) and `epigraph_maintenance`; the two trigger functions
-- revoked from PUBLIC and granted to nobody. Owners and grants are
-- role-guarded as every such block since 060 is. REGISTERED in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs` (`DEFERRED_DEFINER_FUNCTIONS`
-- at 200, and the reader in its grant register): under a non-bypassing owner
-- the reader answers no row, silently (every anchored enrollment falls back to
-- the attested ceremony), the insert guard finds no confirming passkey and
-- refuses every act enrollment (loud), and the cascade finds no dependant and
-- revokes nothing, SILENTLY.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary that reads it serves with the anchored setting on:
-- without it every enrollment challenge errors (42883) once the setting is on.
-- With the setting off (the default) no binary calls the reader; the triggers
-- apply whatever the setting.
--
-- UNDO: `docs/runbooks/200-undo.sql`, only after rolling back every binary
-- that calls the reader or turning the setting off.
SET LOCAL lock_timeout = '3s';

-- (a) The reader.
CREATE OR REPLACE FUNCTION public.epigraph_enrollment_anchor(p_enrollment uuid)
RETURNS TABLE (act_id uuid, act_kind text, act_outcome text, args_digest bytea,
               act_challenge_state jsonb, assertion_evidence jsonb,
               enrollment_person uuid, anchor_id uuid, anchor_person uuid,
               anchor_credential_id bytea, anchor_passkey jsonb, anchor_aaguid uuid,
               anchor_attestation_format text, anchor_backup_eligible boolean,
               anchor_revoked boolean, anchor_lineage jsonb,
               anchor_lineage_complete boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE anchor AS (
        SELECT a.id AS act_id, a.kind, a.outcome, a.args_digest, a.challenge_state,
               a.assertion_evidence, en.person_agent_id AS enrollment_person, k.id AS anchor_id,
               k.person_agent_id, k.credential_id, k.passkey, k.aaguid, k.attestation_format,
               k.backup_eligible, k.revoked_at IS NOT NULL AS revoked
          FROM public.passkey_enrollments en
          JOIN public.pending_admin_acts a ON a.id = en.act_id
          JOIN public.person_authenticators k ON k.id = a.authenticator_id
         WHERE en.id = p_enrollment
           AND en.created_via = 'confirmed_act'
           AND en.consumed_at IS NULL
           AND pg_catalog.now() < en.expires_at
    ),
    -- Step 0 is the anchor itself; each further step is the passkey that
    -- confirmed the act the previous one was enrolled on.
    up (depth, passkey_id, via, parent, passkey, aaguid, attestation_format,
        backup_eligible) AS (
        SELECT 0, k.id, en.created_via, pa.authenticator_id, k.passkey, k.aaguid,
               k.attestation_format, k.backup_eligible
          FROM anchor
          JOIN public.person_authenticators k ON k.id = anchor.anchor_id
          JOIN public.passkey_enrollments en ON en.id = k.enrollment_id
          LEFT JOIN public.pending_admin_acts pa ON pa.id = en.act_id
        UNION ALL
        SELECT up.depth + 1, k.id, en.created_via, pa.authenticator_id, k.passkey, k.aaguid,
               k.attestation_format, k.backup_eligible
          FROM up
          JOIN public.person_authenticators k ON k.id = up.parent
          JOIN public.passkey_enrollments en ON en.id = k.enrollment_id
          LEFT JOIN public.pending_admin_acts pa ON pa.id = en.act_id
         WHERE up.via = 'confirmed_act' AND up.depth < 32
    )
    SELECT anchor.act_id, anchor.kind, anchor.outcome, anchor.args_digest,
           anchor.challenge_state, anchor.assertion_evidence, anchor.enrollment_person,
           anchor.anchor_id, anchor.person_agent_id, anchor.credential_id, anchor.passkey,
           anchor.aaguid, anchor.attestation_format, anchor.backup_eligible, anchor.revoked,
           COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                                 'passkey_id', up.passkey_id, 'passkey', up.passkey,
                                 'aaguid', up.aaguid,
                                 'attestation_format', up.attestation_format,
                                 'backup_eligible', up.backup_eligible) ORDER BY up.depth)
                       FROM up WHERE up.depth > 0), '[]'::jsonb),
           EXISTS (SELECT 1 FROM up WHERE up.via = 'maintenance')
      FROM anchor
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) FROM PUBLIC;

-- (b) An act enrollment completes only while its act's confirming passkey is
-- live, read under a share lock (closes the anchor's check-then-insert window).
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_guard_act_confirmer()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_act       uuid;
    v_confirmer uuid;
    v_revoked   timestamptz;
BEGIN
    SELECT en.act_id INTO v_act
      FROM public.passkey_enrollments en
     WHERE en.id = NEW.enrollment_id AND en.created_via = 'confirmed_act';
    IF v_act IS NULL THEN
        RETURN NEW;  -- a maintenance enrollment (124's guard refused an unknown one)
    END IF;
    SELECT a.authenticator_id INTO v_confirmer
      FROM public.pending_admin_acts a WHERE a.id = v_act;
    -- FOR SHARE: a concurrent revoke of the confirming passkey either
    -- committed first (its revoked_at is read here) or waits for this
    -- transaction, and then reaches the new passkey through (c).
    SELECT k.revoked_at INTO v_revoked
      FROM public.person_authenticators k WHERE k.id = v_confirmer FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV04: enrollment %: the passkey that confirmed act % is not found',
                        NEW.enrollment_id, v_act
            USING ERRCODE = 'ELV04';
    END IF;
    IF v_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'ELV04: enrollment %: the passkey that confirmed act % has been revoked',
                        NEW.enrollment_id, v_act
            USING ERRCODE = 'ELV04',
                  HINT = 'Propose and confirm a new passkey.register act with a live passkey.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_guard_act_confirmer()
    FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_guard_insert_act_confirmer
    ON public.person_authenticators;
CREATE TRIGGER person_authenticators_guard_insert_act_confirmer
    BEFORE INSERT ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_guard_act_confirmer();

-- (c) Revoking a passkey revokes the unattested passkeys it anchored.
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_revoke_anchored()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE public.person_authenticators d
       SET revoked_at = pg_catalog.now(), revoked_by = session_user::text,
           revoked_reason = 'anchor ' || NEW.id::text || ' revoked: ' || NEW.revoked_reason
     WHERE d.revoked_at IS NULL
       AND d.attestation_format = 'none'
       AND d.enrollment_id IN (SELECT en.id
                                 FROM public.passkey_enrollments en
                                 JOIN public.pending_admin_acts a ON a.id = en.act_id
                                WHERE a.authenticator_id = NEW.id);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_revoke_anchored() FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_revoke_anchored ON public.person_authenticators;
CREATE TRIGGER person_authenticators_revoke_anchored
    AFTER UPDATE OF revoked_at ON public.person_authenticators
    FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_person_authenticators_revoke_anchored();

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_guard_act_confirmer() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_revoke_anchored() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_enrollment_anchor(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

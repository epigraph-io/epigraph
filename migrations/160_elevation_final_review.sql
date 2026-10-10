-- Migration 160: the elevation stack's final-review corrections (124-132 are
-- applied and immutable, so each correction lands here; the slot is the
-- first after the drain block 140-159).
--
-- Each section is one decision. Sections 1-3 only re-body functions:
-- `CREATE OR REPLACE` keeps each one's owner (the maintenance role) and its
-- ACL, which 124's, 125's and 130's registers pin. Section 4 ADDS objects:
-- a nullable column and its CHECK on `person_authenticators`, a trigger and
-- its function, and an eight-argument overload of 124's completion definer,
-- owned by the maintenance role with EXECUTE granted to the application and
-- maintenance roles. No section creates a table or changes a policy.
--
-- ===================================================================
-- 1. A MAINTENANCE ENROLLMENT ADMITS ONLY A FIRST PASSKEY, WHEN IT COMPLETES
--
-- 130 made a later passkey ride a confirmed `passkey.register` act: a
-- maintenance enrollment for a person who already holds a live passkey is
-- refused ELV10. It checked that only when the enrollment OPENS. Two
-- maintenance enrollments opened while the person held none both passed, and
-- both completed: the person ended up with a second passkey that no act and
-- no break-glass revoke admitted.
--
-- 124's `person_authenticators` insert guard (the completion) now repeats the
-- test: a passkey admitted by a `maintenance` enrollment is refused ELV10
-- while the person holds a live passkey. A `confirmed_act` enrollment is not
-- tested (its act was consumed when it opened). The guard first takes a
-- transaction-scoped advisory lock on the person, so two completions of one
-- person in flight at once serialise and the second reads the first's
-- passkey; the enrollment row lock 124 takes does not serialise them (they
-- lock different enrollments). The break-glass is unchanged: once every
-- passkey of the person is revoked, a maintenance enrollment completes again.
--
-- ===================================================================
-- 2. AN ACT EXECUTES ONLY UNDER THE ASSIGNMENT IT WAS CONFIRMED UNDER
--
-- 130's confirmation requires the proposer's live elevating assignment to be
-- the act's `assignment_id` (any role whose `platform_roles.elevates` is
-- true), but its consumer asked only whether the proposer held SOME live
-- `role:platform-custodian` assignment. Two consequences: an act confirmed
-- under assignment A still executed after A was ended and a new assignment
-- A' was granted; and an act of a future elevating role other than the
-- custodian could never execute.
--
-- `epigraph_consume_admin_act` now refuses ELV08 unless
-- `epigraph_live_elevating_assignment(proposer, clock_timestamp())` IS the
-- act's assignment, the test the session-liveness predicate already makes.
-- Nothing else in the consumer changes.
--
-- ===================================================================
-- 3. THE OPENED GATE READS THE RECORDER THE MAINTENANCE ROLE OWNS
--
-- 132 made 125's recorder gate, `epigraph_elevated_access_ready()`, a
-- readiness test: true while a relation named `public.elevated_access` and a
-- function named `public.epigraph_record_elevated_access(text, jsonb,
-- integer, uuid[])` exist. That is an EXISTENCE test, the form the review
-- that built the gate rejected as spoofable by CREATE on the schema. With
-- 127 taken back out and 132's undo skipped (which 132's header called
-- safe: "closes the gate by itself"), any login holding CREATE on `public`
-- (on PostgreSQL 15 and later, the database owner) re-created both names as
-- stubs, the gate answered true, sessions were live again, and the API and
-- MCP recorders "succeeded" against a stub that recorded nothing.
--
-- The gate now also requires the recorder to be a SECURITY DEFINER owned by
-- a member of `epigraph_maintenance` (the role 127 hands it to; the same
-- `pg_has_role(owner, 'epigraph_maintenance', 'MEMBER')` test
-- `epigraph_definer_bypass()` and `epigraph-tenancy-backfill verify` make).
-- A login outside that role cannot create a function it owns. On a database
-- without the role the gate stays closed. Who may still replace the gate
-- itself (a maintenance member holding CREATE, a superuser) is unchanged:
-- `epigraph-tenancy-backfill verify` and the deploy preconditions cover it.
--
-- ===================================================================
-- 4. A PASSKEY KEEPS THE REGISTRATION THAT ADMITTED IT, FOR THE VERIFIER
--
-- 124 records what the API says its WebAuthn library verified (the
-- credential, the attestation's format and model, user verification) and
-- cannot check any of it. Its header left detecting a forged completion to
-- the offline verifier, but the verifier re-checked only ASSERTIONS: a
-- holder of the application DSN who learned a live enrollment id could
-- complete it with a key of its own (the attestation allowlist lives only in
-- the API's code), and every ticket and act that key later confirmed
-- re-verified clean.
--
-- `person_authenticators.registration` keeps the authenticator's raw
-- registration response (the `PublicKeyCredential` JSON, attestation object
-- and client data included), and the enrollment keeps the ceremony state it
-- was started with, so `epigraph-operator verify-confirmations` can run the
-- registration again under the API's own attestation policy and compare the
-- result with the stored row. A completion with no stored registration (the
-- seven-argument form, which an older API binary still calls) is reported,
-- not trusted. The new eight-argument
-- `epigraph_complete_passkey_enrollment` is the API's; it refuses a missing
-- registration. The column never changes after the insert.
--
-- WHAT IT STILL CANNOT SEE: a forger holding an authenticator of an
-- allowlisted model produces a registration that verifies (over a challenge
-- it chose, since the application DSN also writes the ceremony state); and
-- under the software policy (tests and development) any key verifies.
--
-- ===================================================================
-- UNDO: `docs/runbooks/160-undo.sql` restores each re-bodied function to the
-- body it had before this file. Run it FIRST, before 132-undo and every other
-- elevation undo.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. 124's completion guard, with ELV10 for a maintenance enrollment
-- (delta from 124: the per-person lock and the ELV10 test after ELV04).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_enrollment public.passkey_enrollments%ROWTYPE;
BEGIN
    IF NOT public.epigraph_is_human_operator(NEW.person_agent_id)
       OR EXISTS (SELECT 1 FROM public.operator_links l
                   WHERE l.agent_id = NEW.person_agent_id) THEN
        RAISE EXCEPTION 'ELV01: % is not a registered human operator that is no other '
                        'human''s agent; a passkey belongs only to a human', NEW.person_agent_id
            USING ERRCODE = 'ELV01';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.revoked_reason IS NOT NULL
       OR NEW.last_used_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM now() THEN
        RAISE EXCEPTION 'ELV03: a passkey is recorded unused and unrevoked, at now()'
            USING ERRCODE = 'ELV03';
    END IF;
    -- Locked, so two completions of one enrollment serialise: the second
    -- reads it consumed.
    SELECT * INTO v_enrollment FROM public.passkey_enrollments en
     WHERE en.id = NEW.enrollment_id FOR UPDATE;
    IF NOT FOUND
       OR v_enrollment.person_agent_id IS DISTINCT FROM NEW.person_agent_id
       OR v_enrollment.consumed_at IS NOT NULL
       OR now() >= v_enrollment.expires_at
       OR v_enrollment.challenge_state IS NULL THEN
        RAISE EXCEPTION 'ELV04: enrollment % is not a live, started enrollment of % (unknown, '
                        'of another person, consumed, expired, or no ceremony was started)',
                        NEW.enrollment_id, NEW.person_agent_id
            USING ERRCODE = 'ELV04';
    END IF;
    IF v_enrollment.created_via = 'maintenance' THEN
        -- Two completions of ONE person serialise here; the test below is a
        -- new statement, so it reads whatever the first committed.
        PERFORM pg_advisory_xact_lock(hashtext('epigraph.person_passkeys'),
                                      hashtext(NEW.person_agent_id::text));
        IF public.epigraph_has_live_passkey(NEW.person_agent_id) THEN
            RAISE EXCEPTION 'ELV10: % already holds a passkey, so enrollment % (opened by a '
                            'maintenance act) cannot add another; a later passkey is enrolled '
                            'on a confirmed passkey.register act', NEW.person_agent_id,
                            NEW.enrollment_id
                USING ERRCODE = 'ELV10',
                      HINT = 'Propose passkey.register while elevated and confirm it with the '
                             'existing passkey, then run epigraph-operator passkey-enroll --act '
                             '<id>. For a lost passkey, revoke it first (revoke-passkey).';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_guard_insert() FROM PUBLIC;

-- ===================================================================
-- 2. 130's act consumer, bound to the act's own assignment
-- (delta from 130: the proposer test).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_consume_admin_act(
    p_act uuid, p_kind text, p_args_digest bytea, p_actor uuid, p_result jsonb)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_act public.pending_admin_acts%ROWTYPE;
BEGIN
    SELECT * INTO v_act FROM public.pending_admin_acts a WHERE a.id = p_act FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV08: no admin act %', p_act
            USING ERRCODE = 'ELV08';
    END IF;
    IF v_act.kind IS DISTINCT FROM p_kind THEN
        RAISE EXCEPTION 'ELV09: act % is a % act, not %', p_act, v_act.kind, p_kind
            USING ERRCODE = 'ELV09';
    END IF;
    IF v_act.outcome IS DISTINCT FROM 'confirmed' THEN
        RAISE EXCEPTION 'ELV08: act % is not confirmed (%)', p_act,
                        COALESCE(v_act.refusal, 'no assertion')
            USING ERRCODE = 'ELV08',
                  HINT = 'Confirm it with the proposer''s passkey at /elevate/act/<id> first.';
    END IF;
    IF v_act.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV08: act % was already consumed at %', p_act, v_act.consumed_at
            USING ERRCODE = 'ELV08';
    END IF;
    IF clock_timestamp() >= v_act.expires_at THEN
        RAISE EXCEPTION 'ELV08: act % expired at %; propose it again', p_act, v_act.expires_at
            USING ERRCODE = 'ELV08';
    END IF;
    IF p_args_digest IS NULL OR v_act.args_digest <> p_args_digest THEN
        RAISE EXCEPTION 'ELV09: the write''s args are not the args act % confirmed '
                        '(digest %, confirmed %)', p_act,
                        COALESCE(encode(p_args_digest, 'hex'), 'none'),
                        encode(v_act.args_digest, 'hex')
            USING ERRCODE = 'ELV09',
                  HINT = 'Run the verb with exactly the args the act shows.';
    END IF;
    IF p_actor IS NOT NULL AND p_actor IS DISTINCT FROM v_act.proposed_by THEN
        RAISE EXCEPTION 'ELV09: act % was proposed and confirmed by %, not by %', p_act,
                        v_act.proposed_by, p_actor
            USING ERRCODE = 'ELV09';
    END IF;
    -- The assignment the act was proposed and confirmed under, still live and
    -- still the proposer's elevating assignment (as the session-liveness test
    -- and the confirmation bind it): not merely SOME live custodian one.
    IF public.epigraph_live_elevating_assignment(v_act.proposed_by, clock_timestamp())
       IS DISTINCT FROM v_act.assignment_id THEN
        RAISE EXCEPTION 'ELV08: the assignment % that act % was confirmed under is no longer '
                        'a live elevating assignment of its proposer %', v_act.assignment_id,
                        p_act, v_act.proposed_by
            USING ERRCODE = 'ELV08',
                  HINT = 'Propose and confirm the act again under the proposer''s current '
                         'assignment.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.person_authenticators a
                    WHERE a.id = v_act.authenticator_id AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'ELV08: the passkey that confirmed act % has been revoked', p_act
            USING ERRCODE = 'ELV08';
    END IF;
    UPDATE public.pending_admin_acts a
       SET consumed_at = now(), consumed_by = session_user, result = p_result
     WHERE a.id = v_act.id;
    RETURN v_act.elevation_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb) FROM PUBLIC;

-- ===================================================================
-- 3. 132's recorder gate, reading the recorder's owner
-- (delta from 132: the owner and SECURITY DEFINER test).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT to_regclass('public.elevated_access') IS NOT NULL
       AND EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_proc p
                WHERE p.oid = to_regprocedure(
                          'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])')
                  AND p.prosecdef
                  AND CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                                         WHERE r.rolname = 'epigraph_maintenance')
                           THEN pg_catalog.pg_has_role(p.proowner, 'epigraph_maintenance',
                                                       'MEMBER')
                           ELSE false
                      END)
$$;

-- ===================================================================
-- 4. The stored registration
-- ===================================================================
ALTER TABLE public.person_authenticators ADD COLUMN IF NOT EXISTS registration jsonb;
ALTER TABLE public.person_authenticators
    ADD CONSTRAINT person_authenticators_registration_shape
    CHECK (registration IS NULL OR jsonb_typeof(registration) = 'object');

-- BEFORE UPDATE: the stored registration never changes (124's update guard
-- predates the column and does not list it).
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_registration_fixed()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.registration IS DISTINCT FROM OLD.registration THEN
        RAISE EXCEPTION 'ELV03: passkey %: the registration it was admitted with never changes; '
                        'nothing was changed', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_registration_fixed()
    FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_registration_fixed
    ON public.person_authenticators;
CREATE TRIGGER person_authenticators_registration_fixed
    BEFORE UPDATE ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_registration_fixed();

-- 124's completion plus the registration response (required). App-callable,
-- as 124's form is.
CREATE OR REPLACE FUNCTION public.epigraph_complete_passkey_enrollment(
    p_enrollment uuid, p_credential_id bytea, p_passkey jsonb, p_aaguid uuid,
    p_attestation_format text, p_user_verified boolean, p_backup_eligible boolean,
    p_registration jsonb)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_person uuid;
    v_label  text;
    v_id     uuid;
BEGIN
    IF p_registration IS NULL OR jsonb_typeof(p_registration) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_complete_passkey_enrollment: the registration response the '
                        'passkey was verified from is required'
            USING ERRCODE = '22004';
    END IF;
    SELECT en.person_agent_id, en.label INTO v_person, v_label
      FROM public.passkey_enrollments en WHERE en.id = p_enrollment;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV04: no enrollment %', p_enrollment
            USING ERRCODE = 'ELV04';
    END IF;
    INSERT INTO public.person_authenticators (person_agent_id, credential_id, passkey, aaguid,
                                              attestation_format, user_verified,
                                              backup_eligible, label, enrollment_id,
                                              registration)
    VALUES (v_person, p_credential_id, p_passkey, p_aaguid, p_attestation_format,
            p_user_verified, p_backup_eligible, v_label, p_enrollment, p_registration)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_complete_passkey_enrollment(
    uuid, bytea, jsonb, uuid, text, boolean, boolean, jsonb) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_registration_fixed() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_complete_passkey_enrollment(uuid, bytea, jsonb, '
                'uuid, text, boolean, boolean, jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_complete_passkey_enrollment(uuid, '
                'bytea, jsonb, uuid, text, boolean, boolean, jsonb) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_complete_passkey_enrollment(uuid, '
                'bytea, jsonb, uuid, text, boolean, boolean, jsonb) TO epigraph_app';
    END IF;
END $$;

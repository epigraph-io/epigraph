-- Migration 124: a registered human's passkeys, and the maintenance
-- enrollment tickets that admit them. Storage only: nothing here verifies a
-- WebAuthn ceremony (the API does, with a WebAuthn library) and nothing reads
-- a passkey for authority yet (the elevation ceremony, a later migration).
--
-- ===================================================================
-- 1. THE MODEL
--
-- `person_authenticators` holds one row per passkey: the human it belongs to,
-- the credential id, the library's serialized credential (`passkey`, its
-- public key included), what the attestation said (AAGUID, format), whether
-- the authenticator verified its user, its signature counter, and the
-- enrollment that admitted it. `passkey_enrollments` holds one row per
-- enrollment ticket: whose passkey it admits, why, who opened it on which
-- login, when it expires (at most 15 minutes after it opens), the ceremony's
-- stored challenge state, and the passkey it was consumed by.
--
-- A PASSKEY BELONGS TO A REGISTERED HUMAN THAT IS NO OTHER HUMAN'S AGENT, as
-- a role does (123's CUS01): `epigraph_is_human_operator` and no
-- `operator_links` row with it as the agent. Refused `ELV01` when the
-- enrollment opens AND again when it completes, so a human linked as an agent
-- in between gets no passkey.
--
-- The first passkey is admitted by a MAINTENANCE act: `epigraph-operator
-- passkey-enroll` opens a ticket on the maintenance DSN and prints the
-- ceremony path; the operator opens it on the device that holds the
-- authenticator. Until the operator ruling D3 takes effect, whoever holds the
-- maintenance DSN can open a ticket, and the attestation policy the API
-- applies is what decides whether a software authenticator could complete it.
--
-- ===================================================================
-- 2. WHO WRITES IT
--
--   * An enrollment is opened only on a privileged session
--     (`epigraph_bypass()`): the INSERT policy admits nothing else, and its
--     definer is maintenance-only.
--   * The ceremony is the request DSN's, UNSTAMPED: the enrollment page is
--     unauthenticated by design (the enrollment id and the authenticator are
--     its credentials). Three definers are EXECUTE-able by the application
--     role, and each takes the enrollment id: the reader, the challenge
--     store and the completion. The tables' write policies admit a
--     privileged session or a maintenance-owned definer frame
--     (`epigraph_definer_bypass()`), and the application role holds no DML
--     grant, so a direct application write is refused (42501) whatever the
--     frame.
--   * The application role keeps table-level SELECT (every public table is
--     reachable by it: `rls_enforcement.rs`), and the SELECT policies admit
--     only a privileged session or a definer frame, so it reads no row.
--   * A revoke is a maintenance act (break-glass, audited).
--
-- The rules live on the TABLES (guard triggers), so a direct maintenance
-- statement meets exactly what the definers meet:
--
--   ELV01  the subject is not a registered human, or is linked as an agent.
--   ELV03  not the append-only shape. An enrollment: no confirmed-act path
--          yet (the act batch adds it), provenance is the database's
--          (`created_by = session_user`, `created_at = now()`), it is born
--          unchallenged and unconsumed, its identity never changes; the only
--          changes are a challenge stored while it is live, and its one
--          consumption by the passkey it admitted. A passkey: born unused and
--          unrevoked, `created_at = now()`; nothing about it ever changes but
--          one revoke (stamped now(), by the revoking login, with a reason)
--          and its use (`last_used_at = now()`, the counter never going
--          back); a revoked passkey is final.
--   ELV04  the enrollment is not live: unknown, expired, consumed, of
--          another person, or (for a completion) no ceremony was started.
--
-- WHAT THE TABLE CANNOT PROVE. The completion's credential, attestation and
-- user-verification flag are what the caller says the library verified: the
-- database cannot verify a WebAuthn attestation. Whoever holds the request
-- DSN and a live enrollment id can complete it with a credential of its own
-- choosing; whoever holds the maintenance DSN can open the ticket too. The
-- stored credential and attestation are kept so the claim can be re-checked
-- later; detecting a forged confirmation is the elevation stack's offline
-- verifier's job.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/124-undo.sql`. Roll back first every binary that calls a
-- function this file creates (docs/deploy.md).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE TABLES
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.passkey_enrollments (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    person_agent_id  uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    reason           text NOT NULL CONSTRAINT passkey_enrollments_reason_present
                         CHECK (length(btrim(reason)) > 0),
    -- A name the operator gives the passkey, copied onto it.
    label            text,
    -- 'maintenance' (an operator act on the maintenance DSN) or
    -- 'confirmed_act' (an executed act of the act batch, which amends the
    -- insert guard; refused until then).
    created_via      text NOT NULL DEFAULT 'maintenance'
                         CONSTRAINT passkey_enrollments_created_via
                         CHECK (created_via IN ('maintenance', 'confirmed_act')),
    act_id           uuid,
    -- The database login that opened it.
    created_by       text NOT NULL DEFAULT session_user,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    -- The WebAuthn library's registration state for the ceremony in flight.
    challenge_state  jsonb,
    consumed_at      timestamptz,
    authenticator_id uuid,
    CONSTRAINT passkey_enrollments_ttl
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    CONSTRAINT passkey_enrollments_act_shape
        CHECK ((created_via = 'confirmed_act') = (act_id IS NOT NULL)),
    CONSTRAINT passkey_enrollments_consumed_shape
        CHECK ((consumed_at IS NULL) = (authenticator_id IS NULL)),
    CONSTRAINT passkey_enrollments_challenge_shape
        CHECK (challenge_state IS NULL OR jsonb_typeof(challenge_state) = 'object')
);
REVOKE ALL ON public.passkey_enrollments FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_passkey_enrollments_person
    ON public.passkey_enrollments (person_agent_id);

CREATE TABLE IF NOT EXISTS public.person_authenticators (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    person_agent_id    uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    -- WebAuthn bounds a credential id to 16..1023 bytes.
    credential_id      bytea NOT NULL CONSTRAINT person_authenticators_credential_id_key UNIQUE
                           CONSTRAINT person_authenticators_credential_id_length
                           CHECK (length(credential_id) BETWEEN 16 AND 1023),
    -- The library's serialized credential (its public key included). Never
    -- changes after the insert; the counter is `sign_count`.
    passkey            jsonb NOT NULL CONSTRAINT person_authenticators_passkey_shape
                           CHECK (jsonb_typeof(passkey) = 'object'),
    -- What the attestation said. An attestation of format `none` carries the
    -- all-zero AAGUID.
    aaguid             uuid NOT NULL,
    attestation_format text NOT NULL CONSTRAINT person_authenticators_format_shape
                           CHECK (attestation_format ~ '^[a-z][a-z0-9-]*$'),
    -- D5: a passkey is registered only with user verification.
    user_verified      boolean NOT NULL CONSTRAINT person_authenticators_user_verified
                           CHECK (user_verified),
    backup_eligible    boolean NOT NULL,
    label              text,
    enrollment_id      uuid NOT NULL CONSTRAINT person_authenticators_enrollment_id_key UNIQUE
                           REFERENCES public.passkey_enrollments(id) ON DELETE RESTRICT,
    -- The authenticator's signature counter (0 when it keeps none).
    sign_count         bigint NOT NULL DEFAULT 0 CONSTRAINT person_authenticators_sign_count_range
                           CHECK (sign_count BETWEEN 0 AND 4294967295),
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    revoked_by         text,
    revoked_reason     text,
    CONSTRAINT person_authenticators_revoke_shape
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
               AND (revoked_at IS NULL) = (revoked_reason IS NULL))
);
REVOKE ALL ON public.person_authenticators FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_person_authenticators_live
    ON public.person_authenticators (person_agent_id) WHERE revoked_at IS NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'passkey_enrollments_authenticator_id_fkey') THEN
        ALTER TABLE public.passkey_enrollments
            ADD CONSTRAINT passkey_enrollments_authenticator_id_fkey
            FOREIGN KEY (authenticator_id) REFERENCES public.person_authenticators(id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- ===================================================================
-- 2. THE GUARDS (section 2 of the header)
-- ===================================================================

-- BEFORE INSERT on `passkey_enrollments`: ELV01 and ELV03.
CREATE OR REPLACE FUNCTION public.epigraph_passkey_enrollments_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_is_human_operator(NEW.person_agent_id)
       OR EXISTS (SELECT 1 FROM public.operator_links l
                   WHERE l.agent_id = NEW.person_agent_id) THEN
        RAISE EXCEPTION 'ELV01: % is not a registered human operator that is no other '
                        'human''s agent; a passkey belongs only to a human', NEW.person_agent_id
            USING ERRCODE = 'ELV01',
                  HINT = 'Enroll the human''s own principal (a live human_operators row with an '
                         'active human OAuth client), never an agent.';
    END IF;
    IF NEW.created_via <> 'maintenance' THEN
        RAISE EXCEPTION 'ELV03: an enrollment is opened by a maintenance act; no confirmed-act '
                        'path exists yet'
            USING ERRCODE = 'ELV03';
    END IF;
    -- Provenance is the database's: the login that opened it, now, and no
    -- ceremony or consumption a writer could pre-supply.
    IF NEW.created_by IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS NOT NULL
       OR NEW.consumed_at IS NOT NULL OR NEW.authenticator_id IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: created_by, created_at, the challenge and the consumption of an '
                        'enrollment are recorded by the database (the opening login, now(), '
                        'none, none); an enrollment does not supply them'
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkey_enrollments_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS passkey_enrollments_guard_insert ON public.passkey_enrollments;
CREATE TRIGGER passkey_enrollments_guard_insert
    BEFORE INSERT ON public.passkey_enrollments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_passkey_enrollments_guard_insert();

-- BEFORE UPDATE on `passkey_enrollments`: a live enrollment takes a stored
-- challenge (any number of times: a restarted ceremony overwrites it) or its
-- one consumption, by the passkey that names it; nothing else, ever.
CREATE OR REPLACE FUNCTION public.epigraph_passkey_enrollments_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF (NEW.id, NEW.person_agent_id, NEW.reason, NEW.label, NEW.created_via, NEW.act_id,
        NEW.created_by, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       (OLD.id, OLD.person_agent_id, OLD.reason, OLD.label, OLD.created_via, OLD.act_id,
        OLD.created_by, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'ELV03: enrollment %: only its challenge and its consumption ever '
                        'change; nothing was changed', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR now() >= OLD.expires_at THEN
        RAISE EXCEPTION 'ELV04: enrollment % is not live (consumed or expired); open a new one '
                        'with epigraph-operator passkey-enroll', OLD.id
            USING ERRCODE = 'ELV04';
    END IF;
    IF NEW.consumed_at IS NULL AND NEW.authenticator_id IS NULL THEN
        -- The challenge.
        IF NEW.challenge_state IS NULL THEN
            RAISE EXCEPTION 'ELV03: enrollment %: a stored challenge is never cleared', OLD.id
                USING ERRCODE = 'ELV03';
        END IF;
    ELSIF NEW.consumed_at IS DISTINCT FROM now()
          OR NEW.challenge_state IS DISTINCT FROM OLD.challenge_state
          OR NOT EXISTS (SELECT 1 FROM public.person_authenticators a
                          WHERE a.id = NEW.authenticator_id AND a.enrollment_id = OLD.id
                            AND a.person_agent_id = OLD.person_agent_id) THEN
        RAISE EXCEPTION 'ELV03: enrollment % is consumed once, now, by the passkey it admitted, '
                        'and nothing else changes with it', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkey_enrollments_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS passkey_enrollments_guard_update ON public.passkey_enrollments;
CREATE TRIGGER passkey_enrollments_guard_update
    BEFORE UPDATE ON public.passkey_enrollments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_passkey_enrollments_guard_update();

-- BEFORE INSERT on `person_authenticators`: ELV01 again (the subject may have
-- been linked as an agent since its enrollment opened), the ELV03 birth
-- shape, and ELV04 (a live, challenged enrollment of the same person).
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
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_guard_insert ON public.person_authenticators;
CREATE TRIGGER person_authenticators_guard_insert
    BEFORE INSERT ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_guard_insert();

-- BEFORE UPDATE on `person_authenticators`: one revoke, or a use; a revoked
-- passkey is final.
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: passkey % is revoked, and a revoked passkey is final', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF (NEW.id, NEW.person_agent_id, NEW.credential_id, NEW.passkey, NEW.aaguid,
        NEW.attestation_format, NEW.user_verified, NEW.backup_eligible, NEW.label,
        NEW.enrollment_id, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.person_agent_id, OLD.credential_id, OLD.passkey, OLD.aaguid,
        OLD.attestation_format, OLD.user_verified, OLD.backup_eligible, OLD.label,
        OLD.enrollment_id, OLD.created_at) THEN
        RAISE EXCEPTION 'ELV03: passkey %: only its revoke and its use ever change; nothing was '
                        'changed', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL
       OR NEW.revoked_reason IS NOT NULL THEN
        -- The revoke: stamped now(), by this login, with a reason, alone.
        IF NEW.revoked_at IS DISTINCT FROM now()
           OR NEW.revoked_by IS DISTINCT FROM session_user::text
           OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
           OR (NEW.last_used_at, NEW.sign_count) IS DISTINCT FROM (OLD.last_used_at, OLD.sign_count)
        THEN
            RAISE EXCEPTION 'ELV03: a passkey is revoked once (revoked_at = now(), revoked_by = '
                            'the revoking login, and a reason), with nothing else; nothing was '
                            'changed'
                USING ERRCODE = 'ELV03',
                      HINT = 'Revoke it with epigraph-operator revoke-passkey.';
        END IF;
    ELSIF NEW.last_used_at IS DISTINCT FROM now()
          OR NEW.sign_count < OLD.sign_count THEN
        -- The use: stamped now(), the counter never going back.
        RAISE EXCEPTION 'ELV03: a passkey''s use is stamped now() and its signature counter never '
                        'goes back (% -> %); nothing was changed', OLD.sign_count, NEW.sign_count
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_guard_update ON public.person_authenticators;
CREATE TRIGGER person_authenticators_guard_update
    BEFORE UPDATE ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_guard_update();

-- ===================================================================
-- 3. THE AUDIT, FROM THE TABLES (123's pattern: whatever path wrote the row)
--
-- `platform.` rows, which 123's restrictive policy admits only from a
-- privileged session or a maintenance-owned definer frame: an application
-- session forges none.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_passkey_enrollments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.passkey_enrollment_created', NEW.person_agent_id, true,
            jsonb_build_object('enrollment_id', NEW.id, 'person', NEW.person_agent_id,
                               'reason', NEW.reason, 'label', NEW.label,
                               'created_via', NEW.created_via, 'created_by', NEW.created_by,
                               'expires_at', NEW.expires_at));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkey_enrollments_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS passkey_enrollments_audit ON public.passkey_enrollments;
CREATE TRIGGER passkey_enrollments_audit
    AFTER INSERT ON public.passkey_enrollments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_passkey_enrollments_audit();

-- AFTER INSERT: the passkey consumes its enrollment (in the same statement,
-- so no passkey exists whose enrollment is still open) and is audited. AFTER
-- UPDATE: a revoke is audited; a use is the elevation's to audit.
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

DROP TRIGGER IF EXISTS person_authenticators_audit ON public.person_authenticators;
CREATE TRIGGER person_authenticators_audit
    AFTER INSERT OR UPDATE ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_audit();

-- ===================================================================
-- 4. ROW SECURITY (section 2 of the header)
--
-- No self arm: the application role reads no passkey, not even its own; the
-- elevation stack reads a ticket's person's passkeys through a ticket-bound
-- definer. No DELETE policy: under FORCE nobody deletes a row.
-- ===================================================================
ALTER TABLE public.passkey_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passkey_enrollments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS passkey_enrollments_read ON public.passkey_enrollments;
CREATE POLICY passkey_enrollments_read ON public.passkey_enrollments
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS passkey_enrollments_maintenance_insert ON public.passkey_enrollments;
CREATE POLICY passkey_enrollments_maintenance_insert ON public.passkey_enrollments
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));
DROP POLICY IF EXISTS passkey_enrollments_definer_update ON public.passkey_enrollments;
CREATE POLICY passkey_enrollments_definer_update ON public.passkey_enrollments
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

ALTER TABLE public.person_authenticators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.person_authenticators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS person_authenticators_read ON public.person_authenticators;
CREATE POLICY person_authenticators_read ON public.person_authenticators
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS person_authenticators_definer_insert ON public.person_authenticators;
CREATE POLICY person_authenticators_definer_insert ON public.person_authenticators
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS person_authenticators_definer_update ON public.person_authenticators;
CREATE POLICY person_authenticators_definer_update ON public.person_authenticators
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- 5. THE DEFINERS
-- ===================================================================

-- Open an enrollment for `p_person`, live for 15 minutes. Maintenance-only
-- (`epigraph-operator passkey-enroll`). Returns its id; the ceremony path is
-- `/elevate/enroll/<id>`.
CREATE OR REPLACE FUNCTION public.epigraph_create_passkey_enrollment(
    p_person uuid, p_reason text, p_label text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_person IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_create_passkey_enrollment: the person and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.passkey_enrollments (person_agent_id, reason, label, expires_at)
    VALUES (p_person, p_reason, NULLIF(btrim(p_label), ''), now() + interval '15 minutes')
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_create_passkey_enrollment(uuid, text, text) FROM PUBLIC;

-- The ceremony page's view of ONE enrollment: its person, reason, expiry and
-- stored challenge, and only while it is live (unconsumed and unexpired);
-- otherwise no row. App-callable, keyed by the enrollment id alone (the page
-- is unauthenticated); it enumerates nothing.
CREATE OR REPLACE FUNCTION public.epigraph_enrollment_for_ceremony(p_enrollment uuid)
RETURNS TABLE (person_agent_id uuid, reason text, label text, expires_at timestamptz,
               challenge_state jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT en.person_agent_id, en.reason, en.label, en.expires_at, en.challenge_state
      FROM public.passkey_enrollments en
     WHERE en.id = p_enrollment
       AND en.consumed_at IS NULL
       AND now() < en.expires_at
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_enrollment_for_ceremony(uuid) FROM PUBLIC;

-- Store the library's registration state for the ceremony in flight (a
-- restarted ceremony overwrites it). App-callable; the table's guard refuses
-- an enrollment that is not live (ELV04), and an unknown one is ELV04 here.
CREATE OR REPLACE FUNCTION public.epigraph_set_passkey_enrollment_challenge(
    p_enrollment uuid, p_state jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_state IS NULL OR jsonb_typeof(p_state) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_set_passkey_enrollment_challenge: a challenge state object is '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.passkey_enrollments SET challenge_state = p_state WHERE id = p_enrollment;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'ELV04: no enrollment %', p_enrollment
            USING ERRCODE = 'ELV04';
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb)
    FROM PUBLIC;

-- Record the passkey a verified ceremony registered, consuming the
-- enrollment (the table's audit trigger) and writing
-- `platform.passkey_registered`. App-callable: the caller is the API, which
-- verified the authenticator's response with the WebAuthn library first. The
-- guards decide everything else (ELV01, ELV03, ELV04; user verification is a
-- CHECK). Returns the passkey's id.
CREATE OR REPLACE FUNCTION public.epigraph_complete_passkey_enrollment(
    p_enrollment uuid, p_credential_id bytea, p_passkey jsonb, p_aaguid uuid,
    p_attestation_format text, p_user_verified boolean, p_backup_eligible boolean)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_person uuid;
    v_label  text;
    v_id     uuid;
BEGIN
    SELECT en.person_agent_id, en.label INTO v_person, v_label
      FROM public.passkey_enrollments en WHERE en.id = p_enrollment;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV04: no enrollment %', p_enrollment
            USING ERRCODE = 'ELV04';
    END IF;
    INSERT INTO public.person_authenticators (person_agent_id, credential_id, passkey, aaguid,
                                              attestation_format, user_verified,
                                              backup_eligible, label, enrollment_id)
    VALUES (v_person, p_credential_id, p_passkey, p_aaguid, p_attestation_format,
            p_user_verified, p_backup_eligible, v_label, p_enrollment)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_complete_passkey_enrollment(
    uuid, bytea, jsonb, uuid, text, boolean, boolean) FROM PUBLIC;

-- Revoke a passkey now (break-glass, maintenance-only: `epigraph-operator
-- revoke-passkey`). False when it was already revoked or does not exist: a
-- revoke is never repeated or re-dated.
CREATE OR REPLACE FUNCTION public.epigraph_revoke_passkey(p_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_id IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_revoke_passkey: the passkey and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.person_authenticators
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason
     WHERE id = p_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_revoke_passkey(uuid, text) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- 077's default privileges hand the application role DML on every new
-- table: taken back here, leaving SELECT (which the row policies narrow to
-- nothing). Every definer is owned by the maintenance role, so its frame
-- passes `epigraph_definer_bypass()`; the application role may EXECUTE only
-- the three ceremony definers.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_passkey_enrollments_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkey_enrollments_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkey_enrollments_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_create_passkey_enrollment(uuid, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_enrollment_for_ceremony(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_complete_passkey_enrollment(uuid, bytea, jsonb, '
                'uuid, text, boolean, boolean) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_revoke_passkey(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.passkey_enrollments, '
                'public.person_authenticators TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_create_passkey_enrollment(uuid, text, text), '
                'public.epigraph_enrollment_for_ceremony(uuid), '
                'public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb), '
                'public.epigraph_complete_passkey_enrollment(uuid, bytea, jsonb, uuid, text, '
                'boolean, boolean), '
                'public.epigraph_revoke_passkey(uuid, text) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.passkey_enrollments, public.person_authenticators '
                'FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.passkey_enrollments, public.person_authenticators '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_enrollment_for_ceremony(uuid), '
                'public.epigraph_set_passkey_enrollment_challenge(uuid, jsonb), '
                'public.epigraph_complete_passkey_enrollment(uuid, bytea, jsonb, uuid, text, '
                'boolean, boolean) TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_create_passkey_enrollment(uuid, text, text), '
                'public.epigraph_revoke_passkey(uuid, text) FROM epigraph_app';
    END IF;
END $$;

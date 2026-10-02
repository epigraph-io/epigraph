-- Migration 125: elevation tickets and elevation sessions, and
-- `epigraph_is_elevated()`. INERT: nothing stamps `epigraph.elevation_id` /
-- `epigraph.family_id` yet (a later batch adds them to the session GUCs), so
-- `epigraph_is_elevated()` answers false on every session until then, and no
-- row policy reads it yet.
--
-- ===================================================================
-- 1. THE MODEL
--
-- An ELEVATION is a short (at most 15 minutes), read-only widening of one
-- human's reads, bound to ONE refresh-token family of that human and to the
-- live assignment of an `elevates` role that justified it. It is opened by a
-- passkey ceremony over a TICKET:
--
--   * `elevation_tickets`: one row per request. Who (the session principal,
--     never a caller-supplied id), on which client and family, in which mode
--     (`grant`: a CLI redeems it at the token endpoint with a secret it was
--     shown once; `connector`: the family's own later requests resolve it),
--     why, the ceremony's stored challenge, and its single outcome
--     (`confirmed` with the session it opened, or `refused` with why). A
--     ticket lives 5 minutes; it is asserted once.
--   * `elevation_sessions`: one row per confirmed ticket. The person, the
--     role assignment it rests on (`assignment_id`), the client, the family,
--     the passkey that confirmed it, when it started, when it expires (CHECK:
--     at most 15 minutes after it started) and, once, how it ended. At most
--     ONE un-ended session per family (partial unique index).
--
-- WHO MAY ELEVATE (operator ruling D2). Only a registered human that is no
-- other human's agent, holding a LIVE assignment of a role whose catalog row
-- says `elevates`, with at least one live passkey, on a family whose live
-- refresh token belongs to that human's own client. `instance_admins` and
-- `epigraph_is_instance_admin` are NEVER consulted: a standing flag is not an
-- elevation. An agent never holds a role (123's CUS01), so an agent never
-- gets a ticket.
--
-- `epigraph_is_elevated()` is true only for the session principal's own
-- un-ended, unexpired session named by BOTH GUCs, and only while the person's
-- live elevating assignment is still the one the session stored. That
-- re-check runs on every statement: a revoked assignment, a revoked
-- registration, a suspended human client, or a later link of the person as
-- an agent turns it false at once, whether or not a trigger has ended the
-- row.
--
-- REFUSALS THAT MUST BE AUDITED DO NOT RAISE. A ceremony completed with
-- another person's credential (the confused deputy), a regressed signature
-- counter (ELV05), and the other use-time refusals mark the ticket
-- `refused`, write their `platform.` rows, and RETURN the refusal: a raise
-- would roll the audit row back with it, and the application role cannot
-- write a `platform.` row itself.
--
-- ===================================================================
-- 2. WHO WRITES IT
--
-- Only the definers (and a privileged session). The application role holds
-- no DML grant on either table and its SELECT reads no row; it reaches them
-- through the definers below, each principal-bound or keyed by a ticket id.
-- The rules live on the TABLES (guard triggers), so a direct maintenance
-- statement meets exactly what the definers meet:
--
--   ELV02  the ticket's subject may not elevate (section 1), or a session's
--          assignment / passkey is not the person's live one.
--   ELV03  not the append-only shape: provenance and identity are the
--          database's and never change; a ticket takes a stored challenge,
--          one outcome and (grant mode) one redemption; a session takes one
--          end.
--   ELV05  the passkey's signature counter went back (refused, audited,
--          returned; never raised).
--   ELV06  the ticket is not live (unknown, expired, already asserted, or no
--          ceremony started), or the family is already elevated.
--
-- WHAT THE TABLE CANNOT PROVE. The confirmation's credential and counter are
-- what the caller says the WebAuthn library verified; the database cannot
-- verify a signature. The evidence is stored so an offline verifier can
-- re-check every confirmation later.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/125-undo.sql`. Roll back first every binary that calls a
-- function this file creates (docs/deploy.md).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE TABLES
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.elevation_tickets (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    person_agent_id    uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    client_id          uuid NOT NULL REFERENCES public.oauth_clients(id) ON DELETE RESTRICT,
    family_id          uuid NOT NULL,
    mode               text NOT NULL CONSTRAINT elevation_tickets_mode
                           CHECK (mode IN ('grant', 'connector')),
    reason             text NOT NULL CONSTRAINT elevation_tickets_reason_present
                           CHECK (length(btrim(reason)) > 0),
    -- Grant mode only: the hash of the secret shown once to the requester.
    redeem_secret_hash bytea,
    -- The WebAuthn library's authentication state for the ceremony in flight.
    challenge_state    jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    asserted_at        timestamptz,
    outcome            text CONSTRAINT elevation_tickets_outcome
                           CHECK (outcome IN ('confirmed', 'refused')),
    refusal            text CONSTRAINT elevation_tickets_refusal
                           CHECK (refusal IN ('credential_unknown', 'person_mismatch',
                                              'credential_revoked', 'counter_regressed',
                                              'backup_eligibility_changed',
                                              'no_live_assignment', 'family_revoked')),
    assertion_evidence jsonb,
    -- The passkey the assertion named (when it is a known one, whoever's).
    authenticator_id   uuid REFERENCES public.person_authenticators(id) ON DELETE RESTRICT,
    session_id         uuid,
    redeemed_at        timestamptz,
    CONSTRAINT elevation_tickets_ttl
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    CONSTRAINT elevation_tickets_secret_shape
        CHECK ((mode = 'grant') = (redeem_secret_hash IS NOT NULL)
               AND (redeem_secret_hash IS NULL OR length(redeem_secret_hash) = 32)),
    CONSTRAINT elevation_tickets_challenge_shape
        CHECK (challenge_state IS NULL OR jsonb_typeof(challenge_state) = 'object'),
    CONSTRAINT elevation_tickets_outcome_shape
        CHECK ((outcome IS NULL) = (asserted_at IS NULL)
               AND (outcome IS NULL) = (assertion_evidence IS NULL)
               AND (session_id IS NOT NULL) = (outcome IS NOT DISTINCT FROM 'confirmed')
               AND (refusal IS NOT NULL) = (outcome IS NOT DISTINCT FROM 'refused')),
    CONSTRAINT elevation_tickets_redeem_shape
        CHECK (redeemed_at IS NULL OR (mode = 'grant' AND outcome = 'confirmed'))
);
REVOKE ALL ON public.elevation_tickets FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_elevation_tickets_person
    ON public.elevation_tickets (person_agent_id);

CREATE TABLE IF NOT EXISTS public.elevation_sessions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    person_agent_id  uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    assignment_id    uuid NOT NULL REFERENCES public.role_assignments(id) ON DELETE RESTRICT,
    client_id        uuid NOT NULL REFERENCES public.oauth_clients(id) ON DELETE RESTRICT,
    family_id        uuid NOT NULL,
    mode             text NOT NULL CONSTRAINT elevation_sessions_mode
                         CHECK (mode IN ('grant', 'connector')),
    reason           text NOT NULL CONSTRAINT elevation_sessions_reason_present
                         CHECK (length(btrim(reason)) > 0),
    ticket_id        uuid NOT NULL CONSTRAINT elevation_sessions_ticket_id_key UNIQUE
                         REFERENCES public.elevation_tickets(id) ON DELETE RESTRICT,
    authenticator_id uuid NOT NULL REFERENCES public.person_authenticators(id)
                         ON DELETE RESTRICT,
    started_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    ended_at         timestamptz,
    ended_reason     text CONSTRAINT elevation_sessions_ended_reason
                         CHECK (ended_reason IN ('unsudo', 'ended', 'expired',
                                                 'assignment_revoked', 'operator_revoked',
                                                 'family_reuse')),
    ended_by         text,
    -- THE BOUND (DESIGN 6.2): an elevation never outlives 15 minutes.
    CONSTRAINT elevation_sessions_ttl
        CHECK (expires_at > started_at AND expires_at <= started_at + interval '15 minutes'),
    CONSTRAINT elevation_sessions_end_shape
        CHECK ((ended_at IS NULL) = (ended_reason IS NULL)
               AND (ended_at IS NULL) = (ended_by IS NULL))
);
REVOKE ALL ON public.elevation_sessions FROM PUBLIC;
-- One un-ended session per family. An expired session stays un-ended until
-- something ends it (lazily: the next ticket of its person, or the next
-- confirmation on its family, ends it `expired` first).
CREATE UNIQUE INDEX IF NOT EXISTS elevation_sessions_one_live_per_family
    ON public.elevation_sessions (family_id) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_elevation_sessions_live_assignment
    ON public.elevation_sessions (assignment_id) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_elevation_sessions_live_person
    ON public.elevation_sessions (person_agent_id) WHERE ended_at IS NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'elevation_tickets_session_id_fkey') THEN
        ALTER TABLE public.elevation_tickets
            ADD CONSTRAINT elevation_tickets_session_id_fkey
            FOREIGN KEY (session_id) REFERENCES public.elevation_sessions(id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- ===================================================================
-- 2. WHO MAY ELEVATE (D2), ANSWERED FOR ANY PERSON
--
-- Not granted to the application role (an unbound answer is a roster
-- oracle); the guards and the principal-bound definers call it.
-- ===================================================================

-- The person's live assignment of an `elevates` role at `p_at` (the earliest
-- by role key, then by 123's own order), or NULL. 123's
-- `epigraph_live_role_assignment` re-checks registration and the agent link.
CREATE OR REPLACE FUNCTION public.epigraph_live_elevating_assignment(
    p_person uuid, p_at timestamptz)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT a FROM (
        SELECT public.epigraph_live_role_assignment(p_person, r.key, p_at) AS a
          FROM public.platform_roles r
         WHERE r.elevates
         ORDER BY r.key) x
     WHERE a IS NOT NULL
     LIMIT 1
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_elevating_assignment(uuid, timestamptz)
    FROM PUBLIC;

-- Is `p_family` a live refresh family of `p_person`'s own active human client
-- `p_client`?
CREATE OR REPLACE FUNCTION public.epigraph_family_of_person_is_live(
    p_person uuid, p_client uuid, p_family uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_person IS NOT NULL AND p_client IS NOT NULL AND p_family IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.refresh_tokens t
                     JOIN public.oauth_clients c ON c.id = t.client_id
                    WHERE COALESCE(t.family_id, t.id) = p_family
                      AND t.client_id = p_client
                      AND t.revoked_at IS NULL AND t.expires_at > now()
                      AND c.agent_id = p_person
                      AND c.client_type = 'human'
                      AND c.status = 'active')
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_family_of_person_is_live(uuid, uuid, uuid)
    FROM PUBLIC;

-- ===================================================================
-- 3. THE GUARDS (section 2 of the header)
-- ===================================================================

-- BEFORE INSERT on `elevation_tickets`: ELV02 (D2) and ELV03 (birth shape).
CREATE OR REPLACE FUNCTION public.epigraph_elevation_tickets_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.created_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS NOT NULL OR NEW.asserted_at IS NOT NULL
       OR NEW.outcome IS NOT NULL OR NEW.refusal IS NOT NULL
       OR NEW.assertion_evidence IS NOT NULL OR NEW.authenticator_id IS NOT NULL
       OR NEW.session_id IS NOT NULL OR NEW.redeemed_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: a ticket is recorded unchallenged and unasserted, at now()'
            USING ERRCODE = 'ELV03';
    END IF;
    -- A registered human that is no other human's agent, holding a LIVE
    -- assignment of an `elevates` role (D2; never `instance_admins`).
    IF public.epigraph_live_elevating_assignment(NEW.person_agent_id, now()) IS NULL THEN
        RAISE EXCEPTION 'ELV02: % holds no live assignment of an elevating role (a registered '
                        'human, no other human''s agent); only such a holder elevates',
                        NEW.person_agent_id
            USING ERRCODE = 'ELV02';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.person_authenticators a
                    WHERE a.person_agent_id = NEW.person_agent_id
                      AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'ELV02: % has no live passkey; register one with '
                        'epigraph-operator passkey-enroll', NEW.person_agent_id
            USING ERRCODE = 'ELV02';
    END IF;
    IF NOT public.epigraph_family_of_person_is_live(NEW.person_agent_id, NEW.client_id,
                                                     NEW.family_id) THEN
        RAISE EXCEPTION 'ELV02: family % is not a live refresh family of %''s own human '
                        'client %', NEW.family_id, NEW.person_agent_id, NEW.client_id
            USING ERRCODE = 'ELV02';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_tickets_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_tickets_guard_insert ON public.elevation_tickets;
CREATE TRIGGER elevation_tickets_guard_insert
    BEFORE INSERT ON public.elevation_tickets
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_tickets_guard_insert();

-- BEFORE UPDATE on `elevation_tickets`: a stored challenge while live and
-- unasserted; one assertion while live and challenged; one redemption of a
-- confirmed grant-mode ticket. Nothing else, ever.
CREATE OR REPLACE FUNCTION public.epigraph_elevation_tickets_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF (NEW.id, NEW.person_agent_id, NEW.client_id, NEW.family_id, NEW.mode, NEW.reason,
        NEW.redeem_secret_hash, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       (OLD.id, OLD.person_agent_id, OLD.client_id, OLD.family_id, OLD.mode, OLD.reason,
        OLD.redeem_secret_hash, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'ELV03: ticket %: its identity never changes', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF OLD.outcome IS NOT NULL THEN
        -- Asserted: only the one redemption of a confirmed grant-mode ticket.
        IF OLD.outcome <> 'confirmed' OR OLD.mode <> 'grant' OR OLD.redeemed_at IS NOT NULL
           OR NEW.redeemed_at IS DISTINCT FROM now()
           OR (NEW.challenge_state, NEW.asserted_at, NEW.outcome, NEW.refusal,
               NEW.assertion_evidence, NEW.authenticator_id, NEW.session_id)
              IS DISTINCT FROM
              (OLD.challenge_state, OLD.asserted_at, OLD.outcome, OLD.refusal,
               OLD.assertion_evidence, OLD.authenticator_id, OLD.session_id) THEN
            RAISE EXCEPTION 'ELV06: ticket % is asserted; only a confirmed grant-mode ticket is '
                            'redeemed, once', OLD.id
                USING ERRCODE = 'ELV06';
        END IF;
        RETURN NEW;
    END IF;
    IF now() >= OLD.expires_at THEN
        RAISE EXCEPTION 'ELV06: ticket % has expired; request a new one', OLD.id
            USING ERRCODE = 'ELV06';
    END IF;
    IF NEW.redeemed_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV06: ticket % is not asserted; nothing to redeem', OLD.id
            USING ERRCODE = 'ELV06';
    END IF;
    IF NEW.outcome IS NULL THEN
        -- The challenge.
        IF NEW.challenge_state IS NULL
           OR (NEW.asserted_at, NEW.refusal, NEW.assertion_evidence, NEW.authenticator_id,
               NEW.session_id) IS DISTINCT FROM (NULL::timestamptz, NULL::text, NULL::jsonb,
                                                  NULL::uuid, NULL::uuid) THEN
            RAISE EXCEPTION 'ELV03: ticket %: before its assertion only a challenge is stored, '
                            'and never cleared', OLD.id
                USING ERRCODE = 'ELV03';
        END IF;
        RETURN NEW;
    END IF;
    -- The assertion: once, now, on a started ceremony, keeping its challenge.
    IF OLD.challenge_state IS NULL THEN
        RAISE EXCEPTION 'ELV06: ticket %: no ceremony was started', OLD.id
            USING ERRCODE = 'ELV06';
    END IF;
    IF NEW.asserted_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS DISTINCT FROM OLD.challenge_state
       OR jsonb_typeof(NEW.assertion_evidence) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'ELV03: ticket % is asserted once, now, with its evidence, keeping its '
                        'challenge', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF NEW.outcome = 'confirmed'
       AND NOT EXISTS (SELECT 1 FROM public.elevation_sessions s
                        WHERE s.id = NEW.session_id AND s.ticket_id = OLD.id
                          AND s.authenticator_id = NEW.authenticator_id) THEN
        RAISE EXCEPTION 'ELV03: ticket % is confirmed only by the session it opened', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_tickets_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_tickets_guard_update ON public.elevation_tickets;
CREATE TRIGGER elevation_tickets_guard_update
    BEFORE UPDATE ON public.elevation_tickets
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_tickets_guard_update();

-- BEFORE INSERT on `elevation_sessions`: ELV03 (birth shape), ELV06 (its
-- ticket is live, started, unasserted, and says the same thing), ELV02 (the
-- assignment is the person's live elevating one NOW, and the passkey is the
-- person's live one). The 15-minute bound is the table's CHECK, which this
-- guard deliberately does not pre-empt.
CREATE OR REPLACE FUNCTION public.epigraph_elevation_sessions_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket public.elevation_tickets%ROWTYPE;
BEGIN
    IF NEW.started_at IS DISTINCT FROM now()
       OR NEW.ended_at IS NOT NULL OR NEW.ended_reason IS NOT NULL
       OR NEW.ended_by IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: a session is recorded un-ended, started now()'
            USING ERRCODE = 'ELV03';
    END IF;
    SELECT * INTO v_ticket FROM public.elevation_tickets t
     WHERE t.id = NEW.ticket_id FOR UPDATE;
    IF NOT FOUND OR v_ticket.outcome IS NOT NULL OR now() >= v_ticket.expires_at
       OR v_ticket.challenge_state IS NULL
       OR (v_ticket.person_agent_id, v_ticket.client_id, v_ticket.family_id, v_ticket.mode,
           v_ticket.reason)
          IS DISTINCT FROM
          (NEW.person_agent_id, NEW.client_id, NEW.family_id, NEW.mode, NEW.reason) THEN
        RAISE EXCEPTION 'ELV06: ticket % is not a live, started, unasserted ticket for this '
                        'session', NEW.ticket_id
            USING ERRCODE = 'ELV06';
    END IF;
    IF NEW.assignment_id IS DISTINCT FROM
       public.epigraph_live_elevating_assignment(NEW.person_agent_id, now()) THEN
        RAISE EXCEPTION 'ELV02: assignment % is not %''s live elevating assignment',
                        NEW.assignment_id, NEW.person_agent_id
            USING ERRCODE = 'ELV02';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.person_authenticators a
                    WHERE a.id = NEW.authenticator_id
                      AND a.person_agent_id = NEW.person_agent_id
                      AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'ELV02: passkey % is not a live passkey of %', NEW.authenticator_id,
                        NEW.person_agent_id
            USING ERRCODE = 'ELV02';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_sessions_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_sessions_guard_insert ON public.elevation_sessions;
CREATE TRIGGER elevation_sessions_guard_insert
    BEFORE INSERT ON public.elevation_sessions
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_sessions_guard_insert();

-- BEFORE UPDATE on `elevation_sessions`: only the one end (now(), by this
-- login, with a reason); an ended session is final.
CREATE OR REPLACE FUNCTION public.epigraph_elevation_sessions_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: session % has ended, and an ended session is final', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF NEW.ended_at IS DISTINCT FROM now()
       OR NEW.ended_by IS DISTINCT FROM session_user::text
       OR NEW.ended_reason IS NULL
       OR (NEW.id, NEW.person_agent_id, NEW.assignment_id, NEW.client_id, NEW.family_id,
           NEW.mode, NEW.reason, NEW.ticket_id, NEW.authenticator_id, NEW.started_at,
           NEW.expires_at)
          IS DISTINCT FROM
          (OLD.id, OLD.person_agent_id, OLD.assignment_id, OLD.client_id, OLD.family_id,
           OLD.mode, OLD.reason, OLD.ticket_id, OLD.authenticator_id, OLD.started_at,
           OLD.expires_at) THEN
        RAISE EXCEPTION 'ELV03: a session is only ever ended (ended_at = now(), ended_by = the '
                        'ending login, and a reason), nothing else; nothing was changed'
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_sessions_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_sessions_guard_update ON public.elevation_sessions;
CREATE TRIGGER elevation_sessions_guard_update
    BEFORE UPDATE ON public.elevation_sessions
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_sessions_guard_update();

-- ===================================================================
-- 4. THE AUDIT, FROM THE TABLES (123's pattern)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_elevation_tickets_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.elevation_requested', NEW.person_agent_id, true,
                jsonb_build_object('ticket_id', NEW.id, 'person', NEW.person_agent_id,
                                   'client_id', NEW.client_id, 'family_id', NEW.family_id,
                                   'mode', NEW.mode, 'reason', NEW.reason,
                                   'expires_at', NEW.expires_at));
    ELSIF OLD.outcome IS NULL AND NEW.outcome = 'refused' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.elevation_refused', NEW.person_agent_id, false,
                jsonb_build_object('ticket_id', NEW.id, 'person', NEW.person_agent_id,
                                   'client_id', NEW.client_id, 'family_id', NEW.family_id,
                                   'mode', NEW.mode, 'refusal', NEW.refusal,
                                   'code', CASE NEW.refusal WHEN 'counter_regressed'
                                                THEN 'ELV05' ELSE 'ELV02' END,
                                   'authenticator_id', NEW.authenticator_id,
                                   'credential_person',
                                   (SELECT a.person_agent_id FROM public.person_authenticators a
                                     WHERE a.id = NEW.authenticator_id)));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_tickets_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_tickets_audit ON public.elevation_tickets;
CREATE TRIGGER elevation_tickets_audit
    AFTER INSERT OR UPDATE ON public.elevation_tickets
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_tickets_audit();

CREATE OR REPLACE FUNCTION public.epigraph_elevation_sessions_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.elevated', NEW.person_agent_id, true,
                jsonb_build_object('session_id', NEW.id, 'person', NEW.person_agent_id,
                                   'assignment_id', NEW.assignment_id,
                                   'client_id', NEW.client_id, 'family_id', NEW.family_id,
                                   'mode', NEW.mode, 'reason', NEW.reason,
                                   'ticket_id', NEW.ticket_id,
                                   'authenticator_id', NEW.authenticator_id,
                                   'started_at', NEW.started_at, 'expires_at', NEW.expires_at));
    ELSIF OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.elevation_ended', NEW.person_agent_id, true,
                jsonb_build_object('session_id', NEW.id, 'person', NEW.person_agent_id,
                                   'assignment_id', NEW.assignment_id,
                                   'family_id', NEW.family_id,
                                   'ended_reason', NEW.ended_reason, 'ended_by', NEW.ended_by,
                                   'started_at', NEW.started_at, 'expires_at', NEW.expires_at,
                                   'ended_at', NEW.ended_at));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_sessions_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS elevation_sessions_audit ON public.elevation_sessions;
CREATE TRIGGER elevation_sessions_audit
    AFTER INSERT OR UPDATE ON public.elevation_sessions
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_elevation_sessions_audit();

-- ===================================================================
-- 5. ENDS BY TRIGGER (each end is audited by the session audit above)
--
-- `epigraph_is_elevated()` already answers false the moment any of these
-- happen (it re-checks on every statement); the triggers make the row say so
-- too, so the trail and the one-per-family index agree with it. A session
-- already past its expiry is ended `expired`, not with the cause.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_end_elevations_on_assignment_revoke()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    UPDATE public.elevation_sessions s
       SET ended_at = now(), ended_by = session_user,
           ended_reason = CASE WHEN now() >= s.expires_at THEN 'expired'
                               ELSE 'assignment_revoked' END
     WHERE s.assignment_id = NEW.id AND s.ended_at IS NULL;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_elevations_on_assignment_revoke() FROM PUBLIC;

DROP TRIGGER IF EXISTS role_assignments_end_elevations ON public.role_assignments;
CREATE TRIGGER role_assignments_end_elevations
    AFTER UPDATE ON public.role_assignments
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_end_elevations_on_assignment_revoke();

CREATE OR REPLACE FUNCTION public.epigraph_end_elevations_on_operator_revoke()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    UPDATE public.elevation_sessions s
       SET ended_at = now(), ended_by = session_user,
           ended_reason = CASE WHEN now() >= s.expires_at THEN 'expired'
                               ELSE 'operator_revoked' END
     WHERE s.person_agent_id = NEW.agent_id AND s.ended_at IS NULL;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_elevations_on_operator_revoke() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_operators_end_elevations ON public.human_operators;
CREATE TRIGGER human_operators_end_elevations
    AFTER UPDATE ON public.human_operators
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_end_elevations_on_operator_revoke();

-- 118's reuse detector revokes every live token of the family with
-- `revoked_reason = 'reuse'`; that, and only that, ends the family's
-- elevation (a rotation is not an end: the family lives on). Amends nothing
-- in 118.
CREATE OR REPLACE FUNCTION public.epigraph_end_elevations_on_family_reuse()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    UPDATE public.elevation_sessions s
       SET ended_at = now(), ended_by = session_user,
           ended_reason = CASE WHEN now() >= s.expires_at THEN 'expired'
                               ELSE 'family_reuse' END
     WHERE s.family_id = COALESCE(NEW.family_id, NEW.id) AND s.ended_at IS NULL;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_elevations_on_family_reuse() FROM PUBLIC;

DROP TRIGGER IF EXISTS refresh_tokens_end_elevations ON public.refresh_tokens;
CREATE TRIGGER refresh_tokens_end_elevations
    AFTER UPDATE ON public.refresh_tokens
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
          AND NEW.revoked_reason = 'reuse')
    EXECUTE FUNCTION public.epigraph_end_elevations_on_family_reuse();

-- ===================================================================
-- 6. ROW SECURITY: the application reads no row and writes none directly.
-- No DELETE policy: under FORCE nobody deletes a row.
-- ===================================================================
ALTER TABLE public.elevation_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.elevation_tickets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS elevation_tickets_read ON public.elevation_tickets;
CREATE POLICY elevation_tickets_read ON public.elevation_tickets
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS elevation_tickets_definer_insert ON public.elevation_tickets;
CREATE POLICY elevation_tickets_definer_insert ON public.elevation_tickets
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS elevation_tickets_definer_update ON public.elevation_tickets;
CREATE POLICY elevation_tickets_definer_update ON public.elevation_tickets
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

ALTER TABLE public.elevation_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.elevation_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS elevation_sessions_read ON public.elevation_sessions;
CREATE POLICY elevation_sessions_read ON public.elevation_sessions
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS elevation_sessions_definer_insert ON public.elevation_sessions;
CREATE POLICY elevation_sessions_definer_insert ON public.elevation_sessions
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS elevation_sessions_definer_update ON public.elevation_sessions;
CREATE POLICY elevation_sessions_definer_update ON public.elevation_sessions
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- 7. THE DEFINERS
-- ===================================================================

-- End every session of `p_person` (or of `p_family`) that is past its expiry
-- but un-ended (`expired`). Internal: the lazy half of the expiry (header).
CREATE OR REPLACE FUNCTION public.epigraph_end_expired_elevations(
    p_person uuid, p_family uuid)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    UPDATE public.elevation_sessions s
       SET ended_at = now(), ended_by = session_user, ended_reason = 'expired'
     WHERE s.ended_at IS NULL AND now() >= s.expires_at
       AND (s.person_agent_id = p_person OR s.family_id = p_family);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_expired_elevations(uuid, uuid) FROM PUBLIC;

-- Open a ticket for the SESSION PRINCIPAL (never a caller-supplied person) on
-- `p_client` / `p_family`, live 5 minutes. The table's guard refuses ELV02
-- (section 1 of the header); this adds the principal binding and refuses a
-- family that is already elevated. `p_redeem_hash` is SHA-256 of the
-- grant-mode secret (NULL in connector mode). Returns the ticket id; the
-- ceremony path is `/elevate/<id>`.
CREATE OR REPLACE FUNCTION public.epigraph_create_elevation_ticket(
    p_client uuid, p_family uuid, p_mode text, p_reason text, p_redeem_hash bytea)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_person uuid := public.epigraph_principal_id();
    v_id     uuid;
BEGIN
    IF v_person IS NULL THEN
        RAISE EXCEPTION 'ELV02: an elevation ticket is requested by an authenticated human '
                        'principal'
            USING ERRCODE = 'ELV02';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_create_elevation_ticket: a reason is required'
            USING ERRCODE = '22004';
    END IF;
    PERFORM public.epigraph_end_expired_elevations(v_person, p_family);
    IF EXISTS (SELECT 1 FROM public.elevation_sessions s
                WHERE s.family_id = p_family AND s.ended_at IS NULL) THEN
        RAISE EXCEPTION 'ELV06: family % is already elevated; end it first', p_family
            USING ERRCODE = 'ELV06';
    END IF;
    INSERT INTO public.elevation_tickets (person_agent_id, client_id, family_id, mode, reason,
                                          redeem_secret_hash, expires_at)
    VALUES (v_person, p_client, p_family, p_mode, p_reason, p_redeem_hash,
            now() + interval '5 minutes')
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_create_elevation_ticket(uuid, uuid, text, text, bytea)
    FROM PUBLIC;

-- The ceremony page's view of ONE ticket, only while it is live (unasserted,
-- unexpired); otherwise no row. App-callable, keyed by the ticket id alone
-- (the page is unauthenticated: the URL is the capability); it enumerates
-- nothing and returns no secret.
CREATE OR REPLACE FUNCTION public.epigraph_ticket_for_ceremony(p_ticket uuid)
RETURNS TABLE (person_agent_id uuid, client_id uuid, client_name text, family_id uuid,
               mode text, reason text, expires_at timestamptz, challenge_state jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT t.person_agent_id, t.client_id, c.client_name, t.family_id, t.mode, t.reason,
           t.expires_at, t.challenge_state
      FROM public.elevation_tickets t
      JOIN public.oauth_clients c ON c.id = t.client_id
     WHERE t.id = p_ticket
       AND t.outcome IS NULL
       AND now() < t.expires_at
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_ticket_for_ceremony(uuid) FROM PUBLIC;

-- Store the library's authentication state for the ceremony in flight (a
-- restarted ceremony overwrites it). App-callable; ELV06 when not live.
CREATE OR REPLACE FUNCTION public.epigraph_set_elevation_ticket_challenge(
    p_ticket uuid, p_state jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_state IS NULL OR jsonb_typeof(p_state) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_set_elevation_ticket_challenge: a challenge state object is '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.elevation_tickets SET challenge_state = p_state WHERE id = p_ticket;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'ELV06: no ticket %', p_ticket
            USING ERRCODE = 'ELV06';
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_elevation_ticket_challenge(uuid, jsonb)
    FROM PUBLIC;

-- The ticket's PERSON's live passkeys (the ceremony's allowCredentials and
-- the verifier's keys), only while the ticket is live. Never anyone else's.
CREATE OR REPLACE FUNCTION public.epigraph_passkeys_for_ticket(p_ticket uuid)
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

-- Record a verified assertion over a live, started ticket. App-callable (the
-- ceremony page is unauthenticated; the caller is the API, which verified the
-- assertion with the WebAuthn library against `epigraph_passkeys_for_ticket`).
--
-- REFUSED (the ticket is marked refused, `platform.elevation_refused` is
-- written, and the refusal is RETURNED, never raised, so the audit commits):
--   credential_unknown, person_mismatch (the credential is another person's:
--   the confused deputy), credential_revoked, counter_regressed (ELV05; also
--   `platform.passkey_counter_regressed`), backup_eligibility_changed (a
--   passkey registered as device-bound asserting as backup-eligible),
--   no_live_assignment (D2 re-checked at use time: the person no longer holds
--   a live elevating assignment, is de-registered, or is linked as an agent),
--   family_revoked.
-- CONFIRMED: the family's expired sessions are ended, the passkey's use and
-- counter are recorded, a session opens (at most 15 minutes, and never past
-- the assignment's own window) with the assignment live at this instant, and
-- `platform.elevated` is written.
-- RAISED (nothing to audit): ELV06 when the ticket is not live and started, or
-- the family is already elevated.
CREATE OR REPLACE FUNCTION public.epigraph_confirm_elevation(
    p_ticket uuid, p_credential_id bytea, p_new_counter bigint, p_backup_eligible boolean,
    p_evidence jsonb)
RETURNS TABLE (outcome text, session_id uuid, expires_at timestamptz, refusal text,
               code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket     public.elevation_tickets%ROWTYPE;
    v_auth       public.person_authenticators%ROWTYPE;
    v_refusal    text;
    v_assignment uuid;
    v_valid_to   timestamptz;
    v_session    uuid;
    v_expires    timestamptz;
BEGIN
    IF p_new_counter IS NULL OR p_backup_eligible IS NULL OR p_evidence IS NULL
       OR jsonb_typeof(p_evidence) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_confirm_elevation: the counter, the backup-eligible flag and '
                        'an evidence object are required'
            USING ERRCODE = '22004';
    END IF;
    SELECT * INTO v_ticket FROM public.elevation_tickets t WHERE t.id = p_ticket FOR UPDATE;
    IF NOT FOUND OR v_ticket.outcome IS NOT NULL OR now() >= v_ticket.expires_at
       OR v_ticket.challenge_state IS NULL THEN
        RAISE EXCEPTION 'ELV06: ticket % is not a live, started ticket', p_ticket
            USING ERRCODE = 'ELV06';
    END IF;

    SELECT * INTO v_auth FROM public.person_authenticators a
     WHERE a.credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND THEN
        v_refusal := 'credential_unknown';
    ELSIF v_auth.person_agent_id IS DISTINCT FROM v_ticket.person_agent_id THEN
        v_refusal := 'person_mismatch';
    ELSIF v_auth.revoked_at IS NOT NULL THEN
        v_refusal := 'credential_revoked';
    ELSIF (p_new_counter <> 0 OR v_auth.sign_count <> 0)
          AND p_new_counter <= v_auth.sign_count THEN
        v_refusal := 'counter_regressed';
    ELSIF NOT v_auth.backup_eligible AND p_backup_eligible THEN
        v_refusal := 'backup_eligibility_changed';
    ELSE
        v_assignment := public.epigraph_live_elevating_assignment(v_ticket.person_agent_id,
                                                                  now());
        IF v_assignment IS NULL THEN
            v_refusal := 'no_live_assignment';
        ELSIF NOT public.epigraph_family_of_person_is_live(v_ticket.person_agent_id,
                                                            v_ticket.client_id,
                                                            v_ticket.family_id) THEN
            v_refusal := 'family_revoked';
        END IF;
    END IF;

    IF v_refusal IS NOT NULL THEN
        IF v_refusal = 'counter_regressed' THEN
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            VALUES ('platform.passkey_counter_regressed', v_auth.person_agent_id, false,
                    jsonb_build_object('authenticator_id', v_auth.id,
                                       'person', v_auth.person_agent_id,
                                       'stored_counter', v_auth.sign_count,
                                       'asserted_counter', p_new_counter,
                                       'ticket_id', v_ticket.id));
        END IF;
        UPDATE public.elevation_tickets t
           SET asserted_at = now(), outcome = 'refused', refusal = v_refusal,
               assertion_evidence = p_evidence, authenticator_id = v_auth.id
         WHERE t.id = v_ticket.id;
        RETURN QUERY SELECT 'refused'::text, NULL::uuid, NULL::timestamptz, v_refusal,
                            CASE WHEN v_refusal = 'counter_regressed' THEN 'ELV05'
                                 ELSE 'ELV02' END;
        RETURN;
    END IF;

    PERFORM public.epigraph_end_expired_elevations(NULL, v_ticket.family_id);
    IF EXISTS (SELECT 1 FROM public.elevation_sessions s
                WHERE s.family_id = v_ticket.family_id AND s.ended_at IS NULL) THEN
        RAISE EXCEPTION 'ELV06: family % is already elevated', v_ticket.family_id
            USING ERRCODE = 'ELV06';
    END IF;

    UPDATE public.person_authenticators a
       SET last_used_at = now(), sign_count = p_new_counter
     WHERE a.id = v_auth.id;

    SELECT ra.valid_to INTO v_valid_to FROM public.role_assignments ra
     WHERE ra.id = v_assignment;
    v_expires := LEAST(now() + interval '15 minutes', COALESCE(v_valid_to, 'infinity'));
    INSERT INTO public.elevation_sessions (person_agent_id, assignment_id, client_id, family_id,
                                           mode, reason, ticket_id, authenticator_id,
                                           expires_at)
    VALUES (v_ticket.person_agent_id, v_assignment, v_ticket.client_id, v_ticket.family_id,
            v_ticket.mode, v_ticket.reason, v_ticket.id, v_auth.id, v_expires)
    RETURNING id INTO v_session;

    UPDATE public.elevation_tickets t
       SET asserted_at = now(), outcome = 'confirmed', assertion_evidence = p_evidence,
           authenticator_id = v_auth.id, session_id = v_session
     WHERE t.id = v_ticket.id;

    RETURN QUERY SELECT 'confirmed'::text, v_session, v_expires, NULL::text, NULL::text;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, jsonb)
    FROM PUBLIC;

-- Grant mode: the token endpoint's redemption. `pending` while the ceremony
-- has not landed; `issued` ONCE for a confirmed ticket whose session is still
-- live (then `redeemed_at` is set); `invalid` for everything else (unknown,
-- wrong secret, a different client, connector mode, refused, redeemed,
-- expired before its assertion, session ended or no longer backed by a live
-- assignment), one answer for all so the endpoint is no oracle.
-- App-callable; the secret is the credential (`p_secret_hash` = SHA-256).
CREATE OR REPLACE FUNCTION public.epigraph_redeem_elevation_ticket(
    p_ticket uuid, p_secret_hash bytea, p_client uuid)
RETURNS TABLE (status text, session_id uuid, person_agent_id uuid, family_id uuid,
               expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket  public.elevation_tickets%ROWTYPE;
    v_session public.elevation_sessions%ROWTYPE;
BEGIN
    SELECT * INTO v_ticket FROM public.elevation_tickets t WHERE t.id = p_ticket FOR UPDATE;
    IF NOT FOUND OR v_ticket.mode <> 'grant'
       OR p_secret_hash IS NULL OR v_ticket.redeem_secret_hash IS DISTINCT FROM p_secret_hash
       OR v_ticket.client_id IS DISTINCT FROM p_client THEN
        RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid, NULL::uuid,
                            NULL::timestamptz;
        RETURN;
    END IF;
    IF v_ticket.outcome IS NULL THEN
        IF now() < v_ticket.expires_at THEN
            RETURN QUERY SELECT 'pending'::text, NULL::uuid, NULL::uuid, NULL::uuid,
                                NULL::timestamptz;
        ELSE
            RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid, NULL::uuid,
                                NULL::timestamptz;
        END IF;
        RETURN;
    END IF;
    SELECT * INTO v_session FROM public.elevation_sessions s WHERE s.id = v_ticket.session_id;
    IF v_ticket.outcome <> 'confirmed' OR v_ticket.redeemed_at IS NOT NULL
       OR v_session.ended_at IS NOT NULL OR now() >= v_session.expires_at
       OR public.epigraph_live_elevating_assignment(v_session.person_agent_id, now())
          IS DISTINCT FROM v_session.assignment_id THEN
        RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid, NULL::uuid,
                            NULL::timestamptz;
        RETURN;
    END IF;
    UPDATE public.elevation_tickets t SET redeemed_at = now() WHERE t.id = v_ticket.id;
    RETURN QUERY SELECT 'issued'::text, v_session.id, v_session.person_agent_id,
                        v_session.family_id, v_session.expires_at;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid)
    FROM PUBLIC;

-- The session principal's live elevation on family `p_fam`: the session named
-- by `p_elv` (any mode), or, when `p_elv` is NULL, the family's live
-- CONNECTOR-mode session (a grant-mode session is reached only through the
-- token that names it). No row when nothing is live. Principal-bound: an
-- unstamped session gets no row. The same test as `epigraph_is_elevated()`.
CREATE OR REPLACE FUNCTION public.epigraph_elevation_live(p_elv uuid, p_fam uuid)
RETURNS TABLE (session_id uuid, assignment_id uuid, family_id uuid, mode text,
               expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT s.id, s.assignment_id, s.family_id, s.mode, s.expires_at
      FROM public.elevation_sessions s
     WHERE p_fam IS NOT NULL
       AND s.family_id = p_fam
       AND ((p_elv IS NOT NULL AND s.id = p_elv)
            OR (p_elv IS NULL AND s.mode = 'connector'))
       AND s.person_agent_id = public.epigraph_principal_id()
       AND s.ended_at IS NULL
       AND now() < s.expires_at
       AND public.epigraph_live_elevating_assignment(s.person_agent_id, now())
           = s.assignment_id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_elevation_live(uuid, uuid) FROM PUBLIC;

-- End a session now. The session principal ends its own; a privileged session
-- ends any. `p_reason`: 'unsudo' or 'ended'. False when there was nothing to
-- end (unknown, someone else's, or already ended): no oracle.
CREATE OR REPLACE FUNCTION public.epigraph_end_elevation(p_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_reason IS NULL OR p_reason NOT IN ('unsudo', 'ended') THEN
        RAISE EXCEPTION 'epigraph_end_elevation: the reason is unsudo or ended, not %', p_reason
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.elevation_sessions s
       SET ended_at = now(), ended_by = session_user,
           ended_reason = CASE WHEN now() >= s.expires_at THEN 'expired' ELSE p_reason END
     WHERE s.id = p_id AND s.ended_at IS NULL
       AND (s.person_agent_id = public.epigraph_principal_id() OR public.epigraph_bypass());
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_elevation(uuid, text) FROM PUBLIC;

-- Is THIS statement's session elevated? STABLE, principal-bound, read by row
-- policies wrapped as `(SELECT public.epigraph_is_elevated())` so it runs once
-- per statement (an InitPlan). Fast false on an empty `epigraph.elevation_id`;
-- a malformed GUC is false, never an error. Otherwise true iff the session
-- named by `epigraph.elevation_id` is on `epigraph.family_id`, is the session
-- principal's, is un-ended and unexpired, and the person's live elevating
-- assignment is STILL the one it stored (registration, agent link, window and
-- revoke all re-checked, every statement). Never `instance_admins`.
CREATE OR REPLACE FUNCTION public.epigraph_is_elevated()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    -- PL/pgSQL, not SQL, deliberately: a SQL body's `current_setting(..)::uuid`
    -- is evaluated by the planner's selectivity estimate even behind a CASE,
    -- so a malformed GUC raised 22P02 "during startup" instead of answering
    -- false. Here the GUCs are checked first and bound as parameters.
    v_elv text := current_setting('epigraph.elevation_id', true);
    v_fam text := current_setting('epigraph.family_id', true);
    v_who text := current_setting('epigraph.principal_id', true);
    v_re  constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
BEGIN
    IF v_elv IS NULL OR v_elv = '' THEN
        RETURN false;
    END IF;
    IF v_elv !~ v_re OR v_fam IS NULL OR v_fam !~ v_re OR v_who IS NULL OR v_who !~ v_re THEN
        RETURN false;
    END IF;
    RETURN EXISTS (
        SELECT 1
          FROM public.elevation_sessions s
         WHERE s.id = v_elv::uuid
           AND s.family_id = v_fam::uuid
           AND s.person_agent_id = v_who::uuid
           AND s.ended_at IS NULL
           AND now() < s.expires_at
           AND public.epigraph_live_elevating_assignment(s.person_agent_id, now())
               = s.assignment_id);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_elevated() FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- 077's default privileges hand the application role DML on every new
-- table: taken back here, leaving SELECT (which the row policies narrow to
-- nothing). Every function is owned by the maintenance role, so its frame
-- passes `epigraph_definer_bypass()`. The application role may EXECUTE the
-- principal-bound definers and the ticket-keyed ceremony definers; never the
-- unbound helpers (`epigraph_live_elevating_assignment`,
-- `epigraph_family_of_person_is_live`, `epigraph_end_expired_elevations`).
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_live_elevating_assignment(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_family_of_person_is_live(uuid, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_tickets_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_tickets_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_sessions_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_sessions_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_tickets_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_sessions_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_elevations_on_assignment_revoke() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_elevations_on_operator_revoke() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_elevations_on_family_reuse() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_expired_elevations(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_create_elevation_ticket(uuid, uuid, text, text, '
                'bytea) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_ticket_for_ceremony(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_elevation_ticket_challenge(uuid, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_ticket(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, '
                'jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_elevation_live(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_elevation(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_is_elevated() OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.elevation_tickets, '
                'public.elevation_sessions TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_live_elevating_assignment(uuid, timestamptz), '
                'public.epigraph_family_of_person_is_live(uuid, uuid, uuid), '
                'public.epigraph_end_expired_elevations(uuid, uuid), '
                'public.epigraph_create_elevation_ticket(uuid, uuid, text, text, bytea), '
                'public.epigraph_ticket_for_ceremony(uuid), '
                'public.epigraph_set_elevation_ticket_challenge(uuid, jsonb), '
                'public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, jsonb), '
                'public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid), '
                'public.epigraph_elevation_live(uuid, uuid), '
                'public.epigraph_end_elevation(uuid, text), '
                'public.epigraph_is_elevated() TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.elevation_tickets, public.elevation_sessions '
                'FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.elevation_tickets, public.elevation_sessions '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_create_elevation_ticket(uuid, uuid, text, text, bytea), '
                'public.epigraph_ticket_for_ceremony(uuid), '
                'public.epigraph_set_elevation_ticket_challenge(uuid, jsonb), '
                'public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_confirm_elevation(uuid, bytea, bigint, boolean, jsonb), '
                'public.epigraph_redeem_elevation_ticket(uuid, bytea, uuid), '
                'public.epigraph_elevation_live(uuid, uuid), '
                'public.epigraph_end_elevation(uuid, text), '
                'public.epigraph_is_elevated() TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_live_elevating_assignment(uuid, timestamptz), '
                'public.epigraph_family_of_person_is_live(uuid, uuid, uuid), '
                'public.epigraph_end_expired_elevations(uuid, uuid) FROM epigraph_app';
    END IF;
END $$;

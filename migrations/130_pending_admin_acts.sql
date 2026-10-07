-- Migration 130: pending admin acts. A custodial write that a passkey holder
-- would make (a role grant, a role end, a custodial supersede, a later
-- passkey) is first PROPOSED while elevated, CONFIRMED by that person's
-- passkey over the act's content, and only then EXECUTED by the maintenance
-- CLI, which consumes the confirmed act in the write's own transaction. The
-- 123 guards are bound to it, so a direct maintenance statement meets the same
-- rule as the CLI.
--
-- ===================================================================
-- 1. THE MODEL
--
-- `pending_admin_acts`: one row per proposed act. Its KIND, its ARGS in
-- canonical form and their SHA-256 digest, the target it names, why it was
-- proposed, WHO proposed it (the session principal, never a caller-supplied
-- id), under which live elevation and role assignment, on which token
-- (`jti`), when it expires (at most an hour; the proposal definer gives it 30
-- minutes), the confirmation ceremony's stored challenge, its single outcome
-- (`confirmed` by a passkey of the proposer, or `refused` with why) with the
-- assertion evidence, and its single consumption (when, by which login, and
-- what it produced). A row is never deleted; every change is one of those
-- steps, in order.
--
-- THE KINDS (closed list):
--   role.grant                 {role, holder, valid_from, valid_to, reason}
--   role.end                   {assignment, reason}
--   claim.custodial_supersede  {claim, content_sha256, truth, reason, allow_owned}
--   passkey.register           {person, label, reason}
--
-- CANONICAL ARGS. `epigraph_admin_act_args(kind, args)` validates the args
-- of a kind (exactly its keys; each of its type) and rebuilds them in one
-- form: ids as lower-case hyphenated uuids, times as UTC with microseconds
-- and a `Z` (`epigraph_canonical_timestamp`), a truth value as a decimal
-- string with exactly six places (no floating-point text ever enters a
-- digest), a content digest as 64 lower-case hex digits; no numbers at all.
-- `epigraph_canonical_json` prints a value with object keys in byte order
-- and no whitespace (jsonb's own text orders keys by length and adds
-- spaces, so it is NOT the canonical form), and the digest is SHA-256 of that
-- text. The maintenance CLI recomputes both from its own flags
-- (`epigraph_db::admin_act`), so the two implementations are tested against
-- each other.
--
-- WHO PROPOSES. `epigraph_propose_admin_act(kind, args, reason, jti)` is
-- refused (`ELV07`) unless THIS connection is elevated
-- (`epigraph_is_elevated()`): only a live elevation of a person holding an
-- elevating role proposes. The insert guard repeats the binding on the TABLE
-- (the act's elevation must be a live session of its proposer on its
-- assignment), so a privileged login, on which no session is ever live,
-- cannot insert an act directly.
--
-- WHO CONFIRMS. `epigraph_confirm_admin_act(act, credential, counter,
-- backup_eligible, evidence)` records the outcome of the ceremony the API ran
-- (the challenge commits to the act: EL-12b). The credential must be a live
-- passkey of the PROPOSER (a different person's credential is refused
-- `person_mismatch`), its counter must not go back (`ELV05`, audited), and the
-- proposer must still hold the assignment the act was proposed under. A
-- refusal is recorded and RETURNED, never raised, so its audit commits (125's
-- rule); a refused act is final.
--
-- WHO EXECUTES (operator ruling OQ-1 (b)). The maintenance verbs
-- `grant-role`, `end-role-assignment`, `custodial-supersede` and
-- `passkey-enroll` take `--act <id>` and call the act-taking definers below.
-- The act is consumed by `epigraph_consume_admin_act` from INSIDE the write:
-- the role-assignment guards, the custodial-act recorder and the enrollment
-- guard. It refuses `ELV08` (no such act, not confirmed, consumed, expired,
-- its confirming passkey revoked, or its proposer no longer a live custodian)
-- and `ELV09` (an act of another kind, args whose digest differs from the
-- write's, or a write naming another actor than the proposer). The write's
-- args are recomputed by the database FROM THE WRITE (the new row, the
-- stored successor claim), never taken from the caller.
--
-- WHEN CONFIRMATION IS REQUIRED (open question EQ-2, default (a): per holder,
-- once that holder has a live passkey). `ELV10`:
--   * a grant naming a grantor (`granted_by`) that holds a live passkey, with
--     no `grant_act_id`;
--   * an end with no `revoke_act_id` while ANY live custodian holds a live
--     passkey (the end names no actor, so the database cannot tell whose
--     act it is, and requires a confirmation whenever one is available);
--   * a `claim.supersede` custodial act whose actor holds a live passkey,
--     with no act (the privatization acts have no act kind yet: they are
--     recorded `confirmation = 'none'` as before);
--   * a passkey enrollment opened on the maintenance DSN for a person who
--     already holds a live passkey (a later passkey comes from a confirmed
--     `passkey.register` act).
-- Bootstrap (no grantor, or a grantor with no passkey) stays a maintenance
-- act, recorded `confirmation = 'none'` in its `platform.` audit row, so the
-- trail shows every unconfirmed act. THE BREAK-GLASS: revoking a lost or
-- suspect passkey (`epigraph-operator revoke-passkey`, audited) lifts the
-- requirement for its holder; it also voids every confirmed, unconsumed act
-- that passkey confirmed.
--
-- WHAT THE TABLE CANNOT PROVE (125's limit, unchanged). The database cannot
-- verify a signature: a holder of the application DSN can confirm an act with
-- fabricated evidence (only for an act it could propose, which needs a live
-- elevation), and a holder of the maintenance DSN can write the rows with
-- triggers off. The evidence is stored so the offline verifier re-checks every
-- confirmation. What this migration closes is the 123 header's admission
-- that `granted_by` and a custodial act's actor were bare uuids the
-- maintenance login supplied: once the person behind them holds a passkey,
-- each such act is bound to that person's assertion over its digest.
--
-- ===================================================================
-- 2. WHAT IT AMENDS (each body is the earlier one plus the delta its comment
--    names; `docs/runbooks/130-undo.sql` restores every earlier body)
--
--   role_assignments: `ADD COLUMN revoke_act_id uuid` (nullable, metadata
--     only); `epigraph_role_assignments_guard_insert` (CUS02 no longer
--     refuses every `grant_act_id`: it must name a confirmed `role.grant`
--     act whose args equal the row and whose proposer is `granted_by`; a
--     `revoke_act_id` is never supplied at birth),
--     `epigraph_role_assignments_guard_update` (the end may carry a
--     `revoke_act_id`, bound the same way to a `role.end` act),
--     `epigraph_role_assignments_audit` (each row names its confirmation);
--   `epigraph_record_custodial_act`: a 7th parameter `p_act_id`, and the
--     six-parameter form kept as a wrapper for the binaries that call it;
--   `epigraph_passkey_enrollments_guard_insert` (124): the `confirmed_act`
--     path, and ELV10 for a later passkey;
--   new overloads `epigraph_grant_role(.., p_act)`,
--     `epigraph_end_role_assignment(.., p_act)` and
--     `epigraph_create_passkey_enrollment(.., p_act)`; the earlier forms keep
--     their bodies.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/130-undo.sql`. Roll back first every binary that calls a
-- function this file creates (docs/deploy.md).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. CANONICAL ARGS (pure; no table read)
-- ===================================================================

-- A JSON value printed canonically: object keys in byte order (COLLATE "C"),
-- arrays in order, no whitespace; strings and literals exactly as jsonb
-- prints them (the JSON escapes `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and
-- `\u00xx` in lower-case hex for the other control characters; every other
-- character verbatim).
CREATE OR REPLACE FUNCTION public.epigraph_canonical_json(p_value jsonb)
RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = public, pg_temp AS $$
DECLARE
    v_out text;
BEGIN
    CASE jsonb_typeof(p_value)
        WHEN 'object' THEN
            SELECT '{' || COALESCE(string_agg(to_jsonb(e.k)::text || ':'
                                              || public.epigraph_canonical_json(e.v),
                                              ',' ORDER BY e.k COLLATE "C"), '') || '}'
              INTO v_out FROM jsonb_each(p_value) AS e(k, v);
        WHEN 'array' THEN
            SELECT '[' || COALESCE(string_agg(public.epigraph_canonical_json(a.v), ','
                                              ORDER BY a.i), '') || ']'
              INTO v_out FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(v, i);
        ELSE
            v_out := p_value::text;
    END CASE;
    RETURN v_out;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_canonical_json(jsonb) FROM PUBLIC;

-- A time in the one form every act uses: UTC, microseconds, a `Z`.
CREATE OR REPLACE FUNCTION public.epigraph_canonical_timestamp(p_at timestamptz)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT
SET search_path = public, pg_temp AS $$
    SELECT to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_canonical_timestamp(timestamptz) FROM PUBLIC;

-- The args of one act of `p_kind`, validated and rebuilt in canonical form
-- (section 1 of the header). `22023` names what is wrong: an unknown kind, a
-- key the kind does not take, a missing or empty required value, a value of
-- the wrong type. Idempotent: canonical args come back unchanged.
CREATE OR REPLACE FUNCTION public.epigraph_admin_act_args(p_kind text, p_args jsonb)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp AS $$
DECLARE
    v_keys    text[];
    v_extra   text;
    v_truth   numeric;
    v_from    timestamptz;
    v_to      timestamptz;
BEGIN
    v_keys := CASE p_kind
                WHEN 'role.grant' THEN
                    ARRAY['role', 'holder', 'valid_from', 'valid_to', 'reason']
                WHEN 'role.end' THEN ARRAY['assignment', 'reason']
                WHEN 'claim.custodial_supersede' THEN
                    ARRAY['claim', 'content_sha256', 'truth', 'reason', 'allow_owned']
                WHEN 'passkey.register' THEN ARRAY['person', 'label', 'reason']
              END;
    IF v_keys IS NULL THEN
        RAISE EXCEPTION 'epigraph_admin_act_args: % is not an admin act kind', p_kind
            USING ERRCODE = '22023';
    END IF;
    IF p_args IS NULL OR jsonb_typeof(p_args) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_admin_act_args: the args of % are a JSON object', p_kind
            USING ERRCODE = '22023';
    END IF;
    SELECT k INTO v_extra FROM jsonb_object_keys(p_args) AS k WHERE k <> ALL (v_keys) LIMIT 1;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_admin_act_args: % takes no key %', p_kind, v_extra
            USING ERRCODE = '22023';
    END IF;
    -- Every kind carries a non-empty reason, as a string.
    IF jsonb_typeof(p_args->'reason') IS DISTINCT FROM 'string'
       OR length(btrim(p_args->>'reason')) = 0 THEN
        RAISE EXCEPTION 'epigraph_admin_act_args: % needs a non-empty string reason', p_kind
            USING ERRCODE = '22023';
    END IF;
    BEGIN
        IF p_kind = 'role.grant' THEN
            IF jsonb_typeof(p_args->'role') IS DISTINCT FROM 'string'
               OR (p_args->>'role') !~ '^role:[a-z][a-z0-9-]*$'
               OR jsonb_typeof(p_args->'holder') IS DISTINCT FROM 'string'
               OR jsonb_typeof(COALESCE(p_args->'valid_from', 'null'))
                  NOT IN ('string', 'null')
               OR jsonb_typeof(COALESCE(p_args->'valid_to', 'null'))
                  NOT IN ('string', 'null') THEN
                RAISE EXCEPTION 'role.grant: role (role:<key>), holder (uuid), valid_from and '
                                'valid_to (RFC 3339 or null)'
                    USING ERRCODE = '22023';
            END IF;
            v_from := (p_args->>'valid_from')::timestamptz;
            v_to := (p_args->>'valid_to')::timestamptz;
            IF NOT isfinite(COALESCE(v_from, now())) OR NOT isfinite(COALESCE(v_to, now())) THEN
                RAISE EXCEPTION 'role.grant: valid_from and valid_to are finite times (null is '
                                '"from the execution" / "open-ended")'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'role', p_args->>'role',
                'holder', ((p_args->>'holder')::uuid)::text,
                'valid_from', public.epigraph_canonical_timestamp(v_from),
                'valid_to', public.epigraph_canonical_timestamp(v_to),
                'reason', p_args->>'reason');
        ELSIF p_kind = 'role.end' THEN
            IF jsonb_typeof(p_args->'assignment') IS DISTINCT FROM 'string' THEN
                RAISE EXCEPTION 'role.end: assignment (uuid)'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'assignment', ((p_args->>'assignment')::uuid)::text,
                'reason', p_args->>'reason');
        ELSIF p_kind = 'claim.custodial_supersede' THEN
            IF jsonb_typeof(p_args->'claim') IS DISTINCT FROM 'string'
               OR jsonb_typeof(p_args->'content_sha256') IS DISTINCT FROM 'string'
               OR (p_args->>'content_sha256') !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(p_args->'truth') NOT IN ('string', 'number')
               OR jsonb_typeof(p_args->'allow_owned') IS DISTINCT FROM 'boolean' THEN
                RAISE EXCEPTION 'claim.custodial_supersede: claim (uuid), content_sha256 (64 '
                                'lower-case hex), truth (a decimal in [0, 1]), allow_owned '
                                '(boolean)'
                    USING ERRCODE = '22023';
            END IF;
            v_truth := (p_args->>'truth')::numeric;
            IF v_truth < 0 OR v_truth > 1 OR v_truth <> round(v_truth, 6) THEN
                RAISE EXCEPTION 'claim.custodial_supersede: truth % is not in [0, 1] with at '
                                'most six decimal places', p_args->>'truth'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'claim', ((p_args->>'claim')::uuid)::text,
                'content_sha256', p_args->>'content_sha256',
                'truth', round(v_truth, 6)::text,
                'reason', p_args->>'reason',
                'allow_owned', (p_args->>'allow_owned')::boolean);
        ELSE
            IF jsonb_typeof(p_args->'person') IS DISTINCT FROM 'string'
               OR jsonb_typeof(COALESCE(p_args->'label', 'null')) NOT IN ('string', 'null') THEN
                RAISE EXCEPTION 'passkey.register: person (uuid), label (string or null)'
                    USING ERRCODE = '22023';
            END IF;
            -- `label` absent reads as null, like the times.
            RETURN jsonb_build_object(
                'person', ((p_args->>'person')::uuid)::text,
                'label', COALESCE(p_args->'label', 'null'::jsonb),
                'reason', p_args->>'reason');
        END IF;
    EXCEPTION
        WHEN invalid_text_representation OR invalid_datetime_format
             OR datetime_field_overflow OR numeric_value_out_of_range THEN
            RAISE EXCEPTION 'epigraph_admin_act_args: a value of % does not parse: %',
                            p_kind, SQLERRM
                USING ERRCODE = '22023';
    END;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_act_args(text, jsonb) FROM PUBLIC;

-- SHA-256 of the canonical text of `p_args` (already canonical: callers pass
-- `epigraph_admin_act_args`' output).
CREATE OR REPLACE FUNCTION public.epigraph_admin_act_digest(p_args jsonb)
RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT
SET search_path = public, pg_temp AS $$
    SELECT sha256(convert_to(public.epigraph_canonical_json(p_args), 'UTF8'))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_act_digest(jsonb) FROM PUBLIC;

-- ===================================================================
-- 2. THE TABLE
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.pending_admin_acts (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               text NOT NULL CONSTRAINT pending_admin_acts_kind
                           CHECK (kind IN ('role.grant', 'role.end',
                                           'claim.custodial_supersede', 'passkey.register')),
    -- Canonical (`epigraph_admin_act_args`), and its digest.
    args               jsonb NOT NULL CONSTRAINT pending_admin_acts_args_shape
                           CHECK (jsonb_typeof(args) = 'object'),
    args_digest        bytea NOT NULL CONSTRAINT pending_admin_acts_digest_length
                           CHECK (length(args_digest) = 32),
    target_type        text NOT NULL CONSTRAINT pending_admin_acts_target_type
                           CHECK (target_type IN ('agent', 'role_assignment', 'claim')),
    target_id          uuid NOT NULL,
    reason             text NOT NULL CONSTRAINT pending_admin_acts_reason_present
                           CHECK (length(btrim(reason)) > 0),
    proposed_by        uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    elevation_id       uuid NOT NULL REFERENCES public.elevation_sessions(id) ON DELETE RESTRICT,
    assignment_id      uuid NOT NULL REFERENCES public.role_assignments(id) ON DELETE RESTRICT,
    -- The proposing token's id, when the caller has one.
    jti                text,
    proposed_at        timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    -- The WebAuthn library's authentication state for the confirmation.
    challenge_state    jsonb,
    asserted_at        timestamptz,
    outcome            text CONSTRAINT pending_admin_acts_outcome
                           CHECK (outcome IN ('confirmed', 'refused')),
    refusal            text CONSTRAINT pending_admin_acts_refusal
                           CHECK (refusal IN ('credential_unknown', 'person_mismatch',
                                              'credential_revoked', 'counter_regressed',
                                              'backup_eligibility_changed',
                                              'no_live_assignment')),
    assertion_evidence jsonb,
    -- The passkey the assertion named (when it is a known one, whoever's).
    authenticator_id   uuid REFERENCES public.person_authenticators(id) ON DELETE RESTRICT,
    consumed_at        timestamptz,
    consumed_by        text,
    result             jsonb,
    CONSTRAINT pending_admin_acts_ttl
        CHECK (expires_at > proposed_at AND expires_at <= proposed_at + interval '1 hour'),
    CONSTRAINT pending_admin_acts_challenge_shape
        CHECK (challenge_state IS NULL OR jsonb_typeof(challenge_state) = 'object'),
    CONSTRAINT pending_admin_acts_outcome_shape
        CHECK ((outcome IS NULL) = (asserted_at IS NULL)
               AND (outcome IS NULL) = (assertion_evidence IS NULL)
               AND (refusal IS NOT NULL) = (outcome IS NOT DISTINCT FROM 'refused')
               AND (outcome IS DISTINCT FROM 'confirmed' OR authenticator_id IS NOT NULL)),
    CONSTRAINT pending_admin_acts_consumed_shape
        CHECK ((consumed_at IS NULL) = (consumed_by IS NULL)
               AND (consumed_at IS NULL OR outcome = 'confirmed')
               AND (result IS NULL OR consumed_at IS NOT NULL))
);
REVOKE ALL ON public.pending_admin_acts FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_pending_admin_acts_proposer
    ON public.pending_admin_acts (proposed_by, proposed_at DESC);

-- ===================================================================
-- 3. WHO HOLDS A LIVE PASSKEY (internal; an unbound answer is an oracle)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_has_live_passkey(p_person uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_person IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.person_authenticators a
                    WHERE a.person_agent_id = p_person AND a.revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_has_live_passkey(uuid) FROM PUBLIC;

-- ===================================================================
-- 4. THE GUARDS (section 1 of the header)
-- ===================================================================

-- BEFORE INSERT: ELV03 (birth shape: canonical args and their digest, the
-- target the args name, unchallenged, unasserted, unconsumed, at now()) and
-- ELV07 (the act's elevation is a LIVE session of its proposer, on the
-- assignment it names: so no privileged login, on which no session is ever
-- live, and no unelevated session inserts an act).
CREATE OR REPLACE FUNCTION public.epigraph_pending_admin_acts_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_args jsonb;
BEGIN
    IF NEW.proposed_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS NOT NULL OR NEW.asserted_at IS NOT NULL
       OR NEW.outcome IS NOT NULL OR NEW.refusal IS NOT NULL
       OR NEW.assertion_evidence IS NOT NULL OR NEW.authenticator_id IS NOT NULL
       OR NEW.consumed_at IS NOT NULL OR NEW.consumed_by IS NOT NULL
       OR NEW.result IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: an act is recorded unchallenged, unasserted and unconsumed, at '
                        'now()'
            USING ERRCODE = 'ELV03';
    END IF;
    v_args := public.epigraph_admin_act_args(NEW.kind, NEW.args);
    IF NEW.args IS DISTINCT FROM v_args
       OR NEW.args_digest IS DISTINCT FROM public.epigraph_admin_act_digest(v_args)
       OR (NEW.target_type, NEW.target_id) IS DISTINCT FROM
          (CASE NEW.kind WHEN 'role.end' THEN 'role_assignment'
                         WHEN 'claim.custodial_supersede' THEN 'claim'
                         ELSE 'agent' END,
           (v_args->>CASE NEW.kind WHEN 'role.grant' THEN 'holder'
                                   WHEN 'role.end' THEN 'assignment'
                                   WHEN 'claim.custodial_supersede' THEN 'claim'
                                   ELSE 'person' END)::uuid) THEN
        RAISE EXCEPTION 'ELV03: an act stores its args in canonical form, their digest, and the '
                        'target they name'
            USING ERRCODE = 'ELV03';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.elevation_sessions s
                    WHERE s.id = NEW.elevation_id
                      AND s.person_agent_id = NEW.proposed_by
                      AND s.assignment_id = NEW.assignment_id
                      AND public.epigraph_elevation_session_is_live(s.id)) THEN
        RAISE EXCEPTION 'ELV07: an act is proposed only under a live elevation of its proposer '
                        '(elevation %)', NEW.elevation_id
            USING ERRCODE = 'ELV07';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_pending_admin_acts_guard_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS pending_admin_acts_guard_insert ON public.pending_admin_acts;
CREATE TRIGGER pending_admin_acts_guard_insert
    BEFORE INSERT ON public.pending_admin_acts
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_pending_admin_acts_guard_insert();

-- BEFORE UPDATE: a stored challenge while live and unasserted; one assertion
-- while live and challenged (a confirmation only by a live passkey of the
-- proposer); one consumption of a confirmed, unexpired act. Nothing else,
-- ever; a consumed or refused act is final.
CREATE OR REPLACE FUNCTION public.epigraph_pending_admin_acts_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF (NEW.id, NEW.kind, NEW.args, NEW.args_digest, NEW.target_type, NEW.target_id,
        NEW.reason, NEW.proposed_by, NEW.elevation_id, NEW.assignment_id, NEW.jti,
        NEW.proposed_at, NEW.expires_at)
       IS DISTINCT FROM
       (OLD.id, OLD.kind, OLD.args, OLD.args_digest, OLD.target_type, OLD.target_id,
        OLD.reason, OLD.proposed_by, OLD.elevation_id, OLD.assignment_id, OLD.jti,
        OLD.proposed_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'ELV03: act %: its identity never changes', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'ELV08: act % was consumed, and a consumed act is final', OLD.id
            USING ERRCODE = 'ELV08';
    END IF;
    IF OLD.outcome IS NOT NULL THEN
        -- Asserted: only the one consumption of a confirmed, unexpired act.
        IF OLD.outcome <> 'confirmed' OR now() >= OLD.expires_at
           OR NEW.consumed_at IS DISTINCT FROM now()
           OR NEW.consumed_by IS DISTINCT FROM session_user::text
           OR (NEW.challenge_state, NEW.asserted_at, NEW.outcome, NEW.refusal,
               NEW.assertion_evidence, NEW.authenticator_id)
              IS DISTINCT FROM
              (OLD.challenge_state, OLD.asserted_at, OLD.outcome, OLD.refusal,
               OLD.assertion_evidence, OLD.authenticator_id) THEN
            RAISE EXCEPTION 'ELV08: act % is asserted; only a confirmed, unexpired act is '
                            'consumed, once, now, by the consuming login', OLD.id
                USING ERRCODE = 'ELV08';
        END IF;
        RETURN NEW;
    END IF;
    IF now() >= OLD.expires_at THEN
        RAISE EXCEPTION 'ELV08: act % has expired; propose it again', OLD.id
            USING ERRCODE = 'ELV08';
    END IF;
    IF NEW.consumed_at IS NOT NULL OR NEW.consumed_by IS NOT NULL OR NEW.result IS NOT NULL THEN
        RAISE EXCEPTION 'ELV08: act % is not confirmed; nothing to consume', OLD.id
            USING ERRCODE = 'ELV08';
    END IF;
    IF NEW.outcome IS NULL THEN
        -- The challenge.
        IF NEW.challenge_state IS NULL
           OR (NEW.asserted_at, NEW.refusal, NEW.assertion_evidence, NEW.authenticator_id)
              IS DISTINCT FROM (NULL::timestamptz, NULL::text, NULL::jsonb, NULL::uuid) THEN
            RAISE EXCEPTION 'ELV03: act %: before its assertion only a challenge is stored, '
                            'and never cleared', OLD.id
                USING ERRCODE = 'ELV03';
        END IF;
        RETURN NEW;
    END IF;
    -- The assertion: once, now, on a started ceremony, keeping its challenge.
    IF OLD.challenge_state IS NULL THEN
        RAISE EXCEPTION 'ELV08: act %: no confirmation ceremony was started', OLD.id
            USING ERRCODE = 'ELV08';
    END IF;
    IF NEW.asserted_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS DISTINCT FROM OLD.challenge_state
       OR jsonb_typeof(NEW.assertion_evidence) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'ELV03: act % is asserted once, now, with its evidence, keeping its '
                        'challenge', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    IF NEW.outcome = 'confirmed'
       AND NOT EXISTS (SELECT 1 FROM public.person_authenticators a
                        WHERE a.id = NEW.authenticator_id
                          AND a.person_agent_id = OLD.proposed_by
                          AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'ELV02: act % is confirmed only by a live passkey of its proposer %',
                        OLD.id, OLD.proposed_by
            USING ERRCODE = 'ELV02';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_pending_admin_acts_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS pending_admin_acts_guard_update ON public.pending_admin_acts;
CREATE TRIGGER pending_admin_acts_guard_update
    BEFORE UPDATE ON public.pending_admin_acts
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_pending_admin_acts_guard_update();

-- AFTER INSERT / UPDATE: one `platform.` row per step (123's pattern).
CREATE OR REPLACE FUNCTION public.epigraph_pending_admin_acts_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.admin_act_proposed', NEW.proposed_by, true,
                jsonb_build_object('act_id', NEW.id, 'kind', NEW.kind, 'args', NEW.args,
                                   'args_digest', encode(NEW.args_digest, 'hex'),
                                   'target_type', NEW.target_type, 'target', NEW.target_id,
                                   'reason', NEW.reason, 'proposed_by', NEW.proposed_by,
                                   'elevation_id', NEW.elevation_id,
                                   'assignment_id', NEW.assignment_id, 'jti', NEW.jti,
                                   'expires_at', NEW.expires_at));
    ELSIF OLD.outcome IS NULL AND NEW.outcome IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES (CASE NEW.outcome WHEN 'confirmed' THEN 'platform.admin_act_confirmed'
                                 ELSE 'platform.admin_act_refused' END,
                NEW.proposed_by, NEW.outcome = 'confirmed',
                jsonb_build_object('act_id', NEW.id, 'kind', NEW.kind,
                                   'args_digest', encode(NEW.args_digest, 'hex'),
                                   'proposed_by', NEW.proposed_by,
                                   'elevation_id', NEW.elevation_id,
                                   'authenticator_id', NEW.authenticator_id,
                                   'refusal', NEW.refusal,
                                   'code', CASE WHEN NEW.refusal = 'counter_regressed'
                                                THEN 'ELV05'
                                                WHEN NEW.refusal IS NOT NULL THEN 'ELV02' END,
                                   'credential_person',
                                   (SELECT a.person_agent_id FROM public.person_authenticators a
                                     WHERE a.id = NEW.authenticator_id)));
    ELSIF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.admin_act_executed', NEW.proposed_by, true,
                jsonb_build_object('act_id', NEW.id, 'kind', NEW.kind,
                                   'args_digest', encode(NEW.args_digest, 'hex'),
                                   'proposed_by', NEW.proposed_by,
                                   'elevation_id', NEW.elevation_id,
                                   'authenticator_id', NEW.authenticator_id,
                                   'consumed_by', NEW.consumed_by, 'result', NEW.result));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_pending_admin_acts_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS pending_admin_acts_audit ON public.pending_admin_acts;
CREATE TRIGGER pending_admin_acts_audit
    AFTER INSERT OR UPDATE ON public.pending_admin_acts
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_pending_admin_acts_audit();

-- Row security, 125's pattern: the application role reads no row and writes
-- only through the definers below; a privileged session and a
-- maintenance-owned definer frame read and write; nobody deletes (no policy).
ALTER TABLE public.pending_admin_acts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pending_admin_acts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pending_admin_acts_definer_read ON public.pending_admin_acts;
CREATE POLICY pending_admin_acts_definer_read ON public.pending_admin_acts
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS pending_admin_acts_definer_insert ON public.pending_admin_acts;
CREATE POLICY pending_admin_acts_definer_insert ON public.pending_admin_acts
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS pending_admin_acts_definer_update ON public.pending_admin_acts;
CREATE POLICY pending_admin_acts_definer_update ON public.pending_admin_acts
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- 5. CONSUMPTION (internal: called from inside the write it authorizes)
--
-- Consume act `p_act` for a write of kind `p_kind` whose args (recomputed by
-- the caller FROM THE WRITE, then canonicalized) digest to `p_args_digest`,
-- made on the authority of `p_actor` (NULL: the write names no actor, as an
-- end does). ELV08: no such act, not confirmed, already consumed, expired,
-- its confirming passkey revoked, or its proposer no longer a live
-- custodian. ELV09: another kind, other args, another actor. Times are the
-- statement's clock. Returns the act's elevation (for the write's audit).
-- Maintenance-only: the application role writes none of the three tables it
-- guards.
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
    IF public.epigraph_live_role_assignment(v_act.proposed_by, 'role:platform-custodian',
                                            clock_timestamp()) IS NULL THEN
        RAISE EXCEPTION 'ELV08: the proposer % of act % no longer holds a live '
                        'role:platform-custodian assignment', v_act.proposed_by, p_act
            USING ERRCODE = 'ELV08';
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
-- 6. THE 123 GUARDS, AMENDED (signatures unchanged)
-- ===================================================================
ALTER TABLE public.role_assignments ADD COLUMN IF NOT EXISTS revoke_act_id uuid;

-- 123's insert guard; deltas: a `grant_act_id` is no longer refused outright
-- but must be consumed (a confirmed `role.grant` act whose args equal the row
-- and whose proposer is `granted_by`); a `revoke_act_id` is never supplied at
-- birth; a grantor holding a live passkey needs the act (ELV10).
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_any_live   boolean;
    v_other_live boolean;
    v_args       jsonb;
BEGIN
    -- A grant and a link of the same principal see each other (CUS06 and the
    -- shared lock: section 5, "A ROLE HOLDER IS NEVER LINKED AS AN AGENT").
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'CUS06: a role assignment is not written under REPEATABLE READ: its '
                        'snapshot predates the wait for a concurrent link of the holder, so '
                        'neither would see the other'
            USING ERRCODE = 'CUS06',
                  HINT = 'Run it under READ COMMITTED (the default) or SERIALIZABLE.';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT public.epigraph_is_human_operator(NEW.holder_person_id)
       OR EXISTS (SELECT 1 FROM public.operator_links l
                   WHERE l.agent_id = NEW.holder_person_id) THEN
        RAISE EXCEPTION 'CUS01: % is not a registered human operator that is no other '
                        'human''s agent; agents never hold a role', NEW.holder_person_id
            USING ERRCODE = 'CUS01',
                  HINT = 'Grant the role to the human''s own principal (a live human_operators '
                         'row with an active human OAuth client), never to an agent.';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.revoked_reason IS NOT NULL
       OR NEW.revoke_act_id IS NOT NULL THEN
        RAISE EXCEPTION 'CUS02: an assignment is recorded live; end it with '
                        'epigraph_end_role_assignment'
            USING ERRCODE = 'CUS02';
    END IF;
    IF NEW.valid_from < now() - interval '1 minute' THEN
        RAISE EXCEPTION 'CUS02: an assignment is never back-dated (valid_from % is before now)',
                        NEW.valid_from
            USING ERRCODE = 'CUS02';
    END IF;
    -- Provenance is the database's, never the writer's: the login that wrote
    -- the row, and when. (A `grant_act_id` is checked below: it must name an
    -- act this grant consumes.)
    IF NEW.granted_via IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now() THEN
        RAISE EXCEPTION 'CUS02: granted_via and created_at are recorded by the database (the '
                        'writing login, now()); a grant does not supply them'
            USING ERRCODE = 'CUS02';
    END IF;
    -- A LIVE custodian is what `epigraph_live_role_assignment` answers: the
    -- window, the end, and the holder re-checked (registered, not linked).
    SELECT EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian'
                      AND public.epigraph_live_role_assignment(ra.holder_person_id,
                              'role:platform-custodian', now()) IS NOT NULL),
           EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian'
                      AND ra.holder_person_id IS DISTINCT FROM NEW.holder_person_id
                      AND public.epigraph_live_role_assignment(ra.holder_person_id,
                              'role:platform-custodian', now()) IS NOT NULL)
      INTO v_any_live, v_other_live;
    IF NEW.granted_by IS NULL THEN
        IF v_any_live THEN
            RAISE EXCEPTION 'CUS03: a live custodian exists, so a grant names the granting '
                            'custodian'
                USING ERRCODE = 'CUS03';
        END IF;
    ELSIF public.epigraph_live_role_assignment(NEW.granted_by, 'role:platform-custodian', now())
          IS NULL THEN
        RAISE EXCEPTION 'CUS03: the grantor % holds no live role:platform-custodian assignment',
                        NEW.granted_by
            USING ERRCODE = 'CUS03';
    ELSIF NEW.granted_by = NEW.holder_person_id AND v_other_live THEN
        RAISE EXCEPTION 'CUS03: % may not extend its own assignment while another custodian '
                        'holds; that custodian grants it', NEW.holder_person_id
            USING ERRCODE = 'CUS03';
    END IF;
    -- 130: the confirmed act. Its args are recomputed from THIS row; a
    -- `valid_from` of now() (the grant definer's default) reads as "from the
    -- execution", which an act states as null.
    IF NEW.grant_act_id IS NOT NULL THEN
        IF NEW.granted_by IS NULL THEN
            RAISE EXCEPTION 'ELV09: a grant made on a confirmed act names its grantor, the '
                            'act''s proposer'
                USING ERRCODE = 'ELV09';
        END IF;
        v_args := public.epigraph_admin_act_args('role.grant', jsonb_build_object(
            'role', NEW.role, 'holder', NEW.holder_person_id,
            'valid_from', CASE WHEN NEW.valid_from = now() THEN NULL
                               ELSE public.epigraph_canonical_timestamp(NEW.valid_from) END,
            'valid_to', public.epigraph_canonical_timestamp(NEW.valid_to),
            'reason', NEW.reason));
        PERFORM public.epigraph_consume_admin_act(
            NEW.grant_act_id, 'role.grant', public.epigraph_admin_act_digest(v_args),
            NEW.granted_by, jsonb_build_object('assignment_id', NEW.id));
    ELSIF public.epigraph_has_live_passkey(NEW.granted_by) THEN
        RAISE EXCEPTION 'ELV10: the grantor % holds a passkey, so a grant it makes needs a '
                        'confirmed role.grant act', NEW.granted_by
            USING ERRCODE = 'ELV10',
                  HINT = 'Propose the grant while elevated, confirm it with the passkey, then '
                         'run epigraph-operator grant-role --act <id> with the same args.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_guard_insert() FROM PUBLIC;

-- 123's update guard; deltas: the end may carry a `revoke_act_id` (set once,
-- with the end), consumed as a confirmed `role.end` act over this assignment
-- and this reason; an end with none while any live custodian holds a live
-- passkey needs one (ELV10).
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'CUS02: assignment % has ended, and an ended assignment is final',
                        OLD.id
            USING ERRCODE = 'CUS02';
    END IF;
    IF NEW.revoked_at IS NULL OR NEW.revoked_at <> now()
       OR NEW.revoked_by IS DISTINCT FROM session_user::text
       OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
       OR (NEW.id, NEW.role, NEW.holder_person_id, NEW.holder_group_id, NEW.valid_from,
           NEW.valid_to, NEW.granted_by, NEW.granted_via, NEW.grant_act_id, NEW.reason,
           NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.role, OLD.holder_person_id, OLD.holder_group_id, OLD.valid_from,
           OLD.valid_to, OLD.granted_by, OLD.granted_via, OLD.grant_act_id, OLD.reason,
           OLD.created_at) THEN
        RAISE EXCEPTION 'CUS02: an assignment is only ever ended (revoked_at = now(), '
                        'revoked_by = the revoking login, and a revoked_reason), nothing '
                        'else; nothing was changed'
            USING ERRCODE = 'CUS02',
                  HINT = 'End it with epigraph-operator end-role-assignment and grant a new one.';
    END IF;
    IF NEW.revoke_act_id IS NOT NULL THEN
        PERFORM public.epigraph_consume_admin_act(
            NEW.revoke_act_id, 'role.end',
            public.epigraph_admin_act_digest(public.epigraph_admin_act_args('role.end',
                jsonb_build_object('assignment', OLD.id, 'reason', NEW.revoked_reason))),
            NULL, jsonb_build_object('assignment_id', OLD.id));
    ELSIF EXISTS (SELECT 1 FROM public.role_assignments ra
                   WHERE ra.role = 'role:platform-custodian'
                     AND ra.revoked_at IS NULL
                     AND public.epigraph_live_role_assignment(ra.holder_person_id,
                             'role:platform-custodian', now()) IS NOT NULL
                     AND public.epigraph_has_live_passkey(ra.holder_person_id)) THEN
        RAISE EXCEPTION 'ELV10: a live custodian holds a passkey, so ending assignment % needs '
                        'a confirmed role.end act', OLD.id
            USING ERRCODE = 'ELV10',
                  HINT = 'Propose the end while elevated, confirm it with the passkey, then run '
                         'epigraph-operator end-role-assignment --act <id>. For a lost passkey, '
                         'revoke it first (epigraph-operator revoke-passkey).';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_guard_update() FROM PUBLIC;

-- 123's audit; delta: each `platform.role_granted` / `platform.role_ended`
-- row names its confirmation ('passkey' with the act and its elevation, or
-- 'none').
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node uuid;
    v_act  uuid;
BEGIN
    SELECT r.role_node_id INTO v_node FROM public.platform_roles r WHERE r.key = NEW.role;
    IF TG_OP = 'INSERT' THEN
        -- Section 5: the projection, holder -> role node, in the edge's own
        -- validity columns. A structural (agent -> agent) edge: 120 owns it
        -- by the world group, public.
        INSERT INTO public.edges (source_id, source_type, target_id, target_type, relationship,
                                  properties, valid_from, valid_to, visibility, owner_group_id)
        VALUES (NEW.holder_person_id, 'agent', v_node, 'agent', 'OCCUPIES',
                jsonb_build_object('assignment_id', NEW.id::text, 'role', NEW.role,
                                   'source', 'role_assignments', 'projection', true),
                NEW.valid_from, NEW.valid_to, 'public',
                '00000000-0000-0000-0000-000000000000'::uuid);
        v_act := NEW.grant_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_granted', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by,
                                   'granted_via', NEW.granted_via, 'reason', NEW.reason,
                                   'migrated', NEW.granted_via = 'migration 123',
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- The projection closes at the end (or keeps an earlier valid_to).
        -- An assignment ended before it began keeps a one-microsecond window
        -- marked never_effective: `temporal_ordering` requires
        -- valid_to > valid_from.
        UPDATE public.edges e
           SET valid_to = CASE
                            WHEN LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                                 <= NEW.valid_from
                            THEN NEW.valid_from + interval '1 microsecond'
                            ELSE LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                          END,
               properties = e.properties
                   || jsonb_build_object('ended_at', NEW.revoked_at,
                                         'never_effective', NEW.revoked_at <= NEW.valid_from)
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.source_id = NEW.holder_person_id
           AND e.properties @> jsonb_build_object('assignment_id', NEW.id::text);
        -- Section 6: the end of the holder's LAST un-ended custodian
        -- assignment is mirrored into a live legacy `instance_admins` row, so a
        -- rollback to 083's body cannot resurrect an authority ended here.
        IF NEW.role = 'role:platform-custodian'
           AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                            WHERE ra.holder_person_id = NEW.holder_person_id
                              AND ra.role = 'role:platform-custodian'
                              AND ra.revoked_at IS NULL AND ra.id <> NEW.id) THEN
            UPDATE public.instance_admins SET revoked_at = now()
             WHERE agent_id = NEW.holder_person_id AND revoked_at IS NULL;
        END IF;
        v_act := NEW.revoke_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_ended', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoked_reason', NEW.revoked_reason,
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_audit() FROM PUBLIC;

-- The maintenance verbs' act-taking forms. They add nothing to the table's
-- rules: the guards above consume the act inside the INSERT / UPDATE.
CREATE OR REPLACE FUNCTION public.epigraph_grant_role(
    p_role text, p_holder uuid, p_valid_from timestamptz, p_valid_to timestamptz,
    p_granted_by uuid, p_reason text, p_act uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_role IS NULL OR p_holder IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_grant_role: the role, the holder and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.role_assignments (role, holder_person_id, valid_from, valid_to,
                                         granted_by, reason, grant_act_id)
    VALUES (p_role, p_holder, COALESCE(p_valid_from, now()), p_valid_to, p_granted_by, p_reason,
            p_act)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text, uuid)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_end_role_assignment(
    p_id uuid, p_reason text, p_act uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_id IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_end_role_assignment: the assignment and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.role_assignments
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason,
           revoke_act_id = p_act
     WHERE id = p_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_role_assignment(uuid, text, uuid) FROM PUBLIC;

-- ===================================================================
-- 7. THE CUSTODIAL ACT RECORDER, AMENDED
--
-- 123's recorder plus `p_act_id`. A `claim.supersede` recorded on a confirmed
-- `claim.custodial_supersede` act consumes it, with args the database
-- recomputes from the STORED successor (`p_details.new_id`, which must
-- supersede `p_target`): its content's SHA-256 and its truth value, the
-- reason and the allow-owned override the record carries. With no act, a
-- `claim.supersede` by an actor holding a live passkey is refused ELV10.
-- The privatization acts have no act kind yet and record as before. Every
-- row names its confirmation.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_record_custodial_act(
    p_assignment uuid, p_actor uuid, p_act text, p_target_type text, p_target uuid,
    p_details jsonb, p_act_id uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_row       public.role_assignments%ROWTYPE;
    v_id        uuid;
    v_successor uuid;
    v_content   text;
    v_truth     double precision;
    v_supersedes uuid;
    v_elevation uuid;
BEGIN
    IF p_act IS NULL OR p_act NOT IN ('claim.supersede', 'privatization.plan_create',
                                      'privatization.plan_transition') THEN
        RAISE EXCEPTION 'epigraph_record_custodial_act: % is not a recorded custodial act', p_act
            USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_row FROM public.role_assignments ra WHERE ra.id = p_assignment;
    IF NOT FOUND
       OR v_row.role <> 'role:platform-custodian'
       OR v_row.holder_person_id IS DISTINCT FROM p_actor
       OR v_row.revoked_at IS NOT NULL
       OR v_row.valid_from > clock_timestamp()
       OR (v_row.valid_to IS NOT NULL AND clock_timestamp() >= v_row.valid_to)
       OR NOT public.epigraph_is_human_operator(p_actor)
       OR EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_actor) THEN
        RAISE EXCEPTION 'CUS04: % is not a live role:platform-custodian assignment held by %; '
                        'nothing was recorded or changed', p_assignment, p_actor
            USING ERRCODE = 'CUS04',
                  HINT = 'Name the actor''s own live assignment: epigraph-operator '
                         'list-role-assignments --role role:platform-custodian.';
    END IF;
    IF p_act_id IS NOT NULL THEN
        IF p_act <> 'claim.supersede' THEN
            RAISE EXCEPTION 'ELV09: % has no admin act kind; it is recorded without one', p_act
                USING ERRCODE = 'ELV09';
        END IF;
        BEGIN
            v_successor := (p_details->>'new_id')::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            v_successor := NULL;
        END;
        SELECT c.content, c.truth_value, c.supersedes
          INTO v_content, v_truth, v_supersedes
          FROM public.claims c WHERE c.id = v_successor;
        IF NOT FOUND OR v_supersedes IS DISTINCT FROM p_target
           OR jsonb_typeof(p_details->'allow_owned') IS DISTINCT FROM 'boolean' THEN
            RAISE EXCEPTION 'ELV09: a confirmed custodial supersede records its successor '
                            '(details.new_id, superseding %) and its allow_owned override',
                            p_target
                USING ERRCODE = 'ELV09';
        END IF;
        v_elevation := public.epigraph_consume_admin_act(
            p_act_id, 'claim.custodial_supersede',
            public.epigraph_admin_act_digest(public.epigraph_admin_act_args(
                'claim.custodial_supersede', jsonb_build_object(
                    'claim', p_target,
                    'content_sha256', encode(sha256(convert_to(v_content, 'UTF8')), 'hex'),
                    'truth', round(v_truth::numeric, 6)::text,
                    'reason', p_details->'reason',
                    'allow_owned', p_details->'allow_owned'))),
            p_actor, jsonb_build_object('old_id', p_target, 'new_id', v_successor));
    ELSIF p_act = 'claim.supersede' AND public.epigraph_has_live_passkey(p_actor) THEN
        RAISE EXCEPTION 'ELV10: the custodian % holds a passkey, so a custodial supersede on '
                        'its authority needs a confirmed claim.custodial_supersede act', p_actor
            USING ERRCODE = 'ELV10',
                  HINT = 'Propose it while elevated, confirm it with the passkey, then run '
                         'epigraph-operator custodial-supersede --act <id> with the same args.';
    END IF;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.custodial_act', p_actor, true,
            jsonb_build_object('assignment_id', v_row.id, 'role', v_row.role,
                               'valid_from', v_row.valid_from, 'valid_to', v_row.valid_to,
                               'actor', p_actor, 'act', p_act,
                               'target_type', p_target_type, 'target', p_target,
                               'details', COALESCE(p_details, '{}'::jsonb),
                               'recorded_by', session_user,
                               'confirmation', CASE WHEN p_act_id IS NULL THEN 'none'
                                                    ELSE 'passkey' END,
                               'act_id', p_act_id, 'elevation_id', v_elevation))
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb, uuid) FROM PUBLIC;

-- 123's six-parameter form, kept for the binaries that call it: the
-- seven-parameter recorder with no act.
CREATE OR REPLACE FUNCTION public.epigraph_record_custodial_act(
    p_assignment uuid, p_actor uuid, p_act text, p_target_type text, p_target uuid,
    p_details jsonb)
RETURNS uuid
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_record_custodial_act(p_assignment, p_actor, p_act, p_target_type,
                                                p_target, p_details, NULL::uuid)
$$;

-- ===================================================================
-- 8. PASSKEY ENROLLMENT, AMENDED (124)
--
-- 124's insert guard; deltas: `created_via = 'confirmed_act'` is admitted
-- when its `act_id` is a confirmed `passkey.register` act of the enrolled
-- person (consumed here); a maintenance enrollment for a person who already
-- holds a live passkey is refused ELV10.
-- ===================================================================
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
    IF NEW.created_via = 'confirmed_act' THEN
        PERFORM public.epigraph_consume_admin_act(
            NEW.act_id, 'passkey.register',
            public.epigraph_admin_act_digest(public.epigraph_admin_act_args('passkey.register',
                jsonb_build_object('person', NEW.person_agent_id, 'label', NEW.label,
                                   'reason', NEW.reason))),
            NEW.person_agent_id, jsonb_build_object('enrollment_id', NEW.id));
    ELSIF public.epigraph_has_live_passkey(NEW.person_agent_id) THEN
        RAISE EXCEPTION 'ELV10: % already holds a passkey, so a later one is enrolled on a '
                        'confirmed passkey.register act', NEW.person_agent_id
            USING ERRCODE = 'ELV10',
                  HINT = 'Propose passkey.register while elevated and confirm it with the '
                         'existing passkey, then run epigraph-operator passkey-enroll --act '
                         '<id>. For a lost passkey, revoke it first (revoke-passkey).';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkey_enrollments_guard_insert() FROM PUBLIC;

-- 124's enrollment opener plus the act (`created_via = 'confirmed_act'` when
-- `p_act` is given). The 124 form keeps its body.
CREATE OR REPLACE FUNCTION public.epigraph_create_passkey_enrollment(
    p_person uuid, p_reason text, p_label text, p_act uuid)
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
    INSERT INTO public.passkey_enrollments (person_agent_id, reason, label, created_via, act_id,
                                            expires_at)
    VALUES (p_person, p_reason, p_label,
            CASE WHEN p_act IS NULL THEN 'maintenance' ELSE 'confirmed_act' END, p_act,
            now() + interval '15 minutes')
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_create_passkey_enrollment(uuid, text, text, uuid) FROM PUBLIC;

-- ===================================================================
-- 9. PROPOSAL AND CONFIRMATION (application-callable)
-- ===================================================================

-- Propose an act as the SESSION PRINCIPAL, under THIS connection's live
-- elevation (ELV07 otherwise). Canonicalizes the args (22023 for args the
-- kind does not take), stores their digest, names the target, gives the act
-- 30 minutes. `platform.admin_act_proposed` is written by the table's audit.
-- Returns the act id; the confirmation path is `/elevate/act/<id>`.
CREATE OR REPLACE FUNCTION public.epigraph_propose_admin_act(
    p_kind text, p_args jsonb, p_reason text, p_jti text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_person     uuid := public.epigraph_principal_id();
    v_elevation  uuid;
    v_assignment uuid;
    v_args       jsonb;
    v_id         uuid;
BEGIN
    IF NOT public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'ELV07: an admin act is proposed only by an elevated session'
            USING ERRCODE = 'ELV07',
                  HINT = 'Elevate first (a passkey ceremony), then propose.';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_propose_admin_act: a reason is required'
            USING ERRCODE = '22004';
    END IF;
    -- `epigraph_is_elevated()` has just checked the setting's shape.
    v_elevation := current_setting('epigraph.elevation_id', true)::uuid;
    SELECT s.assignment_id INTO v_assignment
      FROM public.elevation_sessions s WHERE s.id = v_elevation;
    v_args := public.epigraph_admin_act_args(p_kind, p_args);
    IF p_kind = 'passkey.register' AND (v_args->>'person')::uuid IS DISTINCT FROM v_person THEN
        RAISE EXCEPTION 'epigraph_propose_admin_act: a passkey.register act registers the '
                        'proposer''s own later passkey'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.pending_admin_acts (kind, args, args_digest, target_type, target_id,
                                           reason, proposed_by, elevation_id, assignment_id,
                                           jti, expires_at)
    VALUES (p_kind, v_args, public.epigraph_admin_act_digest(v_args),
            CASE p_kind WHEN 'role.end' THEN 'role_assignment'
                        WHEN 'claim.custodial_supersede' THEN 'claim'
                        ELSE 'agent' END,
            (v_args->>CASE p_kind WHEN 'role.grant' THEN 'holder'
                                  WHEN 'role.end' THEN 'assignment'
                                  WHEN 'claim.custodial_supersede' THEN 'claim'
                                  ELSE 'person' END)::uuid,
            p_reason, v_person, v_elevation, v_assignment, NULLIF(btrim(p_jti), ''),
            now() + interval '30 minutes')
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propose_admin_act(text, jsonb, text, text)
    FROM PUBLIC;

-- The confirmation page's view of ONE act, only while it is live (unasserted,
-- unexpired); otherwise no row. Keyed by the act id alone (the page is
-- unauthenticated: the URL is the capability, as for a ticket).
CREATE OR REPLACE FUNCTION public.epigraph_act_for_ceremony(p_act uuid)
RETURNS TABLE (kind text, args jsonb, args_digest bytea, reason text, proposed_by uuid,
               proposed_at timestamptz, expires_at timestamptz, challenge_state jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT a.kind, a.args, a.args_digest, a.reason, a.proposed_by, a.proposed_at,
           a.expires_at, a.challenge_state
      FROM public.pending_admin_acts a
     WHERE a.id = p_act
       AND a.outcome IS NULL
       AND now() < a.expires_at
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_act_for_ceremony(uuid) FROM PUBLIC;

-- Store the library's authentication state for the confirmation in flight (a
-- restarted ceremony overwrites it). ELV08 when the act is not live.
CREATE OR REPLACE FUNCTION public.epigraph_set_admin_act_challenge(p_act uuid, p_state jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_state IS NULL OR jsonb_typeof(p_state) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_set_admin_act_challenge: a challenge state object is required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.pending_admin_acts SET challenge_state = p_state WHERE id = p_act;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'ELV08: no admin act %', p_act
            USING ERRCODE = 'ELV08';
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_admin_act_challenge(uuid, jsonb) FROM PUBLIC;

-- The PROPOSER's live passkeys (the ceremony's allowCredentials and the
-- verifier's keys), only while the act is live. Never anyone else's.
CREATE OR REPLACE FUNCTION public.epigraph_passkeys_for_act(p_act uuid)
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

-- Record a verified assertion over a live, started act (125's
-- `epigraph_confirm_elevation`, for an act). REFUSED (recorded, audited,
-- RETURNED): credential_unknown, person_mismatch (another person's
-- credential: the proposer confirms its own act), credential_revoked,
-- counter_regressed (ELV05; also `platform.passkey_counter_regressed`),
-- backup_eligibility_changed, no_live_assignment (the proposer no longer holds
-- the assignment it proposed under). CONFIRMED: the passkey's use and counter
-- are recorded, the act is confirmed. RAISED: ELV08 when the act is not live
-- and started.
CREATE OR REPLACE FUNCTION public.epigraph_confirm_admin_act(
    p_act uuid, p_credential_id bytea, p_new_counter bigint, p_backup_eligible boolean,
    p_evidence jsonb)
RETURNS TABLE (outcome text, refusal text, code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_act     public.pending_admin_acts%ROWTYPE;
    v_auth    public.person_authenticators%ROWTYPE;
    v_refusal text;
BEGIN
    IF p_new_counter IS NULL OR p_backup_eligible IS NULL OR p_evidence IS NULL
       OR jsonb_typeof(p_evidence) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_confirm_admin_act: the counter, the backup-eligible flag and '
                        'an evidence object are required'
            USING ERRCODE = '22004';
    END IF;
    SELECT * INTO v_act FROM public.pending_admin_acts a WHERE a.id = p_act FOR UPDATE;
    IF NOT FOUND OR v_act.outcome IS NOT NULL OR now() >= v_act.expires_at
       OR v_act.challenge_state IS NULL THEN
        RAISE EXCEPTION 'ELV08: act % is not a live, started act', p_act
            USING ERRCODE = 'ELV08';
    END IF;

    SELECT * INTO v_auth FROM public.person_authenticators a
     WHERE a.credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND THEN
        v_refusal := 'credential_unknown';
    ELSIF v_auth.person_agent_id IS DISTINCT FROM v_act.proposed_by THEN
        v_refusal := 'person_mismatch';
    ELSIF v_auth.revoked_at IS NOT NULL THEN
        v_refusal := 'credential_revoked';
    ELSIF (p_new_counter <> 0 OR v_auth.sign_count <> 0)
          AND p_new_counter <= v_auth.sign_count THEN
        v_refusal := 'counter_regressed';
    ELSIF NOT v_auth.backup_eligible AND p_backup_eligible THEN
        v_refusal := 'backup_eligibility_changed';
    ELSIF public.epigraph_live_elevating_assignment(v_act.proposed_by, now())
          IS DISTINCT FROM v_act.assignment_id THEN
        v_refusal := 'no_live_assignment';
    END IF;

    IF v_refusal IS NOT NULL THEN
        IF v_refusal = 'counter_regressed' THEN
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            VALUES ('platform.passkey_counter_regressed', v_auth.person_agent_id, false,
                    jsonb_build_object('authenticator_id', v_auth.id,
                                       'person', v_auth.person_agent_id,
                                       'stored_counter', v_auth.sign_count,
                                       'asserted_counter', p_new_counter,
                                       'act_id', v_act.id));
        END IF;
        UPDATE public.pending_admin_acts a
           SET asserted_at = now(), outcome = 'refused', refusal = v_refusal,
               assertion_evidence = p_evidence, authenticator_id = v_auth.id
         WHERE a.id = v_act.id;
        RETURN QUERY SELECT 'refused'::text, v_refusal,
                            CASE WHEN v_refusal = 'counter_regressed' THEN 'ELV05'
                                 ELSE 'ELV02' END;
        RETURN;
    END IF;

    UPDATE public.person_authenticators a
       SET last_used_at = now(), sign_count = p_new_counter
     WHERE a.id = v_auth.id;
    UPDATE public.pending_admin_acts a
       SET asserted_at = now(), outcome = 'confirmed', assertion_evidence = p_evidence,
           authenticator_id = v_auth.id
     WHERE a.id = v_act.id;
    RETURN QUERY SELECT 'confirmed'::text, NULL::text, NULL::text;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- 077's default privileges hand the application role DML on every new table:
-- taken back here, leaving SELECT (which the row policies narrow to nothing).
-- Every definer is owned by the maintenance role. The application role may
-- EXECUTE the proposal definer (principal-bound, elevation-gated), the
-- act-keyed ceremony definers, and the pure canonical-form helpers; never the
-- consumer, the passkey oracle, or the act-taking maintenance verbs' forms.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_has_live_passkey(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_pending_admin_acts_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_pending_admin_acts_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_pending_admin_acts_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_consume_admin_act(uuid, text, bytea, uuid, '
                'jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_grant_role(text, uuid, timestamptz, '
                'timestamptz, uuid, text, uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_role_assignment(uuid, text, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_custodial_act(uuid, uuid, text, text, '
                'uuid, jsonb, uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_create_passkey_enrollment(uuid, text, text, '
                'uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propose_admin_act(text, jsonb, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_act_for_ceremony(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_admin_act_challenge(uuid, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_act(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, '
                'jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.pending_admin_acts '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_canonical_json(jsonb), '
                'public.epigraph_canonical_timestamp(timestamptz), '
                'public.epigraph_admin_act_args(text, jsonb), '
                'public.epigraph_admin_act_digest(jsonb), '
                'public.epigraph_has_live_passkey(uuid), '
                'public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb), '
                'public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text, '
                'uuid), '
                'public.epigraph_end_role_assignment(uuid, text, uuid), '
                'public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb, '
                'uuid), '
                'public.epigraph_create_passkey_enrollment(uuid, text, text, uuid), '
                'public.epigraph_propose_admin_act(text, jsonb, text, text), '
                'public.epigraph_act_for_ceremony(uuid), '
                'public.epigraph_set_admin_act_challenge(uuid, jsonb), '
                'public.epigraph_passkeys_for_act(uuid), '
                'public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.pending_admin_acts FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.pending_admin_acts TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_canonical_json(jsonb), '
                'public.epigraph_canonical_timestamp(timestamptz), '
                'public.epigraph_admin_act_args(text, jsonb), '
                'public.epigraph_admin_act_digest(jsonb), '
                'public.epigraph_propose_admin_act(text, jsonb, text, text), '
                'public.epigraph_act_for_ceremony(uuid), '
                'public.epigraph_set_admin_act_challenge(uuid, jsonb), '
                'public.epigraph_passkeys_for_act(uuid), '
                'public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb) '
                'TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_has_live_passkey(uuid), '
                'public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb), '
                'public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text, '
                'uuid), '
                'public.epigraph_end_role_assignment(uuid, text, uuid), '
                'public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb, '
                'uuid), '
                'public.epigraph_create_passkey_enrollment(uuid, text, text, uuid) '
                'FROM epigraph_app';
    END IF;
END $$;

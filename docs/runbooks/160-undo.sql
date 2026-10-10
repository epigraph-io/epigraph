-- ===================================================================
-- 160-undo.sql: take migration 160 (the elevation stack's final-review
-- corrections) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- WHAT IT DOES: restores, byte for byte, the body each function 160 re-bodied
-- had before it (`CREATE OR REPLACE` keeps the owners and the ACLs, as 160
-- did), and archives, then drops, what 160's section 4 added.
--   1. 124's `epigraph_person_authenticators_guard_insert` (a completion
--      checks only its enrollment's liveness again: a second maintenance
--      enrollment opened before the first passkey completes).
--   2. 130's `epigraph_consume_admin_act` (an act executes while its proposer
--      holds SOME live role:platform-custodian assignment again).
--   3. 132's `epigraph_elevated_access_ready` (the gate answers from the
--      existence of the recorder's names again, whoever owns them).
--   4. Archives every stored passkey registration into `security_events`
--      as one `platform.passkey_registration_archived` event (the passkey
--      id, its person and the registration: what the offline verifier
--      re-checks, which an undo must not erase), then drops the column, its
--      immutability trigger and the eight-argument completion. The API
--      binary that calls that form must be rolled back first.
--
-- ORDER: run this FIRST, before 132-undo and every other elevation undo.
-- Roll back first the API binary that calls 160's eight-argument completion
-- (step 4 drops it; a build older than 160 calls 124's form); nothing else
-- needs a binary rolled back.
--
-- WHAT IT LEAVES: every row 160's rules admitted or refused, and 160's
-- `_sqlx_migrations` row. Re-applying the corrections is a NEW migration,
-- never a re-run of 160. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- 1. 124's completion guard, verbatim.
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


-- 2. 130's act consumer, verbatim.
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

-- 3. 132's recorder gate, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT to_regclass('public.elevated_access') IS NOT NULL
       AND to_regprocedure(
               'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])'
           ) IS NOT NULL
$$;

-- 4. The stored registration: archived, then dropped.
DO $$
DECLARE
    v_rows bigint := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'person_authenticators'
                  AND column_name = 'registration') THEN
        EXECUTE $q$
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            SELECT 'platform.passkey_registration_archived', a.person_agent_id, true,
                   jsonb_build_object('passkey_id', a.id, 'enrollment_id', a.enrollment_id,
                                      'registration', a.registration,
                                      'archived_by', '160-undo')
              FROM public.person_authenticators a
             WHERE a.registration IS NOT NULL
             ORDER BY a.created_at, a.id
        $q$;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
    END IF;
    RAISE NOTICE '160-undo: archived % passkey registration(s) into security_events', v_rows;
END $$;
DROP FUNCTION IF EXISTS public.epigraph_complete_passkey_enrollment(
    uuid, bytea, jsonb, uuid, text, boolean, boolean, jsonb);
DROP TRIGGER IF EXISTS person_authenticators_registration_fixed
    ON public.person_authenticators;
DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_registration_fixed();
ALTER TABLE public.person_authenticators DROP COLUMN IF EXISTS registration;

COMMIT;

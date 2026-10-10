-- Migration 160: the elevation stack's final-review corrections (124-132 are
-- applied and immutable, so each correction re-bodies a function here; the
-- slot is the first after the drain block 140-159).
--
-- Each section is one decision. No section creates a table or changes a
-- policy or a grant: `CREATE OR REPLACE` keeps every re-bodied function's
-- owner (the maintenance role) and its ACL, which 124's, 125's and 130's
-- registers pin.
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

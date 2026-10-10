-- ===================================================================
-- 160-undo.sql: take migration 160 (the elevation stack's final-review
-- corrections) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- WHAT IT DOES: restores, byte for byte, the body each re-bodied function had
-- before 160. `CREATE OR REPLACE` keeps the owners and the ACLs, as 160 did.
--   1. 124's `epigraph_person_authenticators_guard_insert` (a completion
--      checks only its enrollment's liveness again: a second maintenance
--      enrollment opened before the first passkey completes).
--
-- ORDER: run this FIRST, before 132-undo and every other elevation undo. It
-- needs no binary rolled back first.
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


COMMIT;

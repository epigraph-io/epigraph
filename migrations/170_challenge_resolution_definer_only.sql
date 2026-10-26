-- 170: a challenge's resolution columns change only through
-- `epigraph_resolve_challenge` (operator ruling R-13, 2026-10-25; backlog
-- c6e20f43).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 168 made an OUTSIDER's challenge the outsider's own row (ruling
-- R-CH1), and added `epigraph_resolve_challenge` (ruling R-3) as the path by
-- which the challenged claim's owner sets the row's resolution status: it
-- stamps `resolved_by` with the SESSION PRINCIPAL and appends a
-- `security_events` row. But 077's `challenges_tenancy` policy still let the
-- row's owner plain-UPDATE every column of it, the four resolution columns
-- included (`state`, `resolved_by`, `resolved_at`, `resolution_details`), so
-- the outsider could name ANY agent as the resolver readers are shown, or file
-- a challenge born `accepted` with a forged resolver; and a writer of the
-- claim's group could do the same, unaudited, on an insider's row (which
-- inherits the claim's group). 168's header recorded the gap.
--
-- The ruling (R-13): the resolution columns change ONLY through
-- `epigraph_resolve_challenge`, which stamps the real caller; the outsider
-- owner may only set `state = 'withdrawn'` on its own challenge. R-14 (the
-- claim's owner may re-resolve, and resolve `pending` -> `accepted` /
-- `rejected` directly, every change audited) is 168's definer unchanged.
--
-- ===================================================================
-- 1. THE RULE
-- ===================================================================
--
-- One guard function, `epigraph_challenge_resolution_guard()`, on four ROW
-- triggers (three BEFORE, one AFTER INSERT). For an application session
-- (anything 114's `epigraph_session_is_privileged_writer()` says is NOT
-- privileged):
--
--   * UPDATE: the only change of the four resolution columns it may make is
--     the CHALLENGER's own withdrawal: `state` to `withdrawn`, from an
--     UNRESOLVED state (`pending`, `under_review`), on a row whose
--     `challenger_id` is the session principal, with `resolved_by`,
--     `resolved_at` and `resolution_details` unchanged. Anything else is
--     refused, CR07 (42501).
--   * INSERT: a challenge is born unresolved: `state = 'pending'` and the three
--     other columns NULL, else CR07 (42501).
--   * `challenger_id` names the filer and is fixed at filing: an INSERT's
--     `challenger_id` must be the session principal (plain `=`, so NULL is
--     refused), and an UPDATE that changes it is refused, CR08 (42501). The
--     INSERT half is an AFTER row trigger, so row security's `WITH CHECK`
--     answers an unstamped session first, as it did before this file; the
--     exception still aborts the statement, so nothing is written.
--   * DELETE: refused, CR09 (42501). A challenge is never removed by an
--     application session; the challenger retracts it by withdrawing it.
--
-- WHY `challenger_id` IS FIXED. The withdrawal arm above keys on
-- `OLD.challenger_id = epigraph_principal_id()`, and readers are shown
-- `challenger_id` as who filed the challenge. No earlier guard covers the
-- column (114/168's writer-owner guard and 115's owner guard watch tenancy
-- columns only), so without this a session row security lets UPDATE a row
-- could make itself that row's challenger and then withdraw it, or name any
-- agent as the filer of its own row or of a new one. Every filing path an
-- application session uses already passes its own principal: the HTTP
-- `submit_challenge` route (`Some(caller)` on the viewer-stamped transaction,
-- after refusing a body that names another challenger) and the MCP
-- `challenge_claim` tool (`Some(agent_id)` on the author-stamped
-- transaction). The paths that file with a NULL challenger (`gaps.rs`'s gap
-- challenges, `conflicts.rs::resolve_conflict`) run on the API's raw pool: on
-- a privileged connection this guard passes them; on an unstamped
-- `epigraph_app` connection 077's row security already refuses them.
-- `ChallengeRepository::insert_gap_challenge(agent_id)` has no non-test
-- caller; on an application session it now files only as the principal. No
-- path files on another agent's behalf, so none is exempted.
--
-- WHY DELETE IS REFUSED OUTRIGHT. 077 grants `epigraph_app` DELETE, and 115's
-- restrictive DELETE policy admits every writer of the row's owning group. So
-- without this arm the outsider, which owns its row since 168, could remove its
-- own challenge after the claim's owner ruled on it (going around the
-- withdrawn-only rule above), and a writer of the claim's group could remove a
-- colleague's insider challenge; neither leaves a trace on the challenge. No
-- binary path deletes a challenge on an application session: the seal
-- ceremony's derived-row DELETE of an insider's challenge runs on a
-- maintenance connection, which is privileged. `challenges.claim_id`'s foreign
-- key (001) has no `ON DELETE` action, so no cascade reaches this trigger.
-- Refusing every application DELETE, rather than some states of it, keeps
-- this arm independent of how the withdrawal rule is ruled.
--
-- WHY THE CHALLENGER CHECK. Row security alone admits every writer of the
-- row's owning group, and an INSIDER's challenge is owned by the claim's
-- group: without the check the claim's owner could plain-UPDATE a colleague's
-- challenge to `withdrawn`, unaudited, after which 168's CR06 refuses every
-- resolution of it. 077's `WITH CHECK` still applies on top (the challenger
-- must write the row's group), and 126 refuses an elevated session every
-- UPDATE.
--
-- WHY A SETTLED CHALLENGE IS NOT WITHDRAWN. 168's definer refuses to resolve a
-- withdrawn row (CR06: a withdrawal is the challenger's act and a resolution
-- must not overturn it). The converse must hold too: a withdrawal after the
-- claim's owner has ruled `accepted` / `rejected` would bury that verdict in
-- a state from which nobody can restate it. So only an unresolved challenge
-- is withdrawn; a settled one keeps its verdict, which the owner may still
-- re-resolve (R-14).
--
-- TWO READINGS OF R-13 PENDING AN OPERATOR RULING. R-13 says "the outsider
-- owner may only set state='withdrawn' on its own challenge". This file reads
-- it (a) as the CHALLENGER (`challenger_id` = the session principal), not
-- every writer of the row's owning group, and (b) as withdrawing an
-- UNRESOLVED challenge only (the two sections above give the reasons). Both
-- are the narrower reading. If the ruling differs, only the withdrawal arm of
-- the guard below (its `OLD.state IN (...)` and `OLD.challenger_id` clauses)
-- and its test arms change: the `challenger_id` rule and the DELETE refusal do
-- not depend on either answer.
--
-- TRUST BOUNDARY. The challenger check here and 168's resolver stamp both
-- read `epigraph_principal_id()`, the session's `epigraph.principal_id`
-- setting, which the HTTP and MCP transports stamp from the authenticated
-- caller. The guarantees in this file are for sessions stamped that way; a
-- connection that sets its own session settings sits outside them, the same
-- boundary as every principal-keyed rule in this schema.
--
-- The definer passes because it is owned by `epigraph_maintenance` (168
-- section 7), so inside its frame `current_user` is the maintenance role and
-- the invoker guard reads the session as privileged; so does a maintenance
-- session, a superuser and a BYPASSRLS role (the operator CLI, the migrator,
-- the test harness). Arm (c) / arm (d) propagation never names these columns.
--
-- WHY A TRIGGER AND NOT A NARROWER GRANT OR POLICY. A column grant cannot say
-- "`state` only to `withdrawn`", and a policy's `WITH CHECK` sees only the new
-- row, not the old one, so neither can express "unchanged" or "from an
-- unresolved state". 114's writer-owner guard and 115's owner guard on this
-- same table are triggers for the same reason. The trigger also binds every
-- non-privileged role, not only `epigraph_app`.
--
-- ===================================================================
-- 2. WHAT THIS FILE DOES NOT DO
-- ===================================================================
--
--   * It changes no row and no policy, and not 168's definer.
--   * It does not narrow a PRIVILEGED session's DELETE (the seal ceremony, the
--     operator CLI, the migrator).
--   * It does not change who reads a challenge, or who may edit its text.
--   * `ChallengeRepository::update_state` (a plain UPDATE of all four columns)
--     keeps working only on a privileged connection.
--
-- ===================================================================
-- 3. DEPLOY
-- ===================================================================
--
-- Depends on 114 (`epigraph_session_is_privileged_writer`) and 168 (the
-- definer). Four `CREATE TRIGGER`s take a short lock on `challenges`, under
-- `lock_timeout`. Independent of the binaries: no binary path plain-UPDATEs a
-- resolution column on an application session (the resolve routes call the
-- definer), and a binary without the resolve routes against a database with
-- this file loses nothing it had.
--
-- UNDO: DROP TRIGGER challenges_resolution_guard_update,
-- challenges_resolution_guard_insert, challenges_challenger_guard_insert and
-- challenges_resolution_guard_delete ON public.challenges, then DROP FUNCTION
-- public.epigraph_challenge_resolution_guard().
--
-- Checked before claiming: no `origin/main` migration and no open PR carries a
-- `170` (169 is an open PR's).

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_challenge_resolution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    -- DELETE first: NEW is NULL there, and a BEFORE ROW trigger that returns
    -- NULL silently skips the row, so a privileged DELETE must get OLD back.
    IF TG_OP = 'DELETE' THEN
        IF public.epigraph_session_is_privileged_writer() THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'CR09: challenge % is not deleted by an application session; '
            'the challenger withdraws it instead (state withdrawn); nothing was written',
            OLD.id
            USING ERRCODE = '42501';
    END IF;
    -- The AFTER INSERT arm: who filed it. After row security's WITH CHECK, so
    -- an unstamped session is still refused by row security first.
    IF TG_OP = 'INSERT' AND TG_WHEN = 'AFTER' THEN
        IF public.epigraph_session_is_privileged_writer() THEN RETURN NULL; END IF;
        -- Plain `=`: a NULL challenger or a NULL principal never matches.
        IF NOT COALESCE(NEW.challenger_id = public.epigraph_principal_id(), false) THEN
            RAISE EXCEPTION 'CR08: a challenge is filed by its challenger: challenger_id must '
                'be the session principal; nothing was written'
                USING ERRCODE = '42501';
        END IF;
        RETURN NULL;
    END IF;
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state = 'pending'
           AND NEW.resolved_by IS NULL
           AND NEW.resolved_at IS NULL
           AND NEW.resolution_details IS NULL THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'CR07: a challenge is filed unresolved (state pending, no resolver, '
            'time or details); its resolution is set only through '
            'epigraph_resolve_challenge; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.challenger_id IS DISTINCT FROM OLD.challenger_id THEN
        RAISE EXCEPTION 'CR08: challenge % challenger_id is fixed when the challenge is filed; '
            'nothing was written', OLD.id
            USING ERRCODE = '42501';
    END IF;
    -- Plain `=`: a NULL challenger or a NULL principal never matches.
    IF NEW.state = 'withdrawn'
       AND OLD.state IN ('pending', 'under_review')
       AND OLD.challenger_id = public.epigraph_principal_id()
       AND NEW.resolved_by IS NOT DISTINCT FROM OLD.resolved_by
       AND NEW.resolved_at IS NOT DISTINCT FROM OLD.resolved_at
       AND NEW.resolution_details IS NOT DISTINCT FROM OLD.resolution_details THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'CR07: challenge % resolution columns (state, resolved_by, resolved_at, '
        'resolution_details) change only through epigraph_resolve_challenge; an '
        'application session may only withdraw an unresolved challenge it filed (state '
        'pending or under_review -> withdrawn, nothing else changed); nothing was written',
        OLD.id
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_challenge_resolution_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS challenges_resolution_guard_update ON public.challenges;
CREATE TRIGGER challenges_resolution_guard_update
    BEFORE UPDATE OF state, resolved_by, resolved_at, resolution_details, challenger_id
    ON public.challenges
    FOR EACH ROW
    WHEN (OLD.challenger_id IS DISTINCT FROM NEW.challenger_id
          OR OLD.state IS DISTINCT FROM NEW.state
          OR OLD.resolved_by IS DISTINCT FROM NEW.resolved_by
          OR OLD.resolved_at IS DISTINCT FROM NEW.resolved_at
          OR OLD.resolution_details IS DISTINCT FROM NEW.resolution_details)
    EXECUTE FUNCTION public.epigraph_challenge_resolution_guard();

DROP TRIGGER IF EXISTS challenges_resolution_guard_insert ON public.challenges;
CREATE TRIGGER challenges_resolution_guard_insert
    BEFORE INSERT ON public.challenges
    FOR EACH ROW
    WHEN (NEW.state IS DISTINCT FROM 'pending'
          OR NEW.resolved_by IS NOT NULL
          OR NEW.resolved_at IS NOT NULL
          OR NEW.resolution_details IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_challenge_resolution_guard();

DROP TRIGGER IF EXISTS challenges_challenger_guard_insert ON public.challenges;
CREATE TRIGGER challenges_challenger_guard_insert
    AFTER INSERT ON public.challenges
    FOR EACH ROW
    EXECUTE FUNCTION public.epigraph_challenge_resolution_guard();

DROP TRIGGER IF EXISTS challenges_resolution_guard_delete ON public.challenges;
CREATE TRIGGER challenges_resolution_guard_delete
    BEFORE DELETE ON public.challenges
    FOR EACH ROW
    EXECUTE FUNCTION public.epigraph_challenge_resolution_guard();

-- Ownership, as 114 re-owns its invoker guards: the owner changes no answer
-- (the body runs as the caller); it decides who may CREATE OR REPLACE it.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_challenge_resolution_guard() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

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
-- One guard function, `epigraph_challenge_resolution_guard()`, on two BEFORE
-- ROW triggers. For an application session (anything 114's
-- `epigraph_session_is_privileged_writer()` says is NOT privileged):
--
--   * UPDATE: the only change of the four resolution columns it may make is
--     `state` to `withdrawn`, from an UNRESOLVED state (`pending`,
--     `under_review`), with `resolved_by`, `resolved_at` and
--     `resolution_details` unchanged. Anything else is refused, CR07 (42501).
--   * INSERT: a challenge is born unresolved: `state = 'pending'` and the three
--     other columns NULL, else CR07 (42501).
--
-- Who may withdraw is left to row security: 077's `WITH CHECK` admits only a
-- writer of the row's owning group (the outsider's own group for its
-- writer-owned row; the claim's group for an insider's), and 126 refuses an
-- elevated session every UPDATE.
--
-- WHY A SETTLED CHALLENGE IS NOT WITHDRAWN. 168's definer refuses to resolve a
-- withdrawn row (CR06: a withdrawal is the challenger's act and a resolution
-- must not overturn it). The converse must hold too: a withdrawal after the
-- claim's owner has ruled `accepted` / `rejected` would bury that verdict in
-- a state from which nobody can restate it. So only an unresolved challenge
-- is withdrawn; a settled one keeps its verdict, which the owner may still
-- re-resolve (R-14).
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
--   * It does not change who reads a challenge, or who may edit its text.
--   * `ChallengeRepository::update_state` (a plain UPDATE of all four columns)
--     keeps working only on a privileged connection.
--
-- ===================================================================
-- 3. DEPLOY
-- ===================================================================
--
-- Depends on 114 (`epigraph_session_is_privileged_writer`) and 168 (the
-- definer). Two `CREATE TRIGGER`s take a short lock on `challenges`, under
-- `lock_timeout`. Independent of the binaries: no binary path plain-UPDATEs a
-- resolution column on an application session (the resolve routes call the
-- definer), and a binary without the resolve routes against a database with
-- this file loses nothing it had.
--
-- UNDO: DROP TRIGGER challenges_resolution_guard_update and
-- challenges_resolution_guard_insert ON public.challenges, then DROP FUNCTION
-- public.epigraph_challenge_resolution_guard().
--
-- Checked before claiming: no `origin/main` migration and no open PR carries a
-- `170` (169 is an open PR's).

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_challenge_resolution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
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
    IF NEW.state = 'withdrawn'
       AND OLD.state IN ('pending', 'under_review')
       AND NEW.resolved_by IS NOT DISTINCT FROM OLD.resolved_by
       AND NEW.resolved_at IS NOT DISTINCT FROM OLD.resolved_at
       AND NEW.resolution_details IS NOT DISTINCT FROM OLD.resolution_details THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'CR07: challenge % resolution columns (state, resolved_by, resolved_at, '
        'resolution_details) change only through epigraph_resolve_challenge; an '
        'application session may only withdraw an unresolved challenge (state pending or '
        'under_review -> withdrawn, nothing else changed); nothing was written', OLD.id
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_challenge_resolution_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS challenges_resolution_guard_update ON public.challenges;
CREATE TRIGGER challenges_resolution_guard_update
    BEFORE UPDATE OF state, resolved_by, resolved_at, resolution_details ON public.challenges
    FOR EACH ROW
    WHEN (OLD.state IS DISTINCT FROM NEW.state
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

-- Ownership, as 114 re-owns its invoker guards: the owner changes no answer
-- (the body runs as the caller); it decides who may CREATE OR REPLACE it.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_challenge_resolution_guard() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- 307: the consent stamp is the setter's alone on INSERT too (review 2 of the
-- human-identity visibility branch, leaks#5; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 8 and 16.R C11).
--
-- 283 added `agents.profile_public_consented_at`, which the opt-in arm and a
-- human's details rule require (operator ruling C11), and stated "only a
-- definer or a maintenance session writes it". That holds for UPDATE (118
-- grants the application role named UPDATE columns, and not this one). It did
-- not hold for INSERT: 077 grants `epigraph_app` table-level INSERT on
-- `agents`, and the only INSERT policy, 077's `agents_provision`, refuses only
-- a `derived` row. An application session could therefore insert a
-- non-derived agent already stamped "consented", which would read as an
-- opt-in if the row later gained human evidence (a maintenance
-- `human_operators` registration of a pre-existing agent, or R9-class
-- forgery).
--
-- A RESTRICTIVE INSERT policy (123/148's shape) refuses a non-NULL stamp
-- unless the session is maintenance (`epigraph_bypass()`) or a definer frame
-- (`epigraph_definer_bypass()`). No definer inserts a stamped row today (283's
-- setter UPDATEs), so nothing legitimate is refused. The policy grants
-- nothing: every other INSERT is decided by `agents_provision` as before.
--
-- Pinned by `human_identity_visibility.rs::the_consent_stamp_is_the_setters_alone`
-- (the INSERT case, red before; an unstamped insert as CALIBRATION).
--
-- UNDO: DROP POLICY IF EXISTS agents_consent_stamp_definer_only ON public.agents;
SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS agents_consent_stamp_definer_only ON public.agents;
CREATE POLICY agents_consent_stamp_definer_only ON public.agents
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        profile_public_consented_at IS NULL
        OR (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

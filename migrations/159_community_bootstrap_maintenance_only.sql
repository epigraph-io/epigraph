-- 159: a never-populated community group is bootstrapped by a maintenance
-- session only (drain X14, backlog 7cdea6f1, the half PR #447 left).
--
-- ===================================================================
-- THE DEFECT
--
-- Migration 068 projected every legacy community onto a `groups` row with
-- `created_by_agent_id` NULL and no membership row at all: no admin, no
-- member. 106's `epigraph_community_add_member` let ANY actor list a
-- perspective into a group that has NEVER had a membership row ("bootstrap"),
-- because "admin only" would have frozen those groups. The first
-- `groups:admin` principal to reach such a community therefore became its live
-- member, and from then on could admit anyone it liked: the group belonged to
-- whoever arrived first. Route authorization cannot close this (PR #447
-- measured it): the actor holds the scope, and the repo rule is what admits it.
--
-- Communities created through `POST /api/v1/communities` are not affected:
-- `CommunityRepository::create` gives the authenticated creator a live admin
-- row, so the group has had a membership row from its first statement.
--
-- ===================================================================
-- THE CHANGE: the bootstrap arm is the maintenance session's
--
-- `epigraph_community_add_member` is re-stated with ONE condition changed. The
-- deny rule was
--     the group has ever had a row  AND  the actor is not a live member;
-- it is now
--     (the group has ever had a row  OR  the session is not epigraph_bypass())
--     AND the actor is not a live member.
-- So for an app session a never-populated group answers 'denied' (nothing
-- written), exactly as an emptied one already did. For a maintenance session
-- (`epigraph_bypass()`: `session_user` a member of `epigraph_maintenance`,
-- which the operator's CLIs and a superuser are) every outcome is unchanged
-- from 106, so the operator can still seed the first member of a legacy
-- community, and the `groups` row lock still serialises two first joiners.
--
-- The same condition closes one more case, which 106 left open. A community
-- with NO projected group of kind 'community' (068's projection skipped it
-- because a group of another kind already held the id, or the community row
-- was written without its projection) has no membership row under its id, so
-- under 106 any actor's call answered 'applied' and wrote a bare
-- `community_members` row. Under 159 an app session that is not a live member
-- of a group with that id gets 'denied' there too, with nothing written. A
-- maintenance session still gets 106's 'applied'.
--
-- The alternative, naming the platform custodian as each legacy group's admin
-- here, was not taken: the D1 ruling makes administration a timestamped role
-- assignment, never a standing account, so a migration has no agent it may
-- write in as admin. Giving those groups an admin stays an operator task
-- (PR-18's backfill).
--
-- Everything else in the body is 106's, verbatim: the actor rule, the lock
-- order, the 'denied_readmit' arm, the projection. `CREATE OR REPLACE` keeps
-- the function's owner (`epigraph_maintenance`, set by 106) and its ACL
-- (`REVOKE … FROM PUBLIC`, `GRANT EXECUTE … TO epigraph_app`), so neither is
-- re-stated: a re-own after 110 would also have to move the function out of
-- `tenancy_backfill.rs`'s frozen PRE_REGISTER_DEFINERS, for no change in
-- ownership. `SECURITY DEFINER` and `search_path` are NOT kept by
-- `CREATE OR REPLACE`, so the header repeats them.
--
-- Pinned as `epigraph_app` by
-- `epigraph-db/tests/community_membership_integrity.rs::a_memberless_legacy_group_does_not_admit_a_first_joiner`.
--
-- UNDO: re-run 106's `CREATE OR REPLACE FUNCTION
-- public.epigraph_community_add_member` statement (it re-opens the bootstrap
-- to every actor). No rows are created or changed by this file.
--
-- RESTATING THIS FUNCTION LATER: start from THIS body, not 106's, and keep the
-- `OR NOT public.epigraph_bypass()` term. A copy of 106's body silently
-- re-opens the bootstrap to every actor. A fresh database applies files in
-- numeric order, so no test would notice. A deployed database can apply a
-- lower-numbered file after this one (missing versions are applied late),
-- and the older copy would then win.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_community_add_member(
    p_community uuid, p_perspective uuid, p_actor uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_actor uuid;
    v_owner uuid;
    v_group uuid;
BEGIN
    IF public.epigraph_bypass() THEN
        v_actor := p_actor;
    ELSE
        v_actor := public.epigraph_principal_id();
        IF p_actor IS DISTINCT FROM v_actor THEN
            RETURN 'denied';
        END IF;
    END IF;

    -- The roster, then the group row: see 106's header for the order and for
    -- why the group row lock is what serialises first joiners.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = p_community AND m.revoked_at IS NULL
     ORDER BY m.agent_id FOR UPDATE;
    SELECT g.id INTO v_group FROM public.groups g
     WHERE g.id = p_community AND g.kind = 'community'
       FOR UPDATE;

    -- Decided under both locks. 159: a group that has NEVER had a membership
    -- row (migration 068's legacy communities) is bootstrapped only by a
    -- maintenance session; any other actor needs a LIVE membership.
    IF (EXISTS (SELECT 1 FROM public.group_memberships m WHERE m.group_id = p_community)
        OR NOT public.epigraph_bypass())
       AND NOT (v_actor IS NOT NULL AND EXISTS (
                SELECT 1 FROM public.group_memberships m
                 WHERE m.group_id = p_community
                   AND m.agent_id = v_actor
                   AND m.revoked_at IS NULL)) THEN
        RETURN 'denied';
    END IF;

    -- RE-ADMISSION IS AN ADMIN DECISION (106, unchanged). An owner with only
    -- REVOKED rows here was removed: it left, or an admin evicted it, and
    -- restoring that row requires a LIVE admin actor (or a maintenance
    -- session), decided here, under both locks and before anything is written.
    SELECT p.owner_agent_id INTO v_owner FROM public.perspectives p WHERE p.id = p_perspective;
    IF v_group IS NOT NULL AND v_owner IS NOT NULL
       AND NOT public.epigraph_bypass()
       AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                        WHERE m.group_id = v_group AND m.agent_id = v_owner
                          AND m.revoked_at IS NULL)
       AND EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = v_owner)
       AND NOT (v_actor IS NOT NULL AND EXISTS (
                SELECT 1 FROM public.group_memberships m
                 WHERE m.group_id = v_group
                   AND m.agent_id = v_actor
                   AND m.role = 'admin'
                   AND m.revoked_at IS NULL)) THEN
        RETURN 'denied_readmit';
    END IF;

    INSERT INTO public.community_members (community_id, perspective_id)
    VALUES (p_community, p_perspective)
    ON CONFLICT (community_id, perspective_id) DO NOTHING;

    -- The projection. No group of kind 'community' with this id, or a
    -- perspective with no owner: no membership (068's behaviour, a silent
    -- no-op by necessity). Since 159 an app session reaches this line for a
    -- missing group only if it is a live member of a group with this id; a
    -- maintenance session reaches it as before.
    IF v_group IS NULL OR v_owner IS NULL THEN
        RETURN 'applied';
    END IF;

    -- A live row at ANY epoch: leave it, role included.
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = v_owner AND m.revoked_at IS NULL) THEN
        RETURN 'applied';
    END IF;

    -- A revoked row (reachable only by a live admin actor, above) is restored
    -- at the REQUESTED role; the conflict arm only ever touches a revoked row,
    -- so it can never demote a live one either.
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (v_group, v_owner, ''::bytea, 0, 'reader')
    ON CONFLICT (group_id, agent_id, epoch)
    DO UPDATE SET revoked_at = NULL, role = EXCLUDED.role
          WHERE group_memberships.revoked_at IS NOT NULL;

    RETURN 'applied';
END $$;

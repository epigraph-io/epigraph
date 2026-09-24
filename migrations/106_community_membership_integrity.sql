-- 106: community membership integrity (batch F, F4a `afb1cfaf`, F4b `7cdea6f1`).
--
-- ===================================================================
-- THE DEFECTS
--
-- `crates/epigraph-db/src/repos/community.rs` managed the projected
-- `group_memberships` rows of a community with three separate round trips on
-- a pool, and got four things wrong:
--
-- (F4a-1) `remove_member` stamped `revoked_at = now()` with NO role check, NO
--         last-admin guard and NO roster lock. Its authorisation,
--         `may_manage_membership`, accepted ANY live member, so a `reader`
--         holding the `groups:admin` scope could evict the community's last
--         admin. Compare `GroupMembershipRepository::revoke_member_unless_last_admin`.
-- (F4a-2) `add_member` ended in `ON CONFLICT (group_id, agent_id, epoch) DO
--         UPDATE SET revoked_at = NULL` WITHOUT resetting the role, so a revoked
--         ADMIN re-added as a `reader` came back as ADMIN — migration 077's
--         personal-group revival (fixed by 105) on a second path.
-- (F4b-1) `may_manage_membership` returned TRUE for a group with no LIVE
--         membership. The first `groups:admin` principal to post into a
--         memberless community was silently let in — including a community
--         whose members had all been REMOVED, i.e. one that already owns
--         content: `remove_member` could re-open a closed group.
-- (F4b-2) The check ran on the pool OUTSIDE the write transaction: read, then
--         write, with a TOCTOU window between two concurrent first joiners.
--
-- And, under the deployed role, the Rust statements could not have implemented
-- the rule even if it had been right: on a connection stamped from the acting
-- agent, `group_memberships_tenancy`'s WITH CHECK requires
-- `epigraph_is_group_admin(group_id)`, so a member removing ITSELF is refused,
-- and a non-member cannot SEE the revoked rows that "has this group ever had a
-- member?" must count.
--
-- ===================================================================
-- THE SHAPE: two SECURITY DEFINER functions, decision and write in one frame
--
-- Each takes the roster lock, re-reads under it, decides, and writes — one
-- statement for the Rust caller, so there is no read-then-write window.
--
-- THE ACTOR. A definer frame must not take the actor on the caller's word: an
-- app session could then name any agent. So `p_actor` is honoured ONLY for a
-- session that could write these tables directly anyway (`epigraph_bypass()`:
-- `session_user` is a member of `epigraph_maintenance`, which includes a
-- superuser). For every other session the actor IS `epigraph_principal_id()` —
-- the principal the connection was stamped with — and a `p_actor` that differs
-- from it is DENIED, not substituted, so a caller that passed the wrong actor
-- learns it rather than acting as someone else.
--
-- THE LOCKS, in the order every other roster writer takes them:
-- `group_memberships` (the group's live roster, `ORDER BY agent_id FOR
-- UPDATE`, identical to `revoke_member_unless_last_admin` and
-- `GroupKeyEpochRepository::rotate_conn`), then the `groups` row, then
-- `group_key_epochs`. The `groups` row lock is what serialises two FIRST
-- joiners: a `FOR UPDATE` over an EMPTY roster locks nothing, so without it
-- both would read "never had a member" and both would bootstrap. Every
-- decision read happens AFTER both locks, so under READ COMMITTED the second
-- caller sees the first one's committed row.
--
-- THE RULES
--
-- add:    allowed iff the group has NEVER had a membership row of any state
--         (bootstrap: migration 068 left projected groups memberless; a group
--         whose members were all removed is NOT memberless in this sense and
--         does not re-open), or the actor holds a LIVE membership of it (the
--         closed-membership rule PR-12 chose: 068 left most community groups
--         with zero admins, so "admin only" would freeze them; the admin
--         backfill for those groups is an operator task, PR-18). The projected
--         row for the perspective's owner:
--           live row      -> left exactly as it is (an admin re-adding its own
--                            perspective keeps admin);
--           revoked row   -> restored at the REQUESTED role, `reader`, never at
--                            its old role;
--           no row        -> inserted as `reader`.
-- remove: allowed iff the actor owns the perspective (leaving), or holds a
--         LIVE `admin` membership (evicting). Never removes the group's LAST
--         live admin: that returns 'last_admin' with nothing written — the same
--         guard as `revoke_member_unless_last_admin`, because with no admin a
--         group is unmanageable and there is no break-glass path.
--
-- Return values: 'applied' | 'denied' | 'not_found' | 'last_admin'. For
-- remove, 'applied' means "authorised, and the projected membership handled";
-- the `community_members` row itself is deleted by the caller's statement (see
-- the note in the function body for why the definer does not delete).
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

    -- The roster, then the group row: see the header for the order and for why
    -- the group row lock is what serialises first joiners.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = p_community AND m.revoked_at IS NULL
     ORDER BY m.agent_id FOR UPDATE;
    SELECT g.id INTO v_group FROM public.groups g
     WHERE g.id = p_community AND g.kind = 'community'
       FOR UPDATE;

    -- Decided under both locks.
    IF EXISTS (SELECT 1 FROM public.group_memberships m WHERE m.group_id = p_community)
       AND NOT (v_actor IS NOT NULL AND EXISTS (
                SELECT 1 FROM public.group_memberships m
                 WHERE m.group_id = p_community
                   AND m.agent_id = v_actor
                   AND m.revoked_at IS NULL)) THEN
        RETURN 'denied';
    END IF;

    INSERT INTO public.community_members (community_id, perspective_id)
    VALUES (p_community, p_perspective)
    ON CONFLICT (community_id, perspective_id) DO NOTHING;

    -- The projection. No group of kind 'community' with this id, or a
    -- perspective with no owner: no membership, exactly as before (068's
    -- behaviour, a silent no-op by necessity).
    SELECT p.owner_agent_id INTO v_owner FROM public.perspectives p WHERE p.id = p_perspective;
    IF v_group IS NULL OR v_owner IS NULL THEN
        RETURN 'applied';
    END IF;

    -- A live row at ANY epoch: leave it, role included.
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = v_owner AND m.revoked_at IS NULL) THEN
        RETURN 'applied';
    END IF;

    -- A revoked row is restored at the REQUESTED role; the conflict arm only
    -- ever touches a revoked row, so it can never demote a live one either.
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (v_group, v_owner, ''::bytea, 0, 'reader')
    ON CONFLICT (group_id, agent_id, epoch)
    DO UPDATE SET revoked_at = NULL, role = EXCLUDED.role
          WHERE group_memberships.revoked_at IS NOT NULL;

    RETURN 'applied';
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_community_remove_member(
    p_community uuid, p_perspective uuid, p_actor uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_actor   uuid;
    v_owner   uuid;
    v_role    text;
    v_revokes boolean;
    v_revoked integer := 0;
BEGIN
    IF public.epigraph_bypass() THEN
        v_actor := p_actor;
    ELSE
        v_actor := public.epigraph_principal_id();
        IF p_actor IS DISTINCT FROM v_actor THEN
            RETURN 'denied';
        END IF;
    END IF;

    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = p_community AND m.revoked_at IS NULL
     ORDER BY m.agent_id FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = p_community FOR UPDATE;

    SELECT p.owner_agent_id INTO v_owner FROM public.perspectives p WHERE p.id = p_perspective;

    -- Leaving (own perspective) or evicting (a LIVE admin). Nothing else.
    IF NOT (
        (v_actor IS NOT NULL AND v_owner IS NOT NULL AND v_actor = v_owner)
        OR (v_actor IS NOT NULL AND EXISTS (
                SELECT 1 FROM public.group_memberships m
                 WHERE m.group_id = p_community
                   AND m.agent_id = v_actor
                   AND m.role = 'admin'
                   AND m.revoked_at IS NULL))
    ) THEN
        RETURN 'denied';
    END IF;

    -- Locked, so two concurrent removals of the same row serialise here.
    PERFORM 1 FROM public.community_members cm
     WHERE cm.community_id = p_community AND cm.perspective_id = p_perspective
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'not_found';
    END IF;

    -- Would this removal revoke the owner's projected membership? Only if the
    -- owner has no OTHER perspective in the community (two perspectives of one
    -- agent project onto one row).
    SELECT m.role INTO v_role FROM public.group_memberships m
     WHERE m.group_id = p_community AND m.agent_id = v_owner AND m.revoked_at IS NULL;
    v_revokes := v_owner IS NOT NULL AND v_role IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.community_members cm
          JOIN public.perspectives p2 ON p2.id = cm.perspective_id
         WHERE cm.community_id = p_community
           AND cm.perspective_id <> p_perspective
           AND p2.owner_agent_id = v_owner);

    -- The last-admin guard, decided before anything is written.
    IF v_revokes AND v_role = 'admin' AND NOT EXISTS (
        SELECT 1 FROM public.group_memberships m
         WHERE m.group_id = p_community
           AND m.agent_id <> v_owner
           AND m.role = 'admin'
           AND m.revoked_at IS NULL) THEN
        RETURN 'last_admin';
    END IF;

    -- The `community_members` row is NOT deleted here: `epigraph_maintenance`
    -- holds SELECT/INSERT/UPDATE only, by 070's stated rule ("it stamps and
    -- reads; it never destroys"). 'applied' tells the CALLER's statement to
    -- delete it, as the caller's role, in the same statement
    -- (`CommunityRepository::remove_member`); `community_members` carries no
    -- RLS and `epigraph_app` holds DELETE on it.

    IF v_revokes THEN
        UPDATE public.group_memberships
           SET revoked_at = now()
         WHERE group_id = p_community AND agent_id = v_owner AND revoked_at IS NULL;
        GET DIAGNOSTICS v_revoked = ROW_COUNT;
    END IF;

    -- PR-20 / FINAL-PLAN §6.7 point 2: a revoked member keeps a
    -- `wrapped_key_share`, so the group owes a re-seal. Marked only when a
    -- revoke happened; groups before group_key_epochs (the lock order above).
    IF v_revoked > 0 THEN
        UPDATE public.groups
           SET reseal_required_at = COALESCE(reseal_required_at, now())
         WHERE id = p_community;
        UPDATE public.group_key_epochs
           SET status = 'rotating'
         WHERE group_id = p_community AND status = 'active';
    END IF;

    RETURN 'applied';
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_community_add_member(uuid, uuid, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_community_remove_member(uuid, uuid, uuid) FROM PUBLIC;
DO $$ BEGIN
    -- OWNER is a correctness control, not hygiene (see 092 section 5): the
    -- bodies read `group_memberships` rows the caller cannot see, which only
    -- `epigraph_definer_bypass()` (current_user a member of
    -- `epigraph_maintenance`) admits. An owner outside that role would see an
    -- RLS-filtered roster, and "has this group ever had a member?" would answer
    -- NO for a group whose rows it cannot see — re-opening the bootstrap.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_community_add_member(uuid, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_community_remove_member(uuid, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_community_add_member(uuid, uuid, uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_community_remove_member(uuid, uuid, uuid) TO epigraph_app';
    END IF;
END $$;

-- UNDO: DROP FUNCTION IF EXISTS public.epigraph_community_add_member(uuid, uuid, uuid);
--       DROP FUNCTION IF EXISTS public.epigraph_community_remove_member(uuid, uuid, uuid);
-- and restore `community.rs`'s pre-batch-F statements. No rows are created or
-- changed by this file.

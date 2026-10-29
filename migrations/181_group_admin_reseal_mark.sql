-- 181: a group ADMIN marks the group's re-key obligation through a narrow
-- definer (backlog 323773fe, ruling R-56).
--
-- EVIDENCE
-- `DELETE /api/v1/groups/:id/members/:agent_id` revokes the membership and, in
-- the same transaction, sets `groups.reseal_required_at` (FINAL-PLAN section
-- 6.7: a removed member keeps a share that decrypts everything sealed before
-- the next rotation). On the application role the revoke and the epoch's
-- `rotating` mark pass row security on the caller's admin membership, but the
-- `groups` UPDATE must pass `groups_tenancy`'s WITH CHECK (077 section 6),
-- which admits only the group's CREATOR. An admin who did not create the group
-- therefore could not remove anyone: the transaction was refused whole.
--
-- CHANGE
-- One SECURITY DEFINER function, `public.epigraph_mark_group_reseal_required
-- (p_group uuid) RETURNS void`, and nothing else. It:
--   * takes the group id and NO other argument, and writes exactly one column
--     of that one row: `reseal_required_at = COALESCE(reseal_required_at,
--     now())` (the obligation dates from the FIRST unrotated removal; see
--     `GroupMembershipRepository::revoke_member_unless_last_admin`). The
--     `groups_updated_at` trigger (060) still maintains `updated_at`. It never
--     clears the mark: that stays the re-seal job's
--     (`clear_reseal_required_conn`, a maintenance write);
--   * admits a caller only when the SESSION PRINCIPAL is a live admin of that
--     group, decided by 077's `epigraph_is_group_admin(p_group)`, which binds
--     the subject to `epigraph_principal_id()` (so the function is no
--     membership oracle over other principals), OR when the SESSION is
--     privileged (`epigraph_bypass()`, or a superuser, as 164's verbs admit).
--     A privileged session already writes this column directly (it bypasses
--     row security), so that arm grants nothing it did not have; it keeps the
--     repository's pool form usable on the maintenance and superuser pools;
--   * refuses an ELEVATED session first, with `GRA03` / 42501, whoever it is.
--     126's RESTRICTIVE `groups_elevated_no_update` is a policy on
--     `epigraph_app` and so is not applied inside this maintenance-owned
--     frame; before 181 it is what refused an elevated session's direct
--     mark. The definer refuses it itself, as 168's challenge definer does
--     (CR05);
--   * refuses everyone else with `GRA01` / SQLSTATE 42501 and changes nothing,
--     and refuses with `GRA02` / 42501 if the UPDATE matched no row (a group
--     that does not exist, or a body re-owned so that row security filters
--     it): an obligation silently not recorded is the failure this exists to
--     prevent.
-- The groups row's own triggers still apply inside the frame: 164's
-- `groups_team_verbs_only_update` keys on `session_user`, so a verb-made team
-- group's row stays writable only by the maintenance verbs (42501), and 108's
-- identity trigger does not fire (no identity column changes).
--
-- Convention as 172: `SET search_path = pg_catalog, pg_temp`, every public
-- object schema-qualified, `pg_catalog.now()`. Owner `epigraph_maintenance`
-- (inside the frame `current_user` is the owner, so `groups_tenancy` admits
-- the write through its `epigraph_definer_bypass()` arm); EXECUTE revoked from
-- PUBLIC and granted to `epigraph_app`. The owner and grant blocks are
-- role-guarded like every such block since 060 and can silently no-op;
-- `tenancy_backfill.rs`'s registers (`DEFERRED_DEFINER_FUNCTIONS` and the
-- grant list in `verify_operator_function_grants`) report it, and
-- `group_reseal_mark.rs` pins the catalog at head.
--
-- Callers: `GroupMembershipRepository::revoke_member_unless_last_admin_conn`
-- calls it, under the roster lock and BEFORE the guarded revoke (so an admin
-- removing itself is still an admin when the mark is decided), and rolls it
-- back to a savepoint when nothing is revoked.
--
-- UNDO:
--   DROP FUNCTION IF EXISTS public.epigraph_mark_group_reseal_required(uuid);
-- (and revert the repository to its direct `UPDATE groups`, which a
-- non-creator admin cannot pass). No rows, tables or policies change here.
-- **Applied to throwaway databases only, NOT to any deployed database.**
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_mark_group_reseal_required(p_group uuid)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'GRA03: an elevated session marks no re-key obligation; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)
            OR public.epigraph_is_group_admin(p_group)) THEN
        RAISE EXCEPTION 'GRA01: only a live admin of group % marks its re-key obligation; '
                        'nothing was changed', p_group
            USING ERRCODE = '42501';
    END IF;
    UPDATE public.groups g
       SET reseal_required_at = COALESCE(g.reseal_required_at, pg_catalog.now())
     WHERE g.id = p_group;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GRA02: group % was not marked (no such group, or the row was not '
                        'visible to the mark); nothing was changed', p_group
            USING ERRCODE = '42501';
    END IF;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_mark_group_reseal_required(uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_mark_group_reseal_required(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mark_group_reseal_required(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

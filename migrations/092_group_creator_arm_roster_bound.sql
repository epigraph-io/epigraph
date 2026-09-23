-- 092_group_creator_arm_roster_bound.sql
-- Bound migration 077's group-creation bootstrap arm to the group's roster, so
-- it stops at the end of the creator's own membership instead of at nothing.
--
-- Recorded as `D-PR17-creator-arm-outlives-membership` (COMPLETION-PLAN 2.2.5).
-- This is the batch's one migration; `migrations/README.md` is updated in the
-- SAME commit, where `092-099` is recorded as the reserved tenancy block the
-- operator authorized on 2026-09-15. `077_rls_policies.sql` is APPLIED and
-- therefore FROZEN: editing it changes its `_sqlx_migrations` checksum and the
-- next `sqlx migrate run` refuses to start, so the narrowing lands here and the
-- corrections to 077's header can only live in this one.
--
-- Kept at mechanism level, deliberately, exactly as 077's own header and the
-- obligation's `detail` are: this repository is public.
--
-- ===================================================================
-- 1. WHAT 077 SHIPPED, AND WHY IT IS THREE POLICIES RATHER THAN ONE
--
-- 077 section 1 records the bootstrap it had to solve: creating a group and
-- becoming its first administrator is circular, because at the instant the
-- `groups` row is written the creator is a member of nothing, so
-- `epigraph_is_group_admin` is false and `epigraph_session_groups()` cannot
-- contain an id that did not exist when the connection was stamped. The arm it
-- added says "you may write and read a group you declared yourself the creator
-- of, seed its key epoch, and enrol members in it".
--
-- `groups.created_by_agent_id` is never rewritten, so that permission had no
-- end. The arm outlived the creator's own membership in the group.
--
-- THE SURFACE IS WIDER THAN THE OBLIGATION'S `what` RECORDS, AND IT IS SPELLED
-- TWO DIFFERENT WAYS. The obligation names `groups_tenancy`. MEASURED on this
-- tree, the same permission is carried by three policies and six clauses, and
-- nothing between 078 and 091 redefines any of them:
--
--   policy                      table               spelling
--   groups_tenancy              groups              INLINE column comparison
--   group_memberships_tenancy   group_memberships   epigraph_is_group_creator()
--   group_key_epochs_tenancy    group_key_epochs    epigraph_is_group_creator()
--
-- A fix at one spelling is incomplete BY CONSTRUCTION and would still pass a
-- proof written against that spelling: replacing only the helper leaves
-- `groups_tenancy` untouched, and re-issuing only `groups_tenancy` leaves the
-- other two untouched. Both spellings are narrowed below.
--
-- ===================================================================
-- 2. A CORRECTION TO 077's FROZEN HEADER, WHICH IS THE ONLY PLACE IT CAN LIVE
--
-- 077 line 359 and the obligation's `what` both record that the arm is in
-- `groups_tenancy`'s USING clause "because `community.rs`'s `ON CONFLICT` needs
-- the SELECT side". MEASURED on PostgreSQL 16.13, as a non-owner role under a
-- policy that is `USING (false) WITH CHECK (true)`:
--
--   plain INSERT, no RETURNING                     admitted
--   INSERT ... RETURNING                           REFUSED
--   INSERT ... ON CONFLICT DO NOTHING (untargeted) admitted
--   INSERT ... ON CONFLICT (col) DO NOTHING        REFUSED
--   INSERT ... ON CONFLICT (col) DO UPDATE         REFUSED
--
-- `CommunityRepository::create`'s `groups` insert is UNTARGETED
-- `ON CONFLICT DO NOTHING`, so it does not consult the SELECT side at all; its
-- only targeted `ON CONFLICT ... DO UPDATE` is on `group_memberships`, a
-- different table under a different policy. The statement on `groups` that does
-- require the SELECT side is `GroupRepository::create_with_admin`'s
-- `INSERT INTO groups ... RETURNING id`.
--
-- So the USING arm IS load-bearing and must not simply be deleted -- deleting it
-- is a total outage on group creation -- but the recorded reason names the wrong
-- statement. 077 cannot be corrected in place. This is the correction.
--
-- ===================================================================
-- 3. THE SHAPE OF THE NARROWING, AND WHY IT IS ROSTER-SHAPED
--
-- The obligation says narrowing "needs a liveness conjunct that the bootstrap it
-- exists for cannot satisfy". That is true of the NAIVE conjunct -- "the
-- principal has a live membership in this group" is false at every one of the
-- three bootstrap statements. It is not true of the conjunct used here:
--
--     the group has NO membership rows at all   (the bootstrap window)
--  OR the principal has a LIVE membership in it (the steady state)
--
-- At the `groups` insert, the epoch-0 insert and the first admin insert the
-- group's roster is empty in the statement's snapshot, so the first disjunct
-- admits all three. Once the roster exists the first disjunct is false and the
-- second decides, so the permission now ends exactly where the creator's own
-- membership ends.
--
-- ROSTER-SHAPED RATHER THAN REVOCATION-SHAPED, ON PURPOSE. `NOT EXISTS (a
-- revoked row)` would be equivalent today -- MEASURED, every removal in
-- `crates/epigraph-db/src/repos/` is a soft `UPDATE ... SET revoked_at = now()`
-- and there is no `DELETE FROM group_memberships` anywhere in the workspace --
-- but it would be defeated by the first hard delete anyone adds, while still
-- passing a proof written against the revoke path. The roster form does not
-- depend on which of the two spellings a removal uses.
--
-- THE WINDOW IS KEYED ON ROSTER ABSENCE, NOT ON THE BOOTSTRAP TRANSACTION, and
-- that is a RESIDUAL rather than a property. `NOT EXISTS (any roster row)` is a
-- standing condition: a group whose roster is ever emptied re-enters the
-- bootstrap window, so the narrowing bounds the arm by the roster's EXISTENCE
-- and not by the creator's membership having once begun. The alternative
-- spellings were weighed in the paragraph above and each loses more than it
-- gains. Recorded as a named residual on
-- `D-PR17-creator-arm-outlives-membership` rather than left implicit; the
-- reachability analysis is held outside this repository.
--
-- ===================================================================
-- 4. WHY THE `groups` ARM KEEPS ITS INLINE COMPARISON
--
-- The obvious tidy-up -- point `groups_tenancy`'s USING at
-- `epigraph_is_group_creator(id)` so there is one predicate instead of two --
-- BREAKS GROUP CREATION, and it fails in a way no compile and no catalog check
-- would show. MEASURED on 16.13: a `STABLE SECURITY DEFINER` function that
-- SELECTs the target table by primary key, called from a USING clause, is FALSE
-- against an `INSERT ... RETURNING`, because the function evaluates against the
-- statement's snapshot and that snapshot does not contain the row the statement
-- is inserting. An inline comparison on `created_by_agent_id` is evaluated
-- against the NEW tuple and is unaffected.
--
-- The asymmetry that makes this file work: the roster predicate reads
-- `group_memberships`, NOT `groups`, so it never needs the new `groups` row to
-- be visible. That is why a roster helper is safe in a clause where the creator
-- helper is not.
--
-- The `groups_tenancy` WITH CHECK clause is deliberately LEFT UNCHANGED. An
-- INSERT's WITH CHECK runs against a group id that does not exist yet, so the
-- roster conjunct would be vacuously true there; and on an UPDATE the USING
-- clause has already refused. Adding it would be inert text that reads like a
-- control.
--
-- ===================================================================
-- 5. THE GUARDED `OWNER TO` IS THE MECHANISM, NOT HARDENING
--
-- `epigraph_group_roster_admits_principal` reads `group_memberships`, which is
-- itself under FORCEd row security, so the read is complete only inside a
-- definer frame that `epigraph_definer_bypass()` admits -- i.e. only while the
-- function's OWNER is a member of `epigraph_maintenance`. The `ALTER FUNCTION
-- ... OWNER TO` below is inside a `pg_roles` guard and, like every such block
-- since 060, can silently no-op; `tenancy_backfill.rs::verify_definer_ownership`
-- exists because that is not hypothetical.
--
-- THE DIRECTION IS THE POINT, AND IT IS THE OPPOSITE OF ITS SIBLINGS. 077's
-- `epigraph_is_group_creator` is `EXISTS (... FROM groups ...)`: an unbypassed
-- frame reads nothing, `EXISTS` is false, and it fails CLOSED. The roster
-- predicate's first disjunct is `NOT EXISTS (... FROM group_memberships ...)`,
-- so an unbypassed frame reads nothing, `NOT EXISTS` is TRUE, and it ADMITS.
-- Ownership is therefore not hygiene here: it is what makes the narrowing
-- narrow anything at all, and losing it reverts this file to 077's behaviour
-- with no error, no catalog symptom and a green suite. Two controls pin it, and
-- they are named here so the dependency is not left to be rediscovered:
--
--   * `schema_contract.rs::migration_092_roster_definer_is_revoked_from_public`
--     -- CI catalog pin on `proowner`, `proacl` and the PUBLIC grant, on the
--     template 086 and 089 each established for their own definer bodies.
--   * `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS` -- the plan 9.2 step 11c
--     deploy pre-flight. DEFERRED, not unconditional: 11c runs before this
--     migration applies, so an unconditional entry would report `does not exist`
--     and block a correctly sequenced deploy.
--
-- ===================================================================
-- 6. A SECOND CORRECTION TO 077's FROZEN HEADER
--
-- 077 section 7 says of `group_memberships_tenancy`: "USING carries no reference
-- to `group_memberships`, which is what makes the SECURITY DEFINER helper in
-- WITH CHECK safe". That was true when it was written -- that policy's USING
-- reaches the creator arm through `epigraph_is_group_creator`, whose 077 body
-- reads `groups` only. IT NO LONGER HOLDS: this file conjoins the roster
-- predicate into that helper, so `group_memberships_tenancy`'s USING now reads
-- `group_memberships` transitively.
--
-- What carries non-recursion instead is the definer frame of section 5: inside
-- it, `group_memberships_tenancy` is satisfied at its `epigraph_definer_bypass()`
-- disjunct before the creator disjunct is reached, so the nested read does not
-- re-enter the predicate. That is a STRUCTURAL DEPENDENCY now, not a coincidence
-- of the predicate's shape, and it is the same dependency section 5 pins. A
-- future author adding an arm to `group_memberships_tenancy` must read this
-- paragraph and not 077's sentence.
--
-- ===================================================================
-- 7. WHAT THIS DOES NOT CHANGE
--
-- No FUNCTION BODY here touches `epigraph_bypass()`, `epigraph_definer_bypass()`
-- or the `epigraph_session_groups()` disjuncts -- though what DEPENDS on
-- `epigraph_definer_bypass()` does change, see sections 5 and 6 -- so
-- maintenance connections, definer frames and ordinary live members are
-- unaffected in all three policies. A
-- creator who is still a live member keeps every permission the arm ever gave
-- them; that is asserted positively, because a narrowing that refused everyone
-- would satisfy any negative test.
--
-- The policies are amended with `ALTER POLICY` rather than DROP + CREATE so
-- `pg_policy.polcmd` and the grantee list are preserved by construction: a
-- re-CREATE that lost `FOR ALL` would silently drop command coverage, which is
-- what `rls_enforcement.rs::every_protected_relation_covers_every_command_or_
-- records_why` reads the catalog to prevent.
--
-- UNDO. No runbook ships, on the same ground as 089 and 090: reversing this file
-- is `CREATE OR REPLACE FUNCTION public.epigraph_is_group_creator(uuid)` back to
-- 077's body, `ALTER POLICY groups_tenancy ON public.groups USING (...)` back to
-- 077's text, and `DROP FUNCTION IF EXISTS
-- public.epigraph_group_roster_admits_principal(uuid)`. It creates no rows to
-- un-create. **Applied to a throwaway database only, NOT to any deployed
-- database.**
-- ===================================================================

-- The roster predicate. Its OWNER is load-bearing, not hygiene -- section 5 --
-- and the two controls that pin it are named there.
--
-- `SECURITY DEFINER` for the same reason every helper in
-- 077 section 1 is: it reads `group_memberships`, which is itself under RLS, and
-- an inline subquery would make `groups_tenancy` depend on
-- `group_memberships_tenancy`, which in turn calls back into `groups`. `STABLE`,
-- not `VOLATILE`: it reads and does not write, and that difference is
-- load-bearing rather than cosmetic (077 section 1 makes the same point about
-- `epigraph_ensure_personal_group`).
--
-- It grants no read. It returns one boolean about the CALLING principal's own
-- standing in a group the caller already named, so it is bound to the session
-- subject rather than parameterised by it -- unlike
-- `epigraph_live_memberships(uuid)`, whose `Viewer::resolve` caller has no
-- session subject to bind to yet (`D-PR17-live-memberships-is-parameterised-not-
-- principal-bound`).
CREATE OR REPLACE FUNCTION public.epigraph_group_roster_admits_principal(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT NOT EXISTS (
             SELECT 1 FROM public.group_memberships m WHERE m.group_id = p_group)
        OR EXISTS (
             SELECT 1 FROM public.group_memberships m
              WHERE m.group_id = p_group
                AND m.agent_id = public.epigraph_principal_id()
                AND m.revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_roster_admits_principal(uuid) FROM PUBLIC;

-- The helper spelling: covers `group_memberships_tenancy` and
-- `group_key_epochs_tenancy`, USING and WITH CHECK, four clauses in one edit.
-- The body is 077's, conjoined with the roster predicate. The
-- `epigraph_principal_id() IS NOT NULL` guard is kept verbatim so an unstamped
-- session is still FALSE rather than NULL-false by accident.
CREATE OR REPLACE FUNCTION public.epigraph_is_group_creator(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_principal_id() IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.groups g
       WHERE g.id = p_group
         AND g.created_by_agent_id = public.epigraph_principal_id())
     AND public.epigraph_group_roster_admits_principal(p_group)
$$;

-- Ownership and grants, mirroring 077's block exactly. Both halves are guarded:
-- `epigraph_maintenance` and `epigraph_app` exist in a deployed cluster and not
-- in every throwaway, and a missing guard breaks in one environment and not the
-- other. `epigraph_is_group_creator` is re-owned and re-granted too, because
-- `CREATE OR REPLACE` above preserves them but re-issuing costs nothing and
-- keeps this file correct against a database where 077's `DO` block took the
-- no-role branch.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_group_roster_admits_principal(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_is_group_creator(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_group_roster_admits_principal(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_group_creator(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- The inline spelling: `groups_tenancy`'s USING clause. Section 4 above is why
-- the column comparison stays inline and why WITH CHECK is not restated here --
-- `ALTER POLICY` with only a `USING` clause leaves `WITH CHECK` exactly as 077
-- wrote it.
ALTER POLICY groups_tenancy ON public.groups
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR id = ANY ((SELECT public.epigraph_session_groups())::uuid[])
        -- The group-creation bootstrap, bounded by the roster. See 077 section 1
        -- for what it is for and sections 3 and 4 above for where it now stops.
        OR (created_by_agent_id = (SELECT public.epigraph_principal_id())
            AND public.epigraph_group_roster_admits_principal(id)));

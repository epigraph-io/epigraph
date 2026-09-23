-- ===================================================================
-- 088 — the UPDATE policies on `privatization_plans` and
-- `privatization_plan_items`, which are what make a plan's STATE MACHINE
-- reachable at all.
--
-- Version 088 per `migrations/README.md`, which is authoritative and which this
-- commit updates in the same change: 088 was the first row of the "088-090
-- remaining headroom" band. `epigraph-internal` shares this version space, so
-- the number is claimed in the table rather than merely used.
--
-- FINAL-PLAN's PR-18 *Files* line names "migrations 076/077/078/079". Those four
-- numbers are PR-16's and PR-17's under the documented +4 shift, they are applied
-- and frozen, and the work they were meant to carry shipped as 080-083 and 087.
-- The plan therefore assigns this slice no usable number. The README table is
-- the authority and 088 is claimed from its headroom.
--
-- ===================================================================
-- WHY THIS FILE HAS TO EXIST BEFORE ANY OF apply / approve / abort / revert.
--
-- 080 creates both tables with ENABLE + FORCE ROW LEVEL SECURITY. 087 adds
-- SELECT and INSERT policies and stops there, and its own header says so. Under
-- FORCE, a command with NO policy is denied to EVERY role — `epigraph_maintenance`
-- included, because it is `rolbypassrls = f`; `epigraph_bypass()` is a function
-- evaluated INSIDE a policy expression, so with no policy there is nothing to
-- evaluate and the statement fails with "new row violates row-level security
-- policy".
--
-- Every state transition this slice ships is an UPDATE of one of these two
-- tables:
--
--   privatization_plans       approved_by / approved_at (approve)
--                             state -> 'applying' and dispatched_by (apply)
--                             cursor_kind / cursor_depth / cursor_id (batch)
--                             state -> 'applied' | 'applied_with_drift'
--                                    | 'failed' | 'reverting' | 'reverted'
--                             drift_ids (the post-apply rescan)
--   privatization_plan_items  state -> 'applied' | 'skipped' | 'failed'
--                                    | 'reverted', applied_at, error
--
-- So without this file `routes/privatization.rs` could not ship `approve`, and
-- `epigraph-jobs/src/privatization.rs` could not exist. That is exactly what
-- 18b's module doc records as the reason it shipped four read routes and no
-- more.
--
-- ===================================================================
-- BYPASS ONLY, ON BOTH CLAUSES, AND THE `WITH CHECK` IS NOT REDUNDANT.
--
-- The write shape is 083's `instance_admins_maintenance_insert` /`_update` pair
-- and 087's INSERT arms: a single `epigraph_bypass()` disjunct, stopping short of
-- `FOR ALL` so that a command nobody has asked for stays denied. DELETE stays
-- uncovered on both tables and stays registered in
-- `rls_enforcement.rs::DELIBERATELY_UNCOVERED` with its own reasons — a plan is
-- the record that a privatization was attempted and is never deleted, and items
-- cascade with their plan.
--
-- `USING` and `WITH CHECK` are written out separately rather than letting the
-- latter default to the former. They answer different questions — `USING` picks
-- the rows this connection may see as UPDATE candidates, `WITH CHECK` validates
-- the row it produced — and a reader who has to derive one from the other cannot
-- tell an intentional asymmetry from an omission. They are the same expression
-- here BECAUSE the answer to both questions is "this connection is the
-- maintenance one", and that identity is the thing worth being able to read.
--
-- WHY NOT THE §6.6 CONJUNCTION 087's READ POLICY USES. A tempting alternative is
-- to let an instance admin who administers the target group issue the UPDATE
-- from the request path, mirroring `privatization_plans_read`. It is refused on
-- two grounds. First, 080 REVOKEs UPDATE on both tables FROM `epigraph_app`, so
-- such an arm would be unreachable text behind a GRANT denial — the same
-- "unreachable text" 087's header refuses for its INSERT arm. Second, and the
-- reason that survives a future GRANT: `privatization_plan_items.state` is
-- advanced by a batch loop that has just rewritten `claims.visibility` in the
-- same transaction, on a connection that must be able to write both. Splitting
-- that across two authorities would make a partially applied batch reachable.
--
-- The authorization for a state transition is therefore NOT this policy. It is
-- FINAL-PLAN §6.5.5's re-validation in the handler, plus the HTTP layer's
-- §6.6 check, plus 080's `pp_four_eyes` CHECK and 081's approver guard, which
-- are trigger- and constraint-level and bind the maintenance connection too.
-- This file only makes the write POSSIBLE for the one role that is supposed to
-- perform it.
--
-- ===================================================================
-- EVERY TOP-LEVEL `OR` ARM NAMES A SESSION HELPER.
--
-- `rls_enforcement.rs::no_policy_arm_is_session_independent` splits a policy
-- expression on ` OR ` and reports any arm that references none of the session
-- helpers. Both arms below are `epigraph_bypass()` / `epigraph_definer_bypass()`
-- calls, wrapped in `(SELECT …)` so they become an InitPlan evaluated once per
-- statement rather than a per-row Filter. 083's header states the rule.
--
-- `epigraph_definer_bypass()` is included for the reason 077's policies include
-- it everywhere: a `SECURITY DEFINER` function owned by `epigraph_maintenance`
-- that has to touch a plan row would otherwise be denied even though it is
-- running as the very role the other arm admits. No such function exists today;
-- omitting the arm here and adding it later would be a policy change rather than
-- a function addition, which is the harder review.
--
-- ===================================================================
-- WHAT MUST MOVE IN THE SAME COMMIT, AND WHY THIS IS WRITTEN DOWN HERE.
--
-- `rls_enforcement.rs::every_protected_relation_covers_every_command_or_records_why`
-- is exact in BOTH directions: it fails when a pair is uncovered and unregistered,
-- and it fails when a pair is registered and now covered. The two rows
--
--     ("privatization_plans",      "UPDATE", "State transitions …")
--     ("privatization_plan_items", "UPDATE", "Per-item state …")
--
-- are deleted from `DELIBERATELY_UNCOVERED` in the same commit as this file. That
-- coupling is the property that makes the register worth its weight.
--
-- NO GRANTS ARE OWED. 080 already issues `GRANT SELECT, INSERT, UPDATE, DELETE
-- … TO epigraph_maintenance` and `REVOKE INSERT, UPDATE, DELETE … FROM
-- epigraph_app` on both tables. Neither table gains a sequence.
--
-- ORDER-INSENSITIVITY. This file adds policies to tables 080 creates and
-- references nothing from 084-091, so it behaves identically whether it is
-- applied in a single fresh numeric-order run or beneath an existing head.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- privatization_plans — the plan state machine.
-- -------------------------------------------------------------------
DROP POLICY IF EXISTS privatization_plans_maintenance_update ON public.privatization_plans;
CREATE POLICY privatization_plans_maintenance_update ON public.privatization_plans
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

-- -------------------------------------------------------------------
-- privatization_plan_items — per-item state, applied_at, error.
-- -------------------------------------------------------------------
DROP POLICY IF EXISTS privatization_plan_items_maintenance_update
    ON public.privatization_plan_items;
CREATE POLICY privatization_plan_items_maintenance_update ON public.privatization_plan_items
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

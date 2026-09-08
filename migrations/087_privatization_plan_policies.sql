-- ===================================================================
-- 087 — the SELECT and INSERT policies on `privatization_plans` and
-- `privatization_plan_items`.
--
-- Version 087 per `migrations/README.md`, which is authoritative and which this
-- commit updates in the same change: 087 was the first row of the "087-090
-- remaining headroom" band. `epigraph-internal` shares this version space, so
-- the number is claimed in the table rather than merely used.
--
-- ===================================================================
-- WHAT THIS UNBLOCKS, AND WHY IT COULD NOT BE DONE EARLIER.
--
-- 080 creates both tables with ENABLE + FORCE ROW LEVEL SECURITY and NO POLICY.
-- FORCE binds `epigraph_maintenance` too — it is `rolbypassrls = f` — so with an
-- empty policy set NO role can INSERT: the statement fails with "new row
-- violates row-level security policy". That measurement is recorded in
-- `rls_enforcement.rs::DELIBERATELY_UNCOVERED`'s own reason string for the
-- `(privatization_plans, INSERT)` pair.
--
-- FINAL-PLAN §6.5.1 forbids a stateless preview: the selection is FROZEN into
-- `privatization_plan_items` and an apply operates on that frozen id set. So no
-- preview route can exist until a plan can be persisted, and a plan cannot be
-- persisted without a policy. That is the whole reason PR-18's second slice
-- shipped a repo layer and no route.
--
-- ===================================================================
-- THE PLAN DOES NOT SPECIFY THESE POLICIES. THIS FILE DESIGNS THEM.
--
-- `docs/tenancy/FINAL-PLAN.md` contains fourteen `CREATE POLICY` blocks and NOT
-- ONE of them names `privatization_plans` or `privatization_plan_items`; there
-- is no prose about their policies either. Re-measured against the document at
-- this commit. That is a genuine gap in the plan rather than a reading failure,
-- and it is stated here and in the PR body rather than resolved by silence.
--
-- The design is not free-hand. It is the SQL expression of the authorization
-- FINAL-PLAN §6.6 already specifies for the surface these tables serve, using
-- the two in-tree templates:
--
--   * 082/083's `privatization_audit_read` — the three-condition check written
--     as a policy, with the plan-level / entity-level split, and the
--     `epigraph_is_group_admin(<sub-select over privatization_plans>)` idiom
--     this file reuses verbatim for the item table.
--   * 083's `instance_admins_maintenance_insert` / `_update` — the bypass-only
--     write shape, which stops short of `FOR ALL` so that a command nobody has
--     asked for stays denied.
--
-- ===================================================================
-- READ: INSTANCE ADMIN **AND** GROUP ADMIN OF THE TARGET. NOT EITHER ALONE.
--
-- FINAL-PLAN §6.5.2 point 2 records that a previous revision of this design
-- required `instance:admin` PLUS group-admin-in-target to CREATE a plan and only
-- `instance:admin` to READ one, so any instance admin could read any other
-- admin's preview and the complete entity-id list of their private region. The
-- conjunction below is that closure expressed where it cannot be forgotten by a
-- handler: a read endpoint that omits the check still returns nothing, because
-- the policy — not the route — is what narrows the rows.
--
-- `privatization_plan_items.entity_id` is, in migration 082's own words, "a
-- complete index of every private entity id in the instance". Its read policy is
-- therefore the same conjunction, resolved through the plan row.
--
-- ===================================================================
-- A DELIBERATE, STATED WIDENING ON A TABLE THIS FILE DOES NOT OTHERWISE TOUCH.
--
-- 083's `privatization_audit_read` scopes `entity_id` rows with
-- `epigraph_is_group_admin((SELECT p.target_group_id FROM privatization_plans p
-- WHERE p.id = privatization_audit.plan_id))`. That scalar sub-select is itself
-- RLS-filtered. While `privatization_plans` had no SELECT policy under FORCE it
-- yielded NULL for every plan, `epigraph_is_group_admin(NULL)` was false, and
-- the entity arm was unreachable from an app connection — 083's header says so
-- and calls the direction "denial, not disclosure".
--
-- Adding a plans SELECT policy makes that sub-select resolve, so the arm
-- activates: an instance admin who administers a plan's target group now reads
-- that plan's entity-level audit rows. THAT IS §6.5.2 POINT 3's SPECIFIED
-- BEHAVIOUR ARRIVING, and it is the largest read-surface change in this file. It
-- is named here rather than left to be discovered by diffing two migrations,
-- and `privatization_authz.rs` gains the second arm — a plan whose target group
-- the caller does NOT administer stays denied — in the same commit.
--
-- ===================================================================
-- WRITE: BYPASS ONLY, AND THAT IS NOT A BYPASS-ONLY *ROUTE*.
--
-- 080 REVOKEs INSERT, UPDATE and DELETE on both tables FROM `epigraph_app`, so
-- an app-connection INSERT is already denied at the GRANT layer and an INSERT
-- policy arm written for it would be unreachable text. Selection runs on the
-- maintenance connection by necessity — `Viewer::system` cannot be built without
-- a `MaintenanceLease`, and EXECUTE on 080's two selection functions is granted
-- to `epigraph_maintenance` alone — so the freeze is performed on the connection
-- that already holds the selection. The HTTP-layer half of the authorization
-- (`middleware/instance_authz.rs::require_instance_admin_for_group`) runs on a
-- STAMPED app connection before any of that, and 081's plan guard enforces the
-- maturity and plurality conditions in the database on the INSERT itself.
--
-- So the operator path is: authorize on the app connection, select and freeze on
-- the maintenance connection, read back through the SELECT policies above. The
-- route is usable by a real operator; `NO FORCE` is never the fix.
--
-- UPDATE and DELETE are NOT covered here. `DELIBERATELY_UNCOVERED` assigns
-- `(privatization_plans, UPDATE)` to "18c's apply/revert handlers" and
-- `(privatization_plans, DELETE)` to "nothing is expected to claim this pair",
-- and both rows stay. Approving a plan is an UPDATE, so acceptance clauses 3 and
-- 4 are not discharged by this slice; see the PR body.
--
-- ===================================================================
-- EVERY TOP-LEVEL `OR` ARM NAMES A SESSION HELPER.
--
-- `rls_enforcement.rs::no_policy_arm_is_session_independent` splits a policy
-- expression on ` OR ` and reports any arm that references none of
-- `epigraph_bypass`, `epigraph_definer_bypass`, `epigraph_session_groups`,
-- `epigraph_writable_groups`, `epigraph_principal_id`, `epigraph_is_group_admin`,
-- `epigraph_is_group_creator`, `epigraph_is_instance_admin`. 077's header
-- explains why: an arm built only from ROW columns is not a narrowing, it is an
-- unconditional grant. Each arm below names at least one.
--
-- Session-CONSTANT calls are wrapped in `(SELECT …)` so they become an InitPlan
-- evaluated once per statement rather than a per-row Filter; the row-dependent
-- `epigraph_is_group_admin(<column or correlated sub-select>)` is left unwrapped
-- because there is nothing to hoist. 083's header states the rule.
--
-- ===================================================================
-- NO GRANTS ARE OWED. 080 already issues `GRANT SELECT … TO epigraph_app` and
-- `GRANT SELECT, INSERT, UPDATE, DELETE … TO epigraph_maintenance` on both
-- tables. Neither table has a sequence — `privatization_plans.id` is
-- `uuid DEFAULT gen_random_uuid()` and `privatization_plan_items` has a
-- composite primary key — so 082's "ALTER DEFAULT PRIVILEGES covers TABLES, not
-- SEQUENCES" hazard does not apply here. Verified from `pg_class` on the
-- throwaway: the only privatization sequence is `privatization_audit_id_seq`.
--
-- ORDER-INSENSITIVITY. This file adds policies to tables 080 creates and
-- references nothing from 084-091, so it behaves identically whether it is
-- applied in a single fresh numeric-order run or beneath an existing head.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- privatization_plans
-- -------------------------------------------------------------------
DROP POLICY IF EXISTS privatization_plans_read ON public.privatization_plans;
CREATE POLICY privatization_plans_read ON public.privatization_plans FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_is_instance_admin(
                     (SELECT public.epigraph_principal_id())))
            AND public.epigraph_is_group_admin(privatization_plans.target_group_id)));

DROP POLICY IF EXISTS privatization_plans_maintenance_insert ON public.privatization_plans;
CREATE POLICY privatization_plans_maintenance_insert ON public.privatization_plans
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));

-- -------------------------------------------------------------------
-- privatization_plan_items
--
-- The read arm resolves the target group THROUGH the plan row, which is itself
-- filtered by `privatization_plans_read` above. That makes the conjunction
-- doubly stated — the sub-select already yields NULL for a plan the caller may
-- not read — and it is written out anyway for the reason 083 gives: the arm
-- should be legible as the §6.6 check without the reader having to compose two
-- policies in their head, and a later relaxation of either one does not silently
-- open the other.
-- -------------------------------------------------------------------
DROP POLICY IF EXISTS privatization_plan_items_read ON public.privatization_plan_items;
CREATE POLICY privatization_plan_items_read ON public.privatization_plan_items
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_is_instance_admin(
                     (SELECT public.epigraph_principal_id())))
            AND public.epigraph_is_group_admin(
                  (SELECT p.target_group_id FROM public.privatization_plans p
                    WHERE p.id = privatization_plan_items.plan_id))));

DROP POLICY IF EXISTS privatization_plan_items_maintenance_insert
    ON public.privatization_plan_items;
CREATE POLICY privatization_plan_items_maintenance_insert ON public.privatization_plan_items
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));

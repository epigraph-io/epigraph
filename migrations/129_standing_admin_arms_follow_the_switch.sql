-- Migration 129: the STANDING ADMIN READ ARMS follow the admin-scope switch
-- (elevation plan EL-10, DESIGN 6.5).
--
-- ===================================================================
-- 1. WHAT CHANGES
--
-- Four read policies carry a STANDING instance-admin arm,
-- `epigraph_is_instance_admin(principal)`, which 123 answers from a live
-- assignment of the platform custodian role:
--
--   * `security_events_read`          (077, recreated by 083)
--   * `privatization_audit_read`      (082, recreated by 083)
--   * `privatization_plans_read`      (087)
--   * `privatization_plan_items_read` (087)
--
-- A custodian therefore reads the whole actor log, and the plans and audit of
-- the groups it administers, at every moment, elevated or not. DESIGN 6.5
-- makes standing admin authority an elevation: once the admin-scope switch
-- (128, `epigraph_admin_scopes_armed()`) is ARMED, these arms admit only an
-- ELEVATED session (`epigraph_is_elevated()`, 125: a live elevation session of
-- this principal on this connection's family, re-checked every statement).
-- UNARMED they answer exactly as before.
--
-- Each policy is recreated with ONE conjunct replaced. The instance-admin call
-- `(SELECT public.epigraph_is_instance_admin((SELECT
-- public.epigraph_principal_id())))` becomes
--
--     (SELECT CASE WHEN public.epigraph_admin_scopes_armed()
--                  THEN public.epigraph_is_elevated()
--                  ELSE public.epigraph_is_instance_admin(
--                           (SELECT public.epigraph_principal_id()))
--             END)
--
-- and every other conjunct is byte-identical to the body it replaces (the
-- bypass arms, the self arm of `security_events_read`, and the group-admin
-- conjunct of the three privatization policies). Arming is therefore ONE row
-- change in `admin_scope_enforcement`, never policy DDL. The CASE is a session
-- constant wrapped in `(SELECT ...)`, so it stays an InitPlan evaluated once
-- per statement (083's regression guard, restated in its header).
--
-- WHAT AN ELEVATED SESSION SEES THROUGH THEM, armed:
--   * `security_events`: every row (126 already gives an elevated session
--     `security_events_elevated_read`; this arm says the same thing).
--   * `privatization_audit`: rows with no entity, and rows of plans whose
--     target group the elevated principal ADMINISTERS (126's
--     `privatization_audit_elevated_read` already admits every row).
--   * `privatization_plans` / `privatization_plan_items`: only plans whose
--     target group the elevated principal administers. The group-admin
--     conjunct stays: these two tables are EXCLUDED from 126's arms (T-OPS),
--     so an elevated custodian who is not the target group's admin reads none
--     of them, as an unarmed custodian does not either. Unchanged on purpose:
--     the privatization routes decide on that pair.
--
-- WHO EVALUATES IT. The policies stay `TO PUBLIC`. The roles that read these
-- tables through a policy (the application role and the maintenance role; a
-- superuser skips row security) can EXECUTE both new callees: 125 and 128
-- grant them to the application role, and the maintenance role owns them.
--
-- ===================================================================
-- 2. ROLLOUT AND ROLLBACK
--
-- Inert while unarmed. Policy DDL on `security_events` (busy) and the three
-- privatization tables, so the file runs in ONE transaction with a 3 s
-- `lock_timeout` (083's and 087's form): it either recreates all four or
-- none, and a held lock fails it fast instead of queueing every reader behind
-- it. Rerunnable (drop-before-create).
--
-- Undo: `docs/runbooks/129-undo.sql` recreates the four bodies exactly as 083
-- and 087 left them. Run it BEFORE `128-undo.sql`: these policies call
-- `epigraph_admin_scopes_armed()`, whose `DROP FUNCTION` (no CASCADE) refuses
-- while they exist.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR (SELECT CASE WHEN public.epigraph_admin_scopes_armed()
                        THEN public.epigraph_is_elevated()
                        ELSE public.epigraph_is_instance_admin(
                                 (SELECT public.epigraph_principal_id()))
                   END));

DROP POLICY IF EXISTS privatization_audit_read ON public.privatization_audit;
CREATE POLICY privatization_audit_read ON public.privatization_audit FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT CASE WHEN public.epigraph_admin_scopes_armed()
                         THEN public.epigraph_is_elevated()
                         ELSE public.epigraph_is_instance_admin(
                                  (SELECT public.epigraph_principal_id()))
                    END)
            AND (entity_id IS NULL
                 OR public.epigraph_is_group_admin(
                      (SELECT p.target_group_id FROM public.privatization_plans p
                        WHERE p.id = privatization_audit.plan_id)))));

DROP POLICY IF EXISTS privatization_plans_read ON public.privatization_plans;
CREATE POLICY privatization_plans_read ON public.privatization_plans FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT CASE WHEN public.epigraph_admin_scopes_armed()
                         THEN public.epigraph_is_elevated()
                         ELSE public.epigraph_is_instance_admin(
                                  (SELECT public.epigraph_principal_id()))
                    END)
            AND public.epigraph_is_group_admin(privatization_plans.target_group_id)));

DROP POLICY IF EXISTS privatization_plan_items_read ON public.privatization_plan_items;
CREATE POLICY privatization_plan_items_read ON public.privatization_plan_items
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT CASE WHEN public.epigraph_admin_scopes_armed()
                         THEN public.epigraph_is_elevated()
                         ELSE public.epigraph_is_instance_admin(
                                  (SELECT public.epigraph_principal_id()))
                    END)
            AND public.epigraph_is_group_admin(
                  (SELECT p.target_group_id FROM public.privatization_plans p
                    WHERE p.id = privatization_plan_items.plan_id))));

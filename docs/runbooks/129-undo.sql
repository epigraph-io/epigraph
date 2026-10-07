-- ===================================================================
-- 129-undo.sql: take migration 129 (the standing admin read arms follow the
-- admin-scope switch) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. After this runs the four standing read arms answer from
-- `epigraph_is_instance_admin(principal)` again WHATEVER the switch says: an
-- ARMED database goes back to showing a custodian the whole actor log and the
-- plans of the groups it administers without an elevation. Disarm first
-- (`epigraph-operator disarm-admin-scopes`) if the undo is meant to restore
-- the unarmed posture as a whole.
--
-- ORDER: run this BEFORE `128-undo.sql`. The 129 policies call
-- `epigraph_admin_scopes_armed()`, and 128-undo's `DROP FUNCTION` (no
-- CASCADE) refuses while they exist.
--
-- WHAT IT DOES: recreates `security_events_read`, `privatization_audit_read`
-- (083's bodies), `privatization_plans_read` and
-- `privatization_plan_items_read` (087's bodies), byte for byte.
--
-- WHAT IT LEAVES: 129's `_sqlx_migrations` row. Re-introducing the switch
-- form is a NEW migration, never a re-run of 129. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR (SELECT public.epigraph_is_instance_admin(
                    (SELECT public.epigraph_principal_id()))));

DROP POLICY IF EXISTS privatization_audit_read ON public.privatization_audit;
CREATE POLICY privatization_audit_read ON public.privatization_audit FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_is_instance_admin(
                     (SELECT public.epigraph_principal_id())))
            AND (entity_id IS NULL
                 OR public.epigraph_is_group_admin(
                      (SELECT p.target_group_id FROM public.privatization_plans p
                        WHERE p.id = privatization_audit.plan_id)))));

DROP POLICY IF EXISTS privatization_plans_read ON public.privatization_plans;
CREATE POLICY privatization_plans_read ON public.privatization_plans FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_is_instance_admin(
                     (SELECT public.epigraph_principal_id())))
            AND public.epigraph_is_group_admin(privatization_plans.target_group_id)));

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

COMMIT;

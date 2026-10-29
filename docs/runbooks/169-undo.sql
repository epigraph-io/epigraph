-- ===================================================================
-- 169-undo.sql: take migration 169 (applied-cascade audit rows are read by
-- instance admins only) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. After this runs a principal reads the `cascade.admin_applied`
-- and `cascade.belief_rederived` rows naming it again, including the legacy
-- rows that carry the ids of other writers' edges and claims.
--
-- WHAT IT DOES: recreates `security_events_read` with the body of the
-- migration before 169 that last created it (129 today), byte for byte. If a
-- later migration recreates `security_events_read`, undo that one first and
-- re-check this body against the then-preceding migration.
--
-- ORDER: run this BEFORE `129-undo.sql` if that is undone too (129-undo
-- recreates 083's body, which has the same unnarrowed own-row arm).
--
-- WHAT IT LEAVES: 169's `_sqlx_migrations` row, and every `security_events`
-- row (169 changed no data). Re-introducing the narrowing is a NEW
-- migration, never a re-run of 169. Idempotent.
-- ===================================================================
BEGIN;
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

COMMIT;

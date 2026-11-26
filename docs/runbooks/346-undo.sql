-- ===================================================================
-- 309-undo.sql: take migration 309 (the team lists bound to the session
-- principal; `epigraph_is_group_admin` over live membership) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: re-states the three bodies 309 replaced, verbatim from their
-- predecessors (CREATE OR REPLACE keeps owner and grants):
--   * `epigraph_writable_teams` (236's body: answers for ANY agent id again,
--     on the application role too);
--   * `epigraph_readable_teams` (236's body, likewise);
--   * `epigraph_is_group_admin` (077's body: a raw unrevoked admin row, a
--     lapsed one included, on 077's `public, pg_temp` path).
--
-- ORDER: binaries built with 309 work against the restored bodies unchanged
-- (they stamp the principal they ask about, which 236's bodies ignore). Roll
-- back binaries that predate 309 only AFTER this file: on a database still at
-- 309 an operated agent loses its human's teams and writes resolve no team.
--
-- It leaves 309's `_sqlx_migrations` row. Re-introducing the bind is a NEW
-- migration, never a re-run of 309 (or delete the row:
--   DELETE FROM _sqlx_migrations WHERE version = 309;).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_writable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships_unbound(p_agent) m
         WHERE m.role IN ('writer', 'admin')
    ), h AS (
        SELECT public.epigraph_human_of(p_agent, true) AS human
    )
    SELECT g.id,
           CASE WHEN g.id IN (SELECT o.group_id FROM own o) THEN 'own' ELSE 'operator' END
      FROM public.groups g, h
     WHERE p_agent IS NOT NULL
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR (h.human IS NOT NULL AND h.human <> p_agent
                AND public.epigraph_operator_writes_group(h.human, g.id)))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writable_teams(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_readable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships_unbound(p_agent) m
    ), h AS (
        SELECT public.epigraph_human_of(p_agent, true) AS human
    ), hm AS (
        SELECT m.group_id
          FROM h
          JOIN public.group_memberships m ON m.agent_id = h.human
         WHERE h.human IS NOT NULL AND h.human <> p_agent
           AND m.revoked_at IS NULL
           AND public.epigraph_is_human_operator(h.human)
    )
    SELECT g.id,
           CASE WHEN g.id IN (SELECT o.group_id FROM own o) THEN 'own' ELSE 'operator' END
      FROM public.groups g
     WHERE p_agent IS NOT NULL
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR g.id IN (SELECT x.group_id FROM hm x))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_is_group_admin(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_principal_id() IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.group_memberships m
       WHERE m.group_id = p_group
         AND m.agent_id = public.epigraph_principal_id()
         AND m.role = 'admin' AND m.revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid) FROM PUBLIC;

COMMIT;

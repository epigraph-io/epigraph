-- ===================================================================
-- 236-undo.sql: take migration 236 (`epigraph_live_memberships(agent)`
-- answers only for the session principal) back out, in ONE transaction, on
-- the migration (superuser) DSN.
--
-- WHAT IT DOES: re-states the three bodies 236 replaced, verbatim from their
-- predecessors (CREATE OR REPLACE keeps owner and grants), then drops the
-- maintenance-only twin, which nothing calls any more:
--   * `epigraph_live_memberships`  (235's body: answers for ANY agent id
--     again, on the application role too);
--   * `epigraph_writable_teams`    (206's body, calling the read above);
--   * `epigraph_readable_teams`    (234's body, likewise);
--   * DROP `epigraph_live_memberships_unbound(uuid)`.
--
-- ORDER: binaries built with 236 work against the restored body unchanged
-- (they stamp the principal they ask about, which 235's body ignores). Roll
-- back binaries that predate 236 only AFTER this file: on a database still at
-- 236 they resolve every viewer to public-only.
--
-- It leaves 236's `_sqlx_migrations` row. Re-introducing the bind is a NEW
-- migration, never a re-run of 236.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT m.group_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(p_agent, true)))
       -- 235: a personal-group row of an agent allowlisted for the group's
       -- owner lapses with that allowance.
       AND (g.kind <> 'personal'
            OR g.created_by_agent_id = p_agent
            OR NOT EXISTS (SELECT 1 FROM public.author_binding_clients r
                            WHERE r.agent_id = p_agent
                              AND r.operator_id = g.created_by_agent_id)
            OR public.epigraph_human_of(p_agent, true) = g.created_by_agent_id)
    UNION
    SELECT d.group_id, d.role
      FROM public.epigraph_role_derived_memberships(p_agent, now()) d
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_writable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships(p_agent) m
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
        SELECT m.group_id FROM public.epigraph_live_memberships(p_agent) m
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

DROP FUNCTION IF EXISTS public.epigraph_live_memberships_unbound(uuid);

COMMIT;

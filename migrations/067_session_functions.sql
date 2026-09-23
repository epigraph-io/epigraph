-- 067_session_functions.sql
-- The GUC/bypass functions the RLS policies (migration 077) and ScopedPool read.
-- epigraph_visible() is NOT created -- it bought readability at the cost of an
-- inlining assumption and one more SECURITY DEFINER-adjacent surface to REVOKE.
-- epigraph_groups_for() is NOT created -- it is folded into Viewer::resolve's
-- single query (GroupMembershipRepository::list_live_for_agent).
SET LOCAL lock_timeout = '3s';

-- RLS-only. STABLE (fixed within a statement, varies across transactions).
-- Wrapped in (SELECT ...) at the policy site so the planner emits an InitPlan
-- evaluated ONCE per statement rather than once per row. Without the wrapper a
-- seq scan over 1e6 claims parses the GUC 1e6 times.
CREATE OR REPLACE FUNCTION public.epigraph_session_groups() RETURNS uuid[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT array_agg(x::uuid) FROM unnest(string_to_array(
          NULLIF(current_setting('epigraph.group_ids', true), ''), ',')) AS x),
      ARRAY[]::uuid[]);
$$;

-- The WRITABLE subset (group_memberships.role IN ('admin','writer')). Used by
-- every WITH CHECK in migration 077.
CREATE OR REPLACE FUNCTION public.epigraph_writable_groups() RETURNS uuid[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT array_agg(x::uuid) FROM unnest(string_to_array(
          NULLIF(current_setting('epigraph.writable_group_ids', true), ''), ',')) AS x),
      ARRAY[]::uuid[]);
$$;

CREATE OR REPLACE FUNCTION public.epigraph_principal_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('epigraph.principal_id', true), '')::uuid;
$$;

-- The maintenance escape hatch is ROLE MEMBERSHIP, not the BYPASSRLS attribute.
-- A compromised application connection cannot SET its way into it; revoking it
-- is one GRANT and it is visible in pg_auth_members.
--
-- session_user, NOT current_user: inside a SECURITY DEFINER frame current_user
-- resolves to the FUNCTION OWNER, which is exactly the escalation the security
-- review flagged. The EXISTS guard means this is safe to call before the roles
-- exist (managed Postgres -- migration 060's CREATE ROLE only NOTICEs on
-- insufficient_privilege).
CREATE OR REPLACE FUNCTION public.epigraph_bypass() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER')
        WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')),
      false);
$$;

-- THE current_user VARIANT (sec F10). Used ONLY inside the two trigger bodies
-- that must write through their own tables' policies while running as the
-- function owner: epigraph_propagate_tenancy and epigraph_inherit_tenancy
-- (migration 070). Safe because it is REVOKE EXECUTE ... FROM PUBLIC and
-- neither trigger is callable from SQL the app can emit.
CREATE OR REPLACE FUNCTION public.epigraph_definer_bypass() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
        WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')),
      false);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_definer_bypass() FROM PUBLIC;

-- LEAKPROOF on epigraph_bypass() stays DECLINED: it requires superuser and,
-- with the duplicate HNSW index gone, buys nothing.

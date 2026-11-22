-- ===================================================================
-- 257-undo.sql: take migration 257 (the retire verb's dedicated owner role;
-- backlog 9cec11f7) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES:
--   * re-states 191's `epigraph_operator_links_retire_only` body verbatim
--     (no OLR05 arm, no clearing of the audit context): CREATE OR REPLACE
--     keeps its owner and grants;
--   * moves UPDATE (retired) on `operator_links` back from
--     `epigraph_operator_link_retirer` to `epigraph_maintenance`;
--   * re-owns `epigraph_retire_operator_link` to `epigraph_maintenance`
--     (the new owner's ACL entry becomes the maintenance role's, so it keeps
--     EXECUTE; PUBLIC and the application role stay revoked).
--
-- WHAT IT LEAVES:
--   * the role `epigraph_operator_link_retirer`. Roles are cluster-scoped and
--     another database on the cluster may still run its verb as it. Once no
--     database does, drop it as a superuser:
--       REVOKE epigraph_maintenance FROM epigraph_operator_link_retirer;
--       DROP ROLE epigraph_operator_link_retirer;
--   * every link the verb retired (a retired link is permanent, 107) and
--     every audit row (082: immutable);
--   * 257's `_sqlx_migrations` row. Re-introducing 257's control is a NEW
--     migration, never a re-run of 257.
--
-- After it, a maintenance login can again retire a link directly,
-- unserialised and with an advisory audit `via` / reason (191's limits).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_operator_links_retire_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                WHERE r.rolname = session_user AND r.rolsuper) THEN
        RETURN NEW;
    END IF;
    IF NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.operator_group_id IS DISTINCT FROM OLD.operator_group_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.retired AND NOT NEW.retired) THEN
        RAISE EXCEPTION 'OLR04: an operator link is only ever retired (retired false -> true); '
                        'a retired link is permanent and a link is never re-pointed (agent %); '
                        'nothing was changed', OLD.agent_id
            USING ERRCODE = '42501';
    END IF;
    -- ZERO write authority is a precondition of a retire on EVERY path, not
    -- only the verb's (107/122 section 7).
    IF NOT OLD.retired AND NEW.retired
       AND EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = OLD.operator_group_id
                      AND m.agent_id = OLD.agent_id
                      AND m.revoked_at IS NULL
                      AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'OLR03: agent % holds a live writer/admin membership in operator '
                        'group %, and a retired identity may hold no write authority there; '
                        'nothing was changed', OLD.agent_id, OLD.operator_group_id
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership in the same act: epigraph-operator '
                         'retire-link --revoke-membership.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_retire_only() FROM PUBLIC;

GRANT UPDATE (retired) ON public.operator_links TO epigraph_maintenance;
REVOKE UPDATE (retired) ON public.operator_links FROM epigraph_operator_link_retirer;
ALTER FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean)
    OWNER TO epigraph_maintenance;
REVOKE EXECUTE ON FUNCTION public.epigraph_retire_operator_link(uuid, text, boolean) FROM PUBLIC;

COMMIT;

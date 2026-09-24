-- 104_group_memberships_guards.sql
-- Roster guards on `group_memberships` that the tenancy policy cannot express.
--
-- Invoker trigger functions and BEFORE triggers on `group_memberships`. No
-- table, no policy change, no rows written.
--
-- ===================================================================
-- 1. A MEMBERSHIP IS REMOVED BY REVOKING IT, NEVER BY DELETING IT
--
-- `group_memberships_tenancy` (077) is `FOR ALL`, and its USING clause admits
-- the session's OWN row (`agent_id = epigraph_principal_id()`) and every row of
-- a group in the session's group set (`group_id = ANY(epigraph_session_groups())`).
-- `epigraph_app` holds DELETE on the table, and a DELETE is governed by USING
-- alone. So any member of a group could hard-delete any row of that group.
--
-- MEASURED by review as `SET SESSION AUTHORIZATION epigraph_app`, stamped as
-- `Viewer::resolve` stamps a principal:
--
--   * a revoked operated agent X deleted its own revoked row (`DELETE 1`), and
--     102's link then re-created a live writer row (closed separately in 102:
--     the membership is now inserted only by the call that records the link);
--   * a live operated writer Y deleted its OPERATOR's `admin` row in the
--     operator's personal group (`DELETE 1`). The operator then failed
--     `epigraph_is_group_admin` and `epigraph_is_group_creator` (092 binds the
--     creator arm to a live roster row), so its `UPDATE ... SET revoked_at` of
--     Y matched nothing (`UPDATE 0`) and Y stayed live. Only a call to
--     `epigraph_ensure_personal_group` repaired it, and Y could delete again.
--
-- The ledger contract is already that removal is a soft UPDATE: every removal
-- in `crates/` is `UPDATE ... SET revoked_at = now()` (092 section 3,
-- `community.rs`'s revoke), and no production code issues
-- `DELETE FROM group_memberships`. So a BEFORE DELETE row trigger refuses a
-- DELETE outside the two escape hatches every tenancy control admits:
--
--   * `epigraph_bypass()` -- a maintenance or superuser SESSION;
--   * `epigraph_definer_bypass()` -- a SECURITY DEFINER frame owned by a
--     maintenance member.
--
-- A trigger rather than a policy split: splitting the FOR ALL policy would
-- restate its USING clause per command, and the question is not "which rows"
-- but "is a hard delete allowed at all", which is a yes/no on the caller.
-- SECURITY INVOKER on purpose: the question is about the CALLER.
--
-- CASCADES FIRE IT TOO. `group_memberships` references `agents` and `groups`
-- with ON DELETE CASCADE, and a cascaded delete runs this trigger in the
-- deleting session. So an app session can no longer hard-delete an agent or a
-- group that has membership rows. `groups` deletes were already refused
-- (`groups_block_delete`); deleting an agent with memberships erases exactly
-- the history this section protects, and the only in-tree `DELETE FROM agents`
-- paths are test clean-ups on the superuser harness. SQLSTATE 42501.
--
-- ===================================================================
-- UNDO
--
-- `DROP TRIGGER IF EXISTS group_memberships_no_hard_delete ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_no_hard_delete();`.
-- No rows to un-write. **Applied to a throwaway database only, NOT to any
-- deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_no_hard_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'group_memberships: a membership is removed by revoking it '
                    '(UPDATE ... SET revoked_at = now()), never by DELETE outside a '
                    'maintenance session (group %, agent %)', OLD.group_id, OLD.agent_id
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS group_memberships_no_hard_delete ON public.group_memberships;
CREATE TRIGGER group_memberships_no_hard_delete
    BEFORE DELETE ON public.group_memberships
    FOR EACH ROW
    EXECUTE FUNCTION public.epigraph_group_memberships_no_hard_delete();

-- 104_group_memberships_guards.sql
-- Roster guards on `group_memberships` that the tenancy policy cannot express.
--
-- Two invoker trigger functions and two BEFORE triggers on
-- `group_memberships`. No table, no policy change, no rows written.
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
-- 2. A RETIRED IDENTITY NEVER HOLDS WRITE AUTHORITY IN ITS OPERATOR'S GROUP
--
-- 102 section 7: a RETIRED link gives the operator ownership of a historical
-- identity's claims and gives the identity ZERO write authority, because many
-- retired keys are publicly recomputable or were printed to logs.
-- `epigraph_link_retired_agent` creates no membership, but nothing stopped one
-- being added LATER by an ordinary roster write. MEASURED by review: the
-- operator O, stamped as admin of its personal group OG, inserted a `writer`
-- row for a retired R (`INSERT 0 1`), and R, stamped from its live set, then
-- inserted a claim owned by OG (`INSERT 0 1`) -- `Viewer::resolve` derives the
-- writable set from memberships alone, while `epigraph_operator_actor(R)` still
-- returned nothing. A routine "add my agents to my group" would thereby hand a
-- public key write access to the operator's group.
--
-- So a BEFORE INSERT OR UPDATE row trigger refuses, outside the two escape
-- hatches, any row that would leave a LIVE `writer`/`admin` membership for an
-- agent in the group its RETIRED link names. INSERT and UPDATE both, because
-- reviving a revoked row and promoting a `reader` are the same hole. A
-- `reader` row is allowed: it grants no write. The `WHEN` clause keeps the
-- trigger off every other row. The retired bit is read through
-- `epigraph_operator_of_author` (102, EXECUTE granted to `epigraph_app`),
-- because an app session cannot see `operator_links`.
--
-- ===================================================================
-- UNDO
--
-- `DROP TRIGGER IF EXISTS group_memberships_no_hard_delete ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_no_hard_delete();`,
-- and `DROP TRIGGER IF EXISTS group_memberships_no_retired_writer ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_no_retired_writer();`.
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

CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_no_retired_writer()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM public.epigraph_operator_of_author(NEW.agent_id) o
                WHERE o.retired AND o.operator_group_id = NEW.group_id) THEN
        RAISE EXCEPTION 'group_memberships: agent % has a RETIRED operator link to group %, '
                        'and a retired identity may hold no live writer or admin membership '
                        'there (migration 102 section 7)', NEW.agent_id, NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS group_memberships_no_retired_writer ON public.group_memberships;
CREATE TRIGGER group_memberships_no_retired_writer
    BEFORE INSERT OR UPDATE ON public.group_memberships
    FOR EACH ROW
    WHEN (NEW.revoked_at IS NULL AND NEW.role IN ('writer', 'admin'))
    EXECUTE FUNCTION public.epigraph_group_memberships_no_retired_writer();

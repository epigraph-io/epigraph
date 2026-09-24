-- 109_group_memberships_guards.sql
-- A roster guard on `group_memberships` that the tenancy policy cannot express.
--
-- One invoker trigger function and one BEFORE trigger on `group_memberships`.
-- No table, no policy change, no grant change, no rows written.
--
-- ===================================================================
-- 1. HARD DELETES: MIGRATION 106 OWNS THIS, AND THIS FILE ADDS NOTHING
--
-- `group_memberships_tenancy` (077) is `FOR ALL`, and its USING clause admits
-- the session's OWN row (`agent_id = epigraph_principal_id()`) and every row of
-- a group in the session's group set. While `epigraph_app` held DELETE, review
-- measured, as `SET SESSION AUTHORIZATION epigraph_app` stamped as
-- `Viewer::resolve` stamps a principal:
--
--   * a revoked operated agent X deleted its own revoked row (`DELETE 1`), and
--     107's link then re-created a live writer row (closed separately in 107:
--     the membership is now inserted only by the call that records the link);
--   * a live operated writer Y deleted its OPERATOR's `admin` row in the
--     operator's personal group (`DELETE 1`), after which the operator failed
--     `epigraph_is_group_admin` / `epigraph_is_group_creator` and its revoke of
--     Y matched nothing.
--
-- This file's first form (authored as 104, before batch F shipped) closed that
-- with a BEFORE DELETE row trigger refusing any DELETE outside
-- `epigraph_bypass()` / `epigraph_definer_bypass()`. Migration 106 then closed
-- the same hole on main by `REVOKE DELETE ON group_memberships FROM
-- epigraph_app`, and chose the REVOKE over a trigger deliberately (106's
-- "THE LEDGER" section: referential actions run as the table owner, so a
-- forced `DELETE FROM groups` or an agent deletion still cascades, where a row
-- trigger would fire on the cascade). This file runs after 106 on every
-- database, so the trigger was removed rather than stacked on the REVOKE.
-- MEASURED on a test database migrated 001 -> 109 with and without the
-- trigger, the behaviour is identical:
--
--   * `epigraph_app` stamped as X: `DELETE FROM group_memberships ...` ->
--     `permission denied for table group_memberships` (42501) in both, raised
--     by the privilege check before any row trigger could run;
--   * `epigraph_app` stamped as X: `DELETE FROM agents WHERE id = X` ->
--     `DELETE 0` in both (the `agents` policies admit no app DELETE);
--   * the superuser's `DELETE FROM agents` cascades to the membership in both.
--
-- and, on that database, the only roles holding DELETE on the table are
-- superusers and `pg_write_all_data` (which has no members there). So the
-- guarantee that 107 section 3 and the review arms rely on is 106's REVOKE, and
-- `operator_link.rs::an_app_session_cannot_hard_delete_a_membership` pins it:
-- re-granting DELETE to `epigraph_app` makes that test fail.
--
-- ===================================================================
-- 2. A RETIRED IDENTITY NEVER HOLDS WRITE AUTHORITY IN ITS OPERATOR'S GROUP
--
-- 107 section 7: a RETIRED link gives the operator ownership of a historical
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
-- `epigraph_operator_of_author` (107, EXECUTE granted to `epigraph_app`),
-- because an app session cannot see `operator_links`.
--
-- Batch F has no counterpart to this rule, so it is kept. Its writers do not
-- meet it: 106's `epigraph_community_add_member` restores a revoked row only at
-- `reader`, and 105's `epigraph_ensure_personal_group` writes only the agent's
-- OWN personal group (never an operator's group). Both run in definer frames,
-- which the bypass admits anyway.
--
-- ===================================================================
-- UNDO
--
-- `DROP TRIGGER IF EXISTS group_memberships_no_retired_writer ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_no_retired_writer();`.
-- No rows to un-write. Hard deletes stay refused by 106's REVOKE either way.
-- **Applied to a throwaway database only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

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
                        'there (migration 107 section 7)', NEW.agent_id, NEW.group_id
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

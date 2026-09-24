-- 109_group_memberships_guards.sql
-- Two roster guards on `group_memberships` that the tenancy policy cannot
-- express.
--
-- Two invoker trigger functions and two BEFORE triggers on
-- `group_memberships`. No table, no policy change, no grant change, no rows
-- written.
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
-- The trigger covers rows written AFTER the retire. A row that PREDATES it is
-- 107's: `epigraph_link_retired_agent` refuses the retire while the agent holds
-- a live `writer`/`admin` row in the operator's group, checked under row locks
-- (107 section 7). Between the two, a retired identity holds no such row
-- EXCEPT through one concurrent order 107 section 7 records as a reasoned,
-- unmeasured residual: an INSERT whose BEFORE trigger (this one) ran while the
-- retire was uncommitted and whose foreign-key check then waited on it.
--
-- Batch F has no counterpart to this rule, so it is kept. Its writers do not
-- meet it: 106's `epigraph_community_add_member` restores a revoked row only at
-- `reader`, and 105's `epigraph_ensure_personal_group` writes only the agent's
-- OWN personal group (never an operator's group). Both run in definer frames,
-- which the bypass admits anyway.
--
-- ===================================================================
-- 3. A ROW'S (group_id, agent_id) IS ITS IDENTITY: NO APP SESSION MOVES IT
--
-- 106 closed the hard DELETE and section 1 records why nothing is stacked on
-- it. An UPDATE that changes a row's `group_id` or `agent_id` is the same
-- hole by another statement: it removes the row from the (group, agent) it
-- recorded -- a revocation included -- exactly as a DELETE would, and places
-- it under a (group, agent) that no roster rule vetted as an INSERT.
-- `group_memberships_tenancy` (077) is FOR ALL and `epigraph_app` holds UPDATE
-- on the table (the revoke, the epoch rotation and the key re-wrap all UPDATE
-- it), and no policy or trigger restricted WHICH columns an UPDATE may change.
-- Review measured the class: a moved revoked row is no longer seen by 105's
-- "only revoked rows -> RVK01" nor by 107's refusal of links to a revoked
-- operator, and a moved row of ANOTHER member leaves the group it belonged
-- to. `operator_link.rs::an_app_session_cannot_move_a_membership_row` and
-- `personal_group_no_revival.rs::a_revoked_agent_cannot_move_its_row_out_and_reprovision`
-- pin the refusal.
--
-- So a BEFORE UPDATE row trigger refuses, outside the two escape hatches
-- (`epigraph_bypass()` / `epigraph_definer_bypass()`, as in section 2), any
-- change to `group_id` or `agent_id` (42501). Nothing in the application
-- changes either column: every production UPDATE of this table writes
-- `revoked_at` (`GroupMembershipRepository`), `wrapped_key_share` / `epoch`
-- (`GroupKeyEpochRepository::rotate_conn`), or `revoked_at` / `role` inside
-- 106's definer; the ON CONFLICT upserts (077's and the test fixtures') set
-- `revoked_at` / `role` only. `epoch` stays writable. A trigger, not
-- column-scoped grants, because a column REVOKE does not subtract from the
-- table-level UPDATE 077 grants, and replacing that grant with a column list
-- would have to track every future writable column. The `WHEN` clause keeps
-- the trigger off every row whose identity does not change, and the
-- foreign keys to `groups` / `agents` are ON UPDATE NO ACTION, so no
-- referential action can fire it. Rotating a membership to another group is
-- a revoke plus an INSERT, each vetted by the policy on its own.
--
-- ===================================================================
-- UNDO
--
-- `DROP TRIGGER IF EXISTS group_memberships_no_retired_writer ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_no_retired_writer();`,
-- and `DROP TRIGGER IF EXISTS group_memberships_identity_immutable ON public.group_memberships;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_group_memberships_identity_immutable();`.
-- No rows to un-write. Hard deletes stay refused by 106's REVOKE either way;
-- dropping the second trigger reopens section 3's move.
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

-- Section 3.
CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'group_memberships: a membership''s group_id and agent_id are its '
                    'identity and cannot be changed (migration 109 section 3); revoke the '
                    'row and insert a new one instead'
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS group_memberships_identity_immutable ON public.group_memberships;
CREATE TRIGGER group_memberships_identity_immutable
    BEFORE UPDATE OF group_id, agent_id ON public.group_memberships
    FOR EACH ROW
    WHEN (OLD.group_id IS DISTINCT FROM NEW.group_id
          OR OLD.agent_id IS DISTINCT FROM NEW.agent_id)
    EXECUTE FUNCTION public.epigraph_group_memberships_identity_immutable();

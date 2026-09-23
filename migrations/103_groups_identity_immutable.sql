-- 103_groups_identity_immutable.sql
-- A group's IDENTITY columns -- `created_by_agent_id`, `did_key`, `kind` --
-- cannot be changed by an application session.
--
-- One invoker trigger function and one BEFORE UPDATE trigger on `groups`. No
-- table, no policy change, no rows written.
--
-- ===================================================================
-- 1. THE HOLE (pre-existing since 077; 102 is the first path that exposes it)
--
-- `groups_tenancy` (077) is `FOR ALL`, USING "any group in the session's
-- groups" and WITH CHECK `created_by_agent_id = epigraph_principal_id()`. For
-- an UPDATE that means: any member of a group may rewrite ANY column of it, as
-- long as the new row names the session principal as creator. 092's creator
-- arm then treats a creator holding a live membership as admin-equivalent for
-- enrolment and key epochs.
--
-- MEASURED by review (attack 2c) as `SET SESSION AUTHORIZATION epigraph_app`,
-- stamped exactly as `Viewer::resolve` stamps an agent A that migration 102
-- linked as a `writer` in its operator's personal group:
--
--   UPDATE groups SET created_by_agent_id = A WHERE id = <operator group>
--     -> UPDATE 1, the row read back with created_by = A;
--   INSERT group_memberships (<operator group>, Z, 'writer')
--     -> INSERT 0 1.
--
-- A direct enrol of Z and a self-promotion to admin were both refused in the
-- same session, so the creator rewrite was the whole bypass: a `writer` became
-- an admin of the operator's group. No application code writes any of these
-- three columns -- MEASURED: every `UPDATE groups` in `crates/` sets
-- `reseal_required_at`, `updated_at` or `properties`, and the only statements
-- that change `kind` are test fixtures on the superuser harness -- so this is
-- reachable only at the RLS layer, which is exactly the layer the tenancy
-- series exists to make sufficient on its own.
--
-- ===================================================================
-- 2. THE FIX: AN INVOKER TRIGGER, NOT A POLICY SPLIT
--
-- A policy cannot compare OLD with NEW: an UPDATE's WITH CHECK sees only the
-- new row. Splitting `groups_tenancy` so its UPDATE arm re-derives the old
-- creator would mean a self-referencing subquery on `groups` inside `groups`'s
-- own policy -- the recursion shape 077 section 7 spends a page avoiding. A
-- BEFORE UPDATE row trigger sees OLD and NEW directly and costs nothing when
-- the three columns are unchanged (its `WHEN` clause is evaluated before the
-- function is called).
--
-- The function is SECURITY INVOKER on purpose: the question is about the
-- CALLER, so it must run as the caller. It admits exactly the two escape
-- hatches every tenancy control admits:
--
--   * `epigraph_bypass()`  -- a maintenance or superuser SESSION (`session_user`);
--   * `epigraph_definer_bypass()` -- a SECURITY DEFINER frame owned by a
--     maintenance member (`current_user` inside the frame).
--
-- `epigraph_app` holds EXECUTE on both (077 grants `epigraph_definer_bypass`
-- to it; `epigraph_bypass` keeps its default grant), so the trigger evaluates
-- rather than erroring for the role it is aimed at. Any role WITHOUT that
-- EXECUTE is refused with 42501 on these columns too, which is the same
-- answer.
--
-- The refusal is SQLSTATE 42501 with a message naming the columns, so a
-- caller sees a permission failure, not a generic check violation.
--
-- ===================================================================
-- 3. UNDO
--
-- `DROP TRIGGER IF EXISTS groups_identity_immutable ON public.groups;` then
-- `DROP FUNCTION IF EXISTS public.epigraph_groups_identity_immutable();`. No
-- rows to un-write. **Applied to a throwaway database only, NOT to any
-- deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_groups_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'groups: created_by_agent_id, did_key and kind are immutable outside a '
                    'maintenance session (group %)', OLD.id
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS groups_identity_immutable ON public.groups;
CREATE TRIGGER groups_identity_immutable
    BEFORE UPDATE ON public.groups
    FOR EACH ROW
    WHEN (OLD.created_by_agent_id IS DISTINCT FROM NEW.created_by_agent_id
       OR OLD.did_key IS DISTINCT FROM NEW.did_key
       OR OLD.kind IS DISTINCT FROM NEW.kind)
    EXECUTE FUNCTION public.epigraph_groups_identity_immutable();

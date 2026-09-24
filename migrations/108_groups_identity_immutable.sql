-- 108_groups_identity_immutable.sql
-- A group's IDENTITY columns -- `created_by_agent_id`, `did_key`, `kind` --
-- cannot be changed by an application session.
--
-- Two invoker trigger functions, a BEFORE UPDATE and a BEFORE INSERT trigger
-- on `groups`. No table, no policy change, no rows written.
--
-- ===================================================================
-- 1. THE HOLE (pre-existing since 077; 107 is the first path that exposes it)
--
-- `groups_tenancy` (077) is `FOR ALL`, USING "any group in the session's
-- groups" and WITH CHECK `created_by_agent_id = epigraph_principal_id()`. For
-- an UPDATE that means: any member of a group may rewrite ANY column of it, as
-- long as the new row names the session principal as creator. 092's creator
-- arm then treats a creator holding a live membership as admin-equivalent for
-- enrolment and key epochs.
--
-- MEASURED by review (attack 2c) as `SET SESSION AUTHORIZATION epigraph_app`,
-- stamped exactly as `Viewer::resolve` stamps an agent A that migration 107
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
-- 3. A PERSONAL IDENTITY NAMES ITS CREATOR FROM THE FIRST INSERT
--
-- Immutability after insert is only half of it. `groups_tenancy`'s WITH CHECK
-- only asks that the NEW row name the session principal as creator, so ANY
-- principal Z could INSERT a group carrying `did:epigraph:personal:<N>` for an
-- operator N that has no personal group yet (MEASURED by review, attack 2: as
-- `epigraph_app` stamped as Z, `INSERT 0 1`). 107's link functions then refuse
-- N as an operator ("is not a personal group created by that operator"), which
-- is correct, but the squat row can never be removed by the app
-- (`groups_block_delete`) or re-keyed (section 2), so the squatter blocks N's
-- personal group -- and every operator link to N -- permanently, until
-- maintenance repairs it. `GroupRepository::create_with_admin` also takes a
-- caller-supplied did_key for a `kind='team'` group, so the squat is not
-- limited to `kind='personal'`.
--
-- So a BEFORE INSERT row trigger refuses, outside the same two escape
-- hatches, any row whose did_key is in the personal namespace OR whose kind is
-- `personal` unless BOTH hold: `kind = 'personal'` and
-- `did_key = 'did:epigraph:personal:' || created_by_agent_id`. Every in-tree
-- personal-group writer already produces exactly that row (077's
-- `epigraph_ensure_personal_group`, 107's link functions and 071's shim run as
-- definers; `tenancy_backfill` runs on a maintenance DSN), so this refuses
-- nothing legitimate. Squatting becomes impossible rather than merely refused
-- at link time.
--
-- ===================================================================
-- 4. UNDO
--
-- `DROP TRIGGER IF EXISTS groups_identity_immutable ON public.groups;` then
-- `DROP FUNCTION IF EXISTS public.epigraph_groups_identity_immutable();`, and
-- `DROP TRIGGER IF EXISTS groups_personal_identity_names_creator ON public.groups;`
-- then `DROP FUNCTION IF EXISTS public.epigraph_groups_personal_identity_names_creator();`.
-- No rows to un-write. **Applied to a throwaway database only, NOT to any
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

CREATE OR REPLACE FUNCTION public.epigraph_groups_personal_identity_names_creator()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    IF NEW.kind IS DISTINCT FROM 'personal'
       OR NEW.did_key IS DISTINCT FROM
          'did:epigraph:personal:' || NEW.created_by_agent_id::text THEN
        RAISE EXCEPTION 'groups: a personal group must be kind personal and carry '
                        'did:epigraph:personal:<its creator> (did_key %, kind %, creator %)',
                        NEW.did_key, NEW.kind, NEW.created_by_agent_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS groups_personal_identity_names_creator ON public.groups;
CREATE TRIGGER groups_personal_identity_names_creator
    BEFORE INSERT ON public.groups
    FOR EACH ROW
    WHEN (NEW.kind = 'personal' OR NEW.did_key LIKE 'did:epigraph:personal:%')
    EXECUTE FUNCTION public.epigraph_groups_personal_identity_names_creator();

-- ===================================================================
-- 081 — the privatization guards.
--
-- Version 081 per `migrations/README.md`. `docs/tenancy/FINAL-PLAN.md` calls
-- this file "077_privatization_guards.sql"; 077 is PR-17's applied RLS policy
-- migration. Same +4 shift as 080; see that file's header.
--
-- ===================================================================
-- A CORRECTION TO THE PLAN'S DDL: `epigraph_is_group_admin` TAKES ONE ARGUMENT.
--
-- The plan writes `public.epigraph_is_group_admin(NEW.target_group_id,
-- NEW.approved_by)`. No such function exists and it must not be created.
-- `077_rls_policies.sql` creates `epigraph_is_group_admin(uuid)` — group only —
-- and its header records that the two-argument form was CONSIDERED AND
-- REJECTED: because a SECURITY DEFINER frame satisfies
-- `epigraph_definer_bypass()`, a `(group, agent)` helper granted to
-- `epigraph_app` answers truthfully about groups the caller is not a member of,
-- i.e. it is a membership oracle over the whole instance reachable from any app
-- connection. The one-argument form binds the subject to
-- `epigraph_principal_id()` inside the body.
--
-- The approver guard cannot use it, because its subject is `NEW.approved_by`
-- rather than the session principal. It therefore reads `group_memberships`
-- directly, in a trigger that is SECURITY INVOKER. That is the fail-closed
-- direction: a session that cannot see the membership rows under-counts admins
-- and the guard RAISEs.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- One target group per plan, and `seal` requires a KEYED group with a live
-- epoch. This trigger also carries plan 6.6's hardened condition 3.
--
-- WHY MATURITY AND PLURALITY ARE IN THE DATABASE AND NOT ONLY IN THE ROUTE.
-- "Group admin in the target group" prevented nothing on its own:
-- `POST /api/v1/groups` needs only `groups:write` and `create_with_admin`
-- inserts the creator as `role='admin'`, so a compliant target group was one
-- request away and the actor was its sole admin by construction. Two
-- conditions an actor cannot manufacture in one request close that: the group
-- must be at least 24 h old, and it must have at least two live admins OTHER
-- than the plan author.
--
-- ===================================================================
-- THE FIRING CONDITION IS THE CONTROL, AND A COLUMN LIST IS THE WRONG ONE.
--
-- An earlier revision of this file armed the trigger as
-- `BEFORE INSERT OR UPDATE OF target_group_id, mode`. `UPDATE OF <cols>` fires
-- only when the statement NAMES one of those columns, so the guarded predicate
-- — which reads `created_by` as well — was reachable around: an INSERT naming a
-- `created_by` with too few co-admins is refused, and the identical end state
-- reached by `UPDATE … SET created_by = …` was admitted, because `created_by`
-- was not in the list. Measured on the test cluster, with the refused INSERT as
-- the in-transaction control.
--
-- The trigger is therefore armed UNQUALIFIED and the decision of whether to
-- re-check moved INTO the body, where it can name the actual governed set
-- (`target_group_id`, `mode`, `created_by`) instead of a statement's column
-- list. A column list can be defeated by not mentioning a column; an
-- `IS DISTINCT FROM` comparison on the row cannot.
--
-- WHY THE BODY STILL SHORT-CIRCUITS. Re-running maturity and plurality on EVERY
-- update would mean a plan whose target group lost a co-admin mid-flight could
-- no longer be advanced at all — not even to `failed` or `reverted`. That turns
-- a membership change into a stuck plan, which is an availability defect and not
-- a security one. The short-circuit is on "nothing this guard governs changed",
-- not on which columns the statement happened to mention.
--
-- APPROVAL DOES NOT SURVIVE A RE-POINT. Nothing in the row resets `approved_by`
-- when the target moves, so an approval granted against group G would otherwise
-- still read as an approval after the plan is re-pointed at H. A re-point of an
-- already-approved plan is refused outright rather than silently downgraded:
-- a refusal is observable, a silent reset is not, and `state` would then have to
-- be rewound too. `pp_four_eyes` (080) is a CHECK and is re-evaluated on every
-- UPDATE, so the approver <> author half never had this gap; this is the other
-- half.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_privatization_plan_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE k text; g_created timestamptz; ep int; n_other_admins int;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.target_group_id IS NOT DISTINCT FROM OLD.target_group_id
       AND NEW.mode            IS NOT DISTINCT FROM OLD.mode
       AND NEW.created_by      IS NOT DISTINCT FROM OLD.created_by THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.approved_by IS NOT NULL THEN
        RAISE EXCEPTION 'privatization: plan % is already approved; its target, mode and '
                        'author are frozen. Abort it and create a new plan.', OLD.id
            USING ERRCODE = '42501';
    END IF;

    SELECT g.kind, g.created_at INTO k, g_created FROM public.groups g
     WHERE g.id = NEW.target_group_id AND g.status = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'privatization: target group % is absent or not active',
                        NEW.target_group_id USING ERRCODE = '42501';
    END IF;
    IF g_created > now() - interval '24 hours' THEN
        RAISE EXCEPTION 'privatization: target group % is less than 24h old; a '
                        'privatization target must pre-exist the plan',
                        NEW.target_group_id USING ERRCODE = '42501';
    END IF;
    SELECT count(*) INTO n_other_admins FROM public.group_memberships m
     WHERE m.group_id = NEW.target_group_id AND m.role = 'admin'
       AND m.revoked_at IS NULL AND m.agent_id <> NEW.created_by;
    IF n_other_admins < 2 THEN
        RAISE EXCEPTION 'privatization: target group % has % live admin(s) other '
                        'than the plan author; at least 2 are required',
                        NEW.target_group_id, n_other_admins USING ERRCODE = '42501';
    END IF;
    IF NEW.mode = 'seal' THEN
        IF k <> 'team' THEN
            RAISE EXCEPTION 'privatization: mode=seal requires a keyed group '
                            '(kind=team); % is kind=%', NEW.target_group_id, k
                USING ERRCODE = '42501';
        END IF;
        SELECT e.epoch INTO ep FROM public.group_key_epochs e
         WHERE e.group_id = NEW.target_group_id AND e.status = 'active';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'privatization: group % has no active key epoch',
                            NEW.target_group_id USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS privatization_plan_guard ON public.privatization_plans;
CREATE TRIGGER privatization_plan_guard
    BEFORE INSERT OR UPDATE ON public.privatization_plans
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_privatization_plan_guard();

-- The approver must be an admin OF THE TARGET GROUP, not merely a different
-- instance admin. Two instance admins who share no group cannot approve each
-- other's plans. `pp_four_eyes` (080) already forbids approver = author; this
-- is the other half.
--
-- ARMED UNQUALIFIED, FOR THE REASON THE PLAN GUARD ABOVE RECORDS. As
-- `BEFORE UPDATE OF approved_by` this fired only on a statement that NAMED
-- `approved_by`, so `UPDATE … SET target_group_id = H` on an approved plan
-- carried a valid approval to a group the approver does not administer without
-- the guard ever running — measured, with `SET approved_by = <same value>`
-- raising `42501` in the same transaction as the control that proves the
-- predicate itself was right. It also now fires on INSERT, so a plan cannot be
-- created pre-approved by a non-admin of its own target.
--
-- The body short-circuits on "neither the approver nor the target changed", so
-- a later membership change cannot freeze a plan mid-flight; that is the same
-- availability reasoning as the plan guard, and it is deliberately NOT a column
-- list.
CREATE OR REPLACE FUNCTION public.epigraph_privatization_approver_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.approved_by     IS NOT DISTINCT FROM OLD.approved_by
       AND NEW.target_group_id IS NOT DISTINCT FROM OLD.target_group_id THEN
        RETURN NEW;
    END IF;
    IF NEW.approved_by IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                        WHERE m.group_id = NEW.target_group_id
                          AND m.agent_id = NEW.approved_by
                          AND m.role = 'admin' AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'privatization: approver % is not an admin of target group %',
                        NEW.approved_by, NEW.target_group_id USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS privatization_approver_guard ON public.privatization_plans;
CREATE TRIGGER privatization_approver_guard
    BEFORE INSERT OR UPDATE ON public.privatization_plans
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_privatization_approver_guard();

-- ===================================================================
-- (public, Sealed) IS FORBIDDEN, IN BOTH DIRECTIONS.
--
-- Direction 1 — sealing a claim that is still public — is this trigger. It is
-- `BEFORE INSERT OR UPDATE` rather than `UPDATE OF claim_id`, so re-pointing an
-- existing encryption row at a public claim fires it too.
--
-- Direction 2 — declassifying a sealed claim — is already live in
-- `epigraph_claims_block_widening` (migration 070), unconditional, with no GUC
-- override.
--
-- The read of `claims` here is invoker-side and subject to `claims_tenancy`. A
-- session that cannot see the claim reads `v IS NULL`, which is NOT `'public'`,
-- so the guard admits. It is a guard against a KNOWN-public claim, not an
-- authorization check; the authorization is the RLS policy on
-- `claim_encryption` itself.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_no_public_sealed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id;
    IF v = 'public' THEN
        RAISE EXCEPTION 'privatization: refusing to seal claim % while it is '
                        'visibility=public. Restrict first, then seal.', NEW.claim_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS claim_encryption_no_public_sealed ON public.claim_encryption;
CREATE TRIGGER claim_encryption_no_public_sealed
    BEFORE INSERT OR UPDATE ON public.claim_encryption
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_no_public_sealed();

-- A new function is implicitly EXECUTE-able by PUBLIC (a NULL `proacl`), and a
-- trigger body called directly raises "trigger functions can only be called as
-- triggers" — so this is convention alignment rather than the closing of a
-- reachable surface. It matters because the convention is what the next author
-- reads: 070 revokes on `epigraph_edges_tenancy` / `epigraph_propagate_tenancy`,
-- which are trigger bodies too, and a trigger still fires for a role with no
-- EXECUTE (the privilege is checked at CREATE TRIGGER time, not at fire time —
-- 070 has been live proof of that since PR-14).
REVOKE EXECUTE ON FUNCTION public.epigraph_privatization_plan_guard() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_privatization_approver_guard() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_no_public_sealed() FROM PUBLIC;

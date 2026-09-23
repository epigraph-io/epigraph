-- ===================================================================
-- 083 — the D4 authority: who is allowed to privatize.
--
-- Version 083 per `migrations/README.md`. `docs/tenancy/FINAL-PLAN.md` calls
-- this file "079_instance_admins.sql" and says elsewhere that `instance_admins`
-- "is migration 079"; 079 is PR-17's applied FORCE flip. Same +4 shift as 080;
-- see that file's header.
--
-- THIS MIGRATION SEEDS NOTHING. An empty `instance_admins` means nobody can
-- privatize, which is the correct fail-closed initial state for a corpus that
-- starts public. It is an acceptance clause, not an oversight, and
-- `privatization_authz.rs` asserts it at head.
--
-- THERE IS NO HTTP ROUTE THAT WRITES THIS TABLE. Grants are an operator action
-- through the `epigraph-instance-admin` CLI over `epigraph_maintenance`. The
-- pair of controls is the REVOKE below plus, for INSERT and UPDATE, a policy
-- whose only disjunct is `epigraph_bypass()`. DELETE is different and
-- deliberately so: it has no policy at all, so there the control is the REVOKE
-- plus absence, and no role can delete a row. See "THE WRITE POLICIES ARE THE
-- CONTROL" further down, which records a correction to the plan.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.instance_admins (
    agent_id   uuid PRIMARY KEY REFERENCES public.agents(id) ON DELETE RESTRICT,
    granted_by uuid          REFERENCES public.agents(id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    note       text
);
CREATE INDEX IF NOT EXISTS idx_instance_admins_live ON public.instance_admins (agent_id)
    WHERE revoked_at IS NULL;

-- ===================================================================
-- THE SUBJECT IS BOUND IN THE BODY, NOT LEFT TO THE CALLER.
--
-- A `SECURITY DEFINER` predicate that takes a caller-supplied agent id, reads an
-- authority roster, and is EXECUTE-granted to `epigraph_app` is a membership
-- oracle over the whole instance: the SELECT policy below narrows an app
-- connection to its own row, and a definer function that answers about ANY uuid
-- routes around exactly that narrowing. `instance_admins` is the highest-value
-- target list in the system.
--
-- That is the shape 077 CONSIDERED AND REJECTED for `epigraph_is_group_admin`,
-- in the words 081's header quotes approvingly one file up: "a (group, agent)
-- helper granted to epigraph_app answers truthfully about groups the caller is
-- not a member of". Shipping the same shape here, in the same PR that cites the
-- rejection, would be the tree contradicting itself.
--
-- The subject is therefore bound INSIDE the body: the answer is `false` unless
-- the caller is asking about the session principal, or the session is a
-- maintenance login. The signature keeps its `uuid` argument and its
-- `epigraph_app` EXECUTE grant, because the two policies below reference this
-- function and a policy referencing a function the querying role cannot EXECUTE
-- errors at evaluation time rather than denying.
--
-- `epigraph_definer_bypass()` IS DELIBERATELY NOT A DISJUNCT HERE. It reads
-- `current_user`, which inside this frame is the function OWNER
-- (`epigraph_maintenance`), so it would be unconditionally true and the guard
-- would be decorative. `epigraph_bypass()` reads `session_user`, which a definer
-- frame does not change — 067's header states that distinction outright and this
-- is the case it was written for.
--
-- CONSEQUENCE, RECORDED RATHER THAN DISCOVERED LATER: a caller on an UNSTAMPED
-- app connection (no `epigraph.principal_id` GUC) now gets `false` for every
-- agent. `InstanceAdminRepository::is_active`'s doc comment states that
-- requirement, and 18b — the first caller of
-- `middleware/instance_authz.rs::require_instance_admin_for_group` — owns
-- choosing the connection shape. CI and every developer host connect as a
-- superuser, for which `epigraph_bypass()` is true, so nothing in the tree
-- changes behaviour today; the bound bites at plan §9.2 step 11d, when the app
-- role becomes the connecting role.
--
-- THE `COALESCE(…, false)` IS LOAD-BEARING AND NOT DEFENSIVE STYLE.
--
-- Without it this function returns SQL NULL — not `false` — in exactly the case
-- the paragraph above says returns `false`: an unstamped, non-bypass connection
-- asking about an agent that IS on the roster. `epigraph_principal_id()` is NULL
-- with no GUC, so `p_agent = NULL` is NULL and `epigraph_bypass()` is false,
-- making the middle conjunct NULL; the `EXISTS` arm is true (the definer frame
-- reads the table through `epigraph_definer_bypass()`); and
-- `true AND NULL AND true` is NULL.
--
-- NULL is silently correct in a policy — RLS treats a NULL `USING` result as a
-- denial, so the two policies below behave as documented either way. It is NOT
-- correct for the Rust caller: `InstanceAdminRepository::is_active` decodes into
-- `bool`, so a NULL becomes `sqlx::Error::ColumnDecode` and
-- `require_instance_admin_for_group` maps that to a 500 — precisely the outcome
-- `middleware/instance_authz.rs`'s header says the function exists to prevent.
-- The declared return type is `boolean` and every reader of it, in SQL and in
-- Rust, is written against a two-valued answer; the function must supply one.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_is_instance_admin(p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(
        p_agent IS NOT NULL
        AND (p_agent = public.epigraph_principal_id() OR public.epigraph_bypass())
        AND EXISTS (
            SELECT 1 FROM public.instance_admins
             WHERE agent_id = p_agent AND revoked_at IS NULL),
        false)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_instance_admin(uuid) FROM PUBLIC;

-- ===================================================================
-- THE GUARDED `OWNER TO` IS THE MECHANISM, NOT HARDENING.
--
-- A SECURITY DEFINER frame is not an RLS exemption in itself. This body reads
-- `instance_admins`, which is FORCEd below; what admits the read is the
-- `epigraph_definer_bypass()` disjunct in the policy, and
-- `epigraph_definer_bypass()` (067) is
-- `pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')` — `current_user`
-- inside the frame being the FUNCTION OWNER. So the `ALTER FUNCTION … OWNER TO
-- epigraph_maintenance` below is load-bearing, exactly as 077 states for its
-- five definer helpers and 086 for its read helper.
--
-- The guard is a real hazard and not a formality: 060 creates the roles inside
-- a `DO` block that catches `insufficient_privilege` and only `RAISE NOTICE`s,
-- so on a cluster where the role is absent this `ALTER` silently no-ops,
-- ownership stays with the migration runner, and the frame then bypasses only
-- because that role happens to be a superuser. That fails SAFE but with more
-- authority than intended, and it is invisible in `_sqlx_migrations`. The
-- instrument for it is wired in this same commit:
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`
-- carries this function at version 83, and `verify`'s exit code is the
-- documented deploy pre-flight. It is on the DEFERRED list rather than the
-- unconditional one for PR-24's reason: on a correctly sequenced deploy the
-- pre-flight runs before this file is applied, and an unconditional entry would
-- block a working deploy by reporting a function that does not exist yet.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_is_instance_admin(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_instance_admin(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.instance_admins '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_instance_admin(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public.instance_admins FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.instance_admins TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- THE READ POLICY IS SELF-OR-DEFINER, NOT SELF-OR-INSTANCE-ADMIN.
--
-- A CORRECTION TO THE PLAN, MEASURED. The plan's policy is
-- `bypass OR agent_id = principal_id() OR epigraph_is_instance_admin(principal_id())`,
-- and the third arm calls a function whose body reads THIS TABLE under THIS
-- POLICY. That re-entry is the shape 077's header describes for
-- `group_memberships`, and the fix it names is a disjunct "that does not
-- reference `group_memberships`" — i.e. the definer bypass.
--
-- Probed on a scratch database rather than reasoned about: with the plan's
-- three-arm policy the nesting terminates at depth two, because the third arm
-- always passes `epigraph_principal_id()` and the second arm admits exactly the
-- row keyed by `epigraph_principal_id()`. It terminates by coincidence of those
-- two arms agreeing, and a later edit to either one removes the bound silently.
--
-- The definer disjunct removes the cycle instead of bounding it, and it is what
-- the sibling policy `security_events_read` (077) already does. Nothing is lost
-- at PR-18a: the arm's only possible consumer is an app-role connection listing
-- OTHER instance admins, and no such reader exists — the CLI runs on
-- `epigraph_maintenance` and `epigraph_is_instance_admin` reaches every row
-- through the definer frame.
--
-- ===================================================================
-- THE WRITE POLICIES ARE THE CONTROL, AND THIS IS A CORRECTION TO THE PLAN.
--
-- The plan says of this table: "No INSERT/UPDATE/DELETE policy: default deny.
-- Grants are an operator action through `epigraph-instance-admin` over
-- `epigraph_maintenance`." Those two sentences cannot both hold. Under
-- `FORCE ROW LEVEL SECURITY` an absent policy denies the command to EVERY role
-- including the table owner, and `epigraph_bypass()` cannot rescue it: it is a
-- predicate that lives INSIDE a policy, so with no INSERT policy there is
-- nothing for it to appear in. Measured on a scratch table of exactly this
-- shape on the test cluster: an INSERT as `epigraph_maintenance` fails with
-- `new row violates row-level security policy`, and the role has no escape
-- hatch — `067_session_functions.sql` states the design outright ("the
-- maintenance escape hatch is ROLE MEMBERSHIP, not the BYPASSRLS attribute"),
-- and `epigraph_maintenance` is `rolsuper=f rolbypassrls=f`.
--
-- The consequence is not cosmetic. `instance_admins` empty until an operator
-- grants is PR-18a's single acceptance clause, and with no write policy the
-- grant path works ONLY while `MAINTENANCE_DATABASE_URL` happens to log in as a
-- superuser. Under the posture plan §9.2 step 11d prescribes — a real
-- `epigraph_maintenance` login — the operator action fails closed with 42501
-- and the clause has no working grant.
--
-- The fix is 082's own working pattern one file up: `privatization_audit_append`
-- is `FOR INSERT … WITH CHECK ((SELECT epigraph_bypass()))`. `epigraph_bypass()`
-- reads `session_user`, so it is true on a maintenance login and false on an
-- `epigraph_app` connection — which, with the REVOKE above, denies the app role
-- twice over. The plan's intent is preserved exactly; only the instrument
-- changes.
--
-- SEPARATE `FOR INSERT` AND `FOR UPDATE`, NOT ONE `FOR ALL`. `FOR ALL` would
-- also cover DELETE, and revocation here is a `revoked_at` stamp and never a
-- DELETE — the row is the record that the authority once existed. DELETE stays
-- policy-less and default-denied, and that one pair is what
-- `rls_enforcement.rs`'s `DELIBERATELY_UNCOVERED` register carries.
--
-- THE `FOR UPDATE` POLICY CARRIES BOTH `USING` AND `WITH CHECK`, WRITTEN OUT.
-- A `FOR UPDATE` policy with no `USING` sees no rows to update, so the
-- statement matches nothing and reports zero rows affected — a silent no-op
-- rather than an error, which is the worst available failure for
-- `InstanceAdminRepository::revoke`, whose whole return value is
-- `rows_affected() > 0`. It also covers the `ON CONFLICT DO UPDATE` arm of
-- `grant`: per `progress.json`'s `F-PR17-on-conflict-is-checked-against-the-
-- using-clause`, that arm is checked against the SELECT-side policy AND needs
-- UPDATE coverage.
-- ===================================================================
ALTER TABLE public.instance_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.instance_admins FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS instance_admins_self_or_admin ON public.instance_admins;
DROP POLICY IF EXISTS instance_admins_self_or_definer ON public.instance_admins;
CREATE POLICY instance_admins_self_or_definer ON public.instance_admins
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id()));

DROP POLICY IF EXISTS instance_admins_maintenance_insert ON public.instance_admins;
CREATE POLICY instance_admins_maintenance_insert ON public.instance_admins
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));

DROP POLICY IF EXISTS instance_admins_maintenance_update ON public.instance_admins;
CREATE POLICY instance_admins_maintenance_update ON public.instance_admins
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()));

-- ===================================================================
-- THE TWO DISJUNCTS 077 DEFERRED TO THIS FILE.
--
-- (1) `privatization_audit_read`. 082 created the table and its INSERT policy
--     but could not create this one: the function did not exist yet.
--
--     ROW-LEVEL SCOPING. An instance admin sees plan-level rows for every plan,
--     but ENTITY ids only for plans whose target group they administer —
--     `entity_id` is otherwise a complete index of every private entity id in
--     the instance.
--
--     `epigraph_is_group_admin` TAKES ONE ARGUMENT. The plan writes
--     `epigraph_is_group_admin(<group>, <agent>)`; 077 creates the one-argument
--     form and its header records that the two-argument form was rejected as an
--     instance-wide membership oracle. Here the subject IS the calling
--     principal, so the one-argument form is not merely a substitute — it is
--     the correct spelling.
--
--     STATED CONSEQUENCE, FAIL-CLOSED: the sub-select reads
--     `privatization_plans`, which 080 leaves with no SELECT policy, so on an
--     app-role connection it yields NULL and the group-admin arm is false. The
--     arm is therefore unreachable from an app connection until 18b gives that
--     table a read policy. The direction is denial, not disclosure.
--
-- (2) `security_events_read`'s instance-admin disjunct. 077 states verbatim
--     that it "is dropped here and is PR-18's to add back alongside the
--     function". The policy is re-created rather than altered so its full text
--     lives in one place, and the arm is written so that every top-level `OR`
--     fragment names a session helper — `rls_enforcement.rs::
--     no_policy_arm_is_session_independent` splits on ` OR ` and reports an arm
--     that references no session-derived state.
--
--     THIS IS THE LARGEST READ-SURFACE CHANGE IN PR-18a AND IT IS DELIBERATE.
--     A live instance admin can now read every principal's actor-log rows
--     instance-wide, including the unattributed `agent_id IS NULL` rows that
--     `security_events_append` admits from pre-authentication paths. 077
--     assigned that expansion to PR-18; it is named here so a reviewer does not
--     have to rediscover it by diffing two migrations.
--
-- ===================================================================
-- EVERY SESSION-CONSTANT CALL IS WRAPPED IN `(SELECT …)`. THIS IS A REGRESSION
-- GUARD, NOT A MICRO-OPTIMISATION.
--
-- `security_events_read` is a policy 077 already shipped, so an unwrapped call
-- added here would make a live read slower than it was. 067's header states the
-- rule for `epigraph_session_groups()` and the same mechanism applies: an
-- unwrapped call lands in the row `Filter` and is evaluated once per SCANNED
-- row, while `(SELECT f())` becomes an `InitPlan` evaluated once per statement.
-- Measured as `epigraph_app`: unwrapped, `EXPLAIN (COSTS OFF) SELECT count(*)
-- FROM public.security_events` puts `epigraph_is_instance_admin($3)` — a
-- `SECURITY DEFINER` function doing an `EXISTS` over `instance_admins` — inside
-- the Filter alongside three `InitPlan` arms. `SecurityEventRepository::query`
-- takes `agent_id` as OPTIONAL and orders by `created_at DESC LIMIT n`; RLS
-- filters before the LIMIT, so a non-admin caller with few rows of its own scans
-- the whole unboundedly-growing actor log. It is latent only until plan §9.2
-- step 11d makes the app role the connecting role: CI and every developer host
-- connect as a superuser, for which RLS does not filter at all, so the cost does
-- not appear until exactly the posture this series exists to reach.
--
-- The sibling `epigraph_is_group_admin(<column>)` call in
-- `privatization_audit_read` is correctly left UNWRAPPED: its argument is
-- row-dependent, so there is no session constant to hoist.
-- ===================================================================
DROP POLICY IF EXISTS privatization_audit_read ON public.privatization_audit;
CREATE POLICY privatization_audit_read ON public.privatization_audit FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_is_instance_admin(
                     (SELECT public.epigraph_principal_id())))
            AND (entity_id IS NULL
                 OR public.epigraph_is_group_admin(
                      (SELECT p.target_group_id FROM public.privatization_plans p
                        WHERE p.id = privatization_audit.plan_id)))));

DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR (SELECT public.epigraph_is_instance_admin(
                    (SELECT public.epigraph_principal_id()))));

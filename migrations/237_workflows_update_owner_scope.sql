-- 237: an UPDATE of a `workflows` row is owner-scoped; a hierarchical outcome
-- report moves its counters through two definers (backlog 524f89c1).
--
-- Sections: 0 why; 1 the outcome definers (why); 2 their bodies; 3 the
-- policy (why); 4 the policy; 5 the recorded submitter is write-once.
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 183 gave `workflows` row security. Its UPDATE policy, `workflows_update`,
-- admits a row the session can READ: USING and WITH CHECK are both
-- `visibility = 'public' OR owner_group_id = ANY (epigraph_session_groups())`
-- (plus 077's two bypass disjuncts). The read set includes READER
-- memberships. So any application-role session could UPDATE any public
-- workflow row, and a reader could UPDATE a group row: its `metadata`
-- (outcome counters, and `epigraph_submitted_by`, the key the entry points'
-- submitter arm trusts), its `truth_value` (deprecation) and its
-- `goal_embedding`, by a direct statement that skips every entry point's
-- workflow authority gate. Measured as `epigraph_app` on a fresh database at
-- 236 (`epigraph-db/tests/workflows_update_owner_scope.rs`): a non-member
-- set `truth_value` and `epigraph_submitted_by` on a public row, and a
-- reader of a group set `truth_value` on that group's row.
--
-- ===================================================================
-- 1. THE OUTCOME COUNTERS, THROUGH TWO DEFINERS (section 2)
-- ===================================================================
--
-- A hierarchical outcome report (`report_hierarchical_outcome`, REST and
-- MCP) is admitted for any caller that reads the PLAN, by design: an agent
-- that ran a public workflow reports how it went. It moves four counters in
-- `metadata` (`use_count`, `success_count`, `failure_count`,
-- `avg_variance`). Before this file it did that with a row lock
-- (`SELECT ... FOR UPDATE`) and an `UPDATE workflows SET metadata = $1` of the
-- whole document, on the reporter's stamp. Both need the UPDATE policy: a row
-- lock is checked against UPDATE's USING too. So the reader's path moves into
-- two SECURITY DEFINER functions before the policy is narrowed:
--
--   * `epigraph_workflow_lock_readable(workflow)` locks the row (`FOR UPDATE`)
--     when the session reads it, and answers whether it did. `add_step`'s
--     plan lock (`WorkflowRepository::lock_for_plan_edit`) uses it too: it
--     serializes concurrent appends to one plan, and the entry points admit
--     callers that do not write a PUBLIC plan's owner group (section 3), whose
--     lock on the stamp would otherwise take nothing. So does a deprecation's
--     lineage lock (`WorkflowRepository::lock_lineages_for_deprecation`), row
--     by row in id order over the lineage rows the caller reads: a public
--     lineage may hold generations in different owner groups, and a lock on
--     the stamp would take only the rows the caller writes, so two
--     deprecations of one lineage would no longer serialize;
--   * `epigraph_workflow_record_outcome(workflow, success, variance)` locks
--     it again (a no-op inside the same transaction), computes the four
--     counters IN SQL from the stored ones and writes exactly those four keys.
--     It never takes a counter value from the caller, and touches no other
--     key and no other column. It returns the new counters.
--
-- "Reads it" is `workflows_read`'s predicate (183), restated in the body
-- because a definer's own reads bypass row security: the session is a
-- maintenance session, or the row is public, or its owner group is in the
-- session's read set. The PLAN check (a readable step) and the idempotency
-- lookup stay in the repository, between the two calls, unchanged.
--
-- The counter arithmetic is `HierarchicalOutcomeCounters::after_report`'s:
-- a counter that is missing, is not a JSON integer that fits an i64, or is
-- negative counts as 0, and a counter saturates at the i64 maximum;
-- `avg_variance` that is not a JSON number in [0, 1] counts as 0; a
-- `metadata` that is not a JSON object becomes `{}` first. So no stored shape
-- makes a report fail (a stored `use_count` of -1 would otherwise divide by
-- zero, on every later report too). `variance` must be
-- in [0, 1] (the fraction of the report's step rows marked deviated) and is
-- refused otherwise (22023), so a direct caller cannot poison the mean.
--
-- An elevated session is refused (42501). 183's restrictive
-- `workflows_elevated_no_update` is `TO epigraph_app`, and inside a body
-- owned by `epigraph_maintenance` it does not bind, so the bodies say it
-- themselves. Each body is SECURITY DEFINER on 172's path,
-- `SET search_path = pg_catalog, pg_temp`, with every `public` object
-- qualified, owned by `epigraph_maintenance`, EXECUTE revoked from PUBLIC and
-- granted to `epigraph_app` (206's shape). No body keeps session state.
--
-- A direct caller of the second definer can still move the counters of a
-- workflow it reads without a readable step and without writing the report's
-- step rows. That is a reader inflating a usage counter it may already move
-- through the tool; it is not a write of anything else.
--
-- ===================================================================
-- 3. THE POLICY: UPDATE IS OWNER-SCOPED (section 4)
-- ===================================================================
--
-- One RESTRICTIVE, FOR UPDATE policy, `workflows_update_owner`, AND-ed with
-- 183's permissive `workflows_update`: the shape 117 gave `edges` and the
-- four registries. USING and WITH CHECK are both 077's two bypass disjuncts
-- OR `owner_group_id = ANY (epigraph_writable_groups())`, the predicate
-- 183's `workflows_insert` and `workflows_delete_owner` already use. So an
-- application session UPDATEs (or row-locks) a workflow row only when it
-- WRITES the row's owner group, public rows included; any other row is
-- filtered out of its UPDATE (0 rows, no error), as 117's are. 183's
-- permissive policy is not restated, so its read-set rule still holds as
-- well (a writable group is always a read group).
--
-- THE CARVE-OUT is 077's two bypass arms, unchanged: a maintenance session
-- (`epigraph_bypass()`) and a body owned by `epigraph_maintenance`
-- (`epigraph_definer_bypass()`). Every application path that must write a
-- row the caller does not own goes through one of them: the outcome counters
-- (section 1), the privatization and re-own verbs, `set-workflow-submitter`
-- and `embed_backfill` (maintenance connections). An audited admin write of
-- another group's rows takes the same road as 111's `epigraph_admin_patch_claim`:
-- a definer that re-checks the live `claims:admin` grant. None exists for
-- `workflows` yet. Measured before this file, as `epigraph_app`: the admin
-- arm's hierarchical `deprecate_workflow` of another group's public plan
-- already FAILS, because retiring the plan's claims is refused by
-- `claims_tenancy`'s WITH CHECK (42501) on the admin's own stamp; the
-- `workflows` row was the one write row security did not stop. So this file
-- removes no admin deprecation that worked for a plan with a claim left to
-- retire; for a plan with none (every claim shared or already retired) the
-- admin's `truth_value` write now matches no row too.
--
-- WHAT THE ENTRY POINTS ADMIT AND THIS DOES NOT. The workflow authority gate
-- (REST `workflow_authority`, MCP `require_workflow_authority`) admits, after
-- the owner-group writer, the recorded SUBMITTER, its OPERATOR and a DELEGATE
-- (operator ruling R-183) by identity, and the audited admin arm. A caller
-- admitted by one of those arms that does not write the row's owner group now
-- writes nothing to the row itself: its `truth_value` UPDATE (deprecation)
-- and the deprecation's lineage lock match no row. `add_step` keeps its plan
-- lock through the definer (section 1) and writes no `workflows` row. The
-- callers at stake: a legacy row's recorded submitter that does not write its
-- owner group, a delegate or operator acting on a plan in a team its
-- principal writes and it does not, and the admin. Retiring the plan's claims
-- is refused to every one of them already, by the same `claims_tenancy` rule
-- as the admin's (above; for the delegate, pinned by
-- `workflow_delegate_authority.rs::a_delegate_deprecates_its_operators_workflow`).
--
-- 126's elevated census is unaffected: the policy's name has no `_elevated_`
-- and it names no elevation helper.
--
-- ===================================================================
-- 5. THE RECORDED SUBMITTER IS WRITE-ONCE TO AN ORDINARY SESSION
-- ===================================================================
--
-- `metadata.epigraph_submitted_by` is what the entry points' submitter arm
-- (and, through it, the operator and delegate arms) trusts.
-- `WorkflowRepository::record_submitter` writes it once, only when the key is
-- absent. Section 4 leaves `metadata` writable to a writer of the owner
-- group, who could then rewrite the key and name ANY agent as the row's
-- submitter, handing that agent the identity arms over the row. So a BEFORE
-- UPDATE OF metadata trigger, `workflows_submitter_immutable`, refuses (42501)
-- an UPDATE that changes or removes a key that is already present, unless the
-- session is a privileged writer (115/183's
-- `epigraph_session_is_privileged_writer()`: a maintenance session, or a body
-- running as `epigraph_maintenance`). Setting the key where it is absent stays
-- admitted (`record_submitter`), and so does any write that leaves it as it
-- is, the outcome definer's included. `set-workflow-submitter` and the
-- re-own verb run on the maintenance connection and are admitted.
--
-- ===================================================================
-- UNDO: `docs/runbooks/237-undo.sql`.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 2. THE OUTCOME DEFINERS
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_workflow_lock_readable(p_workflow uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'WFO01: an elevated session writes no workflow row'
            USING ERRCODE = '42501';
    END IF;
    PERFORM 1
       FROM public.workflows w
      WHERE w.id = p_workflow
        AND (public.epigraph_bypass()
             OR w.visibility = 'public'
             OR w.owner_group_id = ANY (public.epigraph_session_groups()::uuid[]))
        FOR UPDATE OF w;
    RETURN FOUND;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflow_lock_readable(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_workflow_record_outcome(
    p_workflow uuid,
    p_success  boolean,
    p_variance double precision)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_meta jsonb;
    v_use bigint;
    v_success bigint;
    v_failure bigint;
    v_prev_avg double precision;
    v_avg double precision;
    v_counters jsonb;
    v_written bigint;
BEGIN
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'WFO01: an elevated session writes no workflow row'
            USING ERRCODE = '42501';
    END IF;
    -- NaN compares greater than every number in PostgreSQL, so `<= 1` refuses it.
    IF p_success IS NULL OR p_variance IS NULL
       OR NOT (p_variance >= 0 AND p_variance <= 1) THEN
        RAISE EXCEPTION 'WFO02: an outcome needs success and a variance in [0, 1]; got %, %',
            p_success, p_variance
            USING ERRCODE = '22023';
    END IF;
    SELECT w.metadata INTO v_meta
      FROM public.workflows w
     WHERE w.id = p_workflow
       AND (public.epigraph_bypass()
            OR w.visibility = 'public'
            OR w.owner_group_id = ANY (public.epigraph_session_groups()::uuid[]))
       FOR UPDATE OF w;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'WFO03: no workflow % this session reads', p_workflow
            USING ERRCODE = '42501';
    END IF;
    IF v_meta IS NULL OR pg_catalog.jsonb_typeof(v_meta) <> 'object' THEN
        v_meta := '{}'::jsonb;
    END IF;

    -- A counter is a non-negative JSON integer that fits an i64 (serde's
    -- `as_i64`, then `>= 0`), else 0; it saturates at the i64 maximum.
    v_use := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'use_count') = 'number'
                       AND (v_meta ->> 'use_count') ~ '^[0-9]{1,19}$'
                       AND (v_meta ->> 'use_count')::numeric <= 9223372036854775807
                  THEN (v_meta ->> 'use_count')::bigint ELSE 0 END;
    v_success := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'success_count') = 'number'
                           AND (v_meta ->> 'success_count') ~ '^[0-9]{1,19}$'
                           AND (v_meta ->> 'success_count')::numeric <= 9223372036854775807
                      THEN (v_meta ->> 'success_count')::bigint ELSE 0 END;
    v_failure := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'failure_count') = 'number'
                           AND (v_meta ->> 'failure_count') ~ '^[0-9]{1,19}$'
                           AND (v_meta ->> 'failure_count')::numeric <= 9223372036854775807
                      THEN (v_meta ->> 'failure_count')::bigint ELSE 0 END;
    IF v_use < 9223372036854775807 THEN v_use := v_use + 1; END IF;
    IF p_success AND v_success < 9223372036854775807 THEN v_success := v_success + 1; END IF;
    IF NOT p_success AND v_failure < 9223372036854775807 THEN v_failure := v_failure + 1; END IF;
    -- `avg_variance`: a JSON number in [0, 1] (every running mean of variances
    -- in [0, 1] is), else 0. Compared as numeric first, so a stored number
    -- beyond the float8 range is never cast.
    v_prev_avg := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'avg_variance') = 'number'
                            AND (v_meta ->> 'avg_variance')::numeric BETWEEN 0 AND 1
                       THEN (v_meta ->> 'avg_variance')::double precision ELSE 0 END;
    v_avg := (v_prev_avg * (v_use - 1)::double precision + p_variance)
             / v_use::double precision;

    v_counters := pg_catalog.jsonb_build_object(
        'use_count', v_use,
        'success_count', v_success,
        'failure_count', v_failure,
        'avg_variance', v_avg);
    UPDATE public.workflows w
       SET metadata = v_meta || v_counters
     WHERE w.id = p_workflow;
    GET DIAGNOSTICS v_written = ROW_COUNT;
    IF v_written <> 1 THEN
        -- Only under an owner that is not a maintenance member (then this
        -- body's UPDATE is row-security filtered): loud, never a silent 0.
        RAISE EXCEPTION 'WFO04: the counters of workflow % were not written (% rows); '
                        'is this function owned by epigraph_maintenance?', p_workflow, v_written
            USING ERRCODE = '42501';
    END IF;
    RETURN v_counters;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflow_record_outcome(uuid, boolean, double precision)
    FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_lock_readable(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_record_outcome(uuid, boolean, double precision) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 237 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_workflow_lock_readable(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_workflow_record_outcome(uuid, boolean, double precision) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 4. THE POLICY
-- ===================================================================
DROP POLICY IF EXISTS workflows_update_owner ON public.workflows;
CREATE POLICY workflows_update_owner ON public.workflows AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- ===================================================================
-- 5. THE RECORDED SUBMITTER IS WRITE-ONCE (section 5 above)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_workflows_submitter_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: an UPDATE of workflows % changes its recorded '
                    'submitter; only a maintenance session corrects one', OLD.id
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflows_submitter_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS workflows_submitter_immutable ON public.workflows;
CREATE TRIGGER workflows_submitter_immutable BEFORE UPDATE OF metadata ON public.workflows
    FOR EACH ROW
    WHEN (pg_catalog.jsonb_typeof(OLD.metadata) = 'object'
          AND OLD.metadata ? 'epigraph_submitted_by'
          AND (NEW.metadata -> 'epigraph_submitted_by')
              IS DISTINCT FROM (OLD.metadata -> 'epigraph_submitted_by'))
    EXECUTE FUNCTION public.epigraph_workflows_submitter_guard();

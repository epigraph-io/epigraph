-- 237: an UPDATE of a `workflows` row is owner-scoped; a hierarchical outcome
-- report moves its counters through two definers (backlog 524f89c1).
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
--   * `epigraph_workflow_outcome_lock(workflow)` locks the row (`FOR UPDATE`)
--     when the session reads it, and answers whether it did;
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
-- a counter that is missing, or is not a JSON integer that fits an i64,
-- counts as 0; `avg_variance` that is not a JSON number counts as 0; a
-- `metadata` that is not a JSON object becomes `{}` first. `variance` must be
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
-- UNDO: `docs/runbooks/237-undo.sql`.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 2. THE OUTCOME DEFINERS
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_workflow_outcome_lock(p_workflow uuid)
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
REVOKE EXECUTE ON FUNCTION public.epigraph_workflow_outcome_lock(uuid) FROM PUBLIC;

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

    -- A counter is a JSON integer that fits an i64 (serde's `as_i64`), else 0.
    v_use := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'use_count') = 'number'
                       AND (v_meta ->> 'use_count') ~ '^-?[0-9]{1,19}$'
                       AND (v_meta ->> 'use_count')::numeric
                           BETWEEN -9223372036854775808 AND 9223372036854775807
                  THEN (v_meta ->> 'use_count')::bigint ELSE 0 END + 1;
    v_success := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'success_count') = 'number'
                           AND (v_meta ->> 'success_count') ~ '^-?[0-9]{1,19}$'
                           AND (v_meta ->> 'success_count')::numeric
                               BETWEEN -9223372036854775808 AND 9223372036854775807
                      THEN (v_meta ->> 'success_count')::bigint ELSE 0 END
                 + CASE WHEN p_success THEN 1 ELSE 0 END;
    v_failure := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'failure_count') = 'number'
                           AND (v_meta ->> 'failure_count') ~ '^-?[0-9]{1,19}$'
                           AND (v_meta ->> 'failure_count')::numeric
                               BETWEEN -9223372036854775808 AND 9223372036854775807
                      THEN (v_meta ->> 'failure_count')::bigint ELSE 0 END
                 + CASE WHEN p_success THEN 0 ELSE 1 END;
    -- `avg_variance`: any JSON number (serde's `as_f64`), else 0.
    v_prev_avg := CASE WHEN pg_catalog.jsonb_typeof(v_meta -> 'avg_variance') = 'number'
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
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_outcome_lock(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_record_outcome(uuid, boolean, double precision) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 237 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_workflow_outcome_lock(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_workflow_record_outcome(uuid, boolean, double precision) '
                'TO epigraph_app';
    END IF;
END $$;

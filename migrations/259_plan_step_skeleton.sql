-- 259: a plan's step order as an unrestricted reader sees it, masked to the
-- caller's own steps (backlog a1474e22).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- An outcome report (`report_workflow_outcome`, `report_hierarchical_outcome`,
-- REST `POST /api/v1/workflows/:id/outcome/hierarchical`) attributes each
-- `step_index` to a step claim through
-- `WorkflowRepository::plan_step_claim_ids`, which ran entirely under the
-- caller's row security. A step the caller cannot read is absent from that
-- read, and the reader could only cut its list where the absence LEFT A
-- TRACE: a gap in the `plan_index` ordinals it reads. `add_step` writes no
-- ordinal for a middle insert (ruling R-38) and rewires the `step_follows`
-- chain around it, so a step another group owns inside a plan's chain left
-- none: its `executes` edge and both of its `step_follows` edges are its
-- group's, the caller read `a, b, c` with contiguous ordinals, and listed `b`
-- at slot 1 although plan order is `a, x, b, c`. A report of slot 1 was
-- attributed to `b`, with no error and no warning. Cutting at a visible
-- `step_follows` edge out of the visible set is not a fix: the edges into the
-- hidden step are hidden too, and a step shared with another generation
-- carries that generation's edges to steps that are not in this plan.
--
-- The same blind spot covered the residual the reader documented first: hidden
-- ORDINAL steps after every visible one, followed by a visible unindexed step,
-- which was listed straight after the visible ordinals.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
-- Adds `epigraph_plan_step_skeleton(p_workflow uuid, p_visible uuid[])`, a
-- definer that reads the plan's `executes` edges and the `step_follows` pairs
-- among their targets UNFILTERED, exactly as `plan_step_claim_ids` reads them
-- under a session that reads every row (same predicates, same order key:
-- ordinal, then `created_at`, then claim id; every level; retracted rows
-- included), and returns one row per `executes` edge:
--
--   slot        the edge's 1-based position in that order;
--   token       the claim's identity WITHIN THIS RESULT (the first slot its
--               claim occupies, so two edges onto one claim share a token);
--   claim_id    the claim id when it is in `p_visible`, otherwise NULL;
--   level       the claim's raw `properties->>'level'` text;
--   plan_index  the edge's ordinal, NULL when it carries none;
--   successors  the tokens this claim has a `step_follows` edge to, among the
--               plan's own targets.
--
-- The server runs the reader's own ordering code over the tokens, so a
-- caller's list is the PREFIX of the list an unrestricted reader gets that
-- ends at the first step the caller cannot read. No hidden claim id, content
-- or tenancy leaves the database.
--
-- What it DOES disclose, to whoever can EXECUTE it: the plan's shape for any
-- workflow id named (how many `executes` edges, their levels and ordinals, and
-- the chain's topology), and whether a claim id the caller names is one of the
-- plan's targets. It is granted to the application role only, which calls it
-- for a plan the caller has already been admitted to report on; migration
-- 219's `epigraph_step_lineage_executors` returns workflow ids to the same role
-- on the same terms. The server never returns the skeleton: only the claim
-- ids the caller passed in, in plan order.
--
-- 219's form: `pg_catalog, pg_temp`, every public name qualified, STABLE.
-- Owned by `epigraph_maintenance`, so its reads of the FORCEd `edges` and
-- `claims` are admitted by `epigraph_definer_bypass()`; EXECUTE revoked from
-- PUBLIC and granted to `epigraph_app` (the report runs on the request DSN).
-- Under any other owner the reads are filtered to the calling session's rows
-- and the definer answers exactly what the old reader did: fails OPEN and
-- silent, which `epigraph-tenancy-backfill verify` reports.
--
-- Plain CREATE (not OR REPLACE): a function of this name that 259 did not
-- write fails the migration instead of being replaced.
--
-- Undo: docs/runbooks/259-undo.sql (roll the binary back FIRST: a 259 binary
-- calls this function on every outcome report that names a step).

CREATE FUNCTION public.epigraph_plan_step_skeleton(p_workflow uuid, p_visible uuid[])
RETURNS TABLE (
    slot integer,
    token integer,
    claim_id uuid,
    level text,
    plan_index integer,
    successors integer[]
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH ex AS (
        SELECT e.target_id,
               c.properties->>'level' AS level,
               CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$'
                    THEN (e.properties->>'plan_index')::int END AS plan_index,
               (row_number() OVER (
                    ORDER BY CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$'
                                  THEN (e.properties->>'plan_index')::int
                                  ELSE 2147483647 END,
                             e.created_at ASC, c.id ASC))::int AS slot
          FROM public.edges e
          JOIN public.claims c ON c.id = e.target_id
         WHERE e.source_id = p_workflow AND e.relationship = 'executes'
    ), tok AS (
        SELECT ex.*, (min(ex.slot) OVER (PARTITION BY ex.target_id))::int AS token
          FROM ex
    ), ids AS (
        SELECT DISTINCT tok.target_id, tok.token FROM tok
    )
    SELECT t.slot,
           t.token,
           CASE WHEN t.target_id = ANY (p_visible) THEN t.target_id END,
           t.level,
           t.plan_index,
           COALESCE((SELECT array_agg(DISTINCT n.token ORDER BY n.token)
                       FROM public.edges f
                       JOIN ids n ON n.target_id = f.target_id
                      WHERE f.relationship = 'step_follows'
                        AND f.source_id = t.target_id
                        AND f.target_id <> t.target_id),
                    '{}'::int[])
      FROM tok t
     ORDER BY t.slot
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_plan_step_skeleton(uuid, uuid[]) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_plan_step_skeleton(uuid, uuid[]) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_plan_step_skeleton(uuid, uuid[]) '
                'TO epigraph_app';
    END IF;
END $$;

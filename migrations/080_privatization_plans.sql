-- ===================================================================
-- 080 — D4's persisted object: privatization plans, their frozen item set,
-- and the two selection functions.
--
-- Version 080 per `migrations/README.md`, which is authoritative.
-- `docs/tenancy/FINAL-PLAN.md` calls this file "076_privatization_plans.sql";
-- that number belongs to PR-16's `076_validate_tenancy_remaining.sql`. The
-- cause is the documented +4 shift (README, "Why 060–085 became 060–090").
-- README's row for 080 — "privatization plans, items, closure" — is what this
-- file delivers.
--
-- WHY SELECTION IS MATERIALIZED. A 100k-node selection is too expensive to
-- evaluate twice and too racy to evaluate once at preview and again at apply.
-- The selection is frozen into `privatization_plan_items` and the apply
-- operates on that id set. Preview returns a `plan_digest`; `apply` echoes it.
--
-- ===================================================================
-- THIS FILE FORCEs ITS OWN TABLES, AND THAT IS A CORRECTION TO 079.
--
-- `079_rls_force.sql`'s header says PR-18 "owns adding them to this array".
-- That instruction cannot be followed: 079 is APPLIED, and `migrations/README.md`
-- states the governing rule — editing an applied file changes its checksum and
-- `sqlx migrate run` then refuses to start, which panics the api binary on
-- restart for every database that has run the branch. 079 cannot be corrected
-- either, for the same reason; the disagreement is recorded in the PR body and
-- in the three editable copies of that instruction
-- (`epigraph_api::state::FORCE_PROTECTED_SET`'s doc comment,
-- `locked_decisions.rs::d4_the_force_array_is_tier_a_plus_the_control_tables`'s
-- failure message, and README's 079 row).
--
-- The instrument is the one 079's own comment names: `rls_canary` is absent
-- from 079's array because **078 FORCEs it itself, at creation**. 080–083 do
-- the same.
--
-- ===================================================================
-- ENABLE + FORCE WITH NO POLICY IS FULL DEFAULT DENY, AND IT IS DELIBERATE.
--
-- PR-18a ships no reader and no writer of these two tables — the preview
-- routes are 18b and the apply/revert handlers are 18c. A read policy with no
-- consumer is a grant nobody has asked for, so both tables default-deny every
-- command to every non-owner. The four (table, command) pairs per table are
-- registered in `rls_enforcement.rs::DELIBERATELY_UNCOVERED`, which is an
-- exact-set ratchet in BOTH directions: 18b cannot add a policy here without
-- deleting the matching register row in the same commit.
--
-- This is NOT the `force_without_enable_is_not_satisfied` trap that
-- `repos/entity_type.rs` pins and that 079's `42P17` guard RAISEs on. That trap
-- is FORCE *without* ENABLE, where the table is invisible and no policy exists
-- to make it visible again. Here ENABLE and FORCE are issued together and the
-- policy set is empty on purpose.
--
-- ===================================================================
-- ORDER-INSENSITIVITY WITH RESPECT TO 084–091.
--
-- 080–083 are numbered BELOW migrations that are already applied on every
-- branch database (085, 086, 091). sqlx applies a below-head version without
-- error — measured — so a FRESH database runs 080–083 before 084–091 while a
-- database already at 91 runs them after. This file therefore issues no
-- `GRANT … ON ALL TABLES IN SCHEMA public`, no `DO` block that sweeps
-- `pg_tables` / `pg_class`, and makes no assumption about whether
-- `webhook_subscriptions` (085) exists. It also references nothing that 084
-- drops: a grep for `ownership` over the whole 080–083 DDL returns nothing.
--
-- THE DIVERGENCE ONLY EXISTS WHERE 084–091 ARE ALREADY APPLIED. Any database
-- that has not yet run the 060+ series applies the whole range in one
-- numeric-order run and never sees the two orders at all, so this is a property
-- of long-lived developer and CI databases rather than of a first deploy.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.privatization_plans (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    state             text NOT NULL DEFAULT 'draft',
    mode              text NOT NULL,                -- 'restrict' | 'seal'
    target_group_id   uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    selector          jsonb NOT NULL,               -- the request, verbatim
    on_conflict       text NOT NULL DEFAULT 'abort',-- 'abort'|'skip'|'reassign'
    pad_to            integer NOT NULL DEFAULT 256,
    plan_digest       bytea,                        -- BLAKE3 over sorted (kind,id)
    item_count        integer NOT NULL DEFAULT 0,
    authors_losing_count integer NOT NULL DEFAULT 0, -- drives dual control (plan 6.6)
    acknowledge_author_loss boolean NOT NULL DEFAULT false,
    created_by        uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    approved_by       uuid          REFERENCES public.agents(id) ON DELETE RESTRICT,
    approved_at       timestamptz,
    dispatched_by     uuid          REFERENCES public.agents(id) ON DELETE RESTRICT,
    cursor_kind       text,
    cursor_depth      integer,
    cursor_id         uuid,
    drift_ids         uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pp_state_check CHECK (state IN
        ('draft','selecting','previewed','approved','applying','applied',
         'applied_with_drift','failed','reverting','reverted')),
    CONSTRAINT pp_mode_check  CHECK (mode IN ('restrict','seal')),
    CONSTRAINT pp_conflict_check CHECK (on_conflict IN ('abort','skip','reassign')),
    CONSTRAINT pp_pad_check   CHECK (pad_to IN (0,256,1024,4096)),
    -- FOUR EYES. The approver is never the author; the guard in 081 additionally
    -- requires the approver to administer the TARGET group, so two instance
    -- admins who share no group cannot rubber-stamp each other.
    CONSTRAINT pp_four_eyes  CHECK (approved_by IS NULL OR approved_by <> created_by),
    CONSTRAINT pp_seal_needs_pad CHECK (mode <> 'seal' OR pad_to > 0)
);

CREATE TABLE IF NOT EXISTS public.privatization_plan_items (
    plan_id     uuid NOT NULL REFERENCES public.privatization_plans(id) ON DELETE CASCADE,
    kind        text NOT NULL,     -- 'claim' | 'evidence'
    entity_id   uuid NOT NULL,
    depth       integer NOT NULL,  -- 0 = seed; hull members inherit their anchor's depth
    via         text,              -- 'seed'|'closure:<rel>'|'hull:supersedes'
                                   -- |'hull:step_lineage'|'hull:versions'|'hull:evidence'
    before_visibility     text NOT NULL,
    before_owner_group_id uuid NOT NULL,
    before_had_embedding  boolean NOT NULL,
    state       text NOT NULL DEFAULT 'pending',  -- pending|applied|skipped|failed|reverted
    error       text,
    applied_at  timestamptz,
    PRIMARY KEY (plan_id, kind, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_ppi_work ON public.privatization_plan_items
    (plan_id, state, depth DESC, kind, entity_id);

-- Only one plan may be mid-flight against a given target group.
CREATE UNIQUE INDEX IF NOT EXISTS privatization_one_active_per_group
    ON public.privatization_plans (target_group_id)
 WHERE state IN ('selecting','applying','reverting');

-- ===================================================================
-- THE MANDATORY HULL — `supersedes` UNION `step_lineage_id`.
--
-- Independently of any closure, every selected claim drags in its `supersedes`
-- chain transitively in BOTH directions, plus its `step_lineage_id` siblings at
-- ONE hop. The asymmetry is stated because it is a real one; see "THE SIBLING
-- ARM IS ONE HOP" below.
--
--   * BACKWARDS: predecessors. Older content, `is_current = false`, and no
--     tenancy trigger reaches them.
--   * FORWARDS: successors. A public successor pointing at a now-private
--     predecessor is a dangling-reference EXISTENCE ORACLE.
--   * SIBLINGS: `evolve_step` inserts a successor WITHOUT setting `supersedes`,
--     linking through `step_lineage_id` plus an edge. A hull that recursed on
--     `supersedes` alone left every sibling revision of a workflow step public
--     — successive drafts of the same content, and a public sibling shares the
--     private claim's `step_lineage_id`, which is the same oracle by another
--     route.
--
-- THE SIBLING ARM IS ONE HOP, AND THAT IS AN UNDER-SELECTION, NOT A BOUND.
-- `chain` recurses over `supersedes`; `lineage` is a SEPARATE, NON-RECURSIVE CTE
-- that collects claims sharing a `step_lineage_id` with a `chain` member and is
-- never fed back into `chain`. So a sibling revision does not have its own
-- `supersedes` predecessors or successors walked, and its own `step_lineage`
-- cousins are not followed. By this file's own argument that is the same oracle
-- one hop further out. Closing it means folding the `step_lineage_id` expansion
-- into the recursive term as a third `LATERAL` branch — a real change to what
-- the hull selects, with no consumer in PR-18a to exercise it. It is 18b's,
-- named here rather than left to be inferred from the CTE shape, and the
-- register carries it as an open obligation.
--
-- NOT `SECURITY DEFINER` — AND THE BOUND THAT BUYS IS CONDITIONAL ON THE CALLER'S
-- CONNECTION, WHICH PR-18a DOES NOT CHOOSE.
--
-- This function runs as its invoker, so on a STAMPED `epigraph_app` connection
-- it is bounded by `claims_tenancy` and hulls only claims that caller can
-- already read. That bound does NOT hold on the only connection that can call it
-- today: the sole EXECUTE grantee below is `epigraph_maintenance`, and 077's
-- `claims_tenancy` opens with an `epigraph_bypass()` disjunct, which is exactly
-- membership in that role. On a maintenance connection the invoker bound admits
-- every row and this function is unfiltered by construction.
--
-- That is a latent property and not a live defect: PR-18a ships no caller — a
-- grep for either function name over `crates/` returns nothing. But it means the
-- invoker argument must NOT be inherited as a security control by whoever writes
-- the first one. 18b owns two decisions this file cannot make: WHICH POOL calls
-- the hull and the closure, and whether the returned ids are re-filtered against
-- the requesting principal's `Viewer` before they leave the process. Both are
-- named as 18b acceptance items in the register rather than left implicit.
--
-- THE DEPTH CAP IS A TRUNCATION, NOT A REFUSAL, AND THE CALLER CANNOT SEE IT.
-- `array_length(ch.path,1) < 64` stops the walk at 64 hops and returns the
-- shorter list; no caller can distinguish "this lineage is 40 deep" from "this
-- lineage was cut at 64". A truncated hull leaves a public successor pointing at
-- a privatized predecessor, which is the existence oracle three paragraphs above
-- says the hull exists to prevent — so the cap is NOT fail-closed and must not
-- be described as if it were. Overflow detection belongs with the caller that
-- can turn it into a refusal; see the closure's deferral list below, which names
-- it alongside the edge-type tiers as 18b's.
--
-- The OUT parameter names (`claim_id`, `via`) collide with column names inside
-- the body, so every body reference is table-qualified. An unqualified `via`
-- raises `column reference "via" is ambiguous` at CREATE time.
--
-- BOTH DIRECTIONS TRAVEL IN ONE RECURSIVE TERM, AND THAT IS NOT A STYLE CHOICE.
-- PostgreSQL's `WITH RECURSIVE` admits exactly one `UNION [ALL]` between a
-- non-recursive and a recursive term. Written as three branches — seeds
-- `UNION ALL` predecessors `UNION ALL` successors — the set operations
-- associate left, so the "non-recursive term" is `(seeds UNION ALL
-- predecessors)`, which contains a self-reference, and CREATE fails with
-- `recursive reference to query "chain" must not appear within its
-- non-recursive term`. The two directions are therefore one recursive term
-- whose `LATERAL` subquery branches, which is the shape
-- `epigraph_privatization_closure` below already uses.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_content_lineage_hull(p_seeds uuid[])
RETURNS TABLE (claim_id uuid, via text) LANGUAGE sql STABLE PARALLEL SAFE AS $$
    WITH RECURSIVE chain AS (
        SELECT c.id AS id, c.supersedes AS sup, ARRAY[c.id] AS path,
               'seed'::text AS step
          FROM public.claims c WHERE c.id = ANY(p_seeds)
        UNION ALL
        SELECT nxt.id, nxt.sup, ch.path || nxt.id, 'hull:supersedes'::text
          FROM chain ch
          CROSS JOIN LATERAL (
              -- backwards: predecessors. Older content, `is_current = false`,
              -- and no tenancy trigger reaches them.
              SELECT p.id AS id, p.supersedes AS sup
                FROM public.claims p WHERE p.id = ch.sup
              UNION ALL
              -- forwards: successors.
              SELECT s.id, s.supersedes
                FROM public.claims s WHERE s.supersedes = ch.id
          ) nxt
         WHERE NOT nxt.id = ANY(ch.path) AND array_length(ch.path,1) < 64
    ),
    lineage AS (
        SELECT l.id AS id, 'hull:step_lineage'::text AS step
          FROM public.claims l
         WHERE l.step_lineage_id IN (
                 SELECT c.step_lineage_id FROM public.claims c
                  WHERE c.id IN (SELECT chain.id FROM chain)
                    AND c.step_lineage_id IS NOT NULL)
    ),
    -- `rank` EXISTS BECAUSE `min(step)` PICKS BY SPELLING, NOT BY PROVENANCE.
    -- `'hull:step_lineage' < 'hull:supersedes' < 'seed'` lexically, so a plain
    -- `min(step)` labels a SEED that is also a lineage sibling
    -- `via = 'hull:step_lineage'` — and `privatization_plan_items.depth`'s own
    -- column comment says `0 = seed`, so the stored pair would describe a
    -- traversal that did not happen. 18b materialises these rows into the frozen
    -- item set that an apply and a revert both read, so a wrong `via` is a wrong
    -- audit record. The rank states the intended precedence explicitly: seed,
    -- then the `supersedes` walk, then the one-hop sibling arm.
    unioned AS (
        SELECT chain.id AS id, chain.step AS step,
               CASE WHEN chain.step = 'seed' THEN 0 ELSE 1 END AS rank
          FROM chain
        UNION ALL
        SELECT lineage.id, lineage.step, 2 FROM lineage
    )
    SELECT unioned.id,
           (array_agg(unioned.step ORDER BY unioned.rank, unioned.step))[1]
      FROM unioned GROUP BY unioned.id
$$;

-- ===================================================================
-- CLOSURE TRAVERSAL.
--
-- CASE NORMALISATION IS MANDATORY, NOT COSMETIC. `migrations/011` documents
-- 36,791 rows carrying `relationship = 'DERIVED_FROM'` alongside lowercase
-- `'derived_from'`, with different factor strengths. A closure matching one
-- case silently under-selects by tens of thousands of rows.
--
-- Cycle control is path-array containment, matching `repos/lineage.rs`'s idiom.
--
-- ALSO NOT `SECURITY DEFINER` — BUT NOT FOR THE SAME REASON AS THE HULL, AND
-- SUBJECT TO THE SAME CONDITIONALITY. Everything the hull's header says about
-- the invoker bound being vacuous on `epigraph_maintenance` — the only role
-- granted EXECUTE below — applies here verbatim; read that paragraph first.
-- The hull is bounded (on a stamped app connection) by `claims_tenancy` because
-- its CTEs read `public.claims`. This function never reads `public.claims`: its
-- recursive term
-- walks `public.edges` and emits `edges.source_id` / `target_id` as claim ids,
-- and its non-recursive term echoes `unnest(p_seeds)` back UNFILTERED. Its
-- actual bound is therefore `edges_tenancy` plus 072's co-ownership column — a
-- different predicate, which admits `visibility = 'public'` unconditionally and
-- keys on `owner_group_id` / `co_owner_group_id` rather than on the claim's own
-- tenancy. A future author adding an `evidence` branch, a new edge type, or a
-- `SECURITY DEFINER` variant must re-derive that bound rather than inherit the
-- hull's.
--
-- WHAT THIS FUNCTION DEFERS UPWARD TO THE ROUTE LAYER (18b), IN FULL:
--
--   1. Edge-type TIERS. Restatement types (`decomposes_to`, `derived_from`)
--      default on; epistemic types default off; structural types
--      (`within_frame`, `scoped_by`, `member_of`, `perspective_of`) point at
--      containers and are refused with 400. Passing them here is not an error —
--      the caller is the gate.
--   2. OVERFLOW DETECTION. `LIMIT p_node_cap` with no `ORDER BY` is a silent and
--      nondeterministic truncation, and the hull's 64-hop cap is the same shape.
--      FINAL-PLAN §3.1 requires that exceeding `node_cap` or `max_depth` be "a
--      400, not a truncation"; a 400 needs a route, so the detection and the
--      refusal are both 18b's. Nothing here reports that a cap was reached.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_privatization_closure(
    p_seeds uuid[], p_edge_types text[], p_direction text,
    p_max_depth int, p_node_cap int
) RETURNS TABLE (claim_id uuid, depth int, via text)
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    WITH RECURSIVE norm AS (SELECT array_agg(lower(t)) AS t FROM unnest(p_edge_types) AS t),
    walk AS (
        SELECT s AS id, 0 AS lvl, 'seed'::text AS step, ARRAY[s] AS path
          FROM unnest(p_seeds) AS s
        UNION ALL
        SELECT nxt.id, w.lvl + 1, 'closure:' || lower(nxt.rel), w.path || nxt.id
          FROM walk w
          CROSS JOIN LATERAL (
              SELECT e.target_id AS id, e.relationship::text AS rel
                FROM public.edges e, norm
               WHERE p_direction IN ('out','both')
                 AND e.source_id = w.id AND e.source_type = 'claim'
                 AND e.target_type = 'claim' AND lower(e.relationship) = ANY(norm.t)
              UNION ALL
              SELECT e.source_id AS id, e.relationship::text AS rel
                FROM public.edges e, norm
               WHERE p_direction IN ('in','both')
                 AND e.target_id = w.id AND e.target_type = 'claim'
                 AND e.source_type = 'claim' AND lower(e.relationship) = ANY(norm.t)
          ) nxt
         WHERE w.lvl < p_max_depth
           AND NOT nxt.id = ANY(w.path)
    )
    -- `depth` AND `via` MUST COME FROM THE SAME PATH. Two independent
    -- aggregates — `MIN(lvl)` and `MIN(step)` — pick separately: a node reached
    -- at depth 1 via `closure:supports` and at depth 2 via `closure:derived_from`
    -- would be persisted `(1, 'closure:derived_from')`, a provenance pair that
    -- describes no actual traversal. `array_agg(… ORDER BY lvl, step)` takes the
    -- `via` off the row the minimum depth came from. Seeds need no special case
    -- here, unlike the hull: they are the only rows at `lvl = 0`.
    SELECT walk.id, MIN(walk.lvl)::int,
           (array_agg(walk.step ORDER BY walk.lvl, walk.step))[1]
      FROM walk GROUP BY walk.id LIMIT p_node_cap
$$;

-- ===================================================================
-- RLS. See the header: ENABLE + FORCE, no policy, full default deny.
-- ===================================================================
ALTER TABLE public.privatization_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.privatization_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE public.privatization_plan_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.privatization_plan_items FORCE ROW LEVEL SECURITY;

-- 077's `ALTER DEFAULT PRIVILEGES FOR ROLE epigraph … TO epigraph_app` covers a
-- table created afterwards BY THE MIGRATION RUNNER, which is how these two are
-- created — so the SELECT grant that
-- `rls_enforcement.rs::the_app_role_can_reach_every_public_table_without_the_test_fixture`
-- requires arrives without help. It is re-issued explicitly anyway, because
-- that default only binds when the runner is `epigraph`, and 078 set the
-- precedent of a table granting itself rather than depending on that.
--
-- THE REVOKE IS THE SAME STATEMENT 082 MAKES, FOR THE SAME REASON. That same
-- default privilege grants INSERT, UPDATE and DELETE as well — measured on
-- `webhook_subscriptions` (085), which carries all four. Without the REVOKE the
-- header's "both tables default-deny every command to every non-owner" would be
-- true of the policy layer and FALSE of the grant layer, leaving RLS as the only
-- control on the two tables and leaving the write grants already in place on the
-- day 18b adds a policy to enable preview. 082 and 083 both REVOKE; 080 must
-- not be the odd one out.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public.privatization_plans '
                'FROM epigraph_app';
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public.privatization_plan_items '
                'FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.privatization_plans TO epigraph_app';
        EXECUTE 'GRANT SELECT ON public.privatization_plan_items TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.privatization_plans '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.privatization_plan_items '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_content_lineage_hull(uuid[]) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_privatization_closure(uuid[], text[], text, int, int) '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- PostgreSQL grants EXECUTE on a new function to PUBLIC by default, so the two
-- explicit GRANTs above are decorative unless that default is removed first —
-- the declared surface would not be the actual one. 070 does this for
-- `epigraph_edges_tenancy` / `epigraph_propagate_tenancy`, 077 for
-- `epigraph_is_group_admin`, 086 for `epigraph_claim_tenancy_by_ids`, and 083
-- for `epigraph_is_instance_admin` in this same PR. Both functions here are
-- SECURITY INVOKER, so on a stamped app connection they are RLS-bounded and this
-- is surface alignment rather than the closing of a leak. On the one role that
-- IS granted EXECUTE — `epigraph_maintenance` — that bound is vacuous, per the
-- hull's header, which is the reason the grant is kept to that single role and
-- the reason 18b owns choosing the calling pool. They are the two functions that
-- materialise a privatization selection, and the convention is explicit.
REVOKE EXECUTE ON FUNCTION public.epigraph_content_lineage_hull(uuid[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_privatization_closure(uuid[], text[], text, int, int) FROM PUBLIC;

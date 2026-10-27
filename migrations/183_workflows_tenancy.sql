-- 183: a `workflows` row carries the tenancy of its plan (operator ruling R-74,
-- 2026-10-27; backlog c0ab097a (2)).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `workflows` (020) had no owner group and no row security, so nothing could
-- say whether a caller may read a given PLAN: every reader, and the outcome
-- report's authority check, could only ask about the plan's claims and edges,
-- and those are not plan-specific (several workflow rows can execute the same
-- claim). The authority check therefore decided on readable steps, not on the
-- plan.
--
-- The ruling: give `workflows` tenancy, populated from the plan's declared
-- tenancy, so the decision is made per plan; keep public workflow rows
-- readable instance-wide.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `owner_group_id uuid` and `visibility varchar(16)`, the tier-A shape of
--      062 (the same CHECK, FK and group-needs-real-group constraint names),
--      NOT NULL and with NO default (074's rule: tenancy is declared, never
--      defaulted).
--   2. The backfill (section 2).
--   3. `workflows_require_tenancy` (BEFORE INSERT): 074's
--      `epigraph_root_require_tenancy()`, unchanged. A writer names both
--      columns; the seed role's escape hatch stamps `('public', seed)`.
--   4. Tenancy is immutable to an ordinary session: 115's
--      `epigraph_owner_immutable_guard` on `owner_group_id`, and the same rule
--      for `visibility` (`epigraph_workflows_visibility_guard`). Only a
--      privileged (maintenance) session re-tenants a row.
--   5. Row security, ENABLEd and FORCEd (section 3).
--
-- NOT changed: `epigraph_node_tenancy` (070) still treats a workflow endpoint
-- as tenancy-less, so `executes` edges keep the tenancy of their claim. The
-- row's own tenancy is what decides access to the plan.
--
-- ===================================================================
-- 2. THE BACKFILL: THE PLAN'S DECLARED TENANCY
-- ===================================================================
--
-- A declared ingest (`tenancy: {"visibility": "group", "owner_group_id": G}`)
-- writes every thesis, phase and step claim it CREATES as ('group', G); an
-- undeclared ingest writes them public. Those three levels are scoped to the
-- workflow's `canonical_name` (`content_hash_scope = "canonical_name"`), so
-- they belong to one lineage. Level-3 operation atoms are content-addressed in
-- the namespace every document shares (`atom_id`) and say nothing about the
-- plan; they are not read here.
--
--   * A row whose `executes` targets at levels 0..2 include a group-private
--     claim becomes ('group', G), G the group owning the most of them (ties:
--     the lowest group id). Retracted edges count too: a plan that was ever
--     declared private stays private. A plan with targets in two groups is
--     owned by one of them; members of the other lose sight of the ROW (not of
--     their claims). That is the fail-closed choice, and the count of such
--     rows is a pre-deploy measurement (docs in the PR), not a guess.
--   * Every other row is public, owned by the group owning its earliest public
--     target (the ingest system agent's group for an ingest), or by the seed
--     group when it has none (a step-less root). The world group is never
--     chosen.
--
-- A plan privatized AFTER its ingest (claims restricted by an operator) has
-- group-private targets, so it is backfilled as a group row too. A plan
-- privatized after THIS migration keeps its row's tenancy: re-tenanting a
-- workflow row is a maintenance act, as for every tier-A row.
--
-- ===================================================================
-- 3. ROW SECURITY
-- ===================================================================
--
--   * READ: public, or owned by a group in the session's read set (077's
--     disjuncts, in 077's order).
--   * INSERT: owned by a group the session WRITES (077's tier-A WITH CHECK;
--     no world arm).
--   * UPDATE: a row the session can READ, and the new row must be readable
--     too. The mutable columns (counters in `metadata`, `truth_value`,
--     `goal_embedding`) are written by the outcome report, deprecation, goal
--     embedding and the plan editors, whose authority is the application's
--     (workflow authority, a readable plan), exactly as before this file. The
--     columns that decide READ access cannot be changed by those writers
--     (section 1, item 4).
--   * DELETE: no permissive policy, so an application session deletes no row
--     (none does), plus 115's restrictive owner-writer rule.
--
-- Like all row security here this binds API sessions, not a holder of a
-- maintenance or superuser connection.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. Columns (nullable until the backfill has filled them)
-- ===================================================================
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'workflows'
                AND column_name IN ('owner_group_id', 'visibility')
    LOOP
        RAISE EXCEPTION
            'public.workflows.% already exists (data_type=%). Reconcile by hand, then re-run.',
            r.column_name, r.data_type;
    END LOOP;
END $$;

ALTER TABLE public.workflows
    ADD COLUMN owner_group_id uuid,
    ADD COLUMN visibility character varying(16);

-- ===================================================================
-- 2. Backfill (section 2 above)
-- ===================================================================
WITH private_targets AS (
    SELECT e.source_id AS workflow_id, c.owner_group_id AS group_id, count(*) AS n
      FROM public.edges e
      JOIN public.claims c ON c.id = e.target_id
     WHERE e.source_type = 'workflow' AND e.target_type = 'claim'
       AND e.relationship = 'executes'
       AND c.visibility = 'group'
       AND btrim(c.properties->>'level') ~ '^[+]?0*[0-2]$'
     GROUP BY 1, 2
), owner AS (
    SELECT DISTINCT ON (workflow_id) workflow_id, group_id
      FROM private_targets
     ORDER BY workflow_id, n DESC, group_id
)
UPDATE public.workflows w
   SET owner_group_id = o.group_id, visibility = 'group'
  FROM owner o
 WHERE w.id = o.workflow_id;

UPDATE public.workflows w
   SET visibility = 'public',
       owner_group_id = COALESCE(
           (SELECT c.owner_group_id
              FROM public.edges e
              JOIN public.claims c ON c.id = e.target_id
             WHERE e.source_id = w.id AND e.source_type = 'workflow'
               AND e.target_type = 'claim' AND e.relationship = 'executes'
               AND c.visibility = 'public'
               AND c.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
             ORDER BY e.created_at, e.id
             LIMIT 1),
           '00000000-0000-0000-0000-00000000dead'::uuid)
 WHERE w.visibility IS NULL;

ALTER TABLE public.workflows
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;

ALTER TABLE public.workflows
    ADD CONSTRAINT workflows_visibility_check
        CHECK (visibility IN ('public', 'group')),
    ADD CONSTRAINT workflows_owner_group_fkey
        FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    ADD CONSTRAINT workflows_group_needs_real_group CHECK (
        visibility <> 'group'
        OR owner_group_id NOT IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid));

-- The readers' predicate (`owner_group_id = ANY(...)` beside `visibility`).
CREATE INDEX workflows_group_owner_idx
    ON public.workflows (owner_group_id) WHERE visibility = 'group';

-- ===================================================================
-- 3. Declared, never defaulted
-- ===================================================================
DROP TRIGGER IF EXISTS workflows_require_tenancy ON public.workflows;
CREATE TRIGGER workflows_require_tenancy BEFORE INSERT ON public.workflows
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();

-- ===================================================================
-- 4. Tenancy is immutable to an ordinary session
-- ===================================================================
DROP TRIGGER IF EXISTS workflows_owner_immutable ON public.workflows;
CREATE TRIGGER workflows_owner_immutable BEFORE UPDATE OF owner_group_id ON public.workflows
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

CREATE OR REPLACE FUNCTION public.epigraph_workflows_visibility_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: an UPDATE of workflows changes visibility; '
                    'only a maintenance session re-tenants a workflow row'
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflows_visibility_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS workflows_visibility_immutable ON public.workflows;
CREATE TRIGGER workflows_visibility_immutable BEFORE UPDATE OF visibility ON public.workflows
    FOR EACH ROW
    WHEN (OLD.visibility IS DISTINCT FROM NEW.visibility)
    EXECUTE FUNCTION public.epigraph_workflows_visibility_guard();

-- ===================================================================
-- 5. Row security (section 3 above)
-- ===================================================================
ALTER TABLE public.workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workflows FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workflows_read ON public.workflows;
CREATE POLICY workflows_read ON public.workflows FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

DROP POLICY IF EXISTS workflows_insert ON public.workflows;
CREATE POLICY workflows_insert ON public.workflows FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

DROP POLICY IF EXISTS workflows_update ON public.workflows;
CREATE POLICY workflows_update ON public.workflows FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

DROP POLICY IF EXISTS workflows_delete_owner ON public.workflows;
CREATE POLICY workflows_delete_owner ON public.workflows AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- ===================================================================
-- 6. Elevated sessions (126's census): write refusal, no read arm
-- ===================================================================
-- An elevated session reads `workflows` as its plain viewer does (126 widens
-- only the classes DESIGN 6.3 names, and every widened read is attributed by
-- 127's recorder), and writes none of it, like every table the application
-- writes. `elevation_arms_census.rs` lists `workflows` as refusal-only.
DROP POLICY IF EXISTS workflows_elevated_no_insert ON public.workflows;
CREATE POLICY workflows_elevated_no_insert ON public.workflows
    AS RESTRICTIVE FOR INSERT TO epigraph_app
    WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS workflows_elevated_no_update ON public.workflows;
CREATE POLICY workflows_elevated_no_update ON public.workflows
    AS RESTRICTIVE FOR UPDATE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS workflows_elevated_no_delete ON public.workflows;
CREATE POLICY workflows_elevated_no_delete ON public.workflows
    AS RESTRICTIVE FOR DELETE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));

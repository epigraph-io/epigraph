-- 240: a `behavioral_executions` row carries the tenancy of the workflow it
-- records a run of, under FORCEd row security (backlog 88cf603b).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `behavioral_executions` (002, 021, 022, 056) records the runs of a
-- workflow: the goal text and its embedding, the per-step beliefs and
-- deviation reasons, the tool pattern, the run label. It had no tenancy
-- columns and no row security of its own: 069 ledgered it in
-- `tenancy_exempt` (reviewer PENDING), so EVERY application session read
-- every run of every workflow, group-private plans included. The first-party
-- readers filter on a readable parent workflow (`recent_executions`,
-- `success_stats`, `deviation_summary`, the affinity reads), but the table
-- itself stayed readable to a raw query on the application DSN and to any new
-- reader that forgot the filter, and no narrowing of a workflow
-- (`reown-workflows`, the privatization batch) could hide its run history
-- (`reown-workflows` only counted the rows it could not hide).
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
-- A run belongs to its workflow, so it takes the workflow's tenancy. The
-- workflow id is polymorphic (022): a `workflows` row (hierarchical, tenancy
-- since 183) or, for a legacy flat workflow, a workflow CLAIM. The `workflows`
-- row wins when both exist.
--
--   1. `owner_group_id uuid` and `visibility varchar(16)`, the tier-A shape of
--      062 (the same CHECK, FK and group-needs-real-group constraint names),
--      NOT NULL with NO default.
--   2. The backfill (section 2): every existing run takes its workflow's
--      pair. A run whose workflow is neither a `workflows` row nor a claim (an
--      ORPHAN: 022 dropped the FK) has no owner this file can name, so the
--      migration refuses (BEX01), names the count and changes nothing.
--   3. `behavioral_executions_inherit_tenancy` (BEFORE INSERT): the workflow's
--      pair over any declaration, as 173's audit-report stamp and 070 arm (c).
--      A run of no workflow is refused (23503). The stamp locks the parent row
--      `FOR SHARE` (114 section 2(e)'s reason): a run inserted while its
--      workflow is being narrowed either waits for the narrowing and takes the
--      narrowed pair, or commits first and is then re-stamped by item 4.
--   4. A run FOLLOWS its workflow. `workflows_behavioral_executions_inherit_
--      tenancy` (AFTER UPDATE OF the pair on `workflows`) and
--      `claims_behavioral_executions_inherit_tenancy` (the same on `claims`,
--      for flat workflows; a claim id that is also a `workflows` id is left to
--      the `workflows` trigger) re-stamp the runs whenever the parent's pair
--      changes: the privatization batch's restrict and restore of a plan's
--      workflow rows, `reown-workflows`, `restrict-claims` on a flat workflow
--      claim, or any other maintenance re-tenant. Nothing re-stamps a run from
--      a trigger on `behavioral_executions` itself.
--   5. Row security, ENABLEd and FORCEd (section 5):
--        * READ: public, or owned by a group in the session's read set (077's
--          disjuncts, in 077's order), so a run is read exactly when its
--          workflow's pair admits the session.
--        * INSERT: the SAME predicate as READ, NOT 077's writable-group check.
--          Recording a run of a workflow has always been open to any session
--          that reads the workflow (a public plan owned by another group
--          included; its authority is the application's, as for
--          `workflow_outcome_reports` (221) and `workflows_update` (183)).
--          Because the stamp has already given the row its workflow's pair,
--          this admits a run exactly when the session reads its workflow, and
--          refuses (42501) a run of a workflow the session does not read.
--        * UPDATE: only the maintenance session and its definers (the follow
--          triggers); the application role holds no UPDATE (118 section 6).
--        * DELETE: no permissive policy (the application role holds no DELETE
--          either), plus 115's restrictive owner-writer rule and 115's
--          `owner_immutable` guard.
--        * 126's census: refusal-only (class T-PLAN), the three restrictive
--          elevated policies `workflows` (183) and `workflow_outcome_reports`
--          (221) carry; an elevated session reads runs as its plain viewer.
--   6. The `tenancy_exempt` row goes: a covered table keeps none.
--
-- NOT changed:
--   * grants: the application role keeps SELECT and INSERT (118);
--   * a run is met with its WORKFLOW only, never with its `step_claim_id`'s
--     claim. A public plan's run that names a step claim private to another
--     group stays public, as the plan's own `executes` edge rule decides
--     whether that step is part of the plan;
--   * the readers. Their in-query parent filters stay (defense in depth) and
--     now agree with the row policy.
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser: section 0 refuses (BEX01)
-- whenever the table holds a row and the migrator cannot read every workflow
-- row and claim, because an RLS-filtered backfill would find no private
-- parent and refuse every private run as an orphan (or, worse, see only part
-- of the corpus). Before deploying, measure the orphans (section 2's refusal):
--   SELECT count(*) FROM behavioral_executions be
--    WHERE NOT EXISTS (SELECT 1 FROM workflows w WHERE w.id = be.workflow_id)
--      AND NOT EXISTS (SELECT 1 FROM claims c WHERE c.id = be.workflow_id);
-- A non-zero count blocks the migration until an operator resolves those runs.
--
-- DEPLOY ORDER: migrate BEFORE, or with, the binary built with this change.
-- That binary records the flat `report_workflow_outcome` run and the
-- `POST /api/v1/workflows/:id/behavioral-executions` run on the caller's
-- stamped connection, lists the table in `FORCE_PROTECTED_SET` and requires
-- this file's three triggers once its functions exist. An OLDER binary on a
-- migrated database records those two runs on its unstamped pool: a run of a
-- public workflow still lands, a run of a group workflow is refused (the MCP
-- tool logs a warning and answers success; the HTTP route answers 500), so
-- roll the binary out promptly.
--
-- Undo (roll the binary back first): `docs/runbooks/240-undo.sql` drops the
-- three tenancy triggers and the owner guard, their three functions, every
-- policy, NO FORCE and DISABLE row security, the three constraints, the index
-- and both columns, and restores 069's `tenancy_exempt` row. The table then
-- has the posture it had before this file (`docs/runbooks/079-undo.sql` keeps
-- its name: `NO FORCE` on an un-FORCEd table is a no-op).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. A BACKFILL NEEDS A MIGRATOR THAT READS EVERY PARENT
--
-- The same three admissions `epigraph_session_is_privileged_writer` (114)
-- makes, inlined, as 173 section 0: `epigraph_definer_bypass()` is not
-- executable by PUBLIC, so calling it here would turn this refusal into a
-- 42501. On an empty table there is nothing to derive and this passes.
-- ===================================================================
DO $$
DECLARE reads_all boolean;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.behavioral_executions) THEN
        RETURN;
    END IF;
    SELECT r.rolsuper OR r.rolbypassrls INTO reads_all
      FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
    reads_all := COALESCE(reads_all, false)
        OR public.epigraph_bypass()
        OR COALESCE((SELECT pg_catalog.pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
                      WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                                     WHERE rolname = 'epigraph_maintenance')), false);
    IF NOT reads_all THEN
        RAISE EXCEPTION 'BEX01: migration 240 derives behavioral_executions rows from '
                        'workflows and claims, which are FORCEd, and role % cannot read every '
                        'row of them (not a superuser, no BYPASSRLS, not a member of '
                        'epigraph_maintenance); nothing was changed. Run as a superuser or '
                        'maintenance login.', current_user
            USING ERRCODE = '42501';
    END IF;
END $$;

-- ===================================================================
-- 1. THE COLUMNS, NULLABLE UNTIL THE DERIVATION HAS RUN
--
-- DRIFT GUARD (062's, 173's): a column of either name in another shape is
-- not this file's, and ADD COLUMN IF NOT EXISTS would pass it silently.
-- ===================================================================
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'behavioral_executions'
                AND column_name IN ('owner_group_id', 'visibility')
    LOOP
        IF (r.column_name = 'owner_group_id' AND r.data_type <> 'uuid')
        OR (r.column_name = 'visibility' AND r.data_type <> 'character varying') THEN
            RAISE EXCEPTION 'public.behavioral_executions.% already exists as %, a shape 240 '
                            'did not create. Reconcile by hand, then re-run.',
                r.column_name, r.data_type;
        END IF;
    END LOOP;
END $$;

ALTER TABLE public.behavioral_executions
    ADD COLUMN IF NOT EXISTS owner_group_id uuid,
    ADD COLUMN IF NOT EXISTS visibility character varying(16);

-- ===================================================================
-- 2. DERIVE EXISTING ROWS FROM THEIR WORKFLOW, OR REFUSE
-- ===================================================================
UPDATE public.behavioral_executions be
   SET owner_group_id = w.owner_group_id,
       visibility     = w.visibility
  FROM public.workflows w
 WHERE w.id = be.workflow_id
   AND (be.owner_group_id IS NULL OR be.visibility IS NULL);

UPDATE public.behavioral_executions be
   SET owner_group_id = c.owner_group_id,
       visibility     = c.visibility
  FROM public.claims c
 WHERE c.id = be.workflow_id
   AND NOT EXISTS (SELECT 1 FROM public.workflows w WHERE w.id = be.workflow_id)
   AND (be.owner_group_id IS NULL OR be.visibility IS NULL);

DO $$
DECLARE n_orphans bigint;
BEGIN
    SELECT count(*) INTO n_orphans FROM public.behavioral_executions
     WHERE owner_group_id IS NULL OR visibility IS NULL;
    IF n_orphans > 0 THEN
        RAISE EXCEPTION 'BEX01: migration 240 cannot derive an owner for % behavioral_executions '
                        'row(s): their workflow_id names neither a workflows row nor a claim, '
                        'so no tenancy can be inherited; nothing was changed. Resolve those '
                        'runs (an operator decision: they are runs of a workflow that no longer '
                        'exists) and re-run.', n_orphans
            USING ERRCODE = '23503';
    END IF;
END $$;

ALTER TABLE public.behavioral_executions
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;

-- ===================================================================
-- 3. 062's CONSTRAINTS, VALIDATED AT CREATION
-- ===================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.behavioral_executions'::regclass
                      AND conname = 'behavioral_executions_visibility_check') THEN
        ALTER TABLE public.behavioral_executions
            ADD CONSTRAINT behavioral_executions_visibility_check
            CHECK (visibility IN ('public', 'group'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.behavioral_executions'::regclass
                      AND conname = 'behavioral_executions_owner_group_fkey') THEN
        ALTER TABLE public.behavioral_executions
            ADD CONSTRAINT behavioral_executions_owner_group_fkey
            FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT;
    END IF;
    -- ('group', world) and ('group', seed) are rows nobody can read back:
    -- both groups are memberless by design (062).
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.behavioral_executions'::regclass
                      AND conname = 'behavioral_executions_group_needs_real_group') THEN
        ALTER TABLE public.behavioral_executions
            ADD CONSTRAINT behavioral_executions_group_needs_real_group CHECK (
                visibility <> 'group'
                OR owner_group_id NOT IN (
                     '00000000-0000-0000-0000-000000000000'::uuid,
                     '00000000-0000-0000-0000-00000000dead'::uuid));
    END IF;
END $$;

-- The row policy's predicate (`owner_group_id = ANY(...)` beside `visibility`).
CREATE INDEX IF NOT EXISTS behavioral_executions_group_owner_idx
    ON public.behavioral_executions (owner_group_id) WHERE visibility = 'group';

-- ===================================================================
-- 4. THE WRITE SIDE: STAMPED FROM THE WORKFLOW, AND FOLLOWING IT
-- ===================================================================
-- The stamp. A maintenance-owned definer so the read of the FORCEd
-- `workflows` / `claims` finds the parent for any writer (through 183's and
-- 077's `epigraph_definer_bypass()` arms), as 173's audit-report stamp reads
-- `harvester_fragments`. It returns nothing to the caller but the row it
-- stamps, and the INSERT policy then decides whether the caller may write it.
CREATE OR REPLACE FUNCTION public.epigraph_behavioral_execution_inherit_tenancy()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    SELECT w.owner_group_id, w.visibility INTO g, v
      FROM public.workflows w WHERE w.id = NEW.workflow_id
       FOR SHARE;
    IF NOT FOUND THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.workflow_id
           FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'epigraph tenancy: behavioral_executions.workflow_id=% names '
                            'neither a workflows row nor a workflow claim', NEW.workflow_id
                USING ERRCODE = '23503';
        END IF;
    END IF;
    NEW.owner_group_id := g;
    NEW.visibility     := v;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_behavioral_execution_inherit_tenancy() FROM PUBLIC;
DROP TRIGGER IF EXISTS behavioral_executions_inherit_tenancy ON public.behavioral_executions;
CREATE TRIGGER behavioral_executions_inherit_tenancy
    BEFORE INSERT ON public.behavioral_executions
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_behavioral_execution_inherit_tenancy();

-- A hierarchical workflow's runs follow its `workflows` row. AFTER UPDATE, on
-- the PARENT, so no `behavioral_executions` trigger restamps its own row
-- (115's owner guard and `no_other_table_restamps_its_owner_on_update`).
-- A maintenance-owned definer, because the session that re-tenants a
-- workflow row (the privatization batch, reown-workflows, an operator) is not
-- one the application role's grants would admit, and the runs must follow
-- whoever moved the workflow.
CREATE OR REPLACE FUNCTION public.epigraph_workflow_behavioral_executions_follow()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE public.behavioral_executions be
       SET owner_group_id = NEW.owner_group_id,
           visibility     = NEW.visibility
     WHERE be.workflow_id = NEW.id
       AND (be.owner_group_id, be.visibility)
           IS DISTINCT FROM (NEW.owner_group_id, NEW.visibility);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflow_behavioral_executions_follow() FROM PUBLIC;
DROP TRIGGER IF EXISTS workflows_behavioral_executions_inherit_tenancy ON public.workflows;
CREATE TRIGGER workflows_behavioral_executions_inherit_tenancy
    AFTER UPDATE OF owner_group_id, visibility ON public.workflows
    FOR EACH ROW
    WHEN ((OLD.owner_group_id, OLD.visibility)
          IS DISTINCT FROM (NEW.owner_group_id, NEW.visibility))
    EXECUTE FUNCTION public.epigraph_workflow_behavioral_executions_follow();

-- A flat workflow's runs follow its claim. A row trigger with a WHEN clause,
-- not a statement trigger over transition tables: it fires only on a claim
-- whose pair changed, so the hot `claims` UPDATEs (truth values, embeddings,
-- labels) never reach it. A claim id that is also a `workflows` id is the
-- `workflows` trigger's (the `workflows` row wins, as in the stamp).
CREATE OR REPLACE FUNCTION public.epigraph_claim_behavioral_executions_follow()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.workflows w WHERE w.id = NEW.id) THEN
        RETURN NULL;
    END IF;
    UPDATE public.behavioral_executions be
       SET owner_group_id = NEW.owner_group_id,
           visibility     = NEW.visibility
     WHERE be.workflow_id = NEW.id
       AND (be.owner_group_id, be.visibility)
           IS DISTINCT FROM (NEW.owner_group_id, NEW.visibility);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claim_behavioral_executions_follow() FROM PUBLIC;
DROP TRIGGER IF EXISTS claims_behavioral_executions_inherit_tenancy ON public.claims;
CREATE TRIGGER claims_behavioral_executions_inherit_tenancy
    AFTER UPDATE OF owner_group_id, visibility ON public.claims
    FOR EACH ROW
    WHEN ((OLD.owner_group_id, OLD.visibility)
          IS DISTINCT FROM (NEW.owner_group_id, NEW.visibility))
    EXECUTE FUNCTION public.epigraph_claim_behavioral_executions_follow();

-- ===================================================================
-- 5. ROW SECURITY (section 1, item 5)
-- ===================================================================
ALTER TABLE public.behavioral_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_executions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS behavioral_executions_read ON public.behavioral_executions;
CREATE POLICY behavioral_executions_read ON public.behavioral_executions
    FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

-- READ-based on purpose (section 1, item 5): the stamp has set the pair to
-- the workflow's, so this admits a run exactly when the session reads its
-- workflow.
DROP POLICY IF EXISTS behavioral_executions_insert ON public.behavioral_executions;
CREATE POLICY behavioral_executions_insert ON public.behavioral_executions
    FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

-- Only a maintenance session or its definers (the two follow triggers).
DROP POLICY IF EXISTS behavioral_executions_maintenance_update ON public.behavioral_executions;
CREATE POLICY behavioral_executions_maintenance_update ON public.behavioral_executions
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- 115's DELETE rule. There is no permissive DELETE policy, so this binds a
-- maintenance session's own delete only if one is ever added.
DROP POLICY IF EXISTS behavioral_executions_delete_owner ON public.behavioral_executions;
CREATE POLICY behavioral_executions_delete_owner ON public.behavioral_executions
    AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

DROP TRIGGER IF EXISTS behavioral_executions_owner_immutable ON public.behavioral_executions;
CREATE TRIGGER behavioral_executions_owner_immutable
    BEFORE UPDATE OF owner_group_id ON public.behavioral_executions
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

-- 126's census, refusal-only (class T-PLAN), as `workflows` (183 section 6)
-- and `workflow_outcome_reports` (221).
DROP POLICY IF EXISTS behavioral_executions_elevated_no_insert ON public.behavioral_executions;
CREATE POLICY behavioral_executions_elevated_no_insert ON public.behavioral_executions
    AS RESTRICTIVE FOR INSERT TO epigraph_app
    WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS behavioral_executions_elevated_no_update ON public.behavioral_executions;
CREATE POLICY behavioral_executions_elevated_no_update ON public.behavioral_executions
    AS RESTRICTIVE FOR UPDATE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS behavioral_executions_elevated_no_delete ON public.behavioral_executions;
CREATE POLICY behavioral_executions_elevated_no_delete ON public.behavioral_executions
    AS RESTRICTIVE FOR DELETE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));

-- ===================================================================
-- 6. THE REGISTRY: a covered table keeps no exemption.
-- ===================================================================
DELETE FROM public.tenancy_exempt WHERE table_name = 'behavioral_executions';

-- ===================================================================
-- 7. OWNERSHIP. Guarded on the role, as 074's section 6 and 173's 7.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_behavioral_execution_inherit_tenancy() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_behavioral_executions_follow() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_claim_behavioral_executions_follow() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

COMMENT ON COLUMN public.behavioral_executions.owner_group_id IS
    'The owner group of the run''s workflow (a workflows row, else the flat workflow claim), '
    'stamped at INSERT by behavioral_executions_inherit_tenancy and re-stamped when the '
    'workflow''s pair changes (migration 240). Never declared by a writer.';
COMMENT ON COLUMN public.behavioral_executions.visibility IS
    'The visibility of the run''s workflow; see owner_group_id (migration 240).';

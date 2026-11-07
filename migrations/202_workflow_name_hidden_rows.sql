-- 202: whether a workflow lineage NAME has rows the session cannot read, so a
-- caller-authored workflow write never extends or edits a lineage it cannot
-- see in full.
--
-- ===================================================================
-- 1. WHY
--
-- Workflow writes (`ingest_workflow`, `store_workflow`,
-- `improve_workflow_hierarchy`, `add_step`, `delete_step`) used to run on the
-- shared workflow-ingest system agent's stamp. Every group-private plan had to
-- be in a group that agent wrote (a declared ingest refused otherwise), so the
-- lineage reads on that stamp (the head of a `canonical_name`, the linked
-- parent) saw every generation, and the workflow authority gate decided on
-- the real head.
--
-- They now run on the CALLER's own stamp, and a caller may declare any group
-- it writes. `workflows` is under FORCEd row security (183): a generation
-- private to a group the caller is not in is invisible to it. Measured on the
-- application role: a non-member ingesting `generation + 1` of a lineage whose
-- head is group-private found no head, passed no authority check, and created
-- a PUBLIC generation under that name. Every member then resolved the
-- lineage's head (the latest generation they can read) to the outsider's row,
-- so `add_step`, `delete_step` and `find_workflow` acted on it: a lineage
-- takeover by a caller who could not read it.
--
-- The guard needs one fact the caller's own view cannot give: whether ANY row
-- of the name is unreadable to it.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_workflow_name_has_hidden_rows(text) RETURNS boolean`:
-- SECURITY DEFINER, owned by `epigraph_maintenance` (whose frame reads every
-- `workflows` row through `epigraph_definer_bypass()`), STABLE, with 172's
-- pinned path `pg_catalog, pg_temp`. True iff a `workflows` row with that
-- `canonical_name` exists that 183's `workflows_read` policy would NOT show
-- the calling session: not a privileged session (`epigraph_bypass()`, the
-- session user), not public, and not owned by a group in the session's read
-- set (`epigraph_session_groups()`, the caller's stamp). The definer-frame arm
-- of that policy is deliberately left out: inside this frame it is always
-- true, and the question is about the caller.
--
-- The executor calls it on the write's own (caller-stamped) transaction, for
-- the `canonical_name` and any `parent_canonical_name` of a caller-authored
-- ingest, and for the workflow named by `add_step` / `delete_step`; a true
-- answer refuses the write with nothing written.
--
-- WHAT IT REVEALS. One boolean for one name: whether some row of it is hidden
-- from the caller. The same bit an ingest of an exact hidden
-- `(canonical_name, generation)` already reveals (`WorkflowOutsideView`, 409),
-- and the old system-stamped path revealed through its refusals. No id, row,
-- count, group or content leaves the function.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance`, role-guarded like 193.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 202: under a non-bypassing owner its read of
-- the FORCEd `workflows` is row-security filtered exactly as the caller's
-- would be, so a hidden row reads as absent and the guard fails OPEN (the
-- takeover above). The owner is load-bearing.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose workflow writes call it: without it every
-- caller-authored workflow write errors (42883) and writes nothing. An older
-- binary ignores it. Independent of 198-201.
--
-- UNDO, only AFTER rolling the binary back to one whose workflow writes run on
-- the system agent's stamp:
--   DROP FUNCTION IF EXISTS public.epigraph_workflow_name_has_hidden_rows(text);
-- Undoing under a caller-stamped binary re-opens the takeover in section 1.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_workflow_name_has_hidden_rows(p_canonical_name text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.workflows w
         WHERE w.canonical_name = p_canonical_name
           AND NOT (public.epigraph_bypass()
                    OR w.visibility = 'public'
                    OR w.owner_group_id = ANY (public.epigraph_session_groups()::uuid[])))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_workflow_name_has_hidden_rows(text) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_workflow_name_has_hidden_rows(text) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_workflow_name_has_hidden_rows(text) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_workflow_name_has_hidden_rows(text) TO epigraph_app';
    END IF;
END $$;

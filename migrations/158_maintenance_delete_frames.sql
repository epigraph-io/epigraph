-- Migration 158: let the maintenance role DELETE a `frames` row, so
-- `epigraph-operator delete-frames` (drain U048, backlog 34b3175c) runs on a
-- NOSUPERUSER maintenance login.
--
-- WHY A GRANT. 070 grants `epigraph_maintenance` SELECT / INSERT / UPDATE on
-- every table and deliberately no DELETE ("it never destroys"); 115
-- (`mass_functions`, `edges`), 117 (`factors`, `bp_messages`) and 118
-- (`oauth_authorize_sessions`) each added the narrowest DELETE a reviewed
-- maintenance path needed. `delete-frames` is the next such path: it removes
-- an explicit list of test or probe frames, refuses every frame a real
-- claim's BBA, a factor, a child frame, a cached belief or an edge still
-- depends on, and records one `operator.frames_deleted` audit row. Without
-- this grant its delete fails on a maintenance login with "permission denied
-- for table frames" (measured, `epigraph-cli/tests/operator_delete_frames.rs::
-- delete_frames_applies_as_a_non_superuser_maintenance_login`).
--
-- WHY ONLY `frames`. The four tables that hang off a frame (`mass_functions`,
-- `claim_frames`, `ds_combined_beliefs`, `ds_bayesian_divergence`) are emptied
-- by their foreign keys' ON DELETE CASCADE. A referential action runs as the
-- child table's owner and consults no row-security policy, so the caller needs
-- no DELETE on them, and none is granted. The tool accounts for the cascade
-- itself: a plan printed before the write, re-derived under the frames'
-- `FOR UPDATE` locks, and a `pg_stat_xact_user_tables` census that must match
-- it exactly or the transaction rolls back.
--
-- ROW SECURITY is unchanged. 115's RESTRICTIVE delete policy on `frames` and
-- 126's `frames_elevated_no_delete` (to `epigraph_app`) still apply; a
-- maintenance session passes them through `epigraph_bypass()`, as it does for
-- every other table. No application role gains anything.
--
-- A GRANT takes no table lock beyond a brief catalog update; `lock_timeout`
-- is set like 111-121 and 144-153 all the same.
--
-- UNDO:
--   REVOKE DELETE ON public.frames FROM epigraph_maintenance;

SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.frames TO epigraph_maintenance';
    END IF;
END $$;

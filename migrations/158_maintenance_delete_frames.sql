-- Migration 158: let the maintenance role DELETE a `frames` row, so
-- `epigraph-operator delete-frames` (drain U048, backlog 34b3175c) runs on a
-- NOSUPERUSER maintenance login.
--
-- WHY A GRANT. 070 grants `epigraph_maintenance` SELECT / INSERT / UPDATE on
-- every table and deliberately no DELETE ("it never destroys"); 115
-- (`mass_functions`, `edges`), 117 (`factors`, `bp_messages`), 118
-- (`oauth_authorize_sessions`) and 119 (`jobs` and the timer tables) each
-- added the narrowest DELETE a reviewed maintenance path needed.
-- `delete-frames` is the next such path: it removes
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
-- no DELETE on them. This migration grants none. The role already holds
-- DELETE on `mass_functions` (115) and holds none on `claim_frames`,
-- `ds_combined_beliefs` or `ds_bayesian_divergence` (070). The tool accounts
-- for the cascade itself: a plan printed before the write, re-derived under
-- the frames' `FOR UPDATE` locks, and a `pg_stat_xact_user_tables` census that
-- must match it exactly or the transaction rolls back.
--
-- EFFECTIVE REACH. The grant is on the role, not on the tool. Any session
-- that acts as `epigraph_maintenance` can now DELETE a frame: jobs, scripts
-- and logins on the maintenance DSN, not only `delete-frames`. Through the
-- cascade, that DELETE also removes the frame's rows in `claim_frames`,
-- `ds_combined_beliefs` and `ds_bayesian_divergence`, and the role holds no
-- DELETE on those tables. It removes the frame's `mass_functions` rows too.
-- That differs from the precedent: 117 granted DELETE on `bp_messages`
-- explicitly although it already cascades from `factors`. A FK RESTRICT / NO ACTION reference (`factors`, a
-- child frame, `claims.belief_frame_id`) still fails such a delete. Only
-- `delete-frames` refuses and audits it; a bare `DELETE FROM frames` on the
-- maintenance DSN does neither.
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

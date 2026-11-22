-- Migration 247: let the maintenance role DELETE a `claim_frames` row, so an
-- un-mark whose dedup repair bound a frame onto the canonical completes on a
-- NOSUPERUSER maintenance login (backlog 8ca08222).
--
-- THE FAILURE. A dedup's repair (`repair_marked_duplicate`) copies the
-- duplicate's frame bindings onto the canonical before it moves BBAs there,
-- and records the frames it bound (`copied_frames`). The un-mark's reversal
-- (`reverse_marked_duplicate_conn`, run by `admin_cascade::apply_unmark` on
-- the maintenance connection for the `unmark_duplicate` operator CLI and its
-- MCP/HTTP twins) deletes those bindings again. 070 gives
-- `epigraph_maintenance` SELECT / INSERT / UPDATE and no DELETE, and no later
-- migration grants DELETE on `claim_frames` (158's header says so), so that
-- statement fails with "permission denied for table claim_frames" and the
-- whole un-mark rolls back: the duplicate stays marked, non-current, with its
-- edges and BBAs on the canonical. Measured on a NOSUPERUSER maintenance
-- session by `epigraph-engine/tests/unmark_unbinds_frame_on_maintenance.rs`.
--
-- WHY A GRANT, NOT A DEFINER. Every SECURITY DEFINER in this schema is owned
-- by `epigraph_maintenance` itself, and a definer runs with its owner's
-- privileges: a maintenance-owned "unbind the recorded frames" function would
-- fail the same way. A narrow definer would need a new owner role holding the
-- DELETE (as 161 did for `epigraph_identity_attestor`), which managed
-- Postgres must provision out of band, for no real narrowing (next
-- paragraph). Leaving the binding instead is not a reversal: a `binary_truth`
-- binding at a non-zero index, copied when both claims share an owner group,
-- would keep the canonical reading FALSE on a frame it holds no input on.
--
-- EFFECTIVE REACH. The grant is on the role, so any session acting as
-- `epigraph_maintenance` can now delete any claim's frame binding. It could
-- already rewrite every binding (070's UPDATE on `claim_frames`, pinned by the
-- test above, covers `frame_id` and `hypothesis_index`), insert new ones, and
-- delete a whole frame (158), which empties that frame's `claim_frames` rows
-- through the ON DELETE CASCADE. Deleting a binding row is therefore not new
-- authority over what a claim is bound to. It deletes no frame and no BBA, so
-- it is independent of the open question of whether frame deletion (158)
-- should need stronger credentials than this role: revoking 158 would leave
-- this grant correct.
--
-- ROW SECURITY is unchanged. 115's RESTRICTIVE delete policy on
-- `claim_frames` still applies, and a maintenance session passes it through
-- `epigraph_bypass()`, as on every other table; 126's
-- `claim_frames_elevated_no_delete` (to `epigraph_app`) is untouched. No
-- application role gains anything.
--
-- A GRANT takes no table lock beyond a brief catalog update; `lock_timeout`
-- is set as in 158 all the same.
--
-- UNDO: `docs/runbooks/247-undo.sql`.

SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.claim_frames TO epigraph_maintenance';
    END IF;
END $$;

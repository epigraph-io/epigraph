-- Undo migration 247 (maintenance_delete_claim_frames): take back the
-- maintenance role's DELETE on `claim_frames`.
-- Run on the migration (superuser) DSN. Idempotent. Afterwards an un-mark
-- whose dedup repair bound a frame onto the canonical fails again on a
-- NOSUPERUSER maintenance login ("permission denied for table claim_frames")
-- and changes nothing; un-marks that bound no frame are unaffected.
-- 247's `_sqlx_migrations` row stays: re-granting is a NEW migration, never a
-- re-run of 247.
REVOKE DELETE ON public.claim_frames FROM epigraph_maintenance;

-- 006_provenance_patch_payload.sql (no-op marker; was internal 096)
--
-- The corresponding `ALTER TABLE provenance_log ADD COLUMN patch_payload JSONB`
-- from internal migration 096 is already absorbed into 001_initial_schema.sql:
-- the public.provenance_log CREATE TABLE in 001 includes the patch_payload
-- column directly. Re-applying the ALTER would error ("column already exists"),
-- so this migration is a no-op marker that preserves migration-sequence parity
-- with internal/096 without re-adding what 001 already provides.
SELECT 1;

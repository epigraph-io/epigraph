ALTER TABLE provenance_log ADD COLUMN patch_payload JSONB;
-- Nullable. Existing rows get NULL. All current append() callers are unaffected.

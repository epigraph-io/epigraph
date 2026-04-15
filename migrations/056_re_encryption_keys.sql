-- Proxy re-encryption keys for cross-group sharing
--
-- Evidence: Design spec §4 — re_encryption_keys table
-- Reasoning: PRE keys enable zero-knowledge cross-group claim sharing

CREATE TABLE re_encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    target_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    re_key BYTEA NOT NULL,
    source_epoch INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    UNIQUE(source_group_id, target_group_id, source_epoch)
);

CREATE INDEX idx_re_encryption_keys_source ON re_encryption_keys(source_group_id);
CREATE INDEX idx_re_encryption_keys_target ON re_encryption_keys(target_group_id);

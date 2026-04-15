CREATE TABLE IF NOT EXISTS claim_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    content TEXT NOT NULL,
    truth_value DOUBLE PRECISION NOT NULL,
    created_by UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(claim_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_claim_versions_claim ON claim_versions(claim_id);
CREATE INDEX IF NOT EXISTS idx_claim_versions_created ON claim_versions(created_at);

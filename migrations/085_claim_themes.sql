-- migrations/084_claim_themes.sql
-- Theme clusters for hierarchical retrieval (xMemory-inspired)
-- Each theme is a centroid with a label; claims are assigned to themes.

CREATE TABLE IF NOT EXISTS claim_themes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    centroid vector(1536),
    claim_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Many-to-one: each claim belongs to at most one theme
ALTER TABLE claims ADD COLUMN IF NOT EXISTS theme_id UUID REFERENCES claim_themes(id);

CREATE INDEX IF NOT EXISTS idx_claims_theme ON claims(theme_id);
CREATE INDEX IF NOT EXISTS idx_claim_themes_centroid
    ON claim_themes USING hnsw (centroid vector_cosine_ops)
    WITH (m = 16, ef_construction = 64)
    WHERE centroid IS NOT NULL;

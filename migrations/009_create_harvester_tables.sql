-- Migration: 009_create_harvester_tables
-- Description: Create tables for the Reflective Harvester subsystem
--
-- Evidence:
-- - HARVESTER_IMPLEMENTATION_PLAN.md §6.1 specifies schema
-- - HARDENING_PLAN.md §4.1 requires these tables
--
-- Reasoning:
-- - Five tables capture the full harvester pipeline: source → fragment → audit → claim provenance → concepts
-- - JSONB columns for flexible audit findings (schema varies by probe type)
-- - BYTEA for BLAKE3 content hashes (32 bytes, consistent with epigraph-crypto)
-- - VECTOR(1536) for enriched concept embeddings (OpenAI text-embedding-3-small dimension)

-- ==================== Source Documents ====================

CREATE TABLE IF NOT EXISTS harvester_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Content identity (BLAKE3 hash, 32 bytes)
    content_hash BYTEA NOT NULL UNIQUE,

    -- Source metadata
    filename TEXT,
    mime_type TEXT,
    file_size BIGINT,

    -- Processing modality
    modality TEXT NOT NULL,

    -- Pipeline status
    status TEXT NOT NULL DEFAULT 'pending',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT harvester_sources_modality_check CHECK (
        modality IN ('text', 'pdf', 'audio')
    ),
    CONSTRAINT harvester_sources_status_check CHECK (
        status IN ('pending', 'processing', 'completed', 'failed')
    ),
    CONSTRAINT harvester_sources_file_size_positive CHECK (
        file_size IS NULL OR file_size >= 0
    )
);

-- Deduplication lookup by content hash
CREATE INDEX IF NOT EXISTS idx_harvester_sources_hash
    ON harvester_sources (content_hash);

-- Status-based queue queries
CREATE INDEX IF NOT EXISTS idx_harvester_sources_status
    ON harvester_sources (status)
    WHERE status IN ('pending', 'processing');

-- ==================== Fragments ====================

CREATE TABLE IF NOT EXISTS harvester_fragments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Parent source document
    source_id UUID NOT NULL REFERENCES harvester_sources(id) ON DELETE CASCADE,

    -- Content identity (BLAKE3 hash, 32 bytes)
    content_hash BYTEA NOT NULL,

    -- Fragment content
    content_text TEXT NOT NULL,
    context_window TEXT,

    -- Position within source
    char_offset_start BIGINT,
    char_offset_end BIGINT,
    page_number INT,
    section_title TEXT,

    -- Pipeline status
    status TEXT NOT NULL DEFAULT 'pending',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT harvester_fragments_status_check CHECK (
        status IN ('pending', 'processing', 'completed', 'failed')
    ),
    CONSTRAINT harvester_fragments_offsets_valid CHECK (
        char_offset_start IS NULL OR char_offset_end IS NULL
        OR char_offset_end >= char_offset_start
    )
);

-- Lookup fragments by source
CREATE INDEX IF NOT EXISTS idx_harvester_fragments_source
    ON harvester_fragments (source_id);

-- Queue queries by status
CREATE INDEX IF NOT EXISTS idx_harvester_fragments_status
    ON harvester_fragments (status)
    WHERE status IN ('pending', 'processing');

-- ==================== Audit Reports ====================

CREATE TABLE IF NOT EXISTS harvester_audit_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Fragment this audit covers
    fragment_id UUID NOT NULL REFERENCES harvester_fragments(id) ON DELETE CASCADE,

    -- Extraction run identifier
    extraction_id UUID NOT NULL,

    -- Skeptic results
    skeptic_passed BOOLEAN,
    hallucinations_detected INT DEFAULT 0,
    skeptic_findings JSONB,

    -- Logician results
    logician_passed BOOLEAN,
    contradictions_found INT DEFAULT 0,
    logician_findings JSONB,

    -- Variance Probe results
    variance_passed BOOLEAN,
    similarity_score FLOAT,
    variance_report JSONB,

    -- Overall verdict
    final_confidence FLOAT,
    passed_audit BOOLEAN,
    attempts INT DEFAULT 1,

    -- Processing metadata
    model_used TEXT,
    token_usage JSONB,
    processing_time_ms INT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT harvester_audit_confidence_bounds CHECK (
        final_confidence IS NULL OR (final_confidence >= 0.0 AND final_confidence <= 1.0)
    ),
    CONSTRAINT harvester_audit_similarity_bounds CHECK (
        similarity_score IS NULL OR (similarity_score >= 0.0 AND similarity_score <= 1.0)
    ),
    CONSTRAINT harvester_audit_attempts_positive CHECK (
        attempts >= 1
    )
);

-- Lookup audits by fragment
CREATE INDEX IF NOT EXISTS idx_harvester_audit_fragment
    ON harvester_audit_reports (fragment_id);

-- Filter by audit outcome
CREATE INDEX IF NOT EXISTS idx_harvester_audit_passed
    ON harvester_audit_reports (passed_audit)
    WHERE passed_audit IS NOT NULL;

-- ==================== Claim Provenance ====================

CREATE TABLE IF NOT EXISTS harvester_claim_provenance (
    -- Links extracted claims back to their source fragments and audit reports
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    fragment_id UUID NOT NULL REFERENCES harvester_fragments(id) ON DELETE CASCADE,
    audit_report_id UUID REFERENCES harvester_audit_reports(id) ON DELETE SET NULL,

    -- Extraction confidence from the harvester pipeline
    extraction_confidence FLOAT,

    PRIMARY KEY (claim_id, fragment_id),

    -- Constraints
    CONSTRAINT harvester_provenance_confidence_bounds CHECK (
        extraction_confidence IS NULL
        OR (extraction_confidence >= 0.0 AND extraction_confidence <= 1.0)
    )
);

-- Lookup provenance by claim
CREATE INDEX IF NOT EXISTS idx_harvester_provenance_claim
    ON harvester_claim_provenance (claim_id);

-- Lookup provenance by fragment
CREATE INDEX IF NOT EXISTS idx_harvester_provenance_fragment
    ON harvester_claim_provenance (fragment_id);

-- ==================== Enriched Concepts ====================

CREATE TABLE IF NOT EXISTS harvester_enriched_concepts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Concept identity
    concept_name TEXT NOT NULL,
    canonical_name TEXT,

    -- Knowledge enrichment
    latent_definition TEXT,
    source_model TEXT,

    -- Embedding for semantic search (OpenAI text-embedding-3-small: 1536 dims)
    embedding VECTOR(1536),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup by concept name
CREATE INDEX IF NOT EXISTS idx_harvester_concepts_name
    ON harvester_enriched_concepts (concept_name);

-- Vector similarity search (IVFFlat for cosine similarity)
-- Note: IVFFlat requires at least one row before CREATE INDEX with lists parameter.
-- For initial deployment, use HNSW which works on empty tables.
CREATE INDEX IF NOT EXISTS idx_harvester_concepts_embedding
    ON harvester_enriched_concepts
    USING hnsw (embedding vector_cosine_ops);

-- ==================== Table Comments ====================

COMMENT ON TABLE harvester_sources IS 'Source documents submitted for harvester extraction';
COMMENT ON TABLE harvester_fragments IS 'Text fragments chunked from source documents';
COMMENT ON TABLE harvester_audit_reports IS 'Council of Critics audit results per fragment extraction';
COMMENT ON TABLE harvester_claim_provenance IS 'Links extracted claims to source fragments and audit trails';
COMMENT ON TABLE harvester_enriched_concepts IS 'Concepts enriched with latent knowledge and embeddings';

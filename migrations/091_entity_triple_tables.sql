-- 091_entity_triple_tables.sql
-- RDF-style entity/triple layer for structured claim queries.
-- Spec: docs/superpowers/specs/2026-04-08-rdf-triple-ner-knowledge-graph-design.md

-- Prerequisites
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ── entities ────────────────────────────────────────────────────────────
CREATE TABLE entities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name  TEXT NOT NULL,
    type_top        VARCHAR(50) NOT NULL,
    type_sub        TEXT,
    embedding       vector(1536),
    properties      JSONB NOT NULL DEFAULT '{}',
    is_canonical    BOOLEAN NOT NULL DEFAULT true,
    merged_into     UUID REFERENCES entities(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT entities_canonical_or_merged
        CHECK (is_canonical = true OR merged_into IS NOT NULL),
    CONSTRAINT entities_type_top_valid
        CHECK (type_top IN (
            'Material', 'Molecule', 'Method', 'Instrument', 'Property',
            'Measurement', 'Condition', 'Organism', 'Software',
            'Person', 'Organization', 'Location', 'Concept'
        ))
);

CREATE INDEX idx_entities_type_top ON entities(type_top);
CREATE INDEX idx_entities_canonical_name ON entities(canonical_name);
CREATE INDEX idx_entities_is_canonical ON entities(is_canonical) WHERE is_canonical = true;
CREATE INDEX idx_entities_merged_into ON entities(merged_into) WHERE merged_into IS NOT NULL;
CREATE UNIQUE INDEX idx_entities_canonical_pair
    ON entities(lower(canonical_name), type_top)
    WHERE is_canonical = true;
CREATE INDEX idx_entities_embedding_hnsw ON entities
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64)
    WHERE embedding IS NOT NULL;

-- ── entity_mentions ─────────────────────────────────────────────────────
CREATE TABLE entity_mentions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id       UUID NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
    claim_id        UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    surface_form    TEXT NOT NULL,
    mention_role    VARCHAR(20) NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL,
    extractor       VARCHAR(50) NOT NULL,
    span_start      INT,
    span_end        INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT entity_mentions_role_valid
        CHECK (mention_role IN ('subject', 'object', 'modifier'))
);

CREATE INDEX idx_entity_mentions_entity_id ON entity_mentions(entity_id);
CREATE INDEX idx_entity_mentions_claim_id ON entity_mentions(claim_id);
CREATE INDEX idx_entity_mentions_entity_claim ON entity_mentions(entity_id, claim_id);

-- ── triples ─────────────────────────────────────────────────────────────
CREATE TABLE triples (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id        UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    subject_id      UUID NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
    predicate       TEXT NOT NULL,
    object_id       UUID REFERENCES entities(id) ON DELETE RESTRICT,
    object_literal  TEXT,
    confidence      DOUBLE PRECISION NOT NULL,
    extractor       VARCHAR(50) NOT NULL,
    properties      JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT triples_has_object
        CHECK (object_id IS NOT NULL OR object_literal IS NOT NULL)
);

CREATE INDEX idx_triples_subject_id ON triples(subject_id);
CREATE INDEX idx_triples_object_id ON triples(object_id) WHERE object_id IS NOT NULL;
CREATE INDEX idx_triples_claim_id ON triples(claim_id);
CREATE INDEX idx_triples_subject_predicate ON triples(subject_id, predicate);
CREATE INDEX idx_triples_predicate_trgm ON triples USING gist (predicate gist_trgm_ops);

-- ── entity_merge_candidates ─────────────────────────────────────────────
CREATE TABLE entity_merge_candidates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_a            UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    entity_b            UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    score               DOUBLE PRECISION NOT NULL,
    auto_threshold_used DOUBLE PRECISION NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    reviewed_by         VARCHAR(100),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT merge_candidates_ordered CHECK (entity_a < entity_b),
    CONSTRAINT merge_candidates_status_valid
        CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT merge_candidates_unique_pair UNIQUE (entity_a, entity_b)
);

CREATE INDEX idx_merge_candidates_status ON entity_merge_candidates(status)
    WHERE status = 'pending';

-- Migration 034: Entity extraction experiment tables
--
-- Isolated experiment schema for comparing structured entity/triple retrieval
-- against pure embedding-based semantic search on ~500-1000 DNA origami atoms.
-- All tables prefixed experiment_ to avoid production namespace collision.

-- Canonical entities extracted from atomic claims
CREATE TABLE experiment_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name TEXT NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    aliases TEXT[] DEFAULT '{}',
    embedding vector(1536),
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX idx_experiment_entities_name_type
    ON experiment_entities (lower(canonical_name), entity_type);

CREATE INDEX idx_experiment_entities_type
    ON experiment_entities (entity_type);

-- Surface-form mentions linking entities to claims
CREATE TABLE experiment_entity_mentions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL REFERENCES experiment_entities(id) ON DELETE CASCADE,
    surface_form TEXT NOT NULL,
    mention_role VARCHAR(20) NOT NULL DEFAULT 'context',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_experiment_mentions_claim
    ON experiment_entity_mentions (claim_id);

CREATE INDEX idx_experiment_mentions_entity
    ON experiment_entity_mentions (entity_id);

-- Structured subject-predicate-object triples extracted from claims
CREATE TABLE experiment_triples (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    subject_entity_id UUID NOT NULL REFERENCES experiment_entities(id) ON DELETE CASCADE,
    predicate TEXT NOT NULL,
    object_entity_id UUID NOT NULL REFERENCES experiment_entities(id) ON DELETE CASCADE,
    context_entity_ids UUID[] DEFAULT '{}',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_experiment_triples_claim
    ON experiment_triples (claim_id);

CREATE INDEX idx_experiment_triples_subject
    ON experiment_triples (subject_entity_id);

CREATE INDEX idx_experiment_triples_object
    ON experiment_triples (object_entity_id);

CREATE INDEX idx_experiment_triples_predicate
    ON experiment_triples (predicate);

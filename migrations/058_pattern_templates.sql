-- Pattern templates for structural isomorphism detection
--
-- Evidence: Design spec §6 — pattern_templates table + seed patterns
-- Reasoning: Known subgraph structures enable cross-domain analogy and propaganda detection

CREATE TABLE pattern_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    skeleton JSONB NOT NULL,
    min_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.7,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pattern_templates_category ON pattern_templates(category);

-- Seed patterns
INSERT INTO pattern_templates (name, category, description, skeleton, min_confidence) VALUES
(
    'Card Stacking',
    'propaganda',
    'Single source with 3+ supports edges and no incoming contradicts. Indicates one-sided evidence presentation.',
    '{"nodes": ["src", "t1", "t2", "t3"], "edges": [{"source": "src", "target": "t1", "relationship": "supports"}, {"source": "src", "target": "t2", "relationship": "supports"}, {"source": "src", "target": "t3", "relationship": "supports"}]}',
    0.7
),
(
    'Circular Reasoning',
    'fallacy',
    '3-node cycle with asserts/supports edges. Will only match external/imported graphs (EpiGraph enforces DAG internally).',
    '{"nodes": ["a", "b", "c"], "edges": [{"source": "a", "target": "b", "relationship": "asserts"}, {"source": "b", "target": "c", "relationship": "supports"}, {"source": "c", "target": "a", "relationship": "asserts"}]}',
    0.8
),
(
    'Contradiction Triangle',
    'fallacy',
    '3 nodes with mutual contradicts edges indicating logical inconsistency.',
    '{"nodes": ["a", "b", "c"], "edges": [{"source": "a", "target": "b", "relationship": "contradicts"}, {"source": "b", "target": "c", "relationship": "contradicts"}, {"source": "a", "target": "c", "relationship": "contradicts"}]}',
    0.8
),
(
    'Authority Cascade',
    'propaganda',
    'High-truth node chains through supports edges with no independent evidence paths.',
    '{"nodes": ["auth", "c1", "c2", "c3"], "edges": [{"source": "auth", "target": "c1", "relationship": "supports"}, {"source": "c1", "target": "c2", "relationship": "supports"}, {"source": "c2", "target": "c3", "relationship": "supports"}]}',
    0.7
);

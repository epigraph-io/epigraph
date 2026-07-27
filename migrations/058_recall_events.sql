-- Recall audit log (backlog 8cbffa0e / design F5).
--
-- EpiGraph records rich claim provenance (PROV-O export PR #334, supersede /
-- decomposes_to lineage) but keeps NO record of which claims a given agent
-- query actually retrieved. That gap makes post-hoc audit impossible:
-- embedding-based retrieval is not reproducible across embedder revisions, so
-- re-running a query is not evidence of what it originally returned.
--
-- MOSS (arXiv:2607.04391) adopts embedding-free symbolic memory explicitly to
-- get this guarantee; SelfMem (arXiv:2607.03726) preserves the raw transcript
-- as an immutable source of truth for the same reason. Logging the query and
-- its result set gives EpiGraph the audit property without giving up ANN
-- retrieval.
--
-- query_embedding_hash is BLAKE3 over the pgvector literal, NOT the vector
-- itself: storing raw vectors costs ~16x the row size and buys no additional
-- audit power. The hash is what discriminates the two failure modes —
--   same query text + same hash + different returned_claim_ids => corpus changed
--   same query text + different hash                           => embedder changed

CREATE TABLE IF NOT EXISTS recall_events (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Nullable: unauthenticated / library-level recall paths have no agent.
    agent_id             UUID REFERENCES agents(id) ON DELETE SET NULL,
    tool                 TEXT NOT NULL,
    query_text           TEXT NOT NULL,
    query_embedding_hash BYTEA,
    params               JSONB NOT NULL DEFAULT '{}'::jsonb,
    returned_claim_ids   UUID[] NOT NULL DEFAULT ARRAY[]::UUID[],
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recall_events_agent_time
    ON recall_events (agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_recall_events_time
    ON recall_events (created_at DESC);

-- Answers "which queries ever surfaced this claim?" via `returned_claim_ids @>
-- ARRAY[$claim_id]`.
CREATE INDEX IF NOT EXISTS idx_recall_events_claims
    ON recall_events USING GIN (returned_claim_ids);

COMMENT ON TABLE recall_events IS
    'Audit log of recall queries and the claims they returned (backlog 8cbffa0e). '
    'Written fire-and-forget after the response is built; never blocks a recall. '
    'Retention is enforced by the daily reconciler (RECALL_EVENTS_RETENTION_DAYS, default 90).';

COMMENT ON COLUMN recall_events.query_embedding_hash IS
    'BLAKE3 of the pgvector literal used for the dense leg; NULL when the embedder '
    'was unavailable and the query degraded to lexical-only. Distinguishes a corpus '
    'change from an embedder change when auditing a non-reproducible result.';

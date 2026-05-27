-- Add goal_embedding to workflows table for semantic-similarity search.
--
-- find_workflow_hierarchical previously matched goal text via single ILIKE
-- substring match. Any punctuation, word-order, or paraphrase difference
-- between the caller's query string and the stored goal returned zero hits,
-- defeating cron tasks that called the tool with the exact bootstrap goal
-- text. Adding goal_embedding lets the MCP tool route through the existing
-- OpenAI embedding service (text-embedding-3-small, 1536-dim) for cosine
-- similarity search — same pattern flat find_workflow already uses on
-- claims.embedding. ILIKE remains as fallback when no embedder is available
-- or when goal_embedding has not been backfilled.

ALTER TABLE workflows ADD COLUMN IF NOT EXISTS goal_embedding vector(1536);

-- ivfflat index for cosine distance lookups. lists=10 chosen for the
-- current ~200-row workflows table (rule of thumb: lists = rows^0.5 / 2).
-- Re-tune via REINDEX with WITH (lists = N) when the table crosses ~5k rows.
CREATE INDEX IF NOT EXISTS idx_workflows_goal_embedding
    ON workflows
    USING ivfflat (goal_embedding vector_cosine_ops)
    WITH (lists = 10);

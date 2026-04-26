-- Behavioral execution tracking for task-conditional workflow scoring.
-- Stores per-execution data with goal embeddings so the agent can
-- answer "which workflow works best for goals like THIS one?"
-- Distinct from workflow_executions (080) which tracks orchestrator state.

CREATE TABLE IF NOT EXISTS behavioral_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    goal_text TEXT NOT NULL,
    goal_embedding vector(1536),
    success BOOLEAN NOT NULL,
    step_beliefs JSONB NOT NULL DEFAULT '{}',
    tool_pattern TEXT[] NOT NULL DEFAULT '{}',
    quality DOUBLE PRECISION CHECK (quality IS NULL OR (quality >= 0.0 AND quality <= 1.0)),
    deviation_count INTEGER NOT NULL DEFAULT 0,
    total_steps INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_behav_exec_workflow ON behavioral_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_behav_exec_created ON behavioral_executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behav_exec_success ON behavioral_executions(success);
CREATE INDEX IF NOT EXISTS idx_behav_exec_goal_vec ON behavioral_executions
    USING hnsw (goal_embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

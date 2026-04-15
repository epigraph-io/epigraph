-- Track workflow execution instances
CREATE TABLE IF NOT EXISTS workflow_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state VARCHAR(50) NOT NULL DEFAULT 'created',
    created_by UUID NOT NULL REFERENCES agents(id),
    task_count INTEGER NOT NULL DEFAULT 0,
    tasks_completed INTEGER NOT NULL DEFAULT 0,
    tasks_failed INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_wf_exec_state ON workflow_executions(state);
CREATE INDEX IF NOT EXISTS idx_wf_exec_creator ON workflow_executions(created_by);

-- Add FK from tasks to workflow_executions
ALTER TABLE tasks ADD CONSTRAINT fk_tasks_workflow
    FOREIGN KEY (workflow_id) REFERENCES workflow_executions(id) ON DELETE CASCADE;

-- Persistent task storage for the orchestration engine
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    description TEXT NOT NULL,
    task_type VARCHAR(100) NOT NULL,
    input JSONB NOT NULL DEFAULT '{}',
    output_schema JSONB,
    assigned_agent UUID REFERENCES agents(id),
    priority INTEGER NOT NULL DEFAULT 0,
    state VARCHAR(50) NOT NULL DEFAULT 'created',
    parent_task_id UUID REFERENCES tasks(id),
    workflow_id UUID,
    timeout_seconds INTEGER,
    retry_max INTEGER NOT NULL DEFAULT 3,
    retry_count INTEGER NOT NULL DEFAULT 0,
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_agent);
CREATE INDEX IF NOT EXISTS idx_tasks_workflow ON tasks(workflow_id);
CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_tasks_type ON tasks(task_type);

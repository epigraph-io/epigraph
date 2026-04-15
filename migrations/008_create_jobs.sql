-- Migration: 008_create_jobs
-- Description: Create jobs table for persistent job queue
--
-- This table stores background jobs with JSONB payloads and supports
-- concurrent dequeuing using FOR UPDATE SKIP LOCKED.

-- Create jobs table
CREATE TABLE IF NOT EXISTS jobs (
    -- Primary key: UUID for globally unique job identification
    id UUID PRIMARY KEY,

    -- Job type: String identifier for routing to handlers
    -- Examples: "truth_propagation", "embedding_generation"
    job_type VARCHAR(255) NOT NULL,

    -- Job payload: JSONB for flexible, queryable payloads
    payload JSONB NOT NULL DEFAULT '{}',

    -- Job state: String enum for state machine
    -- Valid values: pending, running, completed, failed, cancelled
    state VARCHAR(50) NOT NULL DEFAULT 'pending',

    -- Retry tracking
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,      -- Set when job transitions to running
    completed_at TIMESTAMPTZ,    -- Set when job transitions to completed/failed/cancelled

    -- Error tracking
    error_message TEXT,

    -- Constraints
    CONSTRAINT jobs_state_check CHECK (
        state IN ('pending', 'running', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT jobs_retry_count_non_negative CHECK (retry_count >= 0),
    CONSTRAINT jobs_max_retries_non_negative CHECK (max_retries >= 0)
);

-- Index for efficient pending job lookup (most common query)
-- Used by dequeue() with ORDER BY created_at
CREATE INDEX IF NOT EXISTS idx_jobs_pending_created
    ON jobs (created_at ASC)
    WHERE state = 'pending';

-- Index for job state queries (monitoring, counts)
CREATE INDEX IF NOT EXISTS idx_jobs_state
    ON jobs (state);

-- Index for job type queries (useful for metrics per job type)
CREATE INDEX IF NOT EXISTS idx_jobs_type
    ON jobs (job_type);

-- Index for cleanup queries (completed_at for old job deletion)
CREATE INDEX IF NOT EXISTS idx_jobs_completed_at
    ON jobs (completed_at)
    WHERE state IN ('completed', 'failed');

-- Index for stale job recovery (running jobs by started_at)
CREATE INDEX IF NOT EXISTS idx_jobs_running_started
    ON jobs (started_at)
    WHERE state = 'running';

-- Comment on table and columns for documentation
COMMENT ON TABLE jobs IS 'Background job queue with persistent storage';
COMMENT ON COLUMN jobs.id IS 'Unique job identifier (UUID v4)';
COMMENT ON COLUMN jobs.job_type IS 'Job type for routing to handlers';
COMMENT ON COLUMN jobs.payload IS 'JSONB payload with job-specific data';
COMMENT ON COLUMN jobs.state IS 'Job state: pending, running, completed, failed, cancelled';
COMMENT ON COLUMN jobs.retry_count IS 'Number of retry attempts made';
COMMENT ON COLUMN jobs.max_retries IS 'Maximum allowed retry attempts';
COMMENT ON COLUMN jobs.started_at IS 'Timestamp when job started running';
COMMENT ON COLUMN jobs.completed_at IS 'Timestamp when job finished (success or failure)';
COMMENT ON COLUMN jobs.error_message IS 'Error message if job failed';

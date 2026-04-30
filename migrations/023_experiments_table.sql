-- Migration 023: add experiments and experiment_results tables
--
-- These tables were created directly on the live database before the migration
-- system was used to track them, leaving a gap that caused every integration
-- test to fail with "relation 'experiments' does not exist" when any edge
-- insert fired validate_edge_reference (which evaluates all CASE branches).
-- Migration 019 and 020 reference experiments/experiment_results in trigger
-- functions; this migration closes the gap so migration-based test DBs have
-- the full schema.
--
-- All DDL uses IF NOT EXISTS / ON CONFLICT DO NOTHING so this is a no-op
-- on live DBs that already have the tables.

CREATE TABLE IF NOT EXISTS experiments (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hypothesis_id   uuid NOT NULL REFERENCES claims(id),
    created_by      uuid NOT NULL REFERENCES agents(id),
    method_ids      uuid[],
    protocol        text,
    protocol_source jsonb,
    status          varchar(20) NOT NULL DEFAULT 'designed'
                    CHECK (status IN ('designed','running','collecting','analyzing','complete','failed')),
    started_at      timestamptz,
    completed_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_experiments_hypothesis  ON experiments (hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_experiments_created_by  ON experiments (created_by);
CREATE INDEX IF NOT EXISTS idx_experiments_status      ON experiments (status);

CREATE TABLE IF NOT EXISTS experiment_results (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id          uuid NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    data_source            text NOT NULL
                           CHECK (data_source IN ('manual','simulation','instrument','literature','computed')),
    raw_measurements       jsonb NOT NULL DEFAULT '[]'::jsonb,
    measurement_count      integer NOT NULL DEFAULT 0,
    effective_random_error jsonb,
    processed_data         jsonb,
    status                 varchar(20) NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','processing','complete','error')),
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_experiment_results_experiment ON experiment_results (experiment_id);
CREATE INDEX IF NOT EXISTS idx_experiment_results_status     ON experiment_results (status);

-- cascade_delete_edges trigger for experiments (removes edges when an
-- experiment row is deleted, matching the pattern used by papers/analyses).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'experiments_cascade_edges'
          AND tgrelid = 'experiments'::regclass
    ) THEN
        CREATE TRIGGER experiments_cascade_edges
            BEFORE DELETE ON experiments
            FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('experiment');
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'experiment_results_cascade_edges'
          AND tgrelid = 'experiment_results'::regclass
    ) THEN
        CREATE TRIGGER experiment_results_cascade_edges
            BEFORE DELETE ON experiment_results
            FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('experiment_result');
    END IF;
END;
$$;

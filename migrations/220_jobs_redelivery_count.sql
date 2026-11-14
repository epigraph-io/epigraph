-- 220_jobs_redelivery_count.sql
-- Bound the crash re-delivery of a one-attempt job (backlog 1320b4e3).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- The drain timer's reaper (`PostgresJobQueue::reap_stale_jobs_counting_attempts`)
-- resets a job still `running` past the stale bound. For a row with a retry
-- budget (`max_retries > 1`) the reap COUNTS as a used attempt, so a job killed
-- on every run ends at its budget. A ONE-attempt row (`max_retries <= 1`: the
-- privatization apply, revert and reseal jobs) cannot be counted that way: a
-- counted reap computes `0 + 1 >= 1` and fails the job before its handler ever
-- runs. So the reaper resets those rows WITHOUT counting, and a one-attempt job
-- that crashes (or is killed by the unit's start timeout) on every run is
-- re-delivered on every run, for ever, and the queue behind it starves.
--
-- `retry_count` cannot carry the bound: it is the handler-error budget the
-- runners compare with `max_retries`, and bumping it on a crash is exactly the
-- counted reap that fails a one-attempt job unrun. So the crash re-deliveries
-- get their own counter.
--
-- ===================================================================
-- 1. THE COLUMN
-- ===================================================================
--
--   jobs.redelivery_count integer NOT NULL DEFAULT 0, CHECK (>= 0)
--
-- Written only by the reaper, on an UNCOUNTED reset: it bumps the counter,
-- and the reap that would take it past `epigraph_jobs::MAX_CRASH_REDELIVERIES`
-- fails the row instead, with its own `error_message`
-- (`REAPED_REDELIVERIES_SPENT_MESSAGE`), so a crash loop is told apart from a
-- spent attempt budget. A counted reset (`max_retries > 1`) leaves it alone.
-- The handlers, the runners and `JobQueue::update` never read or write it, so
-- a row's other columns mean what they meant before.
--
-- A constant DEFAULT makes the ADD COLUMN a catalog change; the CHECK scans
-- `jobs` once to validate, which is a small table (completed and failed rows
-- are pruned). No grant or policy changes: `jobs` carries table-level grants
-- and 119's bypass-only `jobs_app` policy, which cover a new column.
--
-- ===================================================================
-- 2. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- MIGRATE BEFORE rolling out a `drain_jobs` built with the bounded reaper: its
-- reaper names `redelivery_count`, and on a database below 220 every run fails
-- at its first statement (42703, undefined column) and drains nothing. An
-- older `drain_jobs` ignores the column. Undo (`docs/runbooks/220-undo.sql`)
-- only after rolling every such binary back; it loses the counts, which is
-- harmless (an older reaper never bounded re-delivery).
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.jobs
    ADD COLUMN redelivery_count integer NOT NULL DEFAULT 0
        CONSTRAINT jobs_redelivery_count_non_negative CHECK (redelivery_count >= 0);

COMMENT ON COLUMN public.jobs.redelivery_count IS
    'Crash re-deliveries of a one-attempt job (max_retries <= 1), counted by the drain''s '
    'stale-job reaper on each uncounted reset; the reap past MAX_CRASH_REDELIVERIES fails the '
    'row (migration 220, backlog 1320b4e3).';

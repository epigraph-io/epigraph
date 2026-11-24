-- 261_jobs_run_after.sql
-- The drain honours a handler's retry backoff (backlog 6cf042a9).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- `JobHandler::backoff(attempt)` declares how long a job must wait before its
-- next attempt after a retryable failure. The in-process `JobRunner` worker
-- loop honours it by sleeping before it re-enqueues. Since operator decision
-- D9 the queue is drained by the `drain_jobs` timer binary instead, and the
-- drain put a retryable failure straight back to `pending` with no record of
-- when it may run again, so the NEXT drain run claimed it whatever the
-- handler's backoff said. A handler that backs off exponentially (for example
-- against a rate-limited provider) was retried at the timer's cadence and could
-- spend its whole retry budget inside one provider outage.
--
-- ===================================================================
-- 1. THE COLUMN
-- ===================================================================
--
--   jobs.run_after timestamptz NULL
--
-- The earliest time the row may be claimed. NULL (every existing row, and
-- every row any enqueuer writes) means "due now". Written only by the drain,
-- on a retryable failure (`PostgresJobQueue::requeue_after`): `now() +
-- handler.backoff(retry_count - 1)`, computed on the database clock, which is
-- the clock the claim compares against. Read by the claims
-- (`PostgresJobQueue::dequeue_of_types`, `JobQueue::dequeue`) and by
-- `count_pending_of_types`, which skip a pending row whose time has not come.
-- A deferred row is still `pending`: it still blocks `enqueue_job --unique`,
-- is still counted by the monitoring reads, and `--cancel-pending` still
-- cancels it.
--
-- Nullable with no default and no CHECK, so the ADD COLUMN is a catalog
-- change only: no table rewrite and no scan, only a brief ACCESS EXCLUSIVE
-- lock, which the 3 s `lock_timeout` refuses rather than queue behind. No
-- index: every reader already filters on `state = 'pending'`, and the pending
-- set is small. No grant or policy changes: `jobs` carries table-level grants
-- and 119's bypass-only `jobs_app` policy, which cover a new column.
--
-- ===================================================================
-- 2. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- MIGRATE BEFORE rolling out a `drain_jobs` built with this change: its claim
-- names `run_after`, and on a database below 261 every run fails at its first
-- claim (42703, undefined column) and drains nothing. An older `drain_jobs`
-- ignores the column (it neither writes nor reads it, so on rollback any
-- deferred row becomes due at once, which is the old behaviour). Undo
-- (`docs/runbooks/261-undo.sql`) only after rolling every such binary back.
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.jobs
    ADD COLUMN run_after timestamptz;

COMMENT ON COLUMN public.jobs.run_after IS
    'Earliest time a pending job may be claimed; NULL means due now. Set by the drain on a '
    'retryable failure to now() + the handler''s backoff (migration 261, backlog 6cf042a9).';

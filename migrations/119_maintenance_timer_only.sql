-- 119: the maintenance DSN lives only in timers and operator CLIs (batch W12a,
-- operator decision D9).
--
-- ===================================================================
-- 0. WHAT THIS FILE CHANGES, AND WHY
-- ===================================================================
--
-- After D9 no request-serving process (`server`, `epigraph-mcp-full` on any
-- transport) holds a maintenance connection. The two things those processes
-- used one for move to privileged, scheduled binaries that run as a
-- non-superuser LOGIN in `epigraph_maintenance`:
--
--   * the administrative cascade replay (`replay_deferred_cascades`, 117);
--   * the job queue (`drain_jobs`, new in this batch), which used to run as an
--     in-process `JobRunner` inside `server`.
--
-- Two database changes follow from that move, and nothing else:
--
--   (1) GRANTS. The job handlers DELETE from the queue and from their own
--       materializations: `PostgresJobQueue::cleanup_old_jobs` (`jobs`), the
--       graph clustering runner's retention sweep (`graph_cluster_runs`,
--       `graph_clusters`, `cluster_edges`, `claim_cluster_membership`) and the
--       theme rebuild (`claim_themes`). 070 gave `epigraph_maintenance`
--       SELECT/INSERT/UPDATE and no DELETE on them, which was invisible while
--       the queue ran on whatever DSN `server` had (a superuser in every
--       deployment so far). On a non-superuser maintenance login every
--       clustering job would stop at its first DELETE. Rows a foreign key
--       removes by referential action need no grant (the action runs as the
--       table owner), so the list is exactly the tables a handler names in a
--       DELETE statement. `claim_encryption` and the other sealed-content
--       tables are deliberately NOT granted: deleting ciphertext is the
--       privatization lifecycle's decision, and that lifecycle is not served
--       under D9 until it has its own design.
--
--   (2) `jobs_app`. 077's WITH CHECK let any non-privileged session enqueue
--       any job type except the three privatization types (a denylist). After
--       D9 the consumer of `jobs` is a privileged timer, so an application
--       session that can enqueue is an application session that can schedule
--       work to run with maintenance authority. No application-role enqueuer
--       exists: the only producers are the privatization lifecycle (on a
--       maintenance transaction) and the theme rebuild's follow-up (inside a
--       job, on the drain's own connection). So the allowlist is EMPTY: only a
--       privileged session (`epigraph_bypass()`) or a definer
--       (`epigraph_definer_bypass()`) may insert or update a job row. Adding a
--       job type an application session may enqueue is a reviewed migration.
--       USING is unchanged (bypass-only, as 077 wrote it).
--
-- DEPLOY ORDER: apply 119 together with the binaries built with it (the batch
-- W12a runbook). A pre-W12a `server` that still runs its own job runner on a
-- superuser DSN keeps working against 119 (a superuser bypasses both); on a
-- maintenance login it would now succeed where it used to fail, which is the
-- point of (1).
--
-- LOCK BUDGET: policy DDL on `jobs` takes a short ACCESS EXCLUSIVE lock; the
-- grants take none that matter. `lock_timeout` bounds the wait so a busy queue
-- makes this migration fail fast (re-run it) instead of queueing every job
-- behind it.
--
-- Undo: restore 077's `jobs_app` (DROP POLICY IF EXISTS jobs_app ON
-- public.jobs; CREATE POLICY jobs_app ... WITH CHECK (bypass OR definer_bypass
-- OR job_type NOT IN ('privatization_apply','privatization_revert',
-- 'privatization_reseal')), USING unchanged). Optionally REVOKE the DELETE
-- grants below, but only after the drain timer is disabled: a drain on a
-- maintenance login needs them.
-- Checked before claiming: no `origin/*` ref and no local worktree carries a
-- `119`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. DELETE for the maintenance role on the queue and the job-owned
--    materializations
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.jobs, public.graph_cluster_runs, '
                'public.graph_clusters, public.cluster_edges, '
                'public.claim_cluster_membership, public.claim_themes '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 2. jobs_app: no application-role enqueue
-- ===================================================================
DROP POLICY IF EXISTS jobs_app ON public.jobs;
CREATE POLICY jobs_app ON public.jobs FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

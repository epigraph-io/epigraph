-- no-transaction
--
-- Operator ruling C2 (spec docs/superpowers/specs/
-- 2026-11-24-human-identity-visibility-design.md, sections 4, 11 and 16.R):
-- a countersigned authorship of a paper the viewer can read names the human,
-- from the countersigning agent's binding start (C5). The act's time and actor
-- are recorded only in its audit row: 208's `epigraph_countersign_authorship`
-- writes one `security_events` row per act (`event_type =
-- 'authorship.countersigned'`, `agent_id` = the caller, `details.paper_id`),
-- and 208's RESTRICTIVE insert policy reserves that event type to bypass and
-- definer frames with `created_at = now()`. The edge's
-- `epigraph:countersigned_by:<uuid>` label carries no time. 299's arm probes,
-- once per agent bound to H, `s.agent_id = b.agent_id AND s.event_type =
-- 'authorship.countersigned' AND s.created_at >= b.since`.
--
-- 001's `idx_security_events_agent (agent_id)` would walk every event of the
-- agent; this partial index holds only countersign acts.
--
-- INVALID-INDEX TRAP: a cancelled or failed CONCURRENTLY build leaves an
-- INVALID index of this name, and IF NOT EXISTS then skips it on a re-run.
-- Recovery: DROP INDEX CONCURRENTLY idx_security_events_countersigned, re-apply.
--
-- Exactly one statement (see 277).
-- Undo: DROP INDEX CONCURRENTLY IF EXISTS public.idx_security_events_countersigned
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_countersigned
    ON public.security_events (agent_id, created_at)
    WHERE event_type = 'authorship.countersigned';

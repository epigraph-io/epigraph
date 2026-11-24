-- no-transaction
--
-- Operator ruling C6 (spec docs/superpowers/specs/
-- 2026-11-24-human-identity-visibility-design.md, sections 4, 11 and 16.R):
-- a PUBLIC ingest record (`paper -ingested_claim-> claim`, written only by the
-- document walk, `epigraph_db::ClaimIngestRepository`) names the human its
-- ingesting agent is bound to, from that agent's binding start (C5). The record
-- names its ingester in `properties.ingested_by`, a uuid string; there is no
-- column. 295's arm probes, once per agent bound to H,
-- `(r.properties ->> 'ingested_by') = b.agent_id::text AND r.relationship =
-- 'ingested_claim' AND r.visibility = 'public' AND r.created_at >= b.since`.
--
-- An expression index on exactly that expression, partial on the records'
-- relationship and the public predicate, so each probe is one descent and the
-- index holds only public ingest records (one per paper, claim and ingester).
-- The expression and the predicate are written exactly as the arm writes them
-- (the planner matches both syntactically).
--
-- INVALID-INDEX TRAP: a cancelled or failed CONCURRENTLY build leaves an
-- INVALID index of this name, and IF NOT EXISTS then skips it on a re-run.
-- Recovery: DROP INDEX CONCURRENTLY idx_edges_public_ingest_records_by_ingester,
-- re-apply.
--
-- Exactly one statement (see 275).
-- Undo: DROP INDEX CONCURRENTLY IF EXISTS public.idx_edges_public_ingest_records_by_ingester
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_public_ingest_records_by_ingester
    ON public.edges ((properties ->> 'ingested_by'), created_at)
    WHERE relationship = 'ingested_claim' AND visibility = 'public';

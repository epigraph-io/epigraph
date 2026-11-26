-- no-transaction
--
-- 337's ingest-record probe (operator ruling C6; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 6.1 and 11.1): `public.epigraph_ingest_record_ingester(r.properties)
-- = b.agent_text AND r.relationship = 'ingested_claim' AND r.visibility =
-- 'public' AND r.created_at >= b.since`, once per agent bound to H. Indexed on
-- 335's LEAKPROOF accessor, so the probe is an index condition under edges'
-- row security in the core's definer frame (331's index on the bare `->>`
-- never was; 338 drops it). The expression and the predicate are written
-- exactly as the arm writes them.
--
-- INVALID-INDEX TRAP: a cancelled or failed CONCURRENTLY build leaves an
-- INVALID index of this name, and IF NOT EXISTS then skips it on a re-run.
-- Recovery: DROP INDEX CONCURRENTLY idx_edges_public_ingest_records_by_ingester_lp,
-- re-apply.
--
-- Exactly one statement (see 312).
-- Undo: DROP INDEX CONCURRENTLY IF EXISTS public.idx_edges_public_ingest_records_by_ingester_lp
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_public_ingest_records_by_ingester_lp
    ON public.edges (public.epigraph_ingest_record_ingester(properties), created_at)
    WHERE relationship = 'ingested_claim' AND visibility = 'public';

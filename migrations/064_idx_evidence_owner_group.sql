-- no-transaction
-- One statement per file: see the header of 063 for why (sqlx sends the whole
-- file as one simple query; a multi-statement simple query is an implicit
-- transaction block and CREATE INDEX CONCURRENTLY raises 25001 inside one).
-- Covers the MINORITY partition, so disk and insert cost scale with how much
-- of the graph admins have actually privatized (D4), not with the corpus.
--
-- SERVES AN EXPLICIT visibility QUAL, not the D3 read predicate. See 063's
-- header for the measurement: `(visibility = 'public' OR owner_group_id =
-- ANY($V))` implies neither disjunct and gets a Seq Scan on any of these three
-- indexes. What reaches this index is the D4 admin/privatization surface
-- (PR-18) and group-scoped listings, which spell `visibility` explicitly.
-- `<> 'public'` is the dominant spelling and is shared verbatim with 063/065.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_owner_group
    ON public.evidence (owner_group_id) WHERE visibility <> 'public';

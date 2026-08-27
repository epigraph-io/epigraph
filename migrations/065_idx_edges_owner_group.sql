-- no-transaction
-- One statement per file: see 063's header.
-- Serves an EXPLICIT visibility qual (D4 admin surface, PR-18 privatization
-- plans), not the D3 read predicate -- see 063's header for the measurement.
-- Predicate spelled `<> 'public'`, identically to 063 and 064.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_owner_group
    ON public.edges (owner_group_id) WHERE visibility <> 'public';

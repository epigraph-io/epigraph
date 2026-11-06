-- no-transaction
--
-- Backlog 57917c13 (Atlas P3a): GET /api/v1/graph/themes/overview counts, per
-- theme, the CURRENT claims the caller can read, in one GROUP BY theme_id
-- pass (ClaimThemeRepository::overview_page). Every column any qual on that
-- pass touches is in this index: theme_id (key), is_current (partial
-- predicate), visibility and owner_group_id (INCLUDE; the in-query $V
-- predicate and claims_tenancy's USING both read only these), so the pass can
-- be an index-only scan on all-visible pages.
--
-- Why no existing index serves it: idx_claims_theme (theme_id) needs a heap
-- fetch per themed claim to read the other three columns, and
-- idx_claims_group_current (063) is partial on visibility <> 'public', which
-- the read predicate `(visibility = 'public' OR owner_group_id = ANY($V))`
-- does not imply (063's header explains why `A OR B` implies neither disjunct).
--
-- The predicate is `is_current`, not `COALESCE(is_current, true)`: the column
-- is NOT NULL (001_initial_schema.sql), and the planner proves partial-index
-- implication syntactically, so overview_page writes the bare form to match.
--
-- One statement, by rule (tenancy_migration_shape.rs::
-- no_transaction_files_contain_exactly_one_statement; see 063's header).
-- A failure leaves an INVALID index: DROP INDEX it and re-run (IF NOT EXISTS).
-- Undo (nothing reads the index by name):
--   DROP INDEX CONCURRENTLY IF EXISTS public.idx_claims_theme_current_tenancy
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_theme_current_tenancy
    ON public.claims (theme_id) INCLUDE (visibility, owner_group_id)
    WHERE theme_id IS NOT NULL AND is_current;

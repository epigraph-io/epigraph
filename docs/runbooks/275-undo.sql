-- Undo migration 275 (membership_helper_row_estimates): put epigraph_operator_actor
-- back on PostgreSQL's default set-returning estimate. Run on a maintenance (or
-- migrating) connection. Idempotent. No body, owner, ACL or search_path changes.
-- After it, the membership resolve plans above jit_above_cost again on a
-- production-sized database (backlog 8377cf18); set `jit = off` first if JIT is on.
-- It leaves 275's `_sqlx_migrations` row, so a later `migrate` run does NOT
-- re-apply `ROWS 1`; re-introducing the estimate is a NEW migration, never a
-- re-run of 275.
ALTER FUNCTION public.epigraph_operator_actor(uuid) ROWS 1000;

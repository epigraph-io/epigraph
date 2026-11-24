-- Undo migration 275 (membership_helper_row_estimates): put epigraph_operator_actor
-- back on PostgreSQL's default set-returning estimate. Run on a maintenance (or
-- migrating) connection. Idempotent. No body, owner, ACL or search_path changes.
-- After it, the membership resolve plans above jit_above_cost again on a
-- production-sized database (backlog 8377cf18); set `jit = off` first if JIT is on.
ALTER FUNCTION public.epigraph_operator_actor(uuid) ROWS 1000;

-- no-transaction
-- One statement per file: see 063's header.
--
-- Migration 075's guard counts world-owned claims. idx_claims_group_current is
-- partial WHERE visibility='group' and every world-owned row is public, so that
-- index is STRUCTURALLY UNUSABLE for the guard (ops F16). The guard therefore
-- does not live in a migration at all -- it is `epigraph-tenancy-backfill
-- verify`'s exit code -- and this index exists so `verify` is not a seq scan on
-- every run.
--
-- IT IS NOT NARROW YET, AND WILL NOT BE UNTIL PR-16. From 062 onward
-- owner_group_id DEFAULTs to the world group, so at the moment this file runs
-- the partial predicate matches 100 % OF `claims` -- this is a full-size btree
-- over claims.id, built CONCURRENTLY on the largest table in the schema. That
-- is the cost of having it in place before the backfill starts rather than
-- building it against a live system mid-backfill; do not read "partial" as
-- "cheap" here. PR-16's backfill then empties it, leaving ~100 % dead tuples:
--   REINDEX INDEX CONCURRENTLY idx_claims_world_owned;
-- is a REQUIRED step of the PR-16 runbook (docs/deploy.md), not an
-- optimisation. Without it `verify` scans a corpus-sized index to count zero
-- rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_world_owned
    ON public.claims (id)
 WHERE owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid;

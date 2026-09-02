-- Scope `edges_alternative_of_symmetric_uniq` to edges that are IN FORCE.
--
-- WHY. Edge removal is now a retraction (`valid_to = now()`), not a delete, so the
-- row survives. A UNIQUE index knows nothing about `valid_to` unless its predicate
-- says so, which means a RETRACTED alternative_of edge still occupies the
-- uniqueness slot for its {source, target} pair. Deleting used to free that slot.
--
-- Observed failure: `ClaimRepository::mark_duplicate_with_repair` retracts a
-- redundant alternative_of edge and then migrates the survivor's edge onto the
-- canonical claim. With the old predicate the migration collides with the row it
-- just retracted and the whole call returns DuplicateKey / HTTP 500 — reproduced by
-- `mark_duplicate_repo::mark_duplicate_with_shared_alternative_of_edge_succeeds`.
--
-- This is a general hazard of UPDATE-based retraction, not a quirk of this index:
-- any uniqueness constraint over edges must exclude retracted rows or retraction
-- silently becomes a weaker operation than deletion.
--
-- SAFETY. Verified against production before writing this migration: zero in-force
-- alternative_of pairs are duplicated, so the narrowed index builds cleanly. The
-- new predicate is strictly WEAKER than the old one (it indexes a subset of rows),
-- so it cannot reject data the old index accepted.
--
-- Not CONCURRENTLY: sqlx runs each migration inside a transaction and
-- CREATE INDEX CONCURRENTLY cannot run in one. There are 987,857 edges but only
-- ~3 match `relationship = 'alternative_of'`, so the build is trivial and the
-- ACCESS EXCLUSIVE window is negligible. Migration 013's lesson applies — a
-- migration that fails panics the api binary on restart — which is exactly why the
-- zero-duplicates precondition was checked first rather than assumed.

DROP INDEX IF EXISTS edges_alternative_of_symmetric_uniq;

CREATE UNIQUE INDEX edges_alternative_of_symmetric_uniq
    ON public.edges USING btree (LEAST(source_id, target_id), GREATEST(source_id, target_id))
    WHERE ((relationship)::text = 'alternative_of'::text AND valid_to IS NULL);

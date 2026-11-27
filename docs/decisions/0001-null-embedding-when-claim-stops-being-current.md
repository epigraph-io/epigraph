# 0001: A claim that stops being current loses its embeddings

- **Decided:** 2026-05-18
- **Recorded:** 2026-11-27 (retrospective)
- **Sources:**
  - commit fb6c7bf8d, `fix(db): mark_duplicate nulls embedding to enforce
    is_current=false invariant` (its message has no body);
  - commit 7bdd3a185, `docs(claude): embedding policy for is_current invariant
    + write/cleanup paths`;
  - pull request #159, `fix(embeddings): close write-path leaks + enforce
    is_current=false null` (merged 2026-05-18);
  - plan `docs/superpowers/plans/2026-05-18-embedding-pipeline-fix.md`.

## Rule it grounds

The `CLAUDE.md` section "Embedding policy". It says that every claim with
`is_current = false` has `embedding = NULL` and `embedding_3072 = NULL`, and
its subsection "Cleanup paths (must null on `is_current = false`)" lists every
path that retires a claim.

## Decision

When `ClaimRepository::mark_duplicate` retires a duplicate claim
(`is_current = false`), it also clears the duplicate's embedding, inside the
same transaction. `supersede` already did this. The invariant was written into
`CLAUDE.md` in the same pull request, with an audit query.

## Context (from PR #159)

- The share of live claims with no embedding grew from about 1% to about 6%
  in three days. Two causes were found:
  - several claim-creation paths skipped the embedder;
  - `mark_duplicate` left the embedding on a claim it had retired.
- The pull request fixed both. It is the second cause that set the rule for
  retirement paths.

## Reasoning (from PR #159 and the code comment in fb6c7bf8d)

- Semantic recall reads the `embedding` column. A retired claim that keeps
  its vector can still come back in recall. A live claim with no vector
  cannot be found by recall.
- The new statement's comment says it "mirrors supersede()": every path that
  sets `is_current = false` should behave the same way, not just one.
- Writing the invariant into `CLAUDE.md` with an audit query (`live_missing`
  and `stale_present`) was meant to make future write and cleanup paths
  auditable.

## Not recorded

- Why clear the vector, rather than leave it and filter on `is_current` in
  every recall query? The sources do not compare the two approaches.
- Why was a database `CHECK` not added at the time? The pull request lists a
  "stale-embedding sweeper" as a follow-up and adds no constraint.

## Later changes

- Pull request #276 (commit b5a80ac41, 2026-06-15, merged 2026-06-17):
  - migration 052 added the `chk_deprecated_no_embedding` constraint;
  - the same change merged the two-step pattern into one `UPDATE`.
  - Why: the constraint is checked per statement, so fb6c7bf8d's approach
    (set `is_current = false`, then clear the embedding in a second statement)
    is now refused. `CLAUDE.md` requires both columns to be cleared in the
    same statement that sets `is_current = false`.
- Migration 144 (commit 977d7a2ef, 2026-10-06) widened the constraint to
  `embedding_3072`.

# Audit: Edge Collision in `mark_duplicate` — `edges_alternative_of_symmetric_uniq`

## Scope

Covers `crates/epigraph-db/src/repos/claim.rs` `mark_duplicate` (~lines 2598–2683)
and all migration files at or after `018_drop_edges_triple_unique_constraint.sql`.

---

## (a) Did any later migration re-add a UNIQUE index on `edges`?

**Yes — one partial index was added post-018.**

Migration `042_alternative_of_edge_type.sql` adds:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS edges_alternative_of_symmetric_uniq
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'alternative_of';
```

This is a *partial* unique index: it covers only rows where
`relationship = 'alternative_of'`.  No migration re-adds a broad
`(source_id, target_id, relationship)` triple-uniqueness constraint for any
other relationship type (CORROBORATES, supports, DERIVED_FROM, etc.).

All other post-018 index additions are either:
- Non-unique indexes (paragraph/atom embedding partial indexes in 029/030).
- Unique constraints on *other tables* (e.g. `mass_functions` in 034,
  `match_candidates_unique_pair` in 036).

---

## (b) Does any Postgres trigger fire on UPDATE of `edges` that could insert a `duplicate_of` or `supersedes` row?

**No.**

The triggers present on or related to `edges` after migration 018 are:

| Trigger / Function | Fires on | Effect |
|--------------------|----------|--------|
| `validate_edge_reference` | INSERT on `edges` | Validates that source/target IDs exist in their respective entity tables. Rebuilt in 019, 020, 025 to add new entity types. Does **not** fire on UPDATE. |
| `cascade_delete_edges` (per entity table) | DELETE on `claims`, `papers`, `tasks`, `events`, `workflows`, `experiments`, `experiment_results` | Removes orphan edges when an entity is deleted. Does **not** fire on UPDATE of `edges`. Added/extended in 023, 024. |
| `auto_create_factor_from_edge()` | INSERT on `edges` WHERE `relationship = 'CORROBORATES'` (migration 038) | Creates or updates a `mass_function_factors` row from the edge's `properties.score`. Does **not** fire on UPDATE and does **not** insert into `edges`, `claims`, or any supersedes/duplicate_of table. |

No trigger fires on `UPDATE edges`, and none inserts a `duplicate_of` or
`supersedes` row in response to an edge update.

---

## (c) Can the two UPDATE-based edge migrations produce a `(source, target, relationship)` triple that already exists?

**Yes — and for `alternative_of` edges it raises a hard constraint violation.**

### Pre-condition

Three claims exist: **A** (canonical), **B** (dup), **C** (any third claim).
Before `mark_duplicate(dup=B, canonical=A)` is called, the `edges` table
contains both of the following rows:

```
Row 1:  source_id = A,  target_id = C,  relationship = 'alternative_of'
Row 2:  source_id = B,  target_id = C,  relationship = 'alternative_of'
```

(Symmetric-index key for Row 1: `(LEAST(A,C), GREATEST(A,C))`.)

This pre-condition is reachable whenever two claims that are later identified
as duplicates have independently been placed in the same `alternative_of`
equivalence class — a normal outcome of the cross-source matcher promoting
match candidates into `alternative_of` edges via
`POST /api/v1/edges/epistemic`.

### What `mark_duplicate` does

**First UPDATE** (claim.rs line 2661–2668):

```sql
UPDATE edges SET target_id = $1          -- A
WHERE target_id = $2                     -- B
  AND target_type = 'claim'
  AND relationship != 'supersedes'
  AND NOT (source_type = 'claim' AND source_id = $1);
```

Row 2 has `target_id = C`, not `B`, so it is **not matched** by this UPDATE.
No collision here.

**Second UPDATE** (claim.rs line 2671–2679):

```sql
UPDATE edges SET source_id = $1          -- A
WHERE source_id = $2                     -- B
  AND source_type = 'claim'
  AND relationship != 'supersedes'
  AND NOT (target_type = 'claim' AND target_id = $1);
```

Row 2 matches every predicate:

| Predicate | Row 2 value | Passes? |
|-----------|-------------|---------|
| `source_id = B` | B | ✓ |
| `source_type = 'claim'` | 'claim' | ✓ |
| `relationship != 'supersedes'` | 'alternative_of' | ✓ |
| `NOT (target_type = 'claim' AND target_id = A)` | target_id = C ≠ A | ✓ |

PostgreSQL therefore attempts to write:

```sql
-- attempted result of the second UPDATE
source_id = A,  target_id = C,  relationship = 'alternative_of'
```

Row 1 (`source_id=A, target_id=C, relationship='alternative_of'`) already
occupies index key `(LEAST(A,C), GREATEST(A,C))` in
`edges_alternative_of_symmetric_uniq`.

### The exact statement and constraint violated

**Failing statement** (the second UPDATE inside `mark_duplicate`'s transaction):

```sql
UPDATE edges SET source_id = $1            -- canonical UUID
WHERE source_id = $2                       -- dup UUID
  AND source_type = 'claim'
  AND relationship != 'supersedes'
  AND NOT (target_type = 'claim' AND target_id = $1);
```

**Constraint violated:**

```
unique constraint "edges_alternative_of_symmetric_uniq"
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'alternative_of'
```

**Error from PostgreSQL:**

```
ERROR:  duplicate key value violates unique constraint "edges_alternative_of_symmetric_uniq"
DETAIL:  Key (least(source_id, target_id), greatest(source_id, target_id))=(A, C) already exists.
```

Because the UPDATE runs inside the transaction started by `mark_duplicate`,
the entire deduplication transaction is rolled back: the `claims` row is not
marked non-current and no edge migration takes effect.

---

## CORROBORATES / supports: silent collision, no hard error

The same structural situation — canonical A and dup B both having an outbound
CORROBORATES (or supports) edge to the same third claim C — does occur, and
the second UPDATE rewrites `(B, C, CORROBORATES)` to `(A, C, CORROBORATES)`.

Because no unique index exists on CORROBORATES or supports post-migration-018,
PostgreSQL **accepts** the duplicate row.  The transaction commits.  The
visible consequence is that the combined Dempster-Shafer belief for claim C
receives two identical mass contributions from source A — effectively
double-counting that evidence in `auto_create_factor_from_edge` downstream.
This is a semantic corruption, not a hard error, so it does not surface
immediately but degrades belief accuracy.

---

## Fix summary (not implemented here)

The second UPDATE should be extended to also skip rows that would produce an
`(source_id, target_id, relationship)` triple already present in `edges`.
The minimal guard mirrors the self-loop guard already in place:

```sql
UPDATE edges SET source_id = $1
WHERE source_id = $2
  AND source_type = 'claim'
  AND relationship != 'supersedes'
  AND NOT (target_type = 'claim' AND target_id = $1)
  AND NOT EXISTS (
      SELECT 1 FROM edges e2
       WHERE e2.source_id = $1
         AND e2.target_id = edges.target_id
         AND e2.relationship = edges.relationship
  );
```

An equivalent guard is needed on the first UPDATE (target_id direction) to
cover the symmetric case.  Rows that are skipped by either guard should be
deleted rather than left dangling with the dup as their source/target.

# EpiGraph Database Migrations

PostgreSQL schema migrations for the EpiGraph epistemic knowledge graph system.

## Migrations are append-only

Once a migration has been applied (in any environment), its file is **frozen**:
the SHA-384 checksum is recorded in `_sqlx_migrations.checksum` and verified on
every API startup. Editing an applied migration file — even whitespace, comments,
or a typo fix — will cause the next deploy to fail with a checksum mismatch and
refuse to start.

Add a NEW migration (`NNN+1_fix_typo.sql`) instead of editing an existing one.

## Known schema drift: `uq_claims_content_hash_agent` (013)

`_sqlx_migrations` recording a version as applied does **not** prove the
objects it created still exist. On the long-lived `epigraph` database,
migration 013 is recorded `success = true` while its
`uq_claims_content_hash_agent UNIQUE (content_hash, agent_id)` constraint is
absent from `claims`.

Cause: integration-test fixtures in
`crates/epigraph-db/tests/claim_repo_helpers.rs` and
`crates/epigraph-mcp/tests/common/mod.rs` deliberately drop that constraint to
exercise the pre-107 code path. Run with `DATABASE_URL` pointing at a live
database, they dropped it there and left it dropped. Those fixtures now refuse
to run against non-disposable databases (see `db_is_disposable` /
`EPIGRAPH_TEST_DESTRUCTIVE_DB`), so the drift cannot recur — but the existing
drift, and the ~169k duplicate rows that accumulated while `claims` was
unconstrained, still need reconciling.

**Do not "fix" this with a new migration that re-adds the constraint.** A bare
`ADD CONSTRAINT` fails on the duplicates, and per the append-only rule above a
failed migration panics the api binary on restart — turning silent drift into a
deploy outage. Audit first:

```bash
python3 scripts/audit_claims_content_hash_agent.py     # read-only
```

## Version range coordination with epigraph-internal

The private `epigraph-internal` repo also runs `sqlx::migrate!()` against the
same `_sqlx_migrations` table, so its versions and ours **did** share a number
space. As of 2026-09-02 that is no longer true in practice — see "The
epigraph-internal overlap" below — but the numbers it burned are still real and
still recorded here, because a database that ever ran internal carries them.

Current reservation:

- **001–034**: public
- **035–037**: `epigraph-internal` (`claim_supersession`, `challenges_and_events`,
  `analyses`) — applied to prod 2026-05-22. Public has since renumbered these
  same files in-tree to `036–038` (cross-source matching port).
- **038**: public `corroborates_factor_strength_from_score` (PR #173)
- **039–059**: public
- **060–090**: **RESERVED** — the multi-user tenancy series on
  `feat/multi-user-tenancy` (epigraph-io/epigraph#408). 21 migrations plus
  headroom. **Do not allocate here**, even though the branch has not merged:
  its numbers are fixed and its `docs/tenancy/` ledger pins them.
- **091**: public `alternative_of_uniq_ignores_retracted` (PR #411)
- **092+**: public next

Next public migration must be `092` or later. Picking a colliding version
(checksum mismatch on a `_sqlx_migrations` row that's already applied) will
panic the api binary on restart.

### Why 091 and not 060

`alternative_of_uniq_ignores_retracted` was written as `060` and merged to
`main` in #411 while this table still ended at "039+: public next" — nothing
recorded that #408 had already claimed `060`. Git does not catch it: the two
files have different names, so they merge cleanly and the collision only
appears when sqlx sees version 60 already applied under a different checksum
and panics the api binary on startup.

It was renumbered to `091` rather than renumbering #408's 21 migrations,
because it was applied to **no** database at the time (prod `_sqlx_migrations`
max was 59) and because #408 reserved the range first. That window existed only
because #411 had not yet been deployed; had it shipped first, moving it would
itself have been the panic scenario and #408 would have had to shift instead.

**The lesson for this table:** a reservation that lives only on an unmerged
branch protects nothing. Record the range here, on `main`, when the branch is
opened — not when it lands.

### The epigraph-internal overlap

`epigraph-internal` allocated `060`–`112` (110 migration files, `060_prov_o_agent_typing`
onward) long before the tenancy series reserved `060`–`090`, so the two ranges
overlap outright. This is recorded rather than fixed, because internal no
longer shares prod's `_sqlx_migrations`:

```
prod `epigraph` DB, max applied version            : 59   (2026-09-02)
prod rows matching internal migration descriptions : 0
```

Verify both before assuming it still holds. If a database is ever found that
ran internal *and* is targeted by public migrations, `060`–`112` is a minefield
there and public must allocate above `112` for that database.

Note also that `crates/epigraph-api/src/lib.rs` sets
`migrator.set_ignore_missing(true)`, so a *gap* is tolerated but a *checksum
mismatch* is not. Prod's missing version 35 is the benign case: there is no
public `035_*.sql` at all, 035 belongs to internal, and prod's 036/037/038
descriptions match the public filenames.

## Migration Order

Migrations must be applied in numerical order:

1. **001_create_extensions.sql** - Enable pgvector and uuid-ossp extensions
2. **002_create_agents.sql** - Create agents table (cryptographic identities)
3. **003_create_claims.sql** - Create claims table (epistemic assertions)
4. **004_create_evidence.sql** - Create evidence table (supporting materials)
5. **005_create_reasoning_traces.sql** - Create reasoning traces and DAG structure
6. **006_create_relationships.sql** - Add circular FKs and LPG edges table
7. **007_create_indexes.sql** - Create performance indexes (HNSW, composite, partial)

## Schema Overview

### Core Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `agents` | Cryptographic identities | `id`, `public_key` (32 bytes Ed25519) |
| `claims` | Epistemic assertions | `id`, `content`, `truth_value` [0.0, 1.0], `embedding` vector(1536) |
| `evidence` | Supporting materials | `id`, `content_hash`, `evidence_type`, `signature` (64 bytes) |
| `reasoning_traces` | Reasoning provenance | `id`, `claim_id`, `reasoning_type`, `confidence` [0.0, 1.0] |
| `trace_parents` | DAG edges (reasoning dependencies) | `trace_id`, `parent_id` |
| `edges` | LPG-style relationships | `source_id`, `target_id`, `relationship` |

### Label Property Graph (LPG) Features

All core tables include:
- **labels** (`TEXT[]`) - Categorization tags (e.g., `['verified', 'scientific']`)
- **properties** (`JSONB`) - Flexible key-value metadata

### Key Design Decisions

#### 1. UUID Primary Keys
- Matches Rust `Uuid` type in `epigraph-core`
- Uses `gen_random_uuid()` from uuid-ossp extension
- Enables distributed ID generation without coordination

#### 2. Bounded Truth Values
- `truth_value DOUBLE PRECISION CHECK (>= 0.0 AND <= 1.0)`
- Matches `TruthValue` type in `crates/epigraph-core/src/truth.rs`
- 0.0 = definitely false, 0.5 = uncertain, 1.0 = definitely true

#### 3. Cryptographic Integrity
- `content_hash` BYTEA(32) - BLAKE3 hashes
- `public_key` BYTEA(32) - Ed25519 public keys
- `signature` BYTEA(64) - Ed25519 signatures
- CHECK constraints ensure correct byte lengths

#### 4. Vector Embeddings
- `embedding vector(1536)` - OpenAI text-embedding-3-small
- HNSW index for fast approximate nearest neighbor search
- Enables semantic search with cosine similarity

#### 5. DAG Structure for Reasoning
- `trace_parents` junction table represents reasoning dependencies
- Prevents circular reasoning (cycles detected at application layer)
- Enables lineage queries via recursive CTEs

#### 6. Circular FK Resolution
- `claims.trace_id` FK added in migration 006 (after both tables exist)
- Allows claims and traces to reference each other
- Uses `ON DELETE SET NULL` to prevent cascade issues

#### 7. LPG Edges Table
- Generic `edges` table for flexible graph relationships
- Complements fixed schema FKs
- Supports typed, property-decorated edges between any entities
- Example: claim "supports" claim, agent "endorses" claim

## Index Strategy

### Vector Similarity
- **HNSW** index on `claims.embedding` (fast for < 1M vectors)
- For larger datasets, consider migrating to IVFFlat with `lists = sqrt(num_rows)`

### GIN Indexes
- All `labels` columns (array containment queries)
- All `properties` columns (JSONB key/value queries)

### B-tree Indexes
- Primary keys (automatic)
- Foreign keys (forward and reverse lookups)
- `truth_value` (filtering and sorting)
- Composite indexes for common query patterns

### Partial Indexes
- High-truth claims (`truth_value >= 0.7`) for verified queries
- Low-truth claims (`truth_value <= 0.3`) for disputed queries
- Non-null embeddings for semantic search

## Running Migrations

### Using sqlx (Rust)

```bash
# Set DATABASE_URL in .env
export DATABASE_URL="postgres://user:pass@localhost:5432/epigraph"

# Run migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert
```

### Using psql

```bash
# Apply all migrations in order
for file in migrations/*.sql; do
  psql $DATABASE_URL -f $file
done
```

## Schema Validation

### Critical Invariants

The following invariants MUST be maintained:

1. **Truth values bounded**: `0.0 <= truth_value <= 1.0`
2. **No cycles in reasoning DAG**: Application layer must validate before insert
3. **Hash lengths correct**: BLAKE3 = 32 bytes, Ed25519 keys = 32 bytes, Ed25519 sigs = 64 bytes
4. **Signatures require signers**: `signature IS NOT NULL` implies `signer_id IS NOT NULL`
5. **No self-referencing traces**: `trace_id != parent_id` in `trace_parents`

### Test Queries

```sql
-- Verify no truth values out of bounds
SELECT COUNT(*) FROM claims WHERE truth_value < 0.0 OR truth_value > 1.0;
-- Should return 0

-- Verify all signed evidence has a signer
SELECT COUNT(*) FROM evidence WHERE signature IS NOT NULL AND signer_id IS NULL;
-- Should return 0

-- Verify no self-referencing traces
SELECT COUNT(*) FROM trace_parents WHERE trace_id = parent_id;
-- Should return 0

-- Verify hash lengths
SELECT COUNT(*) FROM claims WHERE octet_length(content_hash) != 32;
SELECT COUNT(*) FROM evidence WHERE octet_length(content_hash) != 32;
-- Both should return 0
```

## Performance Monitoring

```sql
-- Index usage statistics
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan ASC;

-- Table sizes
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size('public.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size('public.'||tablename) DESC;

-- Vector index performance (claims)
EXPLAIN ANALYZE
SELECT id, statement, truth_value
FROM claims
WHERE embedding IS NOT NULL
ORDER BY embedding <=> '[0.1, 0.2, ...]'::vector
LIMIT 10;
```

## Future Considerations

### Partitioning
For very large datasets (> 100M claims), consider partitioning:
- `claims` by `created_at` (monthly or yearly)
- `evidence` by `claim_id` hash
- `edges` by `source_type`

### Archival
Low-activity claims can be archived to cold storage:
- Move claims with `truth_value < 0.1` and no recent updates
- Maintain lineage in archived state

### Replication
For high availability:
- PostgreSQL logical replication for read replicas
- pgvector indexes rebuild automatically on replicas

## References

- [pgvector Documentation](https://github.com/pgvector/pgvector)
- [HNSW Algorithm](https://arxiv.org/abs/1603.09320)
- [PostgreSQL GIN Indexes](https://www.postgresql.org/docs/current/gin.html)
- [EpiGraph Implementation Plan](/home/user/EpiGraphV2/IMPLEMENTATION_PLAN.md)
- [TruthValue Type](/home/user/EpiGraphV2/crates/epigraph-core/src/truth.rs)

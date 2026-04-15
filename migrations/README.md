# EpiGraph Database Migrations

PostgreSQL schema migrations for the EpiGraph epistemic knowledge graph system.

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

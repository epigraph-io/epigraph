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
- **060–090**: RESERVED — public multi-user tenancy series (epigraph-io/epigraph
  `feat/multi-user-tenancy`). `epigraph-internal` MUST NOT allocate in this range.

  | Version(s) | PR | What |
  |---|---|---|
  | **060** | PR-01 | group tenancy tables |
  | **061** | PR-02 | `agents.key_kind` |
  | **062** | PR-04 | tenancy columns, stage 1 — metadata-only, idempotent, transition DEFAULTs present |
  | **063–066** | PR-04 | tenancy indexes. `-- no-transaction`, **one `CREATE INDEX CONCURRENTLY` per file**. See the section below; this is not style. |
  | **067** | PR-04 | session / bypass functions (`epigraph_session_groups`, `epigraph_writable_groups`, `epigraph_principal_id`, `epigraph_bypass`, `epigraph_definer_bypass`) |
  | **068–084** | PR-05 … PR-22 | the remaining plan §3.1 migrations, shifted **+4** from the plan's printed numbering after 062 (plan 064 → 068, …, plan 080 → 084) |
  | **085** | PR-10 | `webhook_subscriptions` — **claimed 2026-09-03**, was headroom |
  | **086–090** | — | remaining headroom |

  **The post-shift numbers, pinned.** THIS TABLE IS AUTHORITATIVE; plan §3.1's
  own columns are not, and neither is `docs/tenancy/FINAL-PLAN.md`. Derive
  nothing — a downstream comment that names a migration must name the number in
  this column. **PR-05 takes 068 and 069, not the plan's 065/066.**

  | Actual | PR | What |
  |---|---|---|
  | **068** | PR-05 | communities → groups; `encryption_key_id` de-overload |
  | **069** | PR-05 | `entity_types.tenancy_tier` + `tenancy_exempt` registry |
  | **070** | PR-12 | write-side stamping triggers (statement-level, transition form) — drafted PR-12; **validated on a throwaway DB only, NOT applied to any deployed database** (plan §9.2 puts that at week 11c) |
  | **071** | PR-12 | `ownership` compat shim — drafted PR-12; **validated on a throwaway DB only, NOT applied to any deployed database** |
  | **072** | PR-13 | `edges.co_owner_group_id` — column + FK + shape CHECK (both `NOT VALID`) and the `CREATE OR REPLACE` of 070's `epigraph_edges_tenancy` / `epigraph_propagate_tenancy`. **Drafted PR-13; validated on a throwaway DB only, NOT applied to any deployed database.** File: `072_edge_co_ownership.sql` |
  | **073** | PR-13 | edge co-owner index (`-- no-transaction`, one `CREATE INDEX CONCURRENTLY`). File: `073_idx_edges_co_owner.sql`. NOT the `edges_tenancy` RLS policy — the plan's PR-13 *Files* line says "pre-staged for 073" and means **077**; the clause itself is written out in 072's header. **Drafted PR-13; validated on a throwaway DB only, NOT applied to any deployed database.** |
  | **074** | PR-16 | tenancy REQUIRED: `DROP DEFAULT`, require-tenancy trigger, no-widening trigger |
  | **075** | PR-16 | validate tenancy constraints — `claims` only |
  | **076** | PR-16 | validate tenancy constraints — remaining tier-A tables |
  | **077** | PR-17 | RLS policies (`ENABLE` only) |
  | **078** | PR-17 | RLS canary table |
  | **079** | PR-17 | `FORCE ROW LEVEL SECURITY` |
  | **080** | PR-18 | privatization plans, items, closure |
  | **081** | PR-18 | privatization guards |
  | **082** | PR-18 | privatization audit + `security_events` hardening |
  | **083** | PR-18 | `instance_admins` |
  | **084** | PR-22 | retire `ownership` |
  | **085** | PR-10 | `webhook_subscriptions` (durable webhook registrations, `agent_id` FK) |

  **PR-10 takes 085, NOT the 081 `docs/tenancy/FINAL-PLAN.md` names.** The
  plan's PR-10 note says its migration "takes the next unused number in the
  reserved 060–085 range (081 if nothing else has claimed it)". 081 *is*
  claimed — PR-18's privatization guards, two rows up. The plan was written
  against the pre-shift numbering, before PR-04's index migration became four
  files; that is the same staleness this table's "Derive nothing" rule exists
  to absorb. PR-10 landed ahead of PR-12…PR-22 in wall-clock order, which is
  exactly the case the headroom row was reserved for.

  **Non-table objects the reserved range introduces.** A number in the table
  above names a migration, not everything it creates. These are the objects
  inside 060–090 that a later `DROP` has to know about by name, because they are
  not tables and so do not appear in the Tombstones section below:

  | Object | `relkind` | Created by | Dropped by |
  |---|---|---|---|
  | `public.ownership_key_id_quarantine` | VIEW (`v`) | 068 | **084**, with the `ownership` table it reads. Its pre-flight is `SELECT count(*) FROM ownership_key_id_quarantine` — a non-empty result is an operator action item, and 084 must not `DROP TABLE ownership CASCADE` past it. |
  | `public.tenancy_exempt` | TABLE (`r`) | 069 | **never** — it is the §2.4 exemption registry and outlives the series. Listed here so it is not mistaken for scaffolding. |

  A VIEW is deliberate for the quarantine (ops F20): a `CREATE TABLE AS`
  snapshot taken at 068 time cannot see a row that becomes unparseable
  afterwards, so 084's pre-flight would pass over exactly the value it exists to
  catch. It is created `WITH (security_invoker = true)` — a view without that
  option executes as its OWNER and bypasses the invoker's policies once
  migration 079 FORCEs RLS, which is the open finding migration 069 files
  against `alternative_set` and `alt_set_decisions`. **Any VIEW added in this
  range must set it.** Both properties are pinned by
  `crates/epigraph-db/tests/tenancy_coverage.rs::ownership_key_id_quarantine_is_a_view`.

  Two comments in migrations already applied to a database still carry
  pre-shift numbers and **cannot be corrected**: editing an applied file changes
  its checksum and `sqlx migrate run` then refuses to start. They are
  `060_group_tenancy_tables.sql:110` ("070's seed arm" — now **074**) and
  nothing else. Read them against this table.

  **Why 060–085 became 060–090.** PR-04's index migration could not be one file
  (see below), so it became four, consuming three extra numbers and pushing the
  chain's end from 081 to 084. Against the old reservation that left exactly one
  free number for PR-10's webhook-persistence migration and no slack at all. The
  version space is shared with `epigraph-internal` against the same
  `_sqlx_migrations` table, and `run_migrations` sets `set_ignore_missing(true)`
  (`crates/epigraph-api/src/lib.rs:54`), so a collision is **not** caught by the
  missing-version check — it panics the api binary on restart.

  **Why the +1 shift:** the plan assigns no migration to PR-02, yet PR-02's
  `AgentRepository::ensure_for_client` writes `agents.key_kind = 'derived'` for
  the blake3 placeholder key it materialises for every keyless OAuth principal,
  and `routes/submit.rs` must filter `key_kind = 'ed25519'` on the signature
  path. `key_kind` was scheduled inside PR-04's tenancy-columns migration, which
  would have retroactively stamped every PR-02 placeholder agent as a real
  Ed25519 verifier. PR-02 therefore claims 061 and everything after it moves up
  one. **Do not "correct" this back to the plan's numbering** — 061 is applied.
  PR-04's tenancy-columns file keeps its own guarded `ADD COLUMN IF NOT EXISTS
  key_kind` statements; against a database that has 061 they no-op.
- **091**: public `alternative_of_uniq_ignores_retracted` (PR #411) — the first
  allocation outside the reserved range. It was written as `060` and merged to
  `main` before this table existed there; see "Why 091 and not 060" below.
- **092+**: public next

Next public migration **outside the reserved tenancy range** must be `092` or
later; numbers inside 060–090 are allocated by §3.1 of the tenancy plan and are
claimed one PR at a time on `feat/multi-user-tenancy`. Picking a colliding
version (checksum mismatch on a `_sqlx_migrations` row that's already applied)
will panic the api binary on restart.

## `-- no-transaction` migrations

Migration `063_idx_claims_group_current.sql` is the **first `-- no-transaction`
migration in this repo's history**. Before it, `013_code_review_hardening.sql:8-10`
and `030_atom_embedding_partial_index.sql:11` documented a manual DBA pre-step
for `CREATE INDEX CONCURRENTLY` because the team believed it impossible inside a
migration. It is not: sqlx-core 0.8.6 honours a leading `-- no-transaction` line
(`src/migrate/source.rs:127`) and sqlx-macros-core propagates the flag into the
compile-time `migrate!()` literal, so `epigraph-migrate` honours it too.

### THE RULE: one statement per `-- no-transaction` file

Not style. sqlx-postgres 0.8.6's `execute_migration` runs
`conn.execute(&*migration.sql)` (`src/migrate.rs:280`) — the **simple query
protocol over the whole file**. PostgreSQL wraps a multi-statement simple query
in an *implicit transaction block*, and `CREATE INDEX CONCURRENTLY` inside one
fails with SQLSTATE **25001**, `CREATE INDEX CONCURRENTLY cannot run inside a
transaction block`. Interleaving `COMMIT;` between statements does not help;
that was tested. The four index statements PR-04 needed are therefore four
files, 063–066.

`crates/epigraph-db/tests/tenancy_migration_shape.rs::no_transaction_files_contain_exactly_one_statement`
is the ratchet on this. Without it, the next person merges the files back
together and the whole workspace suite goes red at once, with an error naming
sqlx rather than the edit.

Two further constraints:

* `-- no-transaction` must be the **literal first bytes of the file** — no BOM,
  no blank line, no `-- <name>.sql` header above it (every other migration in
  this tree opens with one; these four must not).
* A `-- no-transaction` file's `_sqlx_migrations` bookkeeping is **not atomic**
  with its DDL (`sqlx-postgres/src/migrate.rs:214`). Keep such files to index
  statements only, all `IF NOT EXISTS`, so a failure can never strand a column.

### Recovery from a failed `CREATE INDEX CONCURRENTLY`

There is no transaction, so a failure leaves an **INVALID index** behind and no
`_sqlx_migrations` row. Re-running the migration is safe (`IF NOT EXISTS`) but
will *not* rebuild the invalid index — an operator must drop it first:

```sql
SELECT c.relname FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
 WHERE NOT i.indisvalid;
```

```sql
DROP INDEX CONCURRENTLY <name>;   -- then re-run the migration
```

### Production window

On a live cluster, `CREATE INDEX CONCURRENTLY` waits for every transaction older
than itself in the same database. `bin/server.rs` sets the background job pool's
`statement_timeout` to **2 700 000 ms (45 minutes)** by default, so a single
long clustering job can stall 063–066 for that long. `SET LOCAL lock_timeout` in
a `-- no-transaction` file is *legal* but useless: outside a transaction block it
is a silent no-op that emits only `WARNING: SET LOCAL can only be used in
transaction blocks`, and it would not bound this wait even if it applied. Run
these during a quiet window, or after confirming
`SELECT max(now() - xact_start) FROM pg_stat_activity WHERE state <> 'idle'` is
small.

### `scripts/prepare-engine-integration-db.sh`

That script applies every `migrations/*.sql` with `psql -v ON_ERROR_STOP=1 -f`
in autocommit and never writes `_sqlx_migrations`. `-- no-transaction` is an
inert comment to psql and autocommit makes `CREATE INDEX CONCURRENTLY` legal, so
063–066 survive that path unchanged. The pre-existing hazard is unaffected: a
database prepared this way then fails every `sqlx::migrate!`.

## Tombstones

Tables that exist in the field but have no owning code. Scheduled for an
explicit `DROP TABLE IF EXISTS` inside the reserved 060–090 range — not dropped
opportunistically, because on the databases where they exist they hold key
material.

- **`embedding_shares`**, **`re_encryption_keys`** — created by
  `epigraph-enterprise/migrations/001_initial_schema.sql`, never created by any
  public migration (060 deliberately skips both). Their repositories
  (`EmbeddingShareRepository`, `ReEncryptionKeyRepository`) and the MPC/PRE code
  paths that used them were deleted in PR-01 of the tenancy series. On an
  enterprise-lineage database both survive with `ON DELETE CASCADE` FKs to
  `groups` and zero readers; PR-21's corpus-wide seal verification must not
  mistake the MPC share material for live ciphertext.

## Provisioning lineage

Migration `060_group_tenancy_tables.sql` opens with a **drift guard**: it
`RAISE`s if any of seven group-tenancy tables already exists in a shape it did
not create (`pattern_templates`, the eighth, is identical in both lineages and
carries no sentinel). This is deliberate. Seven of its eight tables also exist in the
`epigraph-enterprise` schema with different columns, CHECK constraints and
`ON DELETE` actions, and `CREATE TABLE IF NOT EXISTS` is silent about that — the
migration would report success while applying none of its guarantees. If you hit
that error, reconcile the tables to the 060 shape by hand and re-run; do not
hand-insert a `_sqlx_migrations` row.

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

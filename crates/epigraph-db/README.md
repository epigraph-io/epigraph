# epigraph-db

Database access layer for EpiGraph using PostgreSQL and sqlx.

## Setup

Most of this crate's SQL is NOT compile-time checked. Only a minority of its
statements (under one in ten, measured in November 2026 as about 90 `query!` /
`query_scalar!` macro calls against about 1,200 runtime `sqlx::query` /
`query_as` / `query_scalar` calls under `src/`) use the sqlx macros that sqlx
verifies against a database schema at build time. The rest are runtime
statements, checked only when they run (by the DB-backed tests), for these
reasons:

- **Visibility and write splicing.** A tenancy-scoped read or write marks its
  SQL with `/* {VISIBILITY:<alias>} */` or `/* {WRITABLE:<alias>} */` and
  passes it through `Viewer::splice` / `splice_write`, which return a runtime
  `String`. The macros need a compile-time literal of fixed arity, so a spliced
  statement cannot be a macro. The few macro reads that filter by viewer spell
  the static three-bind predicate instead
  (`$N::bool OR visibility = 'public' OR owner_group_id = ANY($M::uuid[])`).
  A write inside a macro can never take the write marker, which is why
  `tests/write_gate_lint.rs` registers every one in `MACRO_WRITE_SITES`.
- **Dynamic SQL.** Many statements are built with `format!` at run time
  (optional filters, per-call column or table choices), which no macro can
  check.
- **Build cost.** Every macro call needs a matching `.sqlx/` entry, or a live
  `DATABASE_URL`, to compile.

Use a macro for a static statement that no viewer or writable marker will ever
need to reach; otherwise use the runtime form, decoded through `query_as` into
a `#[derive(sqlx::FromRow)]` struct rather than `Row::get`, which panics on a
missing column or a type mismatch.

Because the macros that remain are checked at build time, building this crate
needs either:

### Option 1: Prepare queries with a database (recommended)

1. Create a fresh database whose name ends in `_test` and migrate it from
   empty (the repository's `CLAUDE.md`, "Test database"; never the live
   database):
   ```bash
   # From project root
   createdb -U epigraph <name>_test
   MIGRATION_DATABASE_URL=postgres://epigraph:epigraph@localhost/<name>_test \
     cargo run -p epigraph-api --bin epigraph-migrate
   export DATABASE_URL=postgres://epigraph:epigraph@localhost/<name>_test
   ```

2. Prepare the queries:
   ```bash
   cargo sqlx prepare --workspace -- --tests
   ```

   This regenerates the `.sqlx/` directory at the workspace root with query
   metadata for offline compilation. Use `-- --tests`, not `-- --lib`, so the
   `query!` calls in test targets are prepared as well (the repository's
   `CLAUDE.md`, "Schema, migrations, claim mechanics"), and commit `.sqlx/`:
   CI builds with `SQLX_OFFLINE=true`.

3. Build the crate:
   ```bash
   cargo build -p epigraph-db
   ```

### Option 2: Build with live database

Set `DATABASE_URL` environment variable before building:
```bash
export DATABASE_URL="postgres://user:password@localhost/epigraph"
cargo build -p epigraph-db
```

## Features

- **Typed rows**: `FromRow` decoding for runtime queries; compile-time SQL
  verification only for the minority of statements that use the `query!`
  family (see Setup for which, and why)
- **Repository pattern**: Clean separation of data access logic
- **Async/await**: Full async support with tokio
- **Connection pooling**: Efficient connection management with sqlx
- **Error handling**: Comprehensive error types with context

## Repositories

All SQL lives in `src/repos/` (94 files at the time of writing;
`ls src/repos` is the list). The five the crate started with:

- `AgentRepository`: CRUD operations for agents
- `ClaimRepository`: CRUD operations for claims, including truth value queries
- `EvidenceRepository`: CRUD operations for evidence
- `ReasoningTraceRepository`: CRUD operations for reasoning traces and DAG traversal
- `EdgeRepository`: LPG-style flexible relationships

## Usage

```rust
use epigraph_db::{create_pool, AgentRepository};
use epigraph_core::Agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create connection pool
    let pool = create_pool("postgres://user:pass@localhost/epigraph").await?;

    // Create an agent
    let agent = Agent::new([0u8; 32], Some("Alice".to_string()));
    let created = AgentRepository::create(&pool, &agent).await?;

    Ok(())
}
```

## Database Schema

The schema is defined in `/migrations/`: `001_initial_schema.sql` (the
collapsed baseline: agents, claims, evidence, reasoning traces, `trace_parents`,
edges and their indexes) followed by incremental migrations. See
`migrations/README.md` for what each one does and how they are applied.

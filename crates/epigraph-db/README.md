# epigraph-db

Database access layer for EpiGraph using PostgreSQL and sqlx.

## Setup

This crate uses sqlx's compile-time query verification via the `query!` macro. To build this crate, you need to either:

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

- **Type-safe queries**: Compile-time verification of SQL queries
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

# epigraph-db

Database access layer for EpiGraph using PostgreSQL and sqlx.

## Setup

This crate uses sqlx's compile-time query verification via the `query!` macro. To build this crate, you need to either:

### Option 1: Prepare queries with a database (recommended)

1. Start a PostgreSQL database and run migrations:
   ```bash
   # From project root
   export DATABASE_URL="postgres://user:password@localhost/epigraph"
   sqlx database create
   sqlx migrate run
   ```

2. Prepare the queries:
   ```bash
   cargo sqlx prepare --workspace -- --lib
   ```

   This generates `.sqlx/` directory with query metadata for offline compilation.

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

The schema is defined in `/migrations/`:
- `001_create_extensions.sql` - PostgreSQL extensions (pgvector, uuid-ossp)
- `002_create_agents.sql` - Agents table
- `003_create_claims.sql` - Claims table
- `004_create_evidence.sql` - Evidence table
- `005_create_reasoning_traces.sql` - Reasoning traces and trace_parents tables
- `006_create_relationships.sql` - LPG edges table
- `007_create_indexes.sql` - Performance indexes

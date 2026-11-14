# EpiGraph

EpiGraph is an epistemic kernel. It stores claims (nouns), edges between them
(verbs), and the agents that assert them. Each agent signs what it asserts,
and EpiGraph combines those assertions into beliefs using Dempster-Shafer
evidence combination. In place of the static paper, it runs a live loop:
hypothesis, experiment, data, analysis, belief update. Downstream
applications can query that loop, challenge it and extend it.

Most knowledge bases store *what is currently believed*. EpiGraph stores *what
each agent asserted, with what evidence, signed under what identity, and how
those assertions combine into a defensible belief*. The rest of the
epigraph-io stack is built on it.

## Who this is for

- **Developers** who build EpiGraph into an application. You can use the Rust
  crates directly, call the HTTP API, or drive it through the MCP server.
- **Researchers and analysts** who query the graph from an MCP client such as
  Claude Code. The MCP tools cover recall, neighbourhood traversal,
  challenge and verify, and backlog management.
- **Operators** who run an EpiGraph instance for other people. Start with
  [`docs/deploy.md`](docs/deploy.md).
- **Contributors** who extend the kernel. See [`CLAUDE.md`](CLAUDE.md).

## Status

- Version: 0.3.0 (`[workspace.package]` in `Cargo.toml`)
- License: Apache-2.0
- Maturity: alpha. The kernel schema and core primitives are stable. The
  layers built on top (workflows, hierarchical extraction, perspectives) are
  still changing.

## What you get

| Piece | Built from | What it is |
|---|---|---|
| `server` | `crates/epigraph-api` | The HTTP API. Listens on port 8080 by default. Almost every route needs an OAuth2 Bearer token. |
| `epigraph-migrate` | `crates/epigraph-api` | Applies the SQL migrations in `migrations/` and exits. The API never migrates by itself unless you ask it to. |
| `epigraph-mcp-full` | `crates/epigraph-mcp` | The MCP server. It speaks stdio by default and HTTP with `--listen`. |
| `bootstrap_clients`, `epigraph-operator` and other CLIs | `crates/epigraph-cli` | Setup and maintenance tools. `bootstrap_clients` creates the first OAuth clients. |

All of them use one PostgreSQL 16 database with the `pgvector` extension,
version 0.8.0 or newer (`epigraph-migrate` and the server refuse an older one).

## Quickstart (local trial)

This gets a single-machine trial running with the same database setup the CI
pipeline uses: one PostgreSQL superuser for everything. That is fine for
trying EpiGraph out. It is **not** a production layout; for that, read
[`docs/deploy.md`](docs/deploy.md). The
[full quickstart](docs/intro/01-quickstart.md) explains each step, how to
check it worked, and what to do when it fails.

You need:

- Docker (or your own PostgreSQL 16 with pgvector 0.8.0 or newer)
- Rust 1.88 or newer
- a C toolchain, `pkg-config` and the OpenSSL development headers
- `openssl` and `curl` on your `PATH`
- optionally, Claude Code and an OpenAI API key

```bash
# 1. PostgreSQL 16 with pgvector. POSTGRES_USER in this image is a superuser.
docker run -d --name epigraph-db -p 5432:5432 \
  -e POSTGRES_USER=epigraph -e POSTGRES_PASSWORD=epigraph -e POSTGRES_DB=epigraph \
  pgvector/pgvector:pg16

# 2. Build. SQLX_OFFLINE=true makes the build use the query metadata
#    committed in .sqlx/ instead of checking queries against a live database.
git clone https://github.com/epigraph-io/epigraph.git && cd epigraph
SQLX_OFFLINE=true cargo build --release --locked \
  -p epigraph-api -p epigraph-mcp -p epigraph-cli

# 3. Migrate, as the superuser.
export DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph
MIGRATION_DATABASE_URL="$DATABASE_URL" ./target/release/epigraph-migrate
#    Last line on success: migrations: ok db_head=<n> binary_head=<n> applied=<k>

# 4. Start the API from the repository root. It refuses to start without a
#    JWT secret of at least 32 bytes and without a providers.toml file.
#    An empty providers.toml means "no external identity providers".
: > providers.toml
export EPIGRAPH_JWT_SECRET="$(openssl rand -hex 32)"
./target/release/server &
#    Wait for the log line "Server listening on 0.0.0.0:8080", then:
curl -s http://127.0.0.1:8080/health      # {"status":"healthy",...}

# 5. Register the MCP server with Claude Code. A fixed agent key gives every
#    session the same identity; without one, each launch creates a different agent.
openssl rand -hex 32 > ~/.epigraph-mcp-key && chmod 600 ~/.epigraph-mcp-key
claude mcp add --scope user epigraph \
  -e DATABASE_URL="$DATABASE_URL" \
  -e EPIGRAPH_MCP_AGENT_KEY="$(cat ~/.epigraph-mcp-key)" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  -- "$PWD/target/release/epigraph-mcp-full"

# 6. In Claude Code, ask: "Use the epigraph recall tool to search for 'test'."
```

Step 6 works without an OpenAI key, because `recall` falls back to a lexical
search when it cannot embed the query. `recall_with_context` needs the key.
To call the HTTP API yourself, you also need a Bearer token. Step 5 of the
full quickstart shows how to create OAuth clients with `bootstrap_clients` and get a token
from `/oauth/token`.

`claude mcp add` belongs to Claude Code, not to this repository. Check
`claude mcp add --help` for the scopes your version supports.

## Documentation

Start here:

- [`docs/intro/01-quickstart.md`](docs/intro/01-quickstart.md): the local
  trial step by step, with a check after each step and a troubleshooting
  table.
- [`docs/intro/02-concepts.md`](docs/intro/02-concepts.md): noun-claims and
  verb-edges, agents and signing, Dempster-Shafer beliefs, perspectives,
  hierarchical extraction, and backlog discipline.
- [`docs/intro/04-glossary.md`](docs/intro/04-glossary.md): vocabulary.
- [`docs/intro/05-next-steps.md`](docs/intro/05-next-steps.md): pointers for
  contributors, operators and downstream projects.

Running an instance:

- [`docs/deploy.md`](docs/deploy.md): the production install and operations
  runbook. It covers the processes and their database logins, configuration,
  migrations, upgrade notes per migration, and rollback.
- [`docs/tenancy.md`](docs/tenancy.md): groups, visibility, operator binding,
  the custodian role and elevation, in depth.
- [`migrations/README.md`](migrations/README.md): the migration ledger and
  the rules for writing migrations.
- [`scripts/README.md`](scripts/README.md): operational maintenance scripts.

Design:

- [`docs/architecture/noun-claims-and-verb-edges.md`](docs/architecture/noun-claims-and-verb-edges.md):
  what is stored as a claim and what as an edge.
- [`docs/conventions/backlog-retirement.md`](docs/conventions/backlog-retirement.md):
  how operational backlog items are resolved.
- [`CLAUDE.md`](CLAUDE.md): conventions for agent sessions working in this
  repository (backlog, schema, tests, workflow).

## Change log

Newest first. Each line gives the commit that changed this file. Where a
commit reached `main` through a merge, the PR is given as "via #N".

- 2026-11-04 (this revision, PR #764): rewrote the file for a reader new to the
  project, checked against `main` at 5fcd75087.
  - Added a table of the binaries.
  - The quickstart now migrates as a PostgreSQL superuser, the layout CI
    uses, because the migrations create database roles. It builds with
    `SQLX_OFFLINE=true` (the committed `.sqlx/` metadata), and it sets the
    JWT secret and `providers.toml` the server needs to start.
  - The MCP step now gives a fixed agent key (`EPIGRAPH_MCP_AGENT_KEY`) and
    registers the server with `claude mcp add`. It drops
    `EPIGRAPH_API_URL`, which the MCP server never reads.
  - The first call is now the keyless `recall`. Added a pointer to getting a
    Bearer token.
  - Evidence: `server.rs` boot gates; `ci.yml` (`SQLX_OFFLINE`,
    `pgvector/pgvector:pg16`, superuser `POSTGRES_USER`); migrations 060 and
    161 (`CREATE ROLE`); `crates/epigraph-mcp/src/main.rs` (`--agent-key`).
- 2026-10-13 f93d0709d (via #614): dropped the onboarding row for the
  unwritten `03-walkthroughs` doc.
- 2026-09-05 f41d87303 (via #485): quickstart step 3 sets
  `MIGRATION_DATABASE_URL`, and the README notes that migrating needs DDL
  privilege, which the serving process must not have.
- 2026-05-19 fbf24454a (#168) and fbe4c3b82 (#175): first top-level README,
  with the pitch, a 5-minute quickstart and the onboarding tree. The same
  change landed on two branches.

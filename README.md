# EpiGraph

An epistemic kernel: claims (nouns), edges (verbs), agents that cryptographically sign their assertions, and beliefs propagated via Dempster-Shafer evidence combination. EpiGraph replaces the static-paper model of knowledge with a live loop — hypothesis → experiment → data → analysis → belief update — that downstream applications can interrogate, challenge, and extend.

Where most knowledge bases store *what is currently believed*, EpiGraph stores *what each agent has asserted, with what evidence, signed under what identity, and how those assertions combine into a defensible belief*. It is the substrate the rest of the epigraph-io stack builds on.

## Who is this for?

- **Developers** integrating EpiGraph into an application (build with the Rust crates, talk via the HTTP API, drive via the MCP server)
- **Researchers and analysts** querying the graph via Claude Code (the MCP tools cover recall, neighborhood traversal, challenge/verify, backlog management)
- **Contributors** extending the kernel itself (see [`CLAUDE.md`](CLAUDE.md))

## Status

- Version: 0.3.0
- License: Apache-2.0
- Maturity: alpha — kernel schema and core primitives are stable; layers built on top (workflows, hierarchical extraction, perspectives) iterate

## 5-minute quickstart

```bash
# 1. PostgreSQL with pgvector
createuser epigraph -P && createdb -O epigraph epigraph
psql -d epigraph -c "CREATE EXTENSION vector;"
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph

# 2. Build
git clone https://github.com/epigraph-io/epigraph.git && cd epigraph
cargo build --release -p epigraph-api -p epigraph-mcp

# 3. Migrate + start API
cargo run --release --bin epigraph-migrate
cargo run --release -p epigraph-api --bin server &

# 4. Install MCP server
sudo cp target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp

# 5. Add this to ~/.mcp.json
# {
#   "mcpServers": {
#     "epigraph": {
#       "command": "/usr/local/bin/epigraph-mcp",
#       "args": ["--database-url", "postgres://epigraph:epigraph@localhost:5432/epigraph"],
#       "env": { "OPENAI_API_KEY": "${OPENAI_API_KEY}", "EPIGRAPH_API_URL": "http://127.0.0.1:8080" }
#     }
#   }
# }

# 6. Open Claude Code and ask it to call mcp__epigraph__recall_with_context with query "test".
```

If that works, head to the [full quickstart](docs/intro/01-quickstart.md) for explanations and common-error coverage.

## Onboarding tree

- [`docs/intro/01-quickstart.md`](docs/intro/01-quickstart.md) — six-step setup, prereqs, troubleshooting
- [`docs/intro/02-concepts.md`](docs/intro/02-concepts.md) — noun-claims/verb-edges, agents and signing, DST beliefs, perspectives, hierarchical extraction, backlog discipline
- [`docs/intro/03-walkthroughs.md`](docs/intro/03-walkthroughs.md) — four end-to-end Claude Code transcripts (coming soon — captured live)
- [`docs/intro/04-glossary.md`](docs/intro/04-glossary.md) — vocabulary
- [`docs/intro/05-next-steps.md`](docs/intro/05-next-steps.md) — contributor, deploy, and downstream pointers

## Deeper material

- [`docs/architecture/noun-claims-and-verb-edges.md`](docs/architecture/noun-claims-and-verb-edges.md) — the canonical pattern for what gets stored as a claim vs an edge
- [`docs/conventions/backlog-retirement.md`](docs/conventions/backlog-retirement.md) — how operational backlog items are resolved
- [`docs/deploy.md`](docs/deploy.md) — production deploy runbook
- [`CLAUDE.md`](CLAUDE.md) — agent-session conventions (backlog, schema, tests, workflow)
- [`scripts/README.md`](scripts/README.md) — operational maintenance scripts

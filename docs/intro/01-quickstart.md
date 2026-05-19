# Quickstart

This guide takes you from a clean PostgreSQL + Rust toolchain to a first successful MCP `recall_with_context` call in about ten minutes. Everything below assumes a Unix-like environment (Linux or macOS); Windows users should use WSL2. If you want context on *why* you would run any of this, read [`02-concepts.md`](02-concepts.md) first — this page is purely mechanical setup.

## Prerequisites

- **Rust** ≥ 1.75 (`rustup show` to check)
- **PostgreSQL** 16+ with the `pgvector` extension installed and available (`SELECT extname FROM pg_extension;` should be runnable as a superuser)
- **Claude Code** installed and authenticated — this is the MCP client we'll use to drive EpiGraph
- **OpenAI API key** — exported as `OPENAI_API_KEY`. **Mandatory** for the walkthroughs: `recall_with_context` embeds the query string on every call (see `crates/epigraph-mcp/src/tools/recall.rs`) and fails without a configured embedding provider, even against an empty corpus.
- **~$5 of OpenAI credit** for the embedding calls in the walkthroughs

Time budget: ~10 minutes to first MCP call if your prereqs are in place; ~30 minutes including a fresh Postgres/pgvector install.

## Step 1 — PostgreSQL

```bash
# As a Postgres superuser:
createuser epigraph -P  # set password to 'epigraph' (or any password you wire into DATABASE_URL)
createdb -O epigraph epigraph
psql -d epigraph -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

The runtime role does NOT need `SUPERUSER`. If you also intend to run the test suite (`sqlx::test`), grant `SUPERUSER` temporarily or use a separate test-only role — `sqlx::test` `LOCK`s `pg_namespace` and requires it (see the `feedback_sqlx_test_uses_superuser` memory note).

Set the connection string:

```bash
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph
```

## Step 2 — Clone and build

```bash
git clone https://github.com/epigraph-io/epigraph.git
cd epigraph
cargo build --release -p epigraph-api -p epigraph-mcp -p epigraph-cli
```

Note: the `epigraph-mcp` package produces a binary named `epigraph-mcp-full` (see the `[[bin]]` entry in `crates/epigraph-mcp/Cargo.toml`). That's the binary you'll register with Claude Code in Step 5.

## Step 3 — Migrations

```bash
cargo run --release --bin epigraph-migrate
```

This runs all 32 kernel migrations from `migrations/` (currently `001_initial_schema.sql` through `032_claim_themes_properties.sql`). For a fresh database this should complete in under a minute. If you're applying migrations to a pre-existing production database that was previously tracked under the internal-repo numbering, see the one-shot reconcile procedure in [`docs/deploy.md`](../deploy.md) before running this step.

## Step 4 — Start the API server

```bash
cargo run --release -p epigraph-api --bin server
```

In another shell, verify:

```bash
curl http://127.0.0.1:8080/health
```

Expected: an HTTP 200 with a JSON body like

```json
{"status":"healthy","version":"…","timestamp":"…"}
```

The server logs its bound address on startup; the default is `0.0.0.0:8080` (override with `EPIGRAPH_PORT=<n>` if 8080 is busy or you want to run two servers side-by-side). `DATABASE_URL` from Step 1 is read from the environment at startup; if you forgot to `export` it, the server will panic immediately with a clear message.

## Step 5 — Install the MCP server and register it with Claude Code

Option A: copy the built binary to a path on your `$PATH` (matching the `~/.mcp.json` pattern used in this repo's deployment):

```bash
sudo cp target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp
```

Option B: `cargo install` it (installed binary is named `epigraph-mcp-full`):

```bash
cargo install --path crates/epigraph-mcp
```

Register the server in `~/.mcp.json` (creating the file if it doesn't exist). Use the exact path you installed to:

```json
{
  "mcpServers": {
    "epigraph": {
      "command": "/usr/local/bin/epigraph-mcp",
      "args": [
        "--database-url", "postgres://epigraph:epigraph@localhost:5432/epigraph"
      ],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "EPIGRAPH_API_URL": "http://127.0.0.1:8080"
      }
    }
  }
}
```

If you used Option B and didn't rename the binary, change `"command"` to `"/home/youruser/.cargo/bin/epigraph-mcp-full"`.

## Step 6 — Your first MCP call

Open Claude Code (in any working directory). Tell it:

> Use the `recall_with_context` MCP tool to search for "test".

Claude should call `mcp__epigraph__recall_with_context({"query": "test"})` and you should see a JSON response with a `corpus_scope` object showing zero claims, paragraphs, papers, and themes (assuming a fresh database). For background on what `recall_with_context` is actually doing — embedding the query, scoring against paragraph- and claim-level vectors, returning a hybrid result — see [`02-concepts.md#5--hierarchical-extraction`](02-concepts.md#5--hierarchical-extraction).

Next, ask:

> Use `submit_claim` to add this claim: "EpiGraph is installed correctly."

Claude calls `mcp__epigraph__submit_claim(...)` and returns the created claim's UUID. This newly written row is a noun-claim authored by your agent; the conceptual model behind that split is in [`02-concepts.md#1--noun-claims-vs-verb-edges`](02-concepts.md#1--noun-claims-vs-verb-edges). Call `recall_with_context "installed"` again — you should now see the freshly submitted claim in the results.

If you see the claim, your install is working end-to-end.

## Common errors

| Symptom | Fix |
|---|---|
| `sqlx checksum mismatch` at startup | See the reconcile procedure in [`docs/deploy.md`](../deploy.md); this only happens against a pre-existing internal-numbered DB. |
| `Connection refused (os error 111)` on port 5432 | Postgres isn't running. `pg_isready` to check; start it (`brew services start postgresql@16`, `sudo systemctl start postgresql`, etc.). |
| `extension "vector" is not available` | Install pgvector — see https://github.com/pgvector/pgvector#installation for OS-specific instructions. |
| `OPENAI_API_KEY not set` from MCP server | Export the env var in the shell that launches Claude Code, or hardcode the value in `~/.mcp.json` (less secure). |
| Claude Code can't find the MCP tool | `~/.mcp.json` path wrong, or you renamed the binary inconsistently between the file and `cp`. Recheck the exact `"command"` value. |
| `DATABASE_URL must be set` panic from `epigraph-api` | Step 1's `export` only lasts for the shell that ran it; re-export in the shell that launches the server, or put it in your shell rc file. |
| Port 8080 already in use | Set `EPIGRAPH_PORT=<n>` and re-run; update the `curl` and the `EPIGRAPH_API_URL` in `~/.mcp.json` accordingly. |

## Tear-down

```bash
dropdb epigraph
```

Then drop the role with `dropuser epigraph` if reinstalling.

Once your install is working, the next thing to read is [`02-concepts.md`](02-concepts.md) — it walks through what `claims`, `edges`, agents, perspectives, and DST actually mean in the schema you just migrated. Term-level lookups go to [`04-glossary.md`](04-glossary.md).

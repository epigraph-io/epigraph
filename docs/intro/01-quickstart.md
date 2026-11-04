# Quickstart

This guide takes you from an empty machine to a working local EpiGraph: a
migrated database, the HTTP API answering requests, and an MCP client (Claude
Code in the examples) calling EpiGraph's tools. After each step it shows how to
check that the step worked.

It is a **single-machine trial**. It uses one PostgreSQL superuser for
everything, which is exactly how the project's CI runs. A production instance
splits that into separate database logins with different privileges, and
[`docs/deploy.md`](../deploy.md) explains how. To understand what the pieces
*are* before you install them, read [`02-concepts.md`](02-concepts.md) first.
This page is setup only.

The commands assume Linux or macOS with a POSIX shell. On Windows, use WSL2.

## What you will have at the end

| Process | Binary | Listens on | Database login |
|---|---|---|---|
| HTTP API | `target/release/server` | `0.0.0.0:8080`, plus a metrics listener on `127.0.0.1:9090` | `DATABASE_URL` |
| MCP server (stdio) | `target/release/epigraph-mcp-full` | stdin/stdout of the MCP client that starts it | `DATABASE_URL` |
| Migrator (runs once, then exits) | `target/release/epigraph-migrate` | — | `MIGRATION_DATABASE_URL` |
| OAuth client setup (runs once) | `target/release/bootstrap_clients` | — | `DATABASE_URL` |

## Prerequisites

| You need | Why | Check |
|---|---|---|
| **Rust 1.88 or newer** | The locked dependency graph needs 1.88. `rust-version = "1.75"` in `Cargo.toml` is advisory, for clippy only. CI builds on `stable`. | `rustc --version` |
| **A C toolchain, `pkg-config`, and the OpenSSL development headers** | Several dependencies link OpenSSL (`openssl-sys`, through `native-tls` and `webauthn-rs`). Without them the build stops before it compiles any EpiGraph code. Typical packages: `build-essential pkg-config libssl-dev` (Debian/Ubuntu), `gcc pkgconf openssl-devel` (Fedora), `pkg-config openssl@3` (Homebrew). | `pkg-config --modversion openssl` |
| **PostgreSQL 16 with pgvector** | The schema uses the `vector`, `pg_trgm` and `uuid-ossp` extensions. The easiest route is Docker with the image CI uses, `pgvector/pgvector:pg16`. | `docker --version`, or `psql --version` |
| **`openssl` and `curl`** | Generating secrets and calling the API. | `openssl version`, `curl --version` |
| **Claude Code** (optional) | The MCP client used in step 6. Any MCP client that can launch a stdio server works. | `claude --version` |
| **An OpenAI API key** (optional) | Semantic search. Without a key, the flat `recall` tool falls back to lexical search, and `recall_with_context` refuses. The [keyless path](#step-7--first-mcp-calls) covers this. | — |

**Machine size.** The workspace is large. CI's runners have 4 vCPUs, 16 GB of
RAM and about 14 GB of disk, and CI sets `CARGO_BUILD_JOBS=2` because
unrestricted parallel linking ran out of memory (`SIGBUS` in `rust-lld`) and
disk (`ENOSPC`) there. If your build dies while linking, set
`CARGO_BUILD_JOBS=2` and free some disk.

## Step 1 — PostgreSQL

### Option A: Docker (recommended for a trial)

```bash
docker run -d --name epigraph-db -p 5432:5432 \
  -e POSTGRES_USER=epigraph -e POSTGRES_PASSWORD=epigraph -e POSTGRES_DB=epigraph \
  pgvector/pgvector:pg16
```

In this image `POSTGRES_USER` is a superuser, which is what the migrations
need (see step 3).

**Check:**

```bash
docker exec epigraph-db pg_isready -U epigraph
#   /var/run/postgresql:5432 - accepting connections
docker exec epigraph-db psql -U epigraph -d epigraph -tAc \
  "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
#   t
```

### Option B: a PostgreSQL 16 server you already run

You need pgvector installed on the server
(<https://github.com/pgvector/pgvector#installation>). For a trial, create a
superuser login and a database it owns:

```bash
# As an existing PostgreSQL superuser:
createuser --superuser epigraph -P     # choose a password; it goes into DATABASE_URL
createdb -O epigraph epigraph
```

**Check:** `psql -U epigraph -d epigraph -tAc "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"` prints `t`.

**Why a superuser.** Migration `001` creates three extensions (`pg_trgm`,
`uuid-ossp` and `vector`) with `CREATE EXTENSION IF NOT EXISTS`. Later
migrations create database roles: `epigraph_app`, `epigraph_maintenance` and
`epigraph_seed` (migration 060), and `epigraph_identity_attestor`
(migration 161). They also hand ownership of many functions to
`epigraph_maintenance`. A login without CREATEROLE gets only a NOTICE saying
it "Cannot CREATE ROLE", and is told to provision the role out of band. The
superuser path is the one CI verifies. Installing with a non-superuser
migration login is possible only if someone creates those roles and
extensions beforehand; [`docs/deploy.md`](../deploy.md) describes the roles.

### Set the connection string

In every terminal you use below:

```bash
export DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph
```

Use your own password and host if you took option B.

## Step 2 — Clone and build

```bash
git clone https://github.com/epigraph-io/epigraph.git
cd epigraph
SQLX_OFFLINE=true cargo build --release --locked \
  -p epigraph-api -p epigraph-mcp -p epigraph-cli
```

`SQLX_OFFLINE=true` is important. The workspace uses sqlx's compile-time
checked `query!` macros, and the query metadata they check against is
committed in `.sqlx/`. With `SQLX_OFFLINE=true` the build reads that metadata.
Without it, and with `DATABASE_URL` exported, the macros try to check every
query against your database, which has no tables yet, and the build fails.
CI builds the same way (`SQLX_OFFLINE: "true"` in `.github/workflows/ci.yml`).

The `epigraph-mcp` package builds a binary named `epigraph-mcp-full` (its
`[[bin]]` entry in `crates/epigraph-mcp/Cargo.toml`).

**Check:**

```bash
ls target/release/server target/release/epigraph-migrate \
   target/release/epigraph-mcp-full target/release/bootstrap_clients
```

All four paths should be listed.

## Step 3 — Migrate the database

```bash
MIGRATION_DATABASE_URL="$DATABASE_URL" ./target/release/epigraph-migrate
```

`epigraph-migrate` reads `MIGRATION_DATABASE_URL`. If that is unset, it falls
back to `DATABASE_URL` and logs a warning, because migrating needs DDL
privilege that a production serving login must not have. Here both are the
same superuser, so setting it only silences the warning.

The migrations are embedded in the binary at build time from `migrations/`.
At the revision this page was checked against, that directory holds 158
files, numbered `001_initial_schema.sql` to
`194_retracted_bba_delete_guard.sql`, with gaps in the numbering.

The API server does **not** migrate when it starts, unless you set
`EPIGRAPH_MIGRATE_ON_BOOT=1`. Run this step before step 4.

**Check.** The last line on stdout starts with `migrations: ok`:

```
migrations: ok db_head=194 binary_head=194 applied=158
```

The numbers are what a fresh database is expected to show at that revision.
They were not measured for this page. A later checkout has a higher head.
What matters is that `db_head` equals `binary_head`. On any failure the tool
exits non-zero, prints `migrations: FAILED: <reason>` on stderr, and never
prints the `migrations: ok` marker. A second check, from the database side:

```bash
docker exec epigraph-db psql -U epigraph -d epigraph -tAc \
  "SELECT max(version), count(*) FROM _sqlx_migrations WHERE success"
#   194|158   (at the revision above)
```

## Step 4 — Configure and start the API server

Two pieces of configuration are mandatory. The server refuses to start
without either.

1. **A JWT secret of at least 32 bytes** in `EPIGRAPH_JWT_SECRET`. The server
   also refuses the development literal compiled into the code. For local
   experiments only, `EPIGRAPH_ALLOW_INSECURE_SECRET=1` skips this check
   (`true` and `yes` work too).
2. **A `providers.toml` file**: `./providers.toml` in the working directory,
   or the path in `EPIGRAPH_PROVIDERS_CONFIG`. It lists external identity
   providers, such as Google sign-in. An **empty file is valid** and means
   none. `providers.toml.example` is a template, but copying it unchanged is
   not enough to start the server: it enables Google, which needs
   `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `EPIGRAPH_REDIRECT_URI`.
   `providers.toml` is listed in `.gitignore`.

From the repository root (so that `./providers.toml` resolves):

```bash
: > providers.toml
export EPIGRAPH_JWT_SECRET="$(openssl rand -hex 32)"
./target/release/server
```

Keep this terminal open. The server logs to it. Use a second terminal for the
rest of the guide, and export `DATABASE_URL` and `EPIGRAPH_JWT_SECRET` there
too. The server also reads a `.env` file from its working directory, if one
exists. `.env` files match the `*.env` rule in `.gitignore`.

Optional settings for a trial:

| Variable | Default | Use |
|---|---|---|
| `EPIGRAPH_PORT` | `8080` | The API port. The bind address is always `0.0.0.0`. |
| `EPIGRAPH_METRICS_ADDR` | `127.0.0.1:9090` | The internal `/metrics` listener. Give a second instance its own value, for example `127.0.0.1:0`. |
| `OPENAI_API_KEY` | unset | API-side embeddings. Without it, the API tries `JINA_API_KEY` (only in a build with the `jina` feature), then uses a mock embedder meant for development. |
| `EPIGRAPH_ENV` | unset, which means production | Set it to `development`, `dev`, `test`, `testing`, `local` or `ci` to turn the "provider with no allowlist" startup refusal into a warning. With an empty `providers.toml` it has no effect. |
| `RUST_LOG` | `info,epigraph_api=debug` | Log filter. |

**Never set `MAINTENANCE_DATABASE_URL`** in this terminal or in `.env`. A
request-serving process refuses to start when it is set (see
[Troubleshooting](#troubleshooting)).

**Check the log.** The server checks its configuration in this order and
stops at the first failure: the maintenance DSN, the JWT secret, the passkey
settings, the resource-metadata URL, the database connection, the
session-settings probe, the operator-binding posture, the API signing key,
the entity-type cache, the tenancy triggers, row-security posture, and
finally `providers.toml`. A healthy start contains these lines:

```
Session-GUC probe passed
EPIGRAPH_MIGRATE_ON_BOOT unset — skipping migrations; run `epigraph-migrate`
entity_types registry cache loaded
Internal metrics listener started — update the Prometheus scrape target: /metrics is no longer on the application port
Server listening on 0.0.0.0:8080
```

On a superuser trial, these warnings are expected and harmless:

- `connecting as a role other than epigraph_app ...` (production connects
  as `epigraph_app`);
- `operator binding is NOT ARMED on this database: ...` (arming is a
  production step, described in `docs/deploy.md`);
- `Embedding service: Mock (development only)` (only when no
  `OPENAI_API_KEY` is set);
- `passkeys not configured (EPIGRAPH_WEBAUTHN_RP_ID / _ORIGIN unset): the enrollment ceremony answers 503`.

**Check the health endpoint**, from the second terminal:

```bash
curl -s http://127.0.0.1:8080/health
```

The response is HTTP 200 with a JSON body that has `"status":"healthy"`, the
package `version`, a `timestamp`, and a `belief_modes` object (the
belief-mode settings this process started with). `/health` needs no token.

## Step 5 — Get an API token

Every API route needs a Bearer token, apart from 25 paths: `/health`,
`/api/v1/openapi.json`, the passkey and elevation ceremony pages under
`/elevate/`, and the OAuth and discovery endpoints under `/oauth/` and
`/.well-known/`. You can confirm this:

```bash
curl -i http://127.0.0.1:8080/api/v1/claims
#   HTTP/1.1 401 Unauthorized
#   WWW-Authenticate: Bearer resource_metadata="...", error="invalid_token"
```

Create the three standard service clients: `epigraph-admin`, `epigraph-ro`
(read-only) and `epigraph-wo` (read-write).

```bash
./target/release/bootstrap_clients \
  --legal-entity-name "Local trial" \
  --legal-contact-email "you@example.com"
```

It takes the database from `--database-url` or `DATABASE_URL`. On a trial it
logs a warning that `MAINTENANCE_DATABASE_URL is not set`, which is expected.
It prints one line per client:

```
CREATED: name=epigraph-admin   client_id=epigraph_<32 hex> client_secret=<64 hex>
CREATED: name=epigraph-ro      client_id=epigraph_<32 hex> client_secret=<64 hex>
CREATED: name=epigraph-wo      client_id=epigraph_<32 hex> client_secret=<64 hex>
```

**Copy the secrets now.** The database stores only a hash of each, and they
cannot be shown again. Running the command again is safe. It prints
`EXISTS:` for clients that already exist, and brings their scopes up to the
standard set (`scopes=RECONCILED`).

Get a token for the read-only client with the `client_credentials` grant.
The endpoint accepts JSON or form-encoded bodies.

```bash
curl -s -X POST http://127.0.0.1:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"<epigraph-ro client_id>","client_secret":"<its secret>"}'
#   {"access_token":"...","token_type":"...","expires_in":...,"refresh_token":"...","scope":"..."}
export TOKEN=<the access_token value>
```

**Check:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/claims
```

The response is HTTP 200 with a JSON list, empty on a fresh database. The
first token a client gets also gives that client an agent identity, which is
what the API uses as the token's principal.

## Step 6 — Install the MCP server and register it with Claude Code

### Give the MCP server a stable identity

Every claim an MCP server writes is authored by its signing agent. Without
`--agent-key` (or `EPIGRAPH_MCP_AGENT_KEY`, or `--agent-model` with
`--agent-system-prompt` or `--agent-system-prompt-hash`), each launch creates
a fresh random agent. It prints `Generated new agent keypair` and its
secret key to stderr. It also warns that the ownership-gated tools
(`supersede_claim`, `mark_duplicate`, `resolve_backlog_item`) do not enforce
owner-equality on stdio. Every Claude Code session would then author as a
different agent. Create one key and keep it:

```bash
openssl rand -hex 32 > ~/.epigraph-mcp-key
chmod 600 ~/.epigraph-mcp-key
```

The key is 32 bytes as 64 hex characters, an Ed25519 secret key.

### Check the server starts

```bash
DATABASE_URL="$DATABASE_URL" \
EPIGRAPH_MCP_AGENT_KEY="$(cat ~/.epigraph-mcp-key)" \
  ./target/release/epigraph-mcp-full
```

It logs to stderr. Look for `Session-GUC probe passed`, `Database connected`
and `Agent identity ready`, followed by a line saying it is running in `full`
mode with its tool count. Then it waits for an MCP client on stdin; press
Ctrl-C. If you see `Generated new agent keypair`, the key did not reach the
process.

The database connection can be given as `--database-url` or as the
`DATABASE_URL` environment variable. The environment variable keeps the
password out of the process's command line. The MCP server has no setting
for the API's URL: it talks to the database directly.

### Register it

With Claude Code's CLI (user scope, so every project sees it):

```bash
claude mcp add --scope user epigraph \
  -e DATABASE_URL="$DATABASE_URL" \
  -e EPIGRAPH_MCP_AGENT_KEY="$(cat ~/.epigraph-mcp-key)" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  -- "$PWD/target/release/epigraph-mcp-full"
```

This stores the values you pass with `-e` in Claude Code's configuration.
How and where Claude Code stores MCP servers belongs to Claude Code, not to
this repository. Check `claude mcp add --help` for the scopes your version
supports. A project-scoped `.mcp.json` in a project directory works too:

```json
{
  "mcpServers": {
    "epigraph": {
      "command": "/absolute/path/to/epigraph/target/release/epigraph-mcp-full",
      "env": {
        "DATABASE_URL": "postgres://epigraph:epigraph@localhost:5432/epigraph",
        "EPIGRAPH_MCP_AGENT_KEY": "<the 64 hex characters from ~/.epigraph-mcp-key>",
        "OPENAI_API_KEY": "<your key, or leave this line out>"
      }
    }
  }
}
```

If you prefer the binary on your `PATH`, `cargo install --locked --path
crates/epigraph-mcp` installs `epigraph-mcp-full` into `~/.cargo/bin`. Run it
with `SQLX_OFFLINE=true` for the reason given in step 2.

**Check:** in Claude Code, `/mcp` lists the `epigraph` server as connected.

## Step 7 — First MCP calls

Open Claude Code and ask:

> Use the epigraph `recall` tool to search for "test".

On a fresh database the answer has no results. This call works **without an
OpenAI key**: when the server cannot embed the query, `recall` falls back to
lexical (full-text) search, and logs
`recall: embedder failed; degrading to lexical-only claims leg, no workflows leg`.

Then:

> Use `submit_claim` to add this claim: "EpiGraph is installed correctly."

Claude calls `submit_claim` and gets back the new claim's UUID. The claim is
a noun-claim authored by the MCP server's agent; see
[`02-concepts.md#1--noun-claims-vs-verb-edges`](02-concepts.md#1--noun-claims-vs-verb-edges).
Without an OpenAI key the claim is stored without an embedding. The write
does not fail, and the write-side novelty check, which needs an embedding,
is skipped.

Ask `recall` for "installed" and the claim comes back.

**With an OpenAI key** you can also use `recall_with_context`:

> Use the `recall_with_context` MCP tool to search for "installed".

It embeds the query, runs a vector nearest-neighbour search over every
embedded claim, and adds each hit's structural context: paper, section,
atoms, sibling and neighbour paragraphs, and epistemic edges. See
[`02-concepts.md#5--hierarchical-extraction`](02-concepts.md#5--hierarchical-extraction).
The response has a `results` list and a `corpus_scope` object.

- The submitted claim appears with its UUID in the hit's `paragraph_id`.
  That field holds the hit's claim id, whatever kind of claim it is.
- The hit has **no `paper` key**, `section: null`, and empty `atoms` and
  `siblings` lists. Those are filled from `ingest_document`'s paper →
  section → paragraph → atom tree, and a claim submitted on its own has no
  parent paper. That is expected, not a failure.

Without a key, `recall_with_context` refuses with a fault naming
`could not embed the query`. The embedder's own error is
`embeddings disabled (no API key)`. The MCP server's `--help` says the server
"uses mock embeddings" when no key is given, but the code does not do that:
it disables embedding.

If the claim comes back, your install works end to end.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cargo build` stops in an `openssl-sys` build script | OpenSSL headers or `pkg-config` are missing. Install them (see [Prerequisites](#prerequisites)). |
| `cargo build` says a package requires a newer `rustc` | Your toolchain is older than 1.88. Run `rustup update stable`. |
| `cargo build` fails inside a `query!` macro, with an error about a relation that does not exist or about connecting to the database | You built without `SQLX_OFFLINE=true` while `DATABASE_URL` pointed at an unmigrated database. Rebuild with `SQLX_OFFLINE=true`. |
| The build dies while linking (`SIGBUS`, killed, out of memory), or `No space left on device` | Set `CARGO_BUILD_JOBS=2` and free disk. |
| `Connection refused (os error 111)` on port 5432 | PostgreSQL is not running. `docker start epigraph-db`, or start your server, and check with `pg_isready`. |
| `extension "vector" is not available` | pgvector is not installed on the server. Use the `pgvector/pgvector:pg16` image, or see <https://github.com/pgvector/pgvector#installation>. |
| `permission denied to create extension`, or a migration NOTICE `Cannot CREATE ROLE ...: provision it out of band` | The migration login is not a superuser. Use a superuser for `MIGRATION_DATABASE_URL` (step 1), or provision the extensions and roles in advance (`docs/deploy.md`). |
| `migrations: FAILED: sqlx::migrate failed: ...` mentioning a checksum or a previously applied migration | An applied migration file was edited. Migrations are append-only (`migrations/README.md`). Check out the file as it was when it was applied, or start from a fresh database. |
| `migrations: FAILED: REFUSING: the database has N applied migration version(s) this binary does not embed: ...` | A newer build migrated this database. Build from that revision. For a deliberate rollback only, re-run with `--allow-db-ahead` or `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD=1`. |
| `FATAL: EPIGRAPH_JWT_SECRET is empty. Set a real EPIGRAPH_JWT_SECRET (>= 32 bytes, not the dev literal), or set EPIGRAPH_ALLOW_INSECURE_SECRET=1 for local dev/CI.` (or `... is N bytes; minimum is 32`) | Export `EPIGRAPH_JWT_SECRET` in the terminal that starts the server (step 4). |
| The server panics with `failed to build providers registry: "providers.toml not found at ..."` | There is no `providers.toml` in the server's working directory. Create one (`: > providers.toml`) or set `EPIGRAPH_PROVIDERS_CONFIG`. The message says to copy "providers.toml at repo root"; the template in the repository is `providers.toml.example`. |
| `failed to build providers registry: ... env var GOOGLE_CLIENT_ID not set` | `providers.toml` enables Google sign-in (for example, an unedited copy of `providers.toml.example`). Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `EPIGRAPH_REDIRECT_URI`, or use an empty `providers.toml`. |
| `failed to build providers registry: provider '...': auto_provision is enabled with no allowed_emails/allowed_domains ...` | A provider has empty allowlists, and `EPIGRAPH_ENV` is unset, which counts as production. Fill in the allowlists, set `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`, or, for development, set `EPIGRAPH_ENV=development`. |
| `ERROR: MAINTENANCE_DATABASE_URL is set; a request-serving process never holds the maintenance DSN (operator decision D9). ...` | `server` and `epigraph-mcp-full` refuse to start while that variable is set, including from `.env` or Claude Code's `-e` values. Unset it. Only the maintenance timers and CLIs use it (`docs/deploy.md`). |
| `DATABASE_URL must be set when running with db feature` | `DATABASE_URL` is not exported in the terminal that starts the server. |
| `Failed to load entity_types registry cache`, or `refusing to serve: tenancy triggers are not armed` | The database is not fully migrated. Run step 3. |
| `FATAL: session GUCs do not survive between statements on one pooled connection. ...` | `DATABASE_URL` goes through a transaction-mode connection pooler. Point it at a session-mode endpoint, or set `EPIGRAPH_SESSION_GUC_MODE=transaction`. |
| `Failed to bind to address` | Port 8080 is in use. Set `EPIGRAPH_PORT=<n>`, and change the port in your `curl` commands. |
| `Failed to bind the internal metrics listener; metrics will not be scrapeable. The API continues to serve.` | Another process holds `127.0.0.1:9090`, often a second EpiGraph instance. Set `EPIGRAPH_METRICS_ADDR` (for example `127.0.0.1:0`). |
| `/oauth/token` answers 401, or `Client status is '...', must be 'active'` | A wrong `client_id` or secret, or the client is not active. The `client_id` is the `epigraph_<hex>` value, not the name `epigraph-ro`. |
| The MCP server prints `Generated new agent keypair` | No agent key reached it. Check the `EPIGRAPH_MCP_AGENT_KEY` value in your MCP client's configuration. |
| `recall_with_context` fails with `could not embed the query`, or the log says `embeddings disabled (no API key)` | No `OPENAI_API_KEY` reached the MCP server. Add it to its environment, or use the flat `recall` tool. |
| Claude Code does not list the `epigraph` tools | Run `claude mcp list`. Check that the `command` path is absolute and that the binary exists. Run the binary by hand as in step 6 to see its error. |

## Tear-down

```bash
docker rm -f epigraph-db          # option A: removes the container and its data
# option B:
dropdb epigraph && dropuser epigraph
claude mcp remove epigraph        # if you registered it with claude mcp add
```

## Where to go next

- [`02-concepts.md`](02-concepts.md): what claims, edges, agents,
  perspectives and Dempster-Shafer beliefs mean in the schema you just
  migrated.
- [`04-glossary.md`](04-glossary.md): term lookups.
- [`docs/deploy.md`](../deploy.md): running an instance for other people,
  with separate database logins, the maintenance timers, TLS, and upgrades.

## Change log

Newest first. Each line gives the commit that changed this file. Where a
commit reached `main` through a merge, the PR is given as "via #N".

- 2026-11-04 (this revision): rewrote the file for a reader new to the
  project, checked against `main` at 5fcd75087.
  - The Rust floor goes from 1.75 to 1.88, the version the locked dependency
    graph needs.
  - Added the OpenSSL and `pkg-config` prerequisites and the machine-size
    note.
  - The migration login is now a superuser, as in CI, because migrations
    060 and 161 create roles. The build uses `SQLX_OFFLINE=true`.
  - The migration count goes from "32 migrations, 001 to 032" to 158 files,
    001 to 194, with the `migrations: ok` marker as the check. Dropped the
    unmeasured "under a minute" timing.
  - Added the two settings the server cannot start without
    (`EPIGRAPH_JWT_SECRET` or `EPIGRAPH_ALLOW_INSECURE_SECRET`, and
    `providers.toml` or `EPIGRAPH_PROVIDERS_CONFIG`), the order of the
    startup checks, the expected log lines and warnings, the metrics
    listener, and `belief_modes` in `/health`.
  - Added the token step (`bootstrap_clients`, then `/oauth/token`) and the
    stable MCP agent key.
  - Removed `EPIGRAPH_API_URL` from the MCP configuration (the MCP server
    does not read it) and removed a reference to an internal memory note.
  - Added the keyless `recall` path. Replaced the
    `OPENAI_API_KEY not set` row, a message that does not exist, with the
    real messages. Replaced the startup checksum-mismatch row with what
    `epigraph-migrate` prints.
  - Moved the reconcile pointer for legacy databases to `docs/deploy.md`.
  - Evidence: `Cargo.toml` `[workspace.package]` comment; `ci.yml`;
    `crates/epigraph-api/src/bin/server.rs`; `.../bin/epigraph-migrate.rs`;
    `.../src/migrate.rs`; `crates/epigraph-mcp/src/main.rs` and
    `src/embed.rs`; `crates/epigraph-mcp/src/tools/memory.rs`;
    `crates/epigraph-cli/src/bin/bootstrap_clients.rs`;
    `crates/epigraph-api/tests/public_router_allowlist.rs`.
- 2026-10-15 2c7271eb9 (via #622): described the `recall_with_context`
  `section` key as a serialized null.
- 2026-10-15 0c550b9df (via #622): corrected the quickstart for whole-corpus
  recall (a submitted claim's hit has no paper, section or atoms).
- 2026-10-14 452aab226 (via #614): named what needs the OpenAI key, in place
  of a pointer to the unwritten walkthroughs.
- 2026-05-19 2b38c5dd8 (#168) and 0d497ac3d (#175): first six-step
  quickstart, from clone to first MCP call. The same change landed on two
  branches.

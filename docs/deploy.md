# Deploy runbook

This runbook is for operators who run an EpiGraph instance that other people
use. It covers:

- which processes run, and which database login each one uses;
- a production install from an empty PostgreSQL cluster;
- the configuration each binary reads;
- how migrations are applied;
- how to operate the tenancy, operator-binding and elevation features;
- the deploy order and rollback for each migration that has one.

To try EpiGraph on one machine, use
[`docs/intro/01-quickstart.md`](intro/01-quickstart.md) instead. That is a
single-superuser trial and is deliberately simpler than what follows.

Background for the features named here is in [`docs/tenancy.md`](tenancy.md)
(groups, visibility, operator binding, the custodian role, elevation) and in
[`migrations/README.md`](../migrations/README.md) (the migration ledger). Each
migration's own header is the authoritative record of what it does. This
runbook gives the order in which to do things.

Throughout, `<placeholders>` stand for values from your own deployment. No
unit files, container images or host paths ship in this repository. Where a
refusal message names a unit (`epigraph-cascade-replay.timer`,
`epigraph-jobs-drain.timer`), those are the names the code suggests, and you
may use others.

## Contents

1. [What runs, and on which database login](#1-what-runs-and-on-which-database-login)
2. [A production install, from an empty cluster](#2-a-production-install-from-an-empty-cluster)
3. [Configuration reference](#3-configuration-reference)
4. [Database migrations](#4-database-migrations)
5. [The maintenance DSN and the maintenance timers](#5-the-maintenance-dsn-and-the-maintenance-timers)
6. [Session settings and connection poolers](#6-session-settings-and-connection-poolers)
7. [The HTTP surface](#7-the-http-surface)
8. [OAuth clients, scopes and refresh tokens](#8-oauth-clients-scopes-and-refresh-tokens)
9. [Operator binding, the custodian role, identities, groups and the operator CLI](#9-operator-binding-the-custodian-role-identities-groups-and-the-operator-cli)
10. [Elevation (migrations 124–132)](#10-elevation-migrations-124132)
11. [Upgrade notes by migration](#11-upgrade-notes-by-migration)
12. [Undo scripts and rollback order](#12-undo-scripts-and-rollback-order)
13. [Legacy one-time procedures](#13-legacy-one-time-procedures)
14. [Troubleshooting](#14-troubleshooting)
15. [Change log](#change-log)

## 1. What runs, and on which database login

| Process | Binary (package) | Database variable | Login it should be | Notes |
|---|---|---|---|---|
| HTTP API | `server` (`epigraph-api`) | `DATABASE_URL` | `epigraph_app`, the application login | Serves requests. **Refuses to start when `MAINTENANCE_DATABASE_URL` is set.** Builds no job pool, no maintenance pool and no job runner. |
| MCP server | `epigraph-mcp-full` (`epigraph-mcp`) | `--database-url` / `DATABASE_URL` | `epigraph_app` | stdio by default. HTTP with `--listen`, which needs `--jwt-secret`. Same refusal on `MAINTENANCE_DATABASE_URL`, on every transport. |
| Migrator | `epigraph-migrate` (`epigraph-api`) | `MIGRATION_DATABASE_URL` (falls back to `DATABASE_URL` with a WARN, shown only when `RUST_LOG` enables `warn`; the default filter shows errors only) | the migration login: the schema owner or a superuser | Applies every embedded migration up to the build's head, then exits. |
| Cascade replay | `replay_deferred_cascades` (`epigraph-cli`) | `MAINTENANCE_DATABASE_URL` (**required**; no fallback) and `DATABASE_URL` (naming the same database) | the maintenance login | Applies the cascades every request process defers. Suggested unit: `epigraph-cascade-replay.timer`. |
| Job drain | `drain_jobs` (`epigraph-api`) | `MAINTENANCE_DATABASE_URL` (**required**) and `DATABASE_URL` (the same database) | the maintenance login | Drains the job queue once per run. Suggested unit: `epigraph-jobs-drain.timer`. |
| Operator CLI | `epigraph-operator` (`epigraph-cli`) | `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` **only** | the maintenance login (some verbs need a superuser; each says so) | Audited administrative acts. No fallback to any other variable. |
| Other CLIs | `bootstrap_clients`, `embed_backfill`, `recompute_claim_belief`, `epigraph-tenancy-backfill`, `unmark_duplicate`, `sweep_semantic_duplicates`, `backfill_evidence_type`, `prune_recall_events` and others (`epigraph-cli`) | `MAINTENANCE_DATABASE_URL`, falling back to `DATABASE_URL` with a WARN | the maintenance login | Some refuse the fallback (see section 5). `decompose_claims --as-agent <id>` runs on the application login. |

The four logins:

| Login | Who creates it | Privileges |
|---|---|---|
| **migration login** | you, before the first migrate | Owns the schema or is a superuser. DDL on every table; creates roles and extensions. Used by `epigraph-migrate` and the undo runbooks. |
| **`epigraph_app`** | migration 060 creates the role `NOLOGIN`; **you** give it `LOGIN` and a password | The request path's DML, which row security is written against. Never SUPERUSER, BYPASSRLS, CREATEROLE or CREATEDB. |
| **maintenance login** | you: a login role that is a member of `epigraph_maintenance` | `epigraph_bypass()` is true on it, so it can do cross-tenant maintenance. It must be a NON-superuser with no CREATE on schema `public`. |
| **`epigraph_identity_attestor`** (optional) | migration 161 creates the role `NOLOGIN`; **you** give it `LOGIN` | USAGE on schema `public`, EXECUTE on agent-identity registration (161) and on the role-attachment question `epigraph_role_agent_may_run` (166), nothing else. Needed only if a host registers agent identities (section 9). |

Migration 060 also creates `epigraph_seed` (`NOLOGIN`), the fixture escape
hatch of migration 074. Nothing connects as it in production.

Six `epigraph-operator` verbs need a SUPERUSER DSN, because their probe
switches the session to the application role: `reown-claims`,
`reown-linked`, `reown-reverse`, `restrict-claims`, `regroup-claims` and
`hide-evidence` (its `--apply`). For those runs only, point `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` at
a superuser login (the migration login, if it is one). The standing maintenance login, the one in
`MAINTENANCE_DATABASE_URL` and in every other operator run, stays a
non-superuser.

No migration grants a role LOGIN or carries a password.
`crates/epigraph-db/tests/schema_contract.rs::no_migration_grants_a_role_login`
fails on any migration that does. The repository is public, and credentials
never land in it. `schema_contract.rs::tenancy_roles_are_nologin` allows the
out-of-band `epigraph_app` login, and asserts that it is never SUPERUSER,
BYPASSRLS, CREATEROLE or CREATEDB, while `epigraph_maintenance` and
`epigraph_seed` must stay NOLOGIN.

## 2. A production install, from an empty cluster

Run the steps in order. Each ends with a check.

### Step 1 — Build every binary from one commit

```bash
git clone https://github.com/epigraph-io/epigraph.git <deploy-checkout>
cd <deploy-checkout>
git rev-parse HEAD                    # record this commit
SQLX_OFFLINE=true cargo build --release --locked \
  -p epigraph-api -p epigraph-mcp -p epigraph-cli
```

Add `--features epigraph-api/tls` to that command if the API terminates TLS
itself (step 8). The build needs Rust 1.88 or newer, `pkg-config` and the
OpenSSL headers; see the quickstart's prerequisites. Build every binary you
deploy from the same commit. Several deploy orders below depend on it.

**Check:** the newest file in `migrations/` is embedded in the build. See
[Stale binaries from a shared target directory](#stale-binaries-from-a-shared-target-directory).

### Step 2 — Create the database and the migration login

As a PostgreSQL superuser, on PostgreSQL 16 with pgvector installed:

```sql
CREATE ROLE <migration_login> LOGIN SUPERUSER PASSWORD '<secret>';  -- or a schema owner; see below
CREATE DATABASE epigraph OWNER <migration_login>;
```

Migration `001` runs `CREATE EXTENSION IF NOT EXISTS` for `pg_trgm`,
`uuid-ossp` and `vector`, all in schema `public`. Migrations 060 and 161 run
`CREATE ROLE`. A superuser migration login does all of this itself, and it is
the configuration CI verifies (`pgvector/pgvector:pg16`, whose
`POSTGRES_USER` is a superuser). With a non-superuser schema owner, a
superuser must first create the three extensions in the database and the
roles `epigraph_app`, `epigraph_maintenance` and `epigraph_seed` (all
`NOLOGIN`, members of nothing). Without CREATEROLE, migrations 060 and 161
only raise a NOTICE ("Cannot CREATE ROLE ...: provision it out of band"),
and 161 then skips the attestor grant (section 9 has the recipe). That path
is not exercised by CI.

**Check:** `psql "<migration DSN>" -c 'SELECT 1'` connects.

### Step 3 — Migrate

```bash
MIGRATION_DATABASE_URL='<migration DSN>' ./target/release/epigraph-migrate
```

**Check:** the last stdout line is
`migrations: ok db_head=<n> binary_head=<n> applied=<k>`, with `db_head`
equal to `binary_head`. On a fresh database at a build whose newest
migration is `194_retracted_bba_delete_guard.sql`, the expected line is
`migrations: ok db_head=194 binary_head=194 applied=158`. That is computed
from the 158 files in `migrations/`, not measured. Section 4 describes the
marker and every refusal.

### Step 4 — Give the application role a login

Migration 060 created `epigraph_app`. Give it a login out of band:

```sql
ALTER ROLE epigraph_app LOGIN PASSWORD '<secret>';
```

This `ALTER ROLE` is what arms the row-security posture assertion in the
request units. The assertion is keyed on `current_user = 'epigraph_app'`, so
it is inert on any other login and fully armed on this one. A request unit
that connects as any other role logs a WARN, not a refusal
(`epigraph_api::state::rls_verdict` carries the reasoning).

**Check:** `psql "postgres://epigraph_app:<secret>@<host>/epigraph" -c 'SELECT current_user'` prints `epigraph_app`.

### Step 5 — Create the maintenance login

```sql
CREATE ROLE <maintenance_login> LOGIN PASSWORD '<secret>';   -- NOT superuser; INHERIT is the default
GRANT epigraph_maintenance TO <maintenance_login>;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;                  -- see below
```

`epigraph_maintenance` itself is `NOLOGIN`: it is a role you grant, not a
login. Membership is what makes `epigraph_bypass()` true, and what gives the
login the role's table grants (`SELECT, INSERT, UPDATE` schema-wide from
migration 070, `DELETE` on the job tables from 119, and the others listed in
section 5). PostgreSQL 15 and later give `PUBLIC` no CREATE on `public`. A
cluster upgraded from an older default keeps that grant. The `REVOKE` above
removes it, and `epigraph-tenancy-backfill verify` fails until it is gone.
Section 10 explains why that matters: a maintenance login that can CREATE in
`public` could replace an elevation gate function.

The maintenance login must **not** be the superuser. A superuser passes every
bypass check, and the elevation preconditions refuse it.

**Check:**

```bash
MAINTENANCE_DATABASE_URL='<maintenance DSN>' DATABASE_URL='<application DSN>' \
  ./target/release/epigraph-tenancy-backfill verify
```

It checks the owner and grants of the maintenance-owned definer functions,
the CREATE-on-`public` rule above, and that no row lacks a tenancy
declaration. It must report no ownership, grant or CREATE fault. Exit 0 is
the expected result on a correctly provisioned fresh database, but this
runbook has not measured it. Without `--legacy-owner`, `verify` is the
strict check, which also fails on any world-owned row in the tables it
walks. If it reports only world-owned rows, re-run it with
`--legacy-owner platform`. That form treats world-owned rows of unlinked
authors as the platform corpus and reports them instead of failing on them.

### Step 6 — Create the first OAuth clients

```bash
MAINTENANCE_DATABASE_URL='<maintenance DSN>' DATABASE_URL='<application DSN>' \
  ./target/release/bootstrap_clients \
    --legal-entity-name "<your organisation>" \
    --legal-contact-email "<ops contact>"
```

This creates the service clients `epigraph-admin`, `epigraph-ro` and
`epigraph-wo` and prints each `client_id` and `client_secret` **once**. The
database keeps only a blake3 hash. Store the secrets in your secret store. A
re-run prints `EXISTS:` and rewrites an existing canonical client's
`allowed_scopes` and `granted_scopes` to the canonical set
(`scopes=RECONCILED`). Section 8 says how a scope change reaches clients that
already hold refresh tokens.

**Check:** three `CREATED:` lines on the first run.

### Step 7 — Write `providers.toml`

`providers.toml` declares external identity providers (Google sign-in,
Cloudflare Access). The server reads `./providers.toml` from its working
directory, or the path in `EPIGRAPH_PROVIDERS_CONFIG`, and **refuses to
start without the file**. An empty file is valid and configures no provider.
Start from `providers.toml.example`. Every provider with
`auto_provision = true` needs a populated `allowed_emails` or
`allowed_domains`. Otherwise, while `EPIGRAPH_ENV` is unset (which counts as
production), the server refuses to start. The alternatives are
`EPIGRAPH_ALLOW_ALL_IDENTITIES=true` (any identity the provider authenticates
may provision), or, in development only, `EPIGRAPH_ENV=development` (also
`dev`, `test`, `testing`, `local`, `ci`), which turns the refusal into a
warning. The allowlist is checked again on refresh, so removing an address
stops that client renewing. Every scope in `default_scopes` must exist in
`crates/epigraph-core/src/canonical_scopes.rs`.

### Step 8 — Configure and start the API

The minimum production environment for `server`:

```ini
DATABASE_URL=postgres://epigraph_app:<secret>@<host>:5432/epigraph
EPIGRAPH_JWT_SECRET=<at least 32 random bytes>
EPIGRAPH_PUBLIC_BASE_URL=https://<your-host>
EPIGRAPH_PROVIDERS_CONFIG=<path to providers.toml>
# OPENAI_API_KEY=<key>            # semantic search and embedding on write
# EPIGRAPH_METRICS_ADDR=127.0.0.1:9090
```

- **TLS.** Either build with `--features epigraph-api/tls` and set both `EPIGRAPH_TLS_CERT`
  and `EPIGRAPH_TLS_KEY` (PEM paths), or run the API behind a reverse proxy
  that terminates TLS. `EPIGRAPH_PUBLIC_BASE_URL` must be the public origin
  either way. It is used in OAuth discovery documents and consent links, and
  it defaults to `http://localhost:8080`.
- **Metrics** are served only on the internal listener
  `EPIGRAPH_METRICS_ADDR` (default `127.0.0.1:9090`), never on the
  application port. See section 7.
- **The JWT secret is shared** by the API and every HTTP MCP unit (`--jwt-secret`
  / `EPIGRAPH_JWT_SECRET`): one signs, both verify. To rotate it, restart
  both with the new value.
- **Never set `MAINTENANCE_DATABASE_URL`** in this unit's environment. Watch
  out for a `.env` file in its working directory too: the server loads one if
  it exists.

**Check.** The log contains `Session-GUC probe passed`,
`entity_types registry cache loaded`, `Internal metrics listener started`
and `Server listening on 0.0.0.0:<port>`. An operator-binding line is also
logged: `operator binding is NOT ARMED on this database: ...` until you arm it
(section 9). Then:

```bash
curl -s https://<your-host>/health
```

It returns `{"status":"healthy","version":...,"timestamp":...,"belief_modes":{...}}`.
`/health` is anonymous. Everything else needs a token. Get one from
`/oauth/token` with a client from step 6
(`grant_type=client_credentials`; JSON or form-encoded).

### Step 9 — Configure and start the MCP server(s)

stdio, for an agent or an operator's MCP client:

```bash
DATABASE_URL='<application DSN>' \
EPIGRAPH_MCP_AGENT_KEY='<64 hex: a fixed Ed25519 secret key>' \
OPENAI_API_KEY='<key>' \
  ./target/release/epigraph-mcp-full
```

HTTP, for remote MCP clients:

```bash
DATABASE_URL='<application DSN>' EPIGRAPH_JWT_SECRET='<same as the API>' \
EPIGRAPH_PUBLIC_BASE_URL=https://<your-host> \
  ./target/release/epigraph-mcp-full --listen 127.0.0.1:<port> \
    --allowed-host <public MCP host name>
```

- A TCP `--listen` address requires `--jwt-secret`. A `unix:/abs/path`
  listener may use `--allow-unauthenticated-http` instead, because its file
  permissions are the trust gate; TCP may not.
- The HTTP listener rejects any request whose `Host` (or `Origin`) is outside
  its allowlist. The list always holds `localhost`, `127.0.0.1`, `::1` and
  the `--listen` authority. Behind a reverse proxy that preserves the
  client's `Host`, add the public name with `--allowed-host`
  (`EPIGRAPH_MCP_ALLOWED_HOSTS`, comma-separated). Ports are ignored.
- Give every stdio server a declared identity: `--agent-key`, or
  `--agent-model` with `--agent-system-prompt` or `--agent-system-prompt-hash`,
  or the separate-signing-key mode (section 9). Without one, every launch
  prints `Generated new agent keypair` and a secret key to stderr, authors as
  a new random agent, and logs that the ownership-gated tools
  (`supersede_claim`, `mark_duplicate`, `resolve_backlog_item`) do not
  enforce owner-equality on stdio.

**Check:** stderr shows `Session-GUC probe passed`, `Database connected` and
`Agent identity ready`, and does not show `Generated new agent keypair`.

### Step 10 — Schedule the maintenance jobs

Nothing in a request process applies cascades or runs jobs. Create these on
the host that holds the maintenance DSN, each with a 0600 environment file
holding `MAINTENANCE_DATABASE_URL` and `DATABASE_URL` (naming the same
database). All four refuse to start without `DATABASE_URL`; the three
`epigraph-cli` binaries also accept it as `--database-url`, while `drain_jobs`
reads it from the environment only:

| Job | Command | Cadence | Notes |
|---|---|---|---|
| Cascade replay | `replay_deferred_cascades --max-failures 20` | every 90 s (the binary's own documentation) | Exit 2 while a cascade is stuck: read the report and `--retire <event id> --reason <text>` it. `--report-only` is a read-only staleness check that takes no lock. |
| Job drain | `drain_jobs` | your choice; one run drains until empty or `--max-runtime` (default 50 min) | Exit 0 drained (or `{"locked": true}`), 1 a job failed or the run could not start, 3 out of time with work pending. |
| Embedding backfill | `embed_backfill` | as needed | Fills `NULL` claim embeddings and `workflows.goal_embedding`. Needs `OPENAI_API_KEY` (or `--allow-mock` for a non-production smoke run). |
| Retention | `prune_recall_events` | daily | Prunes `recall_events` and telemetry `events` past `RECALL_EVENTS_RETENTION_DAYS` (default 90). Runs on a NOSUPERUSER maintenance login only from migration 186 on. |

`replay_deferred_cascades` and `drain_jobs` each take their own session
advisory lock, so an overlapping or hand-started run prints
`{"locked": true}`, exits 0 and does nothing. `embed_backfill` and
`prune_recall_events` take no lock; do not schedule overlapping runs of
them.

### Step 11 — Bind writers and arm, when you are ready

A fresh database starts **unarmed**: claims by agents that are not bound to a
human operator are accepted, and every request unit logs that at boot. Before
you invite other people:

- register the human operators and link their agents, then arm operator
  binding (the [operator binding section](#operator-binding-migration-122--deploy-order));
- optionally, bootstrap a custodian (the
  [custodian role section](#the-custodian-role-migration-123--deploy-order-and-rollback));
- optionally, set up passkeys and elevation (section 10).

On a fresh database there is no legacy corpus. The legacy steps of those
sections (the legacy-author tie, the backfill, the re-own) find nothing to do.

## 3. Configuration reference

Variables are read once at startup unless a row says otherwise. On/off
switches do not share one parser:

- `EPIGRAPH_MIGRATE_ON_BOOT` and `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD`: `1`,
  `true` or `yes`, case-insensitive, surrounding whitespace ignored.
- `EPIGRAPH_ALLOW_INSECURE_SECRET` and `EPIGRAPH_REQUIRE_SIGNATURES`: `1`,
  `true` or `yes`, case-insensitive, whitespace **not** ignored.
- `EPIGRAPH_ALLOW_ALL_IDENTITIES`: exactly `true`.
- `EPIGRAPH_RUN_TOKENS`, `EPIGRAPH_BP_APPLY` and
  `EPIGRAPH_MCP_CONNECTOR_ELEVATION`: `on`, case-insensitive, whitespace
  ignored.
- `EPIGRAPH_MCP_LOG_PAYLOADS`: `1` or `true` (case-insensitive), whitespace
  ignored.
- `EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION` and
  `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY`: `1`/`true`/`yes` or
  `0`/`false`/`no`, case-insensitive, whitespace ignored. When passkeys are
  configured, any other value stops the server at boot.

For the others, anything else is off.

### `server` (the HTTP API)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | — (required) | The application DSN. A missing value panics with `DATABASE_URL must be set when running with db feature`. |
| `MAINTENANCE_DATABASE_URL` | must be unset | Set (and non-blank) → exit 1 before anything else. |
| `EPIGRAPH_JWT_SECRET` | — | HMAC secret for access tokens, at least 32 bytes and not the committed development literal, or the server exits 1 with `FATAL: ...`. |
| `EPIGRAPH_ALLOW_INSECURE_SECRET` | off | `1`/`true`/`yes` skips the JWT secret check. Local development and CI only. |
| `EPIGRAPH_PROVIDERS_CONFIG` | `./providers.toml` | Path to the identity-provider file. Missing → startup panic. |
| `EPIGRAPH_ENV` | unset = production | `development`, `dev`, `test`, `testing`, `local` or `ci` turn the empty-allowlist refusal into a warning. |
| `EPIGRAPH_ALLOW_ALL_IDENTITIES` | off | Exactly `true` lets any identity an auto-provisioning provider authenticates provision. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `EPIGRAPH_REDIRECT_URI` | — | Read only because `providers.toml.example`'s Google provider names them (`client_id_env`, `client_secret_env`, `audience_env`, `redirect_uri_env`). Missing while the provider is configured → startup refusal (`env var ... not set`). |
| `EPIGRAPH_PUBLIC_BASE_URL` | `http://localhost:8080` | The public origin, with no trailing slash. |
| `EPIGRAPH_RESOURCE_METADATA_URL` | `${EPIGRAPH_PUBLIC_BASE_URL}/.well-known/oauth-protected-resource` | Advertised in every 401's `WWW-Authenticate`. A value that cannot go in an HTTP header → exit 1. |
| `EPIGRAPH_PORT` | `8080` | The application port. The bind address is `0.0.0.0`. |
| `EPIGRAPH_METRICS_ADDR` | `127.0.0.1:9090` | The internal `/metrics` listener. A bind failure logs an error, and the API keeps serving without metrics. |
| `EPIGRAPH_TLS_CERT`, `EPIGRAPH_TLS_KEY` | unset | Both set, in a build with the `tls` feature → HTTPS on the same port. |
| `EPIGRAPH_SESSION_GUC_MODE` | `session` | `transaction` for a transaction-mode pooler (section 6). Any other value is `session`. |
| `EPIGRAPH_MIGRATE_ON_BOOT` | off | `1`/`true`/`yes` → the server applies migrations at boot and panics on failure. The supported path is `epigraph-migrate`. |
| `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD` | off | The deliberate-rollback opt-in, for any entry point that migrates (section 4). |
| `EPIGRAPH_REQUIRE_SIGNATURES` | off | Enforces Ed25519 payload signatures on `POST /api/v1/submit/packet` only (section 7). |
| `EPIGRAPH_API_SIGNING_KEY_FILE` | unset | A file holding the API's own 32-byte Ed25519 edge-signing key, as 64 hex characters. Unset → HTTP edges are written unsigned, logged once. Set but unusable → the server refuses to start. The module doc of `crates/epigraph-api/src/edge_signer.rs` covers rotation. |
| `EPIGRAPH_WEBAUTHN_RP_ID`, `EPIGRAPH_WEBAUTHN_ORIGIN` | unset | The passkey relying party. Both unset → passkeys off, and the ceremonies answer 503. A partial or malformed configuration → exit 1. The RP id is effectively permanent: a passkey registered under one never asserts under another. |
| `EPIGRAPH_WEBAUTHN_AAGUIDS`, `EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE` | — | The attestation allowlist (authenticator model UUIDs) and the PEM file of the roots they chain to: `packed` and `tpm` attestation by a listed model. Both or neither; required unless `EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE` is set. |
| `EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE` | unset | A PEM file of Android hardware attestation roots. They are trusted for EVERY key they attest, but only in the `android-key` format, for a device-bound (not backup-eligible), user-verified credential whose attestation puts it in a TEE or StrongBox; any other format chaining to them is refused. Usable alone or with the allowlist. Requires `EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE`. An unreadable file, one with no certificate, a certificate that does not parse, or a root also in `EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE` → exit 1. Section 10, "Android hardware keys and a synced second passkey". |
| `EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE` | unset | A local copy of Google's attestation status list (the JSON at `https://android.googleapis.com/attestation/status`), refreshed by an operator job; the API never fetches it. REQUIRED with `EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE` (either without the other → exit 1, as is a file that is unreadable or not a status list). Re-read at every Android enrollment and anchor use; a listed certificate anywhere in the chain refuses, and a file older than 48 hours (by modification time) refuses every Android enrollment and anchor. Section 10, as above. |
| `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY` | off | On: a person's LATER passkey, enrolled on a confirmed `passkey.register` act, may carry no attestation (a synced passkey, e.g. a password manager's), when the act was confirmed by one of that person's live passkeys that is hardware-attested under the CURRENT configuration, as is every passkey that authorized it. A first passkey is always attested. Served on an armed database. Needs migration 200. Section 10, as above. |
| `EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION` | off | Tests and development only. Accepts `none` and self attestation. Refused at boot on a database armed for operator binding, and with either setting above (exit 1). |
| `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT` | on | `off` is the emergency valve for operator binding: it relieves `OPL01` only (section 9). |
| `EPIGRAPH_REQUEST_UNIT_RECHECK_SECS` | `30` (1–300) | How often a running request unit re-reads its database posture. |
| `EPIGRAPH_RUN_TOKENS` | `off` | `on` admits delegated run tokens where their delegation is live. Any other value stays off and is warned about. |
| `EPIGRAPH_RUN_TOKEN_MODELS` | empty | The LLM models a run token may be minted for. Empty refuses every mint. |
| `EPIGRAPH_BP_APPLY` | `off` | `on` lets `POST /api/v1/bp/propagate` write results to atom claims. BP apply is retired; compounds are never written. |
| `EPIGRAPH_TENANCY_GAUGE_INTERVAL_SECS` | `30` | The tick of the tenancy gauges exported on the metrics listener. |
| `OPENAI_API_KEY`, `JINA_API_KEY`, `EMBEDDING_DIMENSION` | unset, unset, `1536` | The embedding provider. OpenAI first; then Jina, which works only in a build with the `jina` feature; otherwise a mock provider for development (`Embedding service: Mock (development only)`). |
| `CALIBRATION_PATH` | the `calibration.toml` compiled into the binary | An override file. One that does not load is logged as an error, and the compiled-in calibration is served instead. Changes need a restart. |
| `EPIGRAPH_ATOM_FOLD` (`legacy`\|`aef_standalone`\|`aef`), `EPIGRAPH_COMPOUND_BELIEF` (`legacy`\|`shadow`\|`progressive`\|`strict`), `EPIGRAPH_COMPOUND_WRITE_GUARD` (`warn`\|`refuse`), `EPIGRAPH_COMPOUND_SOURCE_EDGES` (`frozen`\|`excluded`), `EPIGRAPH_ATOM_CACHE_MODE` (`display`\|`pure`), `EPIGRAPH_INFERENCE` (`off`\|`shadow`\|`on`) | the first value listed for each | The belief modes. Logged at boot (`belief modes read at startup`) and reported in `/health`. An unrecognised value runs the default and logs `belief-mode flag ignored`. |
| `RUST_LOG` | `info,epigraph_api=debug` | Log filter. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | In an `otel` build, only logged: the OTLP exporter is not initialised by this binary. |

### `epigraph-mcp-full` (the MCP server)

| Flag / variable | Default | Meaning |
|---|---|---|
| `--database-url` / `DATABASE_URL` | — (required) | The application DSN. The variable keeps it out of `argv`. |
| `MAINTENANCE_DATABASE_URL` | must be unset | Set → exit 1, on every transport. |
| `--agent-key` / `EPIGRAPH_MCP_AGENT_KEY` | unset | The signer's Ed25519 secret key, 64 hex characters. |
| `--agent-model` / `EPIGRAPH_AGENT_MODEL`, with `--agent-system-prompt` / `EPIGRAPH_AGENT_SYSTEM_PROMPT` or `--agent-system-prompt-hash` / `EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH` | unset | Derives the identity deterministically from (model, prompt). It takes precedence over `--agent-key`. The raw prompt is hashed (BLAKE3) and never logged. |
| `--agent-identity-pubkey` / `EPIGRAPH_AGENT_IDENTITY_PUBKEY` with `EPIGRAPH_AGENT_SIGNING_KEY` (environment only) | unset | The separate-signing-key mode: the host registered the identity, and the process signs with a different, active `signing` key of that agent. stdio only. Excludes the two options above. |
| `--openai-api-key` / `OPENAI_API_KEY` | unset | Embeddings. Unset → embedding is disabled (`embeddings disabled (no API key)`). The flag's `--help` text says "mock embeddings"; the code disables embedding instead. |
| `--listen` | stdio | `host:port` or `unix:/abs/path`. |
| `--jwt-secret` / `EPIGRAPH_JWT_SECRET` | — | Required for a TCP `--listen`. At least 32 bytes. The same secret as the API. |
| `--allow-unauthenticated-http`, `--allow-unauthenticated-writes` | off | Unix-socket listeners only. Writes are then authored by the listener's own unlinked signer. |
| `--allowed-host` / `EPIGRAPH_MCP_ALLOWED_HOSTS` | — | Extra `Host`/`Origin` names for the HTTP listener. |
| `--read-only` | off | Query tools only. |
| `--operator-id` / `EPIGRAPH_OPERATOR_ID` | unset | Records `signer --OPERATED_BY--> operator` at startup. stdio only, with a declared identity. The link function is maintenance-only, so the startup fails on an application DSN; run `epigraph-operator link` from the host instead (section 9). |
| `--resource-metadata-url` / `EPIGRAPH_RESOURCE_METADATA_URL` | unset | Advertised in the HTTP listener's 401 challenges. |
| `EPIGRAPH_PUBLIC_BASE_URL` | unset | The API's public origin. HTTP transport only. `sudo` and `propose_admin_act` refuse without it. |
| `EPIGRAPH_MCP_CONNECTOR_ELEVATION` | off | `on` lets the HTTP transport elevate connector-mode sessions. Leave it unset (section 10). |
| `EPIGRAPH_RUN_TOKENS` | `off` | As for the API. |
| `EPIGRAPH_SESSION_GUC_MODE` | `session` | As for the API. |
| `EPIGRAPH_MCP_EXTENSIONS` | unset | Federated downstream MCP servers. A malformed value is a boot error. See `crates/epigraph-mcp/src/federation/`. |
| `EPIGRAPH_MCP_DISCOVERY_TOKEN` (or `EPIGRAPH_SERVICE_TOKEN`) | empty | The gateway's service token for federated tool discovery. |
| `EPIGRAPH_MCP_RECONNECT_SECS` | `30` | How often an unhealthy extension is re-dialled. |
| `EPIGRAPH_MCP_PROFILE_ROOT`, `EPIGRAPH_MCP_PROFILE_PIN`, `EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES` | unset | Label-dedup tool configuration (`crates/epigraph-mcp/src/tools/label_dedup.rs`). |
| `EPIGRAPH_MCP_LOG_PAYLOADS` | off | Lifts the INFO cap on `rmcp` logging, which then writes request and result bodies to the log. Local debugging only. |
| `RUST_LOG` | `epigraph_mcp=info,tenancy=info` | Log filter, to stderr. `rmcp*` is capped at INFO regardless. |
| `CALIBRATION_PATH`, the belief-mode variables | as for the API | |

The MCP server does not read `EPIGRAPH_API_URL`: it talks to the database,
not to the API.

### `epigraph-migrate`

| Flag / variable | Meaning |
|---|---|
| `MIGRATION_DATABASE_URL` | The migration DSN. Unset → `DATABASE_URL`, with a WARN, shown only when `RUST_LOG` enables `warn` (for example `RUST_LOG=info`); the default filter shows errors only. |
| `--allow-db-ahead` / `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD=1` | The deliberate-rollback opt-in (section 4). |

### `drain_jobs` and `replay_deferred_cascades`

| Variable / flag | Binary | Meaning |
|---|---|---|
| `MAINTENANCE_DATABASE_URL` | both | Required. The fallback to `DATABASE_URL` is refused. |
| `DATABASE_URL` | both | Must name the same database: compared by effective database name. A different host or port only WARNs. |
| `EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS` | `drain_jobs` | The drain pool's `statement_timeout`. Default 45 minutes. |
| `--max-runtime <DURATION>` | `drain_jobs` | Seconds, or a number with `s`, `m`/`min` or `h`. Default 50 min. |
| `--limit` (200), `--max-failures`, `--retire <id> --reason <text>`, `--report-only`, `--replayed-by`, `--sweep-withdrawn-edge-bbas --acting-agent <id> --reason <text>` | `replay_deferred_cascades` | See the binary's module doc. |

### `epigraph-operator`

| Variable | Meaning |
|---|---|
| `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` | The only DSN it reads. A login outside `epigraph_maintenance` is refused. Six verbs need a superuser DSN instead and say so (`reown-claims`, `reown-linked`, `reown-reverse`, `restrict-claims`, `regroup-claims`, and `hide-evidence` for its `--apply`). |
| `EPIGRAPH_WEBAUTHN_RP_ID`, `EPIGRAPH_WEBAUTHN_ORIGIN` | Required by `verify-confirmations`: the values the API's ceremonies ran under. |

### Other CLIs and scripts

| Variable | Read by | Meaning |
|---|---|---|
| `MAINTENANCE_DATABASE_URL` | the maintenance CLIs | Preferred over `DATABASE_URL`. The fallback WARNs, and some binaries refuse it (section 5). |
| `EPIGRAPH_API` | `decompose_claims` and the belief-mode check in `recompute_betp`, `backfill_factors` and `refresh_truth_mirrors` (read before `EPIGRAPH_API_URL`); `epigraph-privatize` (the only API variable it reads); `scripts/reconcile_backlog_labels.py` (`--base-url` default) | The API's base URL, explicit override. |
| `EPIGRAPH_API_URL` | among them `dekg`, `decompose_claims`, `recompute_betp`, `backfill_factors`, `refresh_truth_mirrors`, `scripts/maintain_themes.py`, `scripts/run_assessment_worker.py` | The API's base URL, for CLIs that call the HTTP API. |
| `EPIGRAPH_TOKEN` | among them `dekg`, `decompose_claims`, `ingest_literature`, `epigraph-privatize`, `scripts/reconcile_backlog_labels.py`, `scripts/cleanup_backlog_labels.py`, `scripts/maintain_themes.py`, `scripts/fuzzy_dedup_claims.py` | A Bearer token. The listed scripts exit when it is unset (`fuzzy_dedup_claims.py` only with `--execute`). |
| `EPIGRAPH_SERVICE_CLIENT_ID`, `EPIGRAPH_SERVICE_SECRET`, `EPIGRAPH_OAUTH_TOKEN_URL` | `decompose_claims` | Mint a token with `client_credentials` instead of passing `EPIGRAPH_TOKEN`. |
| `EPIGRAPH_AGENT_ID` | `scripts/_api_client.py` | The `agent_id` claim of tokens the Python helpers mint (section 7). |
| `RECALL_EVENTS_RETENTION_DAYS` | `prune_recall_events` | Retention in days, default 90. |

## 4. Database migrations

### How migrations are applied

Migrations are applied by the `epigraph-migrate` binary, run explicitly
**before** the API starts. You can run it by hand, as a oneshot unit ordered
before the API, or as an `ExecStartPre=` of the API unit. An `ExecStartPre=`
runs with the API unit's environment, so the migration DSN then sits in the
serving unit's environment file. A separate unit keeps it out.

The API binary does *not* migrate at boot unless `EPIGRAPH_MIGRATE_ON_BOOT=1`
is set in its environment (`true` and `yes` also work, case-insensitively and
ignoring surrounding whitespace). Any other value, including `0`, `false` and
the empty string, skips. Booting without migrating logs
`EPIGRAPH_MIGRATE_ON_BOOT unset — skipping migrations; run `epigraph-migrate``.
Several migrations (074, 075 and 084 among them) `RAISE` when their
preconditions do not hold, and the boot-time call site panics on failure, so
an unattended boot-time apply turns a precondition failure into a crash loop.
Keep migration an explicit step.

`epigraph-migrate` reads `MIGRATION_DATABASE_URL`, falling back to
`DATABASE_URL` with a `WARN`. That WARN is shown only when `RUST_LOG` enables
`warn` (for example `RUST_LOG=info`); the default filter shows errors only.
The two are different credentials on purpose.
Applying migrations needs **DDL privilege on every tier-A table** (from
migration 074 on, the migrator drops column defaults and creates 23
triggers), which is strictly stronger than either of the other two roles:

| Role | Holds | Can it migrate? |
|---|---|---|
| `epigraph_app` | the application's DML | **No.** After 074 it cannot even `ALTER TABLE … SET DEFAULT`; `tenancy_required.rs` asserts that. |
| `epigraph_maintenance` | `SELECT, INSERT, UPDATE` schema-wide (migration 070), plus the grants listed in section 5 | **No.** No DDL at all. |
| the migration role | table ownership / DDL | Yes. This is what `MIGRATION_DATABASE_URL` points at. |

The fallback keeps a unit that sets only `DATABASE_URL` working, with a
warning. It is not an end state: the serving process must NOT hold DDL
privilege.

`epigraph-migrate` honours `-- no-transaction` migrations (the flag is carried
into the compile-time `migrate!()` literal).

### The success marker and the refusals

On success `epigraph-migrate` prints one stdout line that starts with
`migrations: ok` and names both heads:

```
migrations: ok db_head=<n> binary_head=<n> applied=<k>
```

`applied` counts the embedded migrations this run applied. When the
deliberate-rollback opt-in below is used, ` db_ahead_of_binary=allowed` is
appended. A fresh database at a build whose newest migration is
`194_retracted_bba_delete_guard.sql` is expected to print
`migrations: ok db_head=194 binary_head=194 applied=158`.

It exits nonzero, prints `migrations: FAILED: <reason>` on stderr, and never
prints the marker, when:

* the database is **ahead** of the binary. `_sqlx_migrations` holds a
  successful version this build does not embed: either above the binary's
  highest embedded migration, or one that fills a gap below it, which the
  head alone cannot show. The numbering has gaps (at version 194: 35, 93–99,
  102–104, 113, 133–139, 142, 143, 145–147, 151, 152, 155–157, 160, 167, 177,
  178, 182, 187 and 192), and a newer build may fill any of them. The one
  exemption is version `035`, a private repository's migration known to be
  benign (`KNOWN_FOREIGN_VERSIONS` in `crates/epigraph-api/src/migrate.rs`).
  The reason reads
  `REFUSING: the database has N applied migration version(s) this binary does not embed: [...]`.
  The binary is stale: deploy one built from the revision that applied those
  versions, which the refusal lists. Nothing is applied. For a *deliberate*
  rollback to an older build, re-run with `--allow-db-ahead` or
  `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD=1`. The variable also covers
  `EPIGRAPH_MIGRATE_ON_BOOT=1` on the server. The run then applies the
  pending migrations it embeds, leaves the unknown ones in place, prints a
  `WARNING` naming them, and appends `db_ahead_of_binary=allowed` to the
  marker line;
* after running, any migration embedded in the binary is not recorded as
  successfully applied (`database schema head is ... below this binary's embedded head ...`);
* sqlx itself fails, for example on a checksum mismatch because an applied
  migration file was edited (`sqlx::migrate failed: ...`). Migrations are
  append-only; see `migrations/README.md`.

The `035` exemption rests on a measurement of one long-lived database
recorded in `migrations/README.md`. If a deployed database carries any other
non-embedded version, the first strict run refuses (fail-closed, nothing
applied) until the version is identified.

Both checks and the run itself happen on one connection that holds sqlx's
migration advisory lock, so a second `epigraph-migrate` (or a boot-time
migrate) cannot slip a newer migration in between the check and the run. Two
migrators started together against a *fresh* database can still fail one of
them with a `40P01` deadlock between that lock and a
`CREATE INDEX CONCURRENTLY` migration. The losing run exits nonzero without
the marker, and re-running it is safe.

**What this cannot catch.** A database that stops at an older head *because
the binary itself is stale* (built before the newer migrations existed) still
reports `ok`. The binary cannot know migrations it was never built with, so
nothing inside it can tell "at my head" from "at the head the deployed code
requires". A head-59 build on an empty database exits 0. The marker shows
`binary_head`, so compare it with the newest file in `migrations/` for the
revision you meant to deploy. Making that comparison automatic needs the
expected head supplied from outside the binary.

### Stale binaries from a shared target directory

`sqlx::migrate!("../../migrations")` is a proc-macro that embeds the
migration file list **at compile time**, resolved relative to the crate being
compiled. If several checkouts share one `CARGO_TARGET_DIR`, and another
checkout last built `server` or `epigraph-mcp-full` at an older revision, the
build can reuse the cached artifact. You then install a binary whose embedded
migration list predates the checkout you think you are building from.

Symptoms on deploy. Watch the `epigraph-migrate` run, not the server: the API
does not migrate at boot, so it says nothing about migration state.

* `epigraph-migrate` exits 0 and applies nothing.
* `_sqlx_migrations` is missing the migration version your revision added.
* `information_schema.columns` confirms the new column does not exist.
* The health check passes. The binary does not crash; it just does not know
  about the new migration.

Pre-deploy check, BEFORE you stop the running units:

```bash
strings "$CARGO_TARGET_DIR/release/server" \
    | grep -E '<expected_new_migration_filename>' || \
        echo "STOP: new migration not embedded — cargo clean + rebuild before deploy"
```

`strings` finds the migration filename as a string literal in the binary's
sqlx metadata. If grep is silent, the build is stale: do not install it.

The fix:

```bash
cd <deploy-checkout>
cargo clean -p epigraph-api -p epigraph-db
SQLX_OFFLINE=true CARGO_INCREMENTAL=0 cargo build --release --locked \
    -p epigraph-api -p epigraph-mcp
SQLX_OFFLINE=true CARGO_INCREMENTAL=0 cargo build --release --locked \
    -p epigraph-cli --bin recompute_claim_belief
# stop <your-mcp-units> and <your-api-unit>, install the binaries, start the API, then the MCP units
psql '<migration DSN>' -c \
    "SELECT version FROM _sqlx_migrations ORDER BY version DESC LIMIT 5;"
```

`cargo clean -p epigraph-api -p epigraph-db` is the step that evicts the
stale artifact. Those two crates call `sqlx::migrate!()` and re-export it,
and the crates that depend on them are rebuilt as a side effect. Run the
`strings` check again before installing.

### `-- no-transaction` migrations (063–066 and later)

Migrations 063–066 run `CREATE INDEX CONCURRENTLY`. Later migrations that do
the same follow the same rules. What an operator must know:

* **They hold no `ACCESS EXCLUSIVE` lock**; that is why they are concurrent.
  Writes to `claims`, `evidence` and `edges` continue throughout.
* **sqlx cannot roll them back.** There is no enclosing transaction, and the
  `_sqlx_migrations` bookkeeping is not atomic with the DDL. A failure leaves
  an **INVALID index** behind and no migration row.
* **One statement per file, deliberately.** sqlx sends a whole migration file
  as one simple query. PostgreSQL wraps a multi-statement simple query in an
  implicit transaction block, and `CREATE INDEX CONCURRENTLY` inside one fails
  with SQLSTATE 25001. Do not merge 063–066 into one file; a test fails if you
  do. `migrations/README.md` has the full explanation.

**Detection:**

```sql
SELECT c.relname FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
 WHERE NOT i.indisvalid;
```

**Recovery.** Drop the leftover, then re-run the migration. `IF NOT EXISTS`
makes re-running safe, but it will *not* rebuild an index that already
exists in an invalid state.

```sql
DROP INDEX CONCURRENTLY <name>;
```

**Window.** `CREATE INDEX CONCURRENTLY` waits for every transaction older
than itself in the same database. `drain_jobs` runs with a
`statement_timeout` of 45 minutes by default (`EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS`),
so one long clustering job can stall these migrations for that long. A
`SET LOCAL lock_timeout` in a `-- no-transaction` file is *legal* but
useless: outside a transaction block it is a silent no-op with a `WARNING`,
and it would not bound this wait even if it took effect. Run them in a quiet
window with the timers stopped, or check first:

```sql
SELECT max(now() - xact_start) FROM pg_stat_activity
 WHERE state <> 'idle' AND datname = current_database();
```

### Lock-heavy migrations: 062 as the pattern

`ADD COLUMN ... NOT NULL DEFAULT ...` is metadata-only on PostgreSQL 11 and
later, so widening `claims` does not rewrite the table. Measured against a
5,000,000-row / 1028 MB copy of `claims` on PostgreSQL 16.2, migration 062's
two-column `ADD COLUMN` took **3.5 ms** and the `NOT VALID` CHECK **3.6 ms**,
with `pg_relation_size` identical before and after. Every constraint it adds
is `NOT VALID`: new rows are checked, existing rows are not scanned.
Validation is migration 075's job.

**That is duration, not locks.** Each `ALTER TABLE` still takes
`ACCESS EXCLUSIVE`, and sqlx runs the whole file in one transaction, so each
lock is held until `COMMIT`. By its last table, 062 holds `ACCESS EXCLUSIVE`
on **25 tables at once**, `claims` among them. `SET LOCAL lock_timeout = '3s'`
bounds how long each `ALTER TABLE` *waits*, not how long the transaction
*holds*. While one is queued behind a long-running reader, it blocks every
new query on that table for up to 3 s. The worst case on a busy cluster is a
series of rolling 3-second stalls ending in a rollback and a restart from
table 1. Run such migrations in a quiet window, expect to retry, and
pre-check with the `pg_stat_activity` query above. If 062 aborts on its
`lock_timeout`, sqlx records no row and the fix is to re-run it: the whole
file is `IF NOT EXISTS` / catalog-guarded and applies cleanly a second time.

Many later migrations set `lock_timeout = '3s'` (111–121, 144–150 and others).
The same advice applies to them: on a timeout, re-run in a quiet window.

062 also creates `idx_agents_default_group`, an ordinary `CREATE INDEX` inside
its transaction.

062's `DEFAULT 'public'` and `DEFAULT <world group>` were transition artifacts
and were dropped by migration 074. Do not build anything that relies on them.

### Deleting a group is a maintenance-window operation

Migration `062` adds 25 `owner_group_id → groups(id)` foreign keys, all
`ON DELETE RESTRICT`, and **none of them is indexed**. The partial indexes in
`063`–`065` lead on `owner_group_id` but predicate on `visibility`, and the RI
check for a RESTRICT parent delete is an unqualified `owner_group_id = $1`
lookup, so none of them can serve it.

`DELETE FROM groups` is blocked outright by migration `060`'s trigger. Its
documented escape hatch,

```sql
SET LOCAL epigraph.allow_group_delete = 'yes';
```

therefore costs **25 sequential scans, one of them on `claims`**, inside the
deleting transaction, with row locks held throughout. Do it in a maintenance
window. An online deprovisioning path must first add plain
`(owner_group_id)` indexes on the tables it touches.

## 5. The maintenance DSN and the maintenance timers

### What it is

`MAINTENANCE_DATABASE_URL` is the DSN every background writer connects on:
the CLI binaries, the two maintenance timers (`replay_deferred_cascades` on
`epigraph-cascade-replay.timer`, `drain_jobs` on `epigraph-jobs-drain.timer`),
and the operator scripts under `scripts/`. It should differ from
`DATABASE_URL` **only in the role**: a non-superuser LOGIN that is a member of
`epigraph_maintenance`, so `epigraph_bypass()` is true on it.

### A request-serving process never holds it

The API `server` and `epigraph-mcp-full` on every transport (`--listen` for
HTTP units, stdio for agent containers and operator MCP configurations)
**refuse to start, with exit 1, when the variable is set**, in every
environment, with no override:

```
ERROR: MAINTENANCE_DATABASE_URL is set; a request-serving process never holds the maintenance DSN (operator decision D9). Remove it from this unit's EnvironmentFile; cascades are applied by epigraph-cascade-replay.timer.
```

An exported-but-empty value carries no credential and counts as unset. Unset
is the only supported state for these units. Each logs one INFO line on the
`tenancy.maintenance` target at boot:

```
maintenance surface not served by this unit (D9); cascades defer to epigraph-cascade-replay.timer, jobs run on epigraph-jobs-drain.timer
```

What that means for callers:

* **Cascades defer.** Every supersede, dedup, consolidation and
  match-candidate retirement commits the caller's act and returns its normal
  status (HTTP 200/201, MCP success) with
  `cascade = {status: "deferred", reason, audit_event_id}`. A
  `cascade.deferred` row is written in the act's own transaction. The replay
  timer applies it, normally within about two minutes. Clients must not retry
  the act.
* **The maintenance surface answers MOVED** (structured, non-retryable,
  nothing written).
  * HTTP: `501` with
    `{"error":"maintenance_surface_not_served","runs_on":{...},"retryable":false,"decision":"D9"}`.
    This covers `GET /api/v1/claims/needing-embeddings` (`runs_on` names
    `embed_backfill`; the route also requires `claims:admin`) and EVERY
    privatization lifecycle route, the GETs included (`runs_on` kind `none`).
  * MCP: JSON-RPC `-32600` with `data.status = "moved"` for
    `recompute_beliefs` (→ `recompute_claim_belief`), `backfill_embeddings`
    (→ `embed_backfill`) and `sweep_semantic_duplicates` (→ the
    `sweep_semantic_duplicates` CLI).
  * `embed_backfill` also fills NULL `workflows.goal_embedding` (the
    workflow write paths embed the goal best-effort), so one schedule covers
    both columns.
* **No job runs in the server.** It builds no job pool and no maintenance
  pool, and starts no job runner and no stale-job reaper. `drain_jobs` drains
  the queue.

**The privatization lifecycle and reclassification.** No request-path route
changes an existing node's partition. Moving public claims into a group is
the maintenance CLI's job: `epigraph-operator restrict-claims` (section 9),
reversed by `reown-reverse`.

### Connection budget

The API process opens its application pool only: **10** connections per
replica. Each `epigraph-mcp-full` process opens **10** on the application DSN.
The timers add, while they run, up to 11 for `replay_deferred_cascades` (the
`MaintenancePool` cap, below) and up to 4 for `drain_jobs`, plus the one
connection that holds its advisory lock.

### The timers refuse the fallback

`replay_deferred_cascades`, `drain_jobs`, the `sweep_semantic_duplicates` CLI,
the `unmark_duplicate` CLI and `backfill_evidence_type` require
`MAINTENANCE_DATABASE_URL` to be SET. The documented fallback to
`DATABASE_URL` is refused, so the application DSN never runs maintenance
work.

- An un-mark has no deferred form. The `unmark_duplicate` CLI is the only
  process that completes one: MCP `unmark_duplicate`, HTTP
  `POST /api/v1/claims/:id/undedup` and `revert_label_dedup` with marks refuse
  on a request server.
- `drain_jobs` also refuses a connection that does not satisfy
  `epigraph_bypass()`, whether or not row security is active yet.
- Each timer and the sweep take their own session advisory lock, so a
  hand-run beside the timer does nothing (`{"locked": true}`, exit 0).
  `unmark_duplicate` takes the replay's lock instead. While a replay holds
  it, `unmark_duplicate` exits 1 with nothing written.
- `replay_deferred_cascades --report-only` prints
  `{"pending","stuck","oldest_age_s"}` in a read-only transaction and takes
  no lock. Use it as the staleness check.

`decompose_claims` needs the maintenance DSN only on its maintenance path. A
scheduled decomposition run in an agent container should pass
`--as-agent <agent id>`, the agent its API token acts as. It then runs on the
application login in `DATABASE_URL`, through row-level security, and needs no
maintenance DSN. See the binary's module doc, "Running as an agent".

### The maintenance role's grants

Migration 070 grants `epigraph_maintenance` `SELECT, INSERT, UPDATE`
schema-wide. Migration 119 grants it DELETE on the tables the job handlers
delete from (`jobs`, `graph_cluster_runs`, `graph_clusters`, `cluster_edges`,
`claim_cluster_membership`, `claim_themes`). Migrations 115, 117 and 118
grant the cascade's. Later migrations add DELETE where a maintenance verb
needs it: `frames` (158, for `epigraph-operator delete-frames`), and
`recall_events` and `events` (186, for `prune_recall_events`). The
sealed-content tables are deliberately not granted. 119 also removes the
application role's ability to enqueue any job: `jobs_app`'s WITH CHECK admits
only a privileged session.

The login you create for `MAINTENANCE_DATABASE_URL` gets all of this through
its membership (section 2, step 5). A login that satisfies
`epigraph_bypass()` but lacks these grants passes the boot probe and fails on
first use, which is worse than failing at boot.

`GroupMembershipRepository::list_live_for_agent` reads through
`public.epigraph_live_memberships()`, a `SECURITY DEFINER` function that
migration 077 `REVOKE`s from `PUBLIC`. Only the schema owner, `epigraph_app`
and `epigraph_maintenance` (and so its members) may EXECUTE it. A login
outside those that resolves a viewer fails with
`42501 permission denied for function epigraph_live_memberships`.

### If it is unset on a CLI binary

The other CLIs fall back to `DATABASE_URL` and log a WARN
(`MAINTENANCE_DATABASE_URL is not set; background writes will run on the ...`).
The operator's `DATABASE_URL` is itself an explicit act there.
`epigraph_db::assert_maintenance_privilege` refuses to start once row security
is active on a protected table and the connection cannot bypass it. The
refusal deliberately is *not* an unconditional `epigraph_bypass()` assertion,
because migration 060 downgrades `insufficient_privilege` on its
`CREATE ROLE` to a NOTICE, so on a cluster where that fired the role may not
exist at all.

**The arming signal is `ENABLE`, not `FORCE`.** The probe keys on
`relrowsecurity OR relforcerowsecurity`. A policy filters every role except
the table's owner and holders of `BYPASSRLS`; `FORCE` only *additionally*
subjects the owner. The roles background writers connect as are non-owners
without `BYPASSRLS`, so plain `ENABLE ROW LEVEL SECURITY` already truncates
their results. This matters at two moments: the window between the migration
that applies policies and the one that adds `FORCE` (they are separate
migrations), and after an operator pulls the documented
`ALTER TABLE … NO FORCE ROW LEVEL SECURITY` kill switch, which drops FORCE and
leaves the policies enabled. A FORCE-only probe would be disarmed in both.

**The kill switch covers every FORCEd relation, not only 079's list.**
Migration 079 FORCEd 35 relations. Later migrations FORCE the tables they
create (080, 082 and 083 the privatization tables, 173 the two harvester
tables, and others), and `docs/runbooks/079-undo.sql` is maintained to name
them. The API's boot assertion counts the **catalog**, not 079's array, so
running an undo script from an older tree un-FORCEs only part of the set and
leaves the API refusing to boot on a **partially** FORCEd set: the rollback
becomes an outage. Always run the script from the tree you are rolling back
to, and finish with the VERIFY query at its foot, which is what detects a
partial flip.

### It must name the same database as `DATABASE_URL`

A maintenance DSN pointing elsewhere does not error: it reads zero rows and
writes nowhere. So `maintenance_database_url` compares the two **effective**
database names (the path, or the role name when the DSN is pathless, exactly
as libpq defaults it) and refuses on a mismatch. **Host and port are compared
but only WARN.** Refusing on host equality would fail every deployment where
`localhost`, `127.0.0.1` and a container DNS name denote the same server. The
residual risk is real: a `MAINTENANCE_DATABASE_URL` copied from staging
beside a production `DATABASE_URL` names the same database `epigraph` on a
different cluster, and produces a warning naming both endpoints, not a
refusal. **Read that warning.**

### Pool sizing and the recompute binaries

`MaintenancePool` uses one cap of 11 (10 for work, 1 for the connection the
bypass lease holds) for every CLI binary that uses it. sqlx opens connections
lazily, and most of these binaries are single-threaded, so this is a ceiling
rather than a workload. A cron fleet running several of them at once against
production PostgreSQL has a correspondingly higher ceiling.

`recompute_claim_belief` and `recompute_betp` drive `--concurrency`
concurrent futures on a single task (`buffer_unordered`), borrowing the one
viewer the maintenance session owns.

* **Connection demand:** at most `--concurrency` claims are in flight at
  once, plus the one connection the lease pins. `--concurrency 10` exactly
  saturates the cap.
* **Parallelism:** the per-claim work is dominated by database round trips,
  which interleave on one task. Any CPU-bound stretch of the Dempster–Shafer
  math serialises against its peers. Expect normal wall-clock time on an
  IO-bound cohort and a longer run on a compute-heavy one. **No test covers
  this.** `run_for_real` and `run` live inside their binaries, where Cargo
  integration tests cannot reach them, so a regression shows up as run
  duration, not as a red build.
* **A PANIC inside one claim stops the run**, and the binary says so.
  Ordinary per-claim FAILURES are counted into `errors` and printed, and the
  exit-2-on-errors behaviour applies. The panic unwinds through the
  combinator, so the up to `--concurrency − 1` sibling futures in the buffer
  are dropped at their await points, and one that had begun a per-frame write
  but not committed it simply stops. A handful of claims beyond the panicking
  one can therefore be left partially recomputed. Both binaries are
  idempotent and re-runnable: the remedy is a re-run, and nothing needs
  unpicking by hand.
* **A reversible `recompute_claim_belief` run takes `--snapshot <wave file>`**
  (optionally `--wave <name>`). Each claim is then one transaction (row lock,
  recompute, read-back) whose `belief_cache::WaveRecord` is appended and
  synced before it commits. `restore_belief_cache --from <wave file>` then
  puts back exactly the run's pre-images by compare-and-swap, and leaves any
  claim a later writer changed (`superseded_since_wave`).
  * The wave file must be absent or empty.
  * A file that cannot be opened stops the run before any write. A record
    that cannot be written rolls its claim back and stops the run with
    exit 3.
  * A dropped or panicking claim mid-transaction is rolled back, so the file
    never misses a committed write. At worst it holds a record of a write
    that never committed, which a restore reports as `already_restored`.

### The Python scripts

`scripts/maintenance_dsn.py` mirrors the precedence and the database-name
refusal, and deliberately does **not** assert privilege. These are operator
one-shots, and a second implementation of the verdict rule would drift from
the Rust one. So a script run on an unprivileged role once policies apply
reads a subset and exits 0 with no warning. The refusal that protects you is
at the API and CLI boundary only. It is standard library only, so the
scripts that need the rule but not numpy do not acquire a numpy dependency.
`scripts/theme_lib.py::maintenance_dsn` binds it to that script family's
default.

The precedence carries a refusal that is not optional politeness. Giving
`MAINTENANCE_DATABASE_URL` precedence means that an operator who points
`DATABASE_URL` at a scratch database, while a sibling job has that variable
exported, would otherwise have every write in this family silently
redirected, and several of these scripts write.

Many scripts under `scripts/` fall back to a hardcoded DSN when neither
variable is set. Among them are
`postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph` (also
spelled with `127.0.0.1`), `epigraph_ro` variants, and
`postgres://epigraph:epigraph@127.0.0.1:5432/epigraph`. List the candidates
with:

```bash
grep -rlE 'postgres(ql)?://[a-z_]+:[a-z_]+@' scripts/
```

(The hits under `scripts/e2e/` are example DSNs in comments.) This repository
creates none of those logins. Always set `MAINTENANCE_DATABASE_URL` (or
`DATABASE_URL`) explicitly when you run a script.

## 6. Session settings and connection poolers

### `EPIGRAPH_SESSION_GUC_MODE`

| Value | Meaning |
|---|---|
| *unset* (default), or anything other than `transaction` | `session`: the fast path |
| `transaction` | every scoped read runs inside a transaction |

Tenancy context reaches the database as session settings, stamped once per
connection checkout by `ScopedPool`, in one extra statement and no
transaction. Every checkout stamps FIVE settings: `epigraph.group_ids`,
`epigraph.writable_group_ids` and `epigraph.principal_id` (the tenancy
three), plus `epigraph.elevation_id` and `epigraph.family_id`, which are
empty for every viewer that is not elevated. The release scrub clears all
five. The recording builds (the API, and the MCP server on `--listen`) also
declare `epigraph.access_recorder` once per connection (section 10).

**Behind a transaction-mode pooler that mechanism silently fails.** A
`set_config(..., is_local = false)` on one statement is not visible to the
next, so every row-security policy would collapse to
`visibility = 'public'` and `epigraph_principal_id()` would be NULL. That is a
*fail-closed* failure: no errors, no 500s, just permanently empty result sets
that look like data loss.

**The boot probe.** The API and the MCP server therefore run
`ScopedPool::probe_session_gucs()` right after the pool connects. It:

1. acquires a connection and stamps a sentinel into all five settings,
   through the *same* `set_config` statement the request path uses, not a
   scratch setting;
2. reads them back **as a second statement on the same handle**: they must
   still carry the sentinel;
3. releases the connection, acquires again, and asserts they are now empty.
   That proves the `after_release` scrub is running, because step 1 is what
   put values there.

Stamping the real settings is what makes the check non-vacuous. A probe that
stamped a scratch setting and then checked the tenancy settings would read
empty whether or not the scrub ran.

If step 2 fails, the API **refuses to serve**:

```
FATAL: session GUCs do not survive between statements on one pooled connection.
This deployment is behind a transaction-mode pooler. Set
EPIGRAPH_SESSION_GUC_MODE=transaction to switch every read to begin_as, or
point DATABASE_URL at a session-mode endpoint.
```

On success it logs `Session-GUC probe passed`.

**When to set `transaction`.** pgbouncer with `pool_mode = transaction`, or
RDS Proxy without session pinning, in front of `DATABASE_URL`. Setting it
skips the probe (a `WARN` says so), and every scoped read runs inside
`ScopedPool::begin_as`. **Measured cost: two extra round trips per read**
(`BEGIN` and `COMMIT`). Prefer pointing `DATABASE_URL` at a session-mode
endpoint if one exists; the fallback is supported, not recommended. Elevation
fails closed behind a transaction-mode pooler, because the per-connection
recorder declaration does not survive (section 10).

A typo (`EPIGRAPH_SESSION_GUC_MODE=tranaction`) selects `session`, and the
probe then proves whether that was right. Failing over to the slow mode on a
typo would hide the misconfiguration behind a permanent latency cost that
nobody attributes.

**Not exercised in this repository's CI:** the *refusal* half. There is no
pgbouncer-in-transaction-mode fixture here, so the pooler's behaviour is
reasoned about, not measured. Verify it against staging before you rely on
it in production. What *is* covered: the verdict is a pure function
(`pool.rs::probe_verdict`). Its unit tests pin that a lost stamp is diagnosed
as a pooler and names `EPIGRAPH_SESSION_GUC_MODE=transaction`, that a
carried-over stamp is diagnosed as a dead scrub, and that an all-empty
observation is reported as the former, not the latter.

### The release scrub costs one round trip on every connection

`after_release` runs the scrub statement on every release from a
`ScopedPool`, unconditionally. On a loopback cluster (3000 sequential
statements through `psql`) `SELECT 1` took 0.15–0.19 s and the scrub
0.19–0.20 s: **about 55 µs per release**, of which the statement itself is
about 13 µs and the rest is the round trip. Over a real network hop the round
trip dominates, so budget one extra p50 RTT per released connection. It is
not conditional: a scrub that only runs when someone remembered to set a flag
is not a security control.

After the tenancy backfill on an upgraded database, run
`REINDEX INDEX CONCURRENTLY idx_claims_world_owned;`. That index is
corpus-sized when `066` builds it on a populated database, because
`owner_group_id` then defaults to the world group and the partial predicate
matches every row. The backfill empties it without reclaiming the pages.

## 7. The HTTP surface

### The anonymous surface is an allowlist

Every route requires a Bearer token, except these 25 paths in the `db` build
(the only build that serves):

| Paths | Why they are anonymous |
|---|---|
| `GET /health` | Stateless. Load balancers cannot mint a token. |
| `GET /api/v1/openapi.json` | A client cannot read the schema that tells it how to authenticate if reading it requires authentication. |
| 12 `/elevate/...` paths: `/elevate/enroll/:id` with `/challenge` and `/finish`; `/elevate/:ticket` with `/challenge` and `/assert`; `/elevate/act/:id` with `/challenge` and `/assert`; the assets `/elevate/assets/enroll.js`, `/elevate/assets/elevate.css` and `/elevate/assets/elevate.js` | The passkey enrollment, elevation and admin-act confirmation ceremonies. They are opened on the device that holds the authenticator, with no token to present. The id in the path and the passkey are the credentials, and all of them answer 503 when no relying party is configured (section 10). |
| 11 OAuth and discovery paths: `/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/authorize`, `/oauth/callback`, `/oauth/authorize/consent`, `/oauth/:provider/auth-url`, `/oauth/:provider/exchange`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` | Discovery and token issuance must come before authentication. |

`crates/epigraph-api/tests/public_router_allowlist.rs` pins this list
(`PUBLIC_ALLOWLIST_DB`, `OAUTH_ALLOWLIST_DB`) and fails the build if another
path becomes anonymous.

Everything that returns claim content, claim-derived structure, ACLs,
embeddings or aggregates needs a token. That includes `GET /claims`,
`GET /claims/:id`, `GET /api/v1/claims`, `GET /agents`,
`GET /lineage/:claim_id`, `POST /api/v1/search/semantic`,
`GET /api/v1/query/rag`, `GET /api/v1/search/evidence`,
`GET /api/v1/admin/stats`, `GET /api/v1/themes/:id/embeddings`,
`GET /api/v1/events`, all `/api/v1/graph/*`, all `/frames/*`, all `/belief*`,
and every `/api/v1/perspectives*`, `/communities*`, `/contexts*`,
`/workflows*`, `/methods*` and `/tasks*` read.

A refused request carries an RFC 6750 challenge:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource", error="invalid_token"
```

**A token must carry a principal.** `oauth_clients.agent_id` is what the
JWT's `agent_id` claim is copied from. Every client issued a token gets an
agent identity at its first token, so on a database built by this tree's
code every client has one. `POST /api/v1/claims` and `POST /claims` refuse a
token with no `agent_id` (401 `invalid_token`), and the routes that take a
viewer (`ViewerExtractor`) refuse it with 401 `token carries no agent_id`.
Those refusals emit the structured tracing event
`visibility.viewer.rejected{reason="no_agent_id", route, client_id}`. If you
upgrade a database whose clients predate that, see
[section 13](#before-the-router-allowlist-every-active-client-needs-an-agent_id).

**Known gap.** `GET /api/v1/openapi.json` under-reports authentication.
utoipa's `security(...)` annotations are per-operation, and many read
operations carry none, so the schema advertises them as requiring nothing.
The document itself is anonymous, which is correct.

### Routes that need more than a token

| Route | Needs | Failure |
|---|---|---|
| `GET /api/v1/admin/stats` | `claims:admin` | **403**, not 401. Its `webhooks.webhook_count` field is the cross-tenant count of `webhook_subscriptions`, so the whole aggregate is admin-only. |
| `GET /api/v1/claims/needing-embeddings` | `claims:admin`, and then a maintenance surface | **403** without the scope. With it, `501` MOVED naming `embed_backfill` (section 5). |
| `POST /api/v1/groups`, `POST /api/v1/communities` | `groups:write` | 403 |
| `POST`/`DELETE /api/v1/groups/:id/members`, `POST /api/v1/communities/:id/members` | `groups:admin` **and** live membership | 403 |
| `DELETE /api/v1/communities/:id/members/:perspective_id` | `groups:admin` **and** live membership, or the caller's own perspective | 403 |

`claims:admin` and `groups:admin` are in `ADMIN_ONLY_SCOPES` (with
`clients:admin`, `entity-types:write` and `instance:admin`). Admin-only
scopes are never in `read_only_scopes()`, the read-write role,
`AGENT_PROVISION_SCOPES` or `PUBLIC_CLIENT_READ_SCOPES`. So every
`epigraph-ro` token, every `epigraph-wo` token, every agent auto-provisioned
by `POST /api/v1/agents` and every dynamically registered public client gets
**403** on these routes. Point dashboards and monitoring at an
`epigraph-admin` token, or mint a dedicated client with exactly
`["claims:admin"]`. `groups:write` is in the read-write role, so `epigraph-wo`
can create a community or group.

Community routes cost the same as group routes because migration 068
projects every community onto a `groups` row, ID-preservingly. Creating a
community creates a group and installs the creator as its `role='admin'`
member. Adding a community member writes the same `group_memberships` row
`POST /api/v1/groups/:id/members` writes. **Expected consequence:** a
principal holding only `groups:write` can create a community and cannot then
add another perspective to it. The creator administers what it made by
construction, but populating it with others is admin-only.

The MCP tool `system_stats` is a different aggregate (corpus counts,
viewer-scoped, `claims:read`) from `GET /api/v1/admin/stats`. The
`require_signatures` field of the admin stats body keeps its name on the wire.

### `POST /api/v1/claims/batch`

Each item goes through the same code as `POST /api/v1/claims`, on its own
transaction, and the response ids name real rows.

- An item may carry any `POST /api/v1/claims` field. An item without
  `agent_id` is authored by the caller. `truth_value` is accepted as
  `initial_truth`, but giving both is refused.
- `if_not_exists: true` makes re-running a batch safe. Matched items return
  the existing id with `was_created: false` and are counted in `existing`.
- A matched item writes nothing. Its `AUTHORED`, `HAS_TRACE` (`trace_id`)
  and `DERIVED_FROM` (`evidence_id`) edges and its "create" provenance row are
  written only for a claim the call created. The same holds for
  `POST /api/v1/claims` with `if_not_exists: true`. A client that wants new
  evidence attached to an existing claim must link it with
  `POST /api/v1/edges`.
- Each failed item's result carries `status` (the code the single route
  would return, for example 400 or 409) next to `error`.
- The request needs an authenticated agent with `claims:write`, the same as
  the single route.
- No `ClaimSubmitted` event is published, the same as `POST /api/v1/claims`.
  `start_webhook_dispatcher` is the only wired `EventBus` consumer, and
  `GET /api/v1/events` reads the database, not the in-memory ring.
- Once operator binding is armed (migration 122), the database checks each
  item as it checks a single claim. An item that names an author the caller
  may not write as, and any item from an unbound caller, is refused in its own
  slot with 403 (`OPL01`/`OPL02`). The other items are unaffected.
- A public item is always owned by the token agent's personal group.
  `group_id` does not change that. It is ignored unless `privacy_tier` is
  `fully_private`, which also needs `encrypted_content` and
  `encryption_epoch` and a caller that is a member of the group. That is the
  only way to choose an item's owner group. So under an armed binding, an
  allowlisted service client's public items are refused with `OPL02`, because
  its personal group is not a group its operator writes, and sending
  `group_id` on a public item does not avoid it. Without an armed binding, a
  public item sent with `group_id` lands in the caller's personal group, not
  in the named one. Fleet agents cannot call this route over HTTP, because
  their token mint is refused.
- A batch embeds its items one after another, so a large public batch can
  take tens of seconds. The rate limiter counts the request, not its items.

### Absent, not blanked

A caller that cannot read a row gets an absence, never a placeholder: `404`
on HTTP `GET /claims/:id`, a not-found error from MCP `get_claim`, or
omission from a list. A placeholder body would confirm that a private claim
exists at that id. A client that pattern-matches on a `"[REDACTED]"` string
receives nothing.

### `POST /api/v1/hypothesis`

- **It requires a token bound to a principal.** It takes `ViewerExtractor`,
  which refuses a request with no `AuthContext`, and then one whose
  `agent_id` is `None` (`401`, `token carries no agent_id`). The remedy is to
  re-mint through `/oauth/token`.
- **Ownership comes from the token, not the body.** `claims.owner_group_id`
  for a hypothesis is derived from the authenticated principal, as in
  `routes/claims.rs::create_claim`. `claims.agent_id` still comes from the
  body, so a *delegating* caller (authenticated as A, posting `agent_id: B`)
  writes rows authored by B and owned by A's personal group. That is
  deliberate: `agent_id` records who said it, and `owner_group_id` records
  who is accountable for the row.
- **The VOI score is viewer-scoped.** `voi.score`, `voi.neighbor_count`,
  `voi.avg_belief_gap` and `neighborhood_size` aggregate an
  embedding-neighbourhood scan of `claims`, and that scan (and the `edges`
  subquery that decides which neighbours count as grounded) is filtered by
  the caller's viewer. On a wholly public corpus every caller sees the same
  number. Once private claims exist, a caller outside their groups gets a
  smaller neighbourhood and so a **different VOI score for the same
  statement**. The number is cached in the claim's
  `properties->>'voi_score'`, so dashboards that compare scores across
  callers see them diverge.

### MCP `get_recall_events` is self-scoped

`recall_events` rows are written with `visibility = 'group'` and owned by the
querying principal's personal group. An agent reads its own recall history
and nobody else's. The tool's `agent_id` filter works but is effectively
self-only. **There is no instance-wide audit view:**
`tools/viewer.rs::request_viewer` has no admin or bypass arm, so no
credential restores a cross-agent view of this table. If an operator needs
one, it has to be built.

One path writes instance-wide rows on purpose. The `epigraph-engine` library
recall has no principal at all, so there is no personal group to name, and
migration 062's `recall_events_group_needs_real_group` CHECK forbids a
sentinel. Rows from that path are `('public', world)` and can be identified
by `agent_id IS NULL`.

On a database upgraded from before this scoping, older `recall_events` rows
keep `visibility = 'public'`. Section 13 covers them.

### Metrics live on a separate internal listener

`/metrics` is **not on the application port**. A second listener serves it,
bound from `EPIGRAPH_METRICS_ADDR` (default `127.0.0.1:9090`). Point
Prometheus at that address:

```ini
# <your-api-unit>
Environment=EPIGRAPH_METRICS_ADDR=127.0.0.1:9090
```

Binding to loopback means a scraper must be on the host or in the same
network namespace. Widen it deliberately (for example `0.0.0.0:9090` inside a
private network) if yours is not. A bind failure on this listener logs an
error and lets the API keep serving, because losing metrics must not take the
API down. So check for the log line `Internal metrics listener started`
rather than assuming.

**If you run two instances side by side with `EPIGRAPH_PORT`, set
`EPIGRAPH_METRICS_ADDR` on the second one too** (for example
`127.0.0.1:0`). There is no per-instance default, so the second instance
tries to bind the same `127.0.0.1:9090`, fails, logs
`Failed to bind the internal metrics listener`, and serves the API with no
metrics. That is easy to miss precisely because the API itself is fine.

The listener is spawned before the TLS branch, so it works under both
`EPIGRAPH_TLS_CERT`/`EPIGRAPH_TLS_KEY` and plain HTTP.

The tenancy gauges on this listener (`epigraph_tenancy_undeclared_writes`
among them) are sampled every `EPIGRAPH_TENANCY_GAUGE_INTERVAL_SECS` (default
30). A failed sample is logged and retried, and the gauge goes stale rather
than reading zero.

### `EPIGRAPH_RESOURCE_METADATA_URL`

Defaults to `${EPIGRAPH_PUBLIC_BASE_URL}/.well-known/oauth-protected-resource`,
which is the document the API serves, so most deployments need nothing. Set
it only when the metadata document is served from a different host. A value
that cannot go into an HTTP header (control characters, non-ASCII, an
embedded newline) makes the process `exit(1)` at boot, rather than silently
dropping the challenge from every 401. `epigraph-mcp`'s
`--resource-metadata-url` fails fast the same way.

### `EPIGRAPH_REQUIRE_SIGNATURES`

It gates **only** payload-level Ed25519 packet signatures on
`POST /api/v1/submit/packet` (`ApiConfig::require_packet_signatures`).
Transport authentication is OAuth2 Bearer, unconditionally. There is no
request-signing middleware and no `X-Signature` / `X-Public-Key` /
`X-Timestamp` headers. That middleware was the only writer of
`SecurityEvent::signature_verification` and `auth_attempt` rows into
`security_events`, so dashboards that read those two event types read empty.

### Webhook egress guard

One shared module, `epigraph_jobs::egress`, decides whether a webhook
destination may be dialled: for `POST /api/v1/webhooks`, for the API's
delivery dispatcher, and for `epigraph-jobs`' `ConfigurableWebhookHandler`.

**Registration resolves the host, and refuses it if any answer is internal.**
`POST /api/v1/webhooks` validates the URL (scheme `http`/`https`, a parseable
URL that names a host). It resolves a host **name** once, through the
operating system's resolver, with a 5-second bound. It returns **400** when:

* **any** address in the answer is internal (see the range table below). A
  round-robin answer with one internal member is refused as a whole, because
  a client may try any member;
* the name **does not resolve**, returns no addresses, or times out. Nothing
  can be vetted, so nothing is stored. This includes a *transient* resolver
  failure, and the registering client should retry.

Both cases return the **same** body, naming only the host ("Webhook URL host
`<host>` is not an acceptable public destination"). The resolved address,
its range and the resolver's error text come from the server's resolver, not
from anything the caller supplied, so they are not returned: echoing them
would let any `webhooks:write` holder learn what internal-only names resolve
to. They are logged at WARN as
`Refusing webhook registration: target host failed egress vetting`, with the
caller's `agent_id`. **Operators:** a transient resolver failure looks like
any other refusal to the caller, so diagnose a burst of these 400s from that
log line, and check the API host's resolver before you suspect the caller.
A caller can still observe 201 versus 400 and how long the lookup took. That
cannot be removed without dropping the registration-time check, and it is
accepted.

IP-literal URLs are judged without resolution, and their refusal names the
literal, since it is the caller's own input. Names RFC 6761 reserves to
loopback (`localhost` and anything under `.localhost`) are refused.
Migration 085's `CHECK (btrim(url) <> '')` mirrors only the non-empty check;
the rest of the policy lives in the code.

**Every delivery re-vets.** Each delivery resolves the name, applies the same
policy, and refuses the send if any answer is internal. That is logged at
WARN as `Refusing webhook delivery to disallowed target URL` with
`attempts: 0` (nothing was dialled). A subscription that points at an
internal consumer is never delivered to, and the subscriber sees no error.
`bin/server.rs` re-hydrates the webhook store from `webhook_subscriptions` at
every boot, so this applies to every stored row.

Delivery then connects **only** to the addresses it vetted. The HTTP client
does not resolve the name a second time, so a record that changes between
the check and the send (DNS rebinding) is never consulted. `Host` and TLS SNI
stay the registered host's. All retries of one delivery reuse that one
resolution. A resolution failure is retried with the normal backoff, and
nothing is dialled until a resolution is vetted. Redirects are refused.

**Operator action when you upgrade from a build without this guard:** audit
`webhook_subscriptions` for active rows whose host is, or resolves to, an
internal address, and decide per row whether to re-point it at a public
endpoint or deactivate it. There is no allowlist override. An internal
consumer needs a public-facing endpoint.

**The refused ranges**, as literals and as resolved answers:

* loopback, link-local, RFC 1918 private, unspecified;
* IPv6 loopback, link-local and unique-local;
* **CGNAT `100.64.0.0/10`**, which overlay VPNs commonly use, so a consumer
  reached over such a network is refused;
* the **documentation** ranges (TEST-NET-1/2/3, `2001:db8::/32`);
* multicast, limited broadcast, `0.0.0.0/8`, `192.0.0.0/24`, benchmarking
  `198.18.0.0/15`, reserved `240.0.0.0/4`, IPv6 site-local `fec0::/10`, and
  the other IANA special-purpose blocks that are not globally reachable;
* every IPv6 form that **embeds** an internal IPv4 address. IPv4-mapped,
  IPv4-compatible, NAT64 `64:ff9b::/96` and 6to4 `2002::/16` are judged by the
  IPv4 address they carry. So a NAT64 or 6to4 form of a *public* address is
  still accepted; DNS64 synthesises these for ordinary names.

URL parsing is WHATWG (`url::Url`) everywhere, so userinfo tricks and
alternate numeric spellings of loopback are judged as the address they name.

**Webhook delivery ignores `HTTP_PROXY` / `HTTPS_PROXY`.** The API's delivery
client is built with `no_proxy()`, because a forward proxy resolves the
target name itself and would bypass the pinned addresses. **A deployment
that routes outbound webhook traffic through a proxy must allow direct egress
from the API process instead**, on the webhook ports its subscribers use.
Other outbound HTTP from the process is unaffected.

`epigraph-jobs` ships one sanctioned production `HttpClient`,
`PinnedHttpClient`. It builds each request's client with
`epigraph_jobs::egress::pinned_client`, the same function the API's dispatcher
uses, so both paths dial only the vetted addresses, never resolve the name
again (a fallback resolver refuses every other name), and follow no redirects
or proxies. Nothing in this repository wires `ConfigurableWebhookHandler` into
a runner. Anything that does should pass `PinnedHttpClient`. The `HttpClient`
trait stays open for test mocks, so a second production implementation is a
review red flag, not a compile error.

### Tokens for the in-repo Python helpers

`scripts/_api_client.py::mint_bearer_token` takes its `agent_id` claim from
`EPIGRAPH_AGENT_ID`. There is deliberately no default: `agent_id` names the
principal whose group membership decides what the token can read, and a
default would hand every script one identity's view of the corpus by
accident.

`scripts/_api_client.py::EpiGraphClient` **exits at construction** when
neither an explicit `agent_id=` nor `EPIGRAPH_AGENT_ID` is available, rather
than minting a principal-less token and dying on an opaque 401 at the first
request. That covers `anchor_papers_to_themes.py`,
`classify_paper_document_type.py`, `update_theme_workflow_steps.py` and
`lib/nli_stance.py`. The lower-level `mint_bearer_token` is deliberately *not*
guarded: a caller that exercises the 401 path is a legitimate use of a raw
token helper.

`scripts/reconcile_backlog_labels.py` (the daily reconciler named in
`CLAUDE.md`), `scripts/cleanup_backlog_labels.py` and
`scripts/maintain_themes.py` **exit** when `EPIGRAPH_TOKEN` is unset. The
`dekg` CLI requires `--token` / `EPIGRAPH_TOKEN`.

## 8. OAuth clients, scopes and refresh tokens

### `bootstrap_clients` and the canonical scopes

`bootstrap_clients` provisions `epigraph-admin`, `epigraph-ro` and
`epigraph-wo` (section 2, step 6). It is convergent: an existing canonical
client has its `allowed_scopes` and `granted_scopes` rewritten to
`scopes_for(<name>)` and is reported `EXISTS: … scopes=RECONCILED`.
Non-canonical clients are untouched.

Scopes are persisted per client at registration, so when a release adds a
canonical scope (for example `groups:write` and `groups:admin`, which the
group routes check), clients bootstrapped before it keep their old arrays and
get 403 until you re-run `bootstrap_clients`. No migration can fix that: the
rows are data, not schema.

```bash
MAINTENANCE_DATABASE_URL='<maintenance DSN>' DATABASE_URL='<application DSN>' \
  ./target/release/bootstrap_clients \
    --legal-entity-name "<same as before>" --legal-contact-email "<same as before>"
```

A refresh never adds a scope to a refresh-token chain (migration 140, below).
So a consumer that only refreshes does not pick up a newly added canonical
scope: it needs a fresh `client_credentials` grant or, for a human connector,
a re-authorization. Externally provisioned humans get their scopes from
`default_scopes` in `providers.toml`. `groups:manage` never existed; the
scope is `groups:write` (see `providers.toml.example`).

### `EPIGRAPH_ENV` and the identity allowlist

Unset `EPIGRAPH_ENV` counts as production. With a provider whose
`allowed_emails` and `allowed_domains` are both empty, `auto_provision = true`,
and no `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`, the server **refuses to boot**.
`provision_external_user_client` and the refresh-token gate deny by default,
so an instance that booted in that posture would 403 every provisioned
identity at its next refresh, with nothing in the logs naming the cause. The
boot refusal is how you find out. Choose one:

* populate `allowed_emails` / `allowed_domains` in `providers.toml`
  (recommended);
* or set `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`, to declare that any identity
  the provider authenticates may have an account here;
* dev and CI only: set `EPIGRAPH_ENV` to `development` / `dev` / `test` /
  `testing` / `local` / `ci` to downgrade the abort to a warning.

External clients are re-checked against the allowlist on **refresh** too, so
removing an address stops that client renewing.

### Claim acts: `supersede` and `mark_duplicate` need `claims:write`

A supersede or a dedup is the CALLER's act, its own write to its own claim.
Only the cascade after it is administrative.

| Surface | Scope |
|---|---|
| MCP `supersede_claim`, `mark_duplicate` | `claims:write` + the rule below |
| `POST /api/v1/claims/:id/supersede` | `claims:write` + the rule below |
| `POST /api/v1/claims/:id/dedup` | `claims:write` + the rule below |

The per-claim rule, shared by both transports (`epigraph_auth::claim_act`):
the caller may perform the act when its viewer **writes the group that owns
the claim** (live `admin` or `writer` membership), or when it holds
**`claims:admin`** (any claim it can read). For a dedup, the **canonical** is
judged by the same rule as the duplicate: the cascade re-points other
writers' edges and BBAs onto it, so a `claims:write` caller may only choose a
canonical it could write.

* **Authorship alone admits nothing.** An author whose membership in the
  owning group was revoked, or downgraded to `reader`, cannot retire or
  rewrite that claim at `claims:write`. The non-admin rule is exactly
  `claims_tenancy`'s `WITH CHECK`, so the code refuses by name what the
  database would refuse anyway.
* MCP's operator-link arm does not admit a claim act.
  `resolve_backlog_item` and `patch_claim` keep it. Claims an operated agent
  submits after its operator link are owned by the operator's personal
  group, which the operator writes, so the operator is admitted by the rule
  above on its own stamp. Claims still owned by the agent's own personal
  group (written before the link, or by a write path that does not re-own)
  are NOT: the operator needs `claims:admin` for those, or must first move
  them with `epigraph-operator reown-claims`.

**Which claims that reaches.** A claim written through an MCP server is
authored by that server's signer agent and owned by the signer's group, not
by the human behind the OAuth token. For such a claim, a `claims:write`
caller is admitted only if it writes the signer's group, so retiring it over
OAuth otherwise needs `claims:admin`. Before you withdraw an administrative
grant from a human client, check which groups own the claims that human
retires, and whether the human writes them.

* A claim the caller cannot read answers exactly like a missing one (HTTP
  `404`; MCP `claim <id> not found`). For a dedup this holds for the
  duplicate AND the canonical.
* A claim the caller can read but may not retire (or a canonical it may not
  choose) is refused by name: HTTP `403` with
  `{"error": "not_owner", "rule": "not_claim_writer", "claim_id": ..., "retryable": false}`,
  with `claim_id` naming the refused claim. MCP gives `-32600` with the same
  keys in `data`. Nothing is written.
* The act runs on a transaction stamped with the CALLER's own authority, the
  one the authority read ran on. The single exception is over MCP: a
  `claims:admin` caller on a claim it does not write acts with the MCP server
  agent's stamp, but only while the token's client record still grants it
  `claims:admin` (`ADM02`, below). No other admission borrows the server
  agent's stamp. Over HTTP the database still decides a `claims:admin` write,
  so an admin whose stamp cannot write the row's group is refused (`403`,
  nothing written) on an application-role deployment.
* The cascade is reported `{"status": "deferred"}` and applied by the replay
  timer on the maintenance DSN (section 5).

A token holding `claims:admin` WITHOUT `claims:write` does not reach these
two acts. An administrative client should hold both, as `epigraph-admin`
does.

### `epigraph-operator grant-client-scope` / `revoke-client-scope`

```
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
  epigraph-operator grant-client-scope <oauth_clients.id> <scope> --dry-run
EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
  epigraph-operator grant-client-scope <oauth_clients.id> <scope> --apply --reason "..."
```

The audited way for an operator to give a HUMAN's own client an admin-only
scope, instead of a raw `UPDATE oauth_clients`:

* maintenance DSN only: the dedicated variable, with no fallback to
  `DATABASE_URL` or `MAINTENANCE_DATABASE_URL`, and a login outside
  `epigraph_maintenance` is refused;
* scopes from `ADMIN_ONLY_SCOPES` only, checked before connecting;
* `client_type = 'human'` only. Service clients (`bootstrap_clients`) and
  agent clients (the approval path) are refused;
* a GRANT only to a client whose `status` is `active` (a revoked, suspended
  or pending client would carry the scope once reactivated or approved). A
  revoke works on any status. Every run prints the status;
* the scope is added to, or removed from, BOTH `allowed_scopes` and
  `granted_scopes`, and every other element of each array is kept in order;
* idempotent. Exactly one of `--dry-run` / `--apply` is required;
* every `--apply` writes one `security_events` row
  (`oauth.client_scope_granted` / `oauth.client_scope_revoked`, with
  `agent_id` = the client's agent). Its `details` hold the operator, the
  client (with its status), the scope, `changed`, and both arrays before and
  after.
  * The operator is recorded as several facts, none of them an identity on
    its own: the database login (`session_user`); the process's REAL uid and
    its passwd name (the first field of the `Uid:` line in
    `/proc/self/status`, from the kernel); its audit login uid and passwd
    name (`/proc/self/loginuid`, which `sudo` does not change; `null` where
    the kernel has none); the connection's client address (also the row's
    `ip_address`) and `application_name`; and `os_user` from
    `SUDO_USER`/`USER`/`LOGNAME`, which is advisory (`os_user_source` says
    so: anyone can set it).
  * Run the binary directly as yourself. Under `sudo -u` the real uid names
    the target account, and only the login uid still names you. A shared
    maintenance login names no person; a per-operator login does.
  * A no-op `--apply` is recorded too (`changed: false`), which is how a
    grant made some other way is ratified. A dry run writes nothing.

**A human's agents carry at most that human's scopes.** Agents acting through
the human's OAuth client hold what the human CONSENTED to, narrowed to what
the client is still granted. The refresh grant issues the refresh token's own
scopes intersected with `granted_scopes`, and never widens them (RFC 6749
section 6). A grant made here therefore does NOT reach an existing connector
at its next refresh: the human must re-authorize it (a new
authorization-code grant, for example by reconnecting the connector) so the
consent can include the new scope. A revocation does take effect at the next
refresh. An access token minted before it keeps the scope until it expires,
except on the paths that re-read the grant on every call: the audited admin
writes (migrations 111 and 112) and the MCP server-stamp borrow below.

While the admin-scope switch is armed (migration 128), `grant-client-scope`
refuses; `revoke-client-scope` still works.

### The MCP server-stamp borrow re-checks the live grant (`ADM02`)

The borrow above (MCP `supersede_claim` / `mark_duplicate` by a
`claims:admin` caller on a claim it does not write, acting with the MCP
server agent's stamp) does not trust the token's `claims:admin` scope alone.
MCP verifies a token's signature and expiry, but not its revocation. So on
every such call the server also requires the token's client record to grant
the scope live, with the same predicate the audited admin paths
(`patch_claim`'s admin write, migration 111, and the admin audit write, 112)
apply:

* an `oauth_clients` row whose `id` is the token's client id,
* whose `agent_id` is the token's agent principal (a token with no agent
  principal is refused before the grant is read),
* whose `status` is `active`,
* and whose `granted_scopes` contains `claims:admin`.

Otherwise the call is refused with `ADM02` wording (MCP invalid-request; the
message names the caller agent and the client record), and nothing is
written: the claim stays current, with no successor and no deferred cascade.
Calls on a claim the caller writes itself never borrow and are unaffected.

Callers this refuses:

* a client whose `claims:admin` was revoked (`revoke-client-scope`), or whose
  status is no longer `active`, while an access token minted before that is
  still unexpired: refused at once, not at expiry;
* a **hand-minted** admin token (signed outside the token endpoint), whose
  client id names no `oauth_clients` row, a row for a different agent, or a
  row without the grant: refused on every such call, however long it lives;
* the injected context of an `--allow-unauthenticated-http` listener, which
  has no client record.

List the admin tokens your MCP clients use and confirm each came from the
token endpoint, for a client that holds the grant.

**How to restore the borrow for a caller that should have it.**

* A human's own client: grant it through `grant-client-scope`, as yourself,
  on the maintenance DSN:

  ```
  EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
    epigraph-operator grant-client-scope <oauth_clients.id> claims:admin --dry-run
  EPIGRAPH_OPERATOR_MAINTENANCE_DSN=... \
    epigraph-operator grant-client-scope <oauth_clients.id> claims:admin --apply --reason "..."
  ```

  The command grants only to an `active` human client, so a revoked or
  suspended client must be reactivated first, through whatever reviewed path
  the deployment uses. From migration 122 on, that path is a privileged
  (maintenance or admin) session: an application-role session is refused
  (`42501`) for a client that is `suspended` or `revoked`. Because the check
  is live, a token that already carries `claims:admin` in its scope lands
  again as soon as the grant is applied. A token minted without the scope
  never gains it by refreshing, so the human must re-authorize the connector
  before it reaches the borrow at all.
* A hand-minted token cannot be re-granted: there is no client row, or no
  row for its agent, to grant. Replace it with a token the token endpoint
  issues to a client that holds the grant, then grant that client as above if
  it is a human's.
* The command refuses `service` and `agent` clients. A service client's
  scopes are defined by `bootstrap_clients`, and an agent client's by the
  approval path. Do not work around either with a raw `UPDATE oauth_clients`;
  that is the unaudited path this command replaces.

### Approving, suspending and revoking clients

**Client approval is a maintenance act (migration 188).** The application
role cannot EXECUTE `epigraph_oauth_client_approve`.
`POST /api/v1/admin/clients/:id/approve` answers `501` MOVED on a request
unit, whether or not 188 is applied. A maintenance session calls
`public.epigraph_oauth_client_approve(uuid, text[], uuid)` directly. While
the admin-scope switch is armed, or when it cannot be read, approval refuses
an admin-only scope and never grants `platform:admin`. Registration
(`POST /oauth/register`) grants a fixed set whatever it is asked, and refuses
(400) a request that names an admin-only scope while the switch is armed.

`epigraph-operator suspend-client --client <oauth_clients.id> --reason <text> --apply`
sets `suspended`, revokes every live refresh chain and writes one
`oauth.client_suspended` audit row, in one transaction. `revoke-client` does
the same with the final status `revoked` (`oauth.client_revoked`).
Already-minted access tokens stay valid until they expire, and both verbs
print when that is. Both are idempotent. `suspend-client` refuses a revoked
client.

`epigraph-operator list-dcr-clients [--older-than-hours 24]` lists every
dynamically registered (RFC 7591) client with its authorization-code count.
`sweep-dcr-clients [--older-than-hours 24] [--reason <text>] --apply` revokes
those that never completed an authorization and are older than the floor,
with one audit row per client.

**Access-token revocation (migration 141).** `POST /oauth/revoke` with an
access token records its `jti` in a durable denylist, which the API and the
MCP bearer middleware read. A binary built with it on a database without 141
fails CLOSED: every authenticated request is refused while the lookup errors.
So apply 141 with or before the binaries that read it.

### Refresh scope (migration 140) — a refresh never widens a chain

`epigraph_refresh_token_rotate` (migration 140) and
`oauth/token.rs::handle_refresh_token` issue the PRESENTED refresh token's own
scopes, narrowed to the client's current `granted_scopes` (RFC 6749 section
6), never the client's whole grant. A new chain stores its CONSENTED scopes
(`oauth::scopes::chain_scopes`), not the mint chokepoint's output.

1. **Deploy order (when upgrading across 140).** Migrations apply in number
   order, so 140 goes out after every lower-numbered migration, never ahead
   of them. Migrate 140 BEFORE, or together with, the API binary built for
   it. Either half alone still widens. A binary built for 140, on 118's definer,
   issues a narrow access token but stores a whole-grant successor, which the
   next refresh then issues. A binary built before 140, on 140, stores a
   narrow successor but issues whole-grant access tokens.
2. **A grant does not reach an existing chain.** A scope added to a client
   after its refresh chain was minted is never picked up by refreshing. That
   covers `epigraph-operator grant-client-scope` and the `bootstrap_clients`
   canonical-scope reconcile. A human connector must be re-authorized (a new
   authorization-code grant), and a refresh-only service consumer must run a
   fresh `client_credentials` grant. A revocation still takes effect at the
   next refresh.
3. **A refresh `scope` that names nothing issuable is refused.** A refresh
   request whose `scope` names none of the chain's issuable scopes gets
   `400` with the RFC 6749 section 5.2 body `{"error":"invalid_scope"}`, and
   the presented refresh token is NOT spent. That includes a `scope` whose
   every name the mint chokepoint strips (an admin-only scope while migration
   128's switch is armed, or when the switch cannot be read). A `scope` that
   names some issuable scopes narrows the access token to them (unknown names
   are dropped, as for `client_credentials`), and the chain keeps its scopes.
4. **If you upgrade a database whose chains were rotated under migration
   118's definer:** migration 140 changes only future rotations. A chain
   rotated under 118 already stores the client's whole grant. Every rotation
   re-caps its expiry at now() plus the client type's TTL (human 30 days,
   service 90 days, agent 24 hours), with no family-age cap, so a connector
   that refreshes at least once per TTL keeps the widened scopes
   indefinitely. Decide, per chain.

   **What a revoke stops, and what it does not.** Revoking a chain (either
   function below) stops its NEXT refresh, and ends any elevation session on
   that family at once (migration 125's `refresh_tokens_end_elevations`
   trigger). Access tokens the chain already issued stay valid until they
   expire: at most 1 hour for a `human` or `service` client, and 15 minutes
   for an `agent` one. The bearer check consults only the per-`jti`
   access-token denylist (migration 141), never the refresh family. To cut a
   known access token off sooner, revoke it by value at `POST /oauth/revoke`.

   Every query below is read-only and runs on the maintenance DSN. A
   family's root is its first token: its row has `family_id` NULL and its
   `id` is the family id, and every successor a rotation inserts carries
   `family_id` = that id. A live row with `family_id` NULL has never been
   rotated, so 118 cannot have widened it.
   * **Rootless chains: start with these.** A chain whose root row is gone
     (most chains rotated under 118 are in this shape) does not record what
     its consent granted. The only census is a HEURISTIC against the
     client's grant as it stands now:
     ```sql
     SELECT t.id AS live_token_id, c.id AS client, c.client_id, c.client_type,
            t.scopes, c.granted_scopes,
            t.scopes @> c.granted_scopes AS holds_whole_grant
       FROM refresh_tokens t JOIN oauth_clients c ON c.id = t.client_id
      WHERE t.revoked_at IS NULL AND t.expires_at > now()
        AND t.family_id IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.id = t.family_id)
      ORDER BY c.client_type, c.client_id;
     ```
     `holds_whole_grant` errs both ways. It is true for a chain whose last
     118 rotation stored the grant as it stands now, but equally for a
     consent that genuinely asked for everything, and for a client whose
     grant is empty (every array contains `{}`). It is false for a chain that
     WAS widened under 118 when the client's grant has grown since (a scope
     added after that rotation). The stored rows cannot tell these apart, so
     the decision is the operator's.
   * **Chains that still have their root.** The root's scopes are what the
     consent granted, so a live successor holding a scope its root does not
     was widened:
     ```sql
     SELECT t.id AS live_token_id, c.id AS client, c.client_id, c.client_type,
            r.scopes AS consented, t.scopes AS live
       FROM refresh_tokens t
       JOIN refresh_tokens r ON r.id = t.family_id
       JOIN oauth_clients c ON c.id = t.client_id
      WHERE t.revoked_at IS NULL AND t.expires_at > now()
        AND NOT (t.scopes <@ r.scopes)
      ORDER BY c.client_type, c.client_id;
     ```
   * **Revoke one chain** (both cases). A family has exactly one live row, so
     revoking that row ends the chain, and only that one connector must be
     re-authorized (a human re-authorizes it; a service runs a new
     `client_credentials` grant):
     `SELECT public.epigraph_refresh_token_revoke('<live_token_id>', 'revoked');`
     It returns true when it revoked the row, and false when the row was
     already revoked.
   * **Revoke a whole client** (the coarse option):
     `SELECT public.epigraph_refresh_token_revoke_client('<oauth_clients.id>');`
     returns the number of tokens revoked. Mind the blast radius: a human's
     connectors all refresh on that human's ONE per-user client, so this logs
     the human out of EVERY connector, and the same trigger ends every
     elevation session on those families.
   * **Accept** the widening for chains whose consumer is trusted with the
     whole grant, and record that decision.

   Rollback: re-run 118's `CREATE OR REPLACE FUNCTION
   public.epigraph_refresh_token_rotate` block verbatim (owner and ACL
   survive it), and roll the API binary back with it (step 1). Migration 172
   re-states the same definer with pinned built-ins; its undo re-runs 140's
   block.

### Refresh-grant hardening (migration 174) — confidential clients authenticate on refresh; a chain is bound to its connector app

1. **An agent or service refresh carries the client's credential.** RFC 6749
   section 6: a confidential client authenticates on the `refresh_token`
   grant. An agent sends a fresh `client_assertion` (with
   `client_assertion_type=urn:epigraph:ed25519`), and a service sends its
   `client_secret`. Each is checked exactly as the `client_credentials` grant
   checks it (one shared check). A `client_id` on the request must be the
   chain's own. A refresh that does not authenticate is refused (`400` for a
   missing credential, `401` for a wrong one or a foreign `client_id`) and
   changes nothing: the presented token is neither burned nor rotated, so the
   client can retry with its credential. A later secret rotation or key change
   therefore cuts a live chain. No in-tree consumer refreshes an agent or
   service chain (the agents re-run `client_credentials`). An out-of-tree
   consumer that does must send its credential, or switch to re-running
   `client_credentials`. Human (connector) chains are unaffected. Rollback:
   the previous API binary.
2. **Migration 174 BEFORE the API binary.** 174 adds
   `refresh_tokens.issued_to_client_id` (the connector app that obtained an
   authorization-code chain; no foreign key), a `BEFORE INSERT` trigger that
   gives every rotated successor its family's app, and the operator revoke
   below. It does not restate `epigraph_refresh_token_rotate`, so it commutes
   with any migration that does (172 and 174 may apply in either order). The
   binary built for it reads the column on every refresh and writes it on
   every refresh-token mint. On a database without 174, every grant that
   mints or refreshes a refresh token fails with `500`: the code exchange,
   `client_credentials` (every agent and service token), the
   external-provider grants (every login) and the refresh grant. The same
   holds after 174's UNDO if the binary was not rolled back first. The
   previous binary runs unchanged on a migrated database.
3. **Suspending a connector app cuts that app's sessions only.** A code
   exchange binds the new chain to the app that obtained the code, and refuses
   (`403`) when that app is no longer active. A refresh of a bound chain whose
   app is suspended, revoked or gone is refused (`403`) and burns the
   presented token. The same person's chains through other apps keep
   refreshing. Chains minted before 174 store no app, and are not bound until
   their person re-connects; nothing is backfilled.
4. **Operator revoke keyed by (person, app)**, on the maintenance DSN:
   `SELECT public.epigraph_refresh_token_revoke_client_app('<per-user oauth_clients.id>', '<app oauth_clients.id>');`
   revokes that person's live chains issued to that app and returns how many
   (reason `client`). Migration 125's trigger ends the elevation sessions of
   those families, as for any revoke. It is `SECURITY INVOKER`, and EXECUTE
   is the maintenance role's alone. The coarse per-person lever,
   `epigraph_refresh_token_revoke_client`, still logs the person out of every
   connector. Chains minted before 174 carry no app, so only the coarse lever
   reaches them.
5. **Rollback:** roll the API binary back first, then 174's UNDO (its
   header): drop the trigger and its function, drop
   `epigraph_refresh_token_revoke_client_app`, drop the partial index, and
   drop the column. The rotate definer is untouched by 174, so nothing is
   re-run for it.

## 9. Operator binding, the custodian role, identities, groups and the operator CLI

### Operator binding (migration 122) — deploy order

Every claim must be authored, and written, by an agent bound to a human
operator: a human operator itself, or the holder of a live `operator_links`
row. Anything else is refused with `OPL01`. A write that crosses from one
human into another's group or name is refused with `OPL02`. The invariant,
the error codes and the valve are described in `docs/tenancy.md`
("Operator binding"). This section is the ORDER, because arming is one-way
and every step before it must leave no live writer unbound.

**On a fresh database** (section 2), steps 4–7 find no legacy rows. Do steps
1–3 and 8–9: register the humans, link the writers, register the
workflow-ingest system agent, arm, and smoke-test.

1. **Build** every binary from one commit (api, mcp, `epigraph-migrate`,
   `epigraph-operator`, `epigraph-tenancy-backfill`).
2. **Migrate 122** (`epigraph-migrate`, on the migration DSN). It enforces
   nothing: it adds the trigger, the arming table (empty) and the definers.
   Binaries built before it keep working. Binaries built with it need it on
   their default-declaration path (it fails closed with `42883` without it),
   so migrate BEFORE they serve.

   2b. **Register the human operator(s)** (maintenance DSN, audited):
   `epigraph-operator register-human-operator --agent <the human's own agent>
   --client <that human's own OAuth client id> --reason <text> --apply`.
   Then read back `human_operators.client_id` and confirm it is the client
   you named.
   - `--client` is required, never inferred. The application role may insert
     `oauth_clients` rows, so take the client id from an out-of-band record
     of the person's own client, not from a listing of active `human`
     clients.
   - Only the agent of an active human OAuth client can be registered. From
     122 on, no link can be recorded to anyone else, so this step precedes
     every link below.
   - Check that no dynamically registered `human` client's agent is in the
     registry.
   - The registration records that one client. Suspending it later is what
     un-registers the human in effect. `revoke-human-operator --agent <id>
     --reason <text> --apply` revokes the registration outright. That is final
     for the row: every agent live-linked to the human stops authoring
     (`OPL01`).
3. **Live-link the live writers** that are not human operators:
   `epigraph-operator link --agent <id> --operator <human> --apply`, on the
   maintenance DSN. `link` also takes `--agent-model` with
   `--agent-system-prompt-hash`, or `--identity-pubkey`, to name an agent by
   the identity a stdio `epigraph-mcp` derives.
   - `link` refuses an OAuth principal. See "HTTP principals" in
     `docs/tenancy.md`, and resolve those before step 8. An HTTP service or
     agent client can instead be allowed to write as a bound agent without
     a link: `allow-author-binding-client --client <id> --operator <human>
     --reason <text> --apply` (migration 149). It exits 3 when the allowance
     is recorded but does not bind (`ALLOWED-BUT-INEFFECTIVE`);
     `revoke-author-binding-client` ends it.
   - Read `link`'s `FOREIGN-WRITE` lines (writer rows in groups the operator
     does not write) and decide each; `--revoke-foreign-writes` revokes them.
   - Linking a SHARED system identity (the workflow-ingest agent) to one
     human makes that human own every workflow row, and the request paths
     then refuse other humans' callers.
   - Resolve each identity to link by a value the code sets (its public key,
     or the id a service is configured with), never by a display name: an
     identity minted lazily by a shared code path can carry a generic name.
   - Include every service that writes claims on a PRIVILEGED DSN as a
     configured service agent (a downstream product mounted through the MCP
     federation, for example). Such a session is checked on its author alone,
     so that agent must be bound.
   - Do all of this here, before step 4. A writer that step 4 finds quiet is
     tied RETIRED, and a retired link is permanent: it is never promoted to a
     live one.
   - To end one live link later, `retire-link --agent <id> --reason <text>
     [--revoke-membership] --apply` (migration 191): the agent stops acting
     for its operator, which keeps ownership of its claims. It is refused
     while the agent still holds a live writer/admin row in the operator's
     group, unless `--revoke-membership`.
4. **Tie the legacy authors** (an upgraded database only). Register EVERY
   human first (step 2b). The other-human lineage skip consults the registry,
   so an agent operated by a not-yet-registered person would be tied to
   `--operator` for good; the read-only query is in `docs/tenancy.md`,
   "Existing rows". Then run `epigraph-operator link-legacy-authors --operator
   <human>` (a dry run: read the SKIPPED lines), then `--apply`. Give every
   `recent_writer` it skips a live link (step 3) or an explicit decision.
   `link-retired --agents-file <f> --operator <human> --apply` records
   retired links for an explicit list.
5. **Backfill** as the maintenance login (an upgraded database only), ONLY
   after the operator has decided who owns the legacy corpus
   (`--legacy-owner operator|platform`, required, with no default):
   `ANALYZE claims`, then `epigraph-tenancy-backfill run --legacy-owner
   <decision> --dry-run`, then the same without `--dry-run`.
   - It is batched, resumable and boundable: `--max-runtime` stops between
     batches with exit 3, and `--entity` runs one arm.
   - It rewrites claims and, through 070's arm (d), their derived rows. Check
     free disk first (the write volume lands in WAL), and
     `VACUUM (ANALYZE)` the rewritten tables between windows.
   - Embedded claims dominate the cost, because each update inserts into the
     HNSW indexes. See `docs/tenancy.md` "Running the backfill" for the cost
     model and the drop-and-rebuild alternative.
6. **Re-own** what linked authors' own groups still hold (an upgraded
   database only): `epigraph-operator reown-linked --operator <human>
   --legacy-owner <decision> --manifest-out <path>` (a dry run), then
   `--apply` with a new manifest path. Keep the manifests. `reown-linked` and
   its undo `reown-reverse` need a SUPERUSER DSN, because their probe switches
   the session to the application role. A plain maintenance login is refused
   before anything is written.
7. **Verify**: `epigraph-tenancy-backfill verify --legacy-owner <decision>`
   exits 0. Its REPORT line for linked authors' personal-group rows should
   read zero, or be explained. Rows left there, including those `reown-linked`
   held, cannot be superseded by their author once armed (`OPL02`). They are
   revised on a maintenance DSN (`docs/tenancy.md`, "Existing rows").
8. **Deploy the request binaries** (api, then mcp), and the fleet host
   change: pass the operator id, and run `link` at every spawn, on a
   maintenance DSN.
   - **Register the workflow-ingest system agent BEFORE arming** (migration
     148): `epigraph-operator register-system-agent --role workflow-ingest
     --agent <id> --reason <text>` (a dry run: check that the `AGENT` line
     reads `key=LEGACY`), then `--apply`. Do it BEFORE rotating that agent's
     key, and only once every API and MCP binary (including any container
     image that embeds the stdio MCP server) is at or above 148. The
     registration is immutable. Once armed, an unregistered system agent
     refuses every workflow write, and the census prints
     `SYSTEM-AGENT-UNREGISTERED` while one is missing.
   - Then **arm**: `epigraph-operator arm-operator-binding` (a census; the
     default window is 14 days, `--recent-days`), then `--apply`.
     `--allow-unbound-writers` arms although the census lists unbound recent
     writers, whose writes are then refused.
   - Before `--apply`, confirm that no request unit or stdio MCP
     configuration connects on a privileged DSN. Once armed, such a unit
     refuses to start ("The custodian role", step 4). A unit ALREADY RUNNING
     on a privileged DSN when you arm does not wait for a restart. It
     re-reads its posture every `EPIGRAPH_REQUEST_UNIT_RECHECK_SECS` (30 by
     default, 1 to 300) and exits 1 with `ERROR: stopping: ...` on stderr, so
     an overlooked privileged unit goes down within that interval of
     `--apply`. Restart every request unit after `--apply` anyway, and confirm
     that each boot log carries the `operator binding ENFORCED:` line.
   - The census must list no unbound recent writer you intend to keep. The
     census lists AUTHORS. Writers that do not appear there, and that you
     must inventory separately:
     - a writer that authors as someone else (a service client posting on an
       agent's behalf, a listener acting under a borrowed admin stamp). It is
       bound on its own principal once armed;
     - a claim written on an application connection with NO principal (a CLI
       or job on the application DSN). Once armed it is refused `OPL01`;
     - a tool that registers a FRESH agent per run (or per source) and
       authors as it. Such an author does not exist before the run, so it
       cannot be linked in advance, and once armed its claims are refused.
       Decide each such ingester before arming: author as a bound identity,
       or stop it.
   - Arming binds claim INSERTs. Claim UPDATEs other than a change of author
     stay gated by row security alone. So while a database still carries
     orphan permissive `*_privacy` policies, arming does not isolate claim
     updates between humans (`docs/tenancy.md`, "Scope: claim INSERTs").
9. **Smoke-test**, through the real HTTP route (not a hand-stamped SQL
   session):
   - a claim posted by an unbound principal naming a bound author is refused
     (`OPL01`; HTTP 403);
   - an INSERT on an unstamped application connection is refused (`OPL01`);
   - a claim by a live-linked agent, and one by the human, succeed;
   - the boot logs say "operator binding ENFORCED".

   Count refusals in the logs by the refusal prefix `OPL01:` / `OPL02:` (with
   the colon). The boot lines name the code without it.

**Rollback.** Before step 8's arm, every step is reversible or harmless.
Links are permanent records but grant nothing new, and `reown-reverse` undoes
step 6. After arming, set `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off` on the
affected units and restart them. Only binaries built with 122 carry the
valve. The valve relieves `OPL01` only, including the refusal of an unstamped
application session. `OPL02` stays in force, including for an unbound writer
(or another human's agent) that names a bound author or a retired identity
tied to a human. Removing the arming row, or dropping the trigger, is a
superuser DDL act on the migration DSN. To remove migration 122's functions
after step 8, first roll back EVERY binary built against them, not only the
MCP server:

* `epigraph-api`: every claim write through a default declaration calls
  `epigraph_require_bound_author` and `epigraph_require_operator_scope`, and
  every REST workflow write (`/api/v1/workflows/ingest|store|improve`,
  `/steps`, `/steps/delete`) calls the writer-authority checks. Without 122,
  each answers 500 (`42883`).
* `epigraph-mcp`: the HTTP listener reads its signer's binding through a 122
  function at startup and on every tool call, and fails closed without it: it
  refuses to start, and it refuses every call.
* `epigraph-tenancy-backfill`: `verify` inventories 122's definers. Its
  deferred list is presence-gated, so an older build is the safe one.
* `epigraph-operator`: its binding verbs call 122's definers.

Then drop the trigger and the functions. If migration 123 is applied, undo it
FIRST (next section), because its bodies call 122's. If migration 149 is
applied, run `docs/runbooks/149-undo.sql` before removing 122's functions:
it restores 122's bodies of `epigraph_author_binding` and
`epigraph_human_of`, and every allowlisted client's agent becomes unbound.

No environment variable is required. `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT`
exists only as the emergency valve.

### The custodian role (migration 123) — deploy order and rollback

Instance administration is `role:platform-custodian`, held by a registered
human operator through a timestamped `role_assignments` row. Agents never
hold it. `epigraph_is_instance_admin` keeps its name and answers from the
role. The model and the audit trail are in `docs/tenancy.md` ("The custodian
role").

1. **Preconditions.** Migration 122 applied, and every human who should keep
   instance-admin authority REGISTERED (`register-human-operator`, step 2b
   above) before 123 runs. 123 carries a live `instance_admins` row into an
   assignment only for a registered human, and loudly skips every other live
   row (a NOTICE and a `platform.role_migration_skipped` event). On an ARMED
   database, also measure which application paths rely on an instance-admin
   principal writing across groups or humans: from 123 on, no application
   session is relieved of `OPL02`, so each such write is refused and moves to
   the maintenance DSN (`custodial-supersede`, step 5).
2. **Migrate 123** (`epigraph-migrate`, migration DSN). It adds tables and
   function bodies, one restrictive policy on `security_events`, and small
   triggers on `instance_admins`, `human_operators` and `operator_links`. No
   backfill. `lock_timeout` is 3s; retry on a lock timeout. Binaries built
   before it keep working against it, except `epigraph-instance-admin grant`
   (always) and `revoke` of a principal that holds a live custodian
   assignment, which fail (`CUS05`) by design: end the role with
   `end-role-assignment`. A build with 123 refuses both before connecting and
   names their replacements.
3. **Deploy** `epigraph-api`, `epigraph-mcp`, `epigraph-operator`,
   `epigraph-instance-admin` and `epigraph-tenancy-backfill`, built from the
   same commit.
4. **Check.** `epigraph-operator list-role-assignments` shows the carried
   rows. Bootstrap a custodian if none was carried:
   `epigraph-operator grant-role --role role:platform-custodian --holder <the
   human's own agent> (--valid-to <RFC3339> | --open-ended) --reason <text>
   --apply`. Omit `--granted-by` only while no live custodian exists.
   - Confirm that each request unit connects as `epigraph_app` with
     `epigraph_bypass() = false`. On an armed database, its boot log must
     carry the line that starts `operator binding ENFORCED:` (with the
     colon).
   - On an armed database, a request unit (`epigraph-api`, and
     `epigraph-mcp` on every transport, a stdio configuration included) on a
     privileged DSN REFUSES TO START. It exits 1 after the ERROR line that
     starts `operator binding NOT ENFORCED for the writer on this privileged
     DSN:`, with `ERROR: refusing to start:` on stderr. Grep the prefix, not
     the word: both lines contain "ENFORCED".
   - Check every unit and every stdio MCP configuration's DSN BEFORE arming.
     Arming turns a privileged request DSN into a unit that no longer
     starts, and a running one into a unit that stops within its re-read
     interval (`ERROR: stopping:` on stderr).
5. **Custodial revisions** of the platform corpus use
   `epigraph-operator custodial-supersede --claim <id> --content-file <f>
   --truth <x> --assignment <the actor's live assignment> --actor <the
   custodian> --reason <text> [--allow-owned] [--apply]` on the maintenance
   DSN.
   - It records a `platform.custodial_act` against the assignment in the same
     transaction.
   - A claim the world group does not own is refused unless `--allow-owned`
     is given, and the act records whether it was.
   - The same transaction records a `supersede` cascade deferral naming the
     custodian. The edge migration and the belief cascade run from it in the
     next `replay_deferred_cascades` run, as for any deferred supersede.
   - The successor has no embedding until the next embedding backfill.

`end-role-assignment` ends an assignment. Once migration 130 is applied and
the acting person holds a live passkey, `grant-role`, `end-role-assignment`
and `custodial-supersede` need a confirmed act (`--act <id>`; the exact
conditions are in "Pending admin acts (migration 130)").

**Rollback.** First roll back every binary that calls a 123 function:
`epigraph-operator` (the role verbs and `custodial-supersede`),
`epigraph-api` (privatization records a custodial act and reads the
assignment), and `epigraph-tenancy-backfill` (an older `verify` is the safe
one). If migration 153 is applied, run `docs/runbooks/153-undo.sql` first,
and before it `docs/runbooks/185-undo.sql` if migration 185 is applied. If
migration 130 is applied, run `130-undo.sql` first too (it adds act-taking
overloads of 123's definers).

Then run `docs/runbooks/123-undo.sql` on the migration DSN, in one
transaction:
- it stamps every live `instance_admins` row whose agent holds no live
  custodian assignment, so 083's restored body resurrects no authority ended
  after 123;
- it drops 123's triggers and re-applies 083's and 122's function bodies
  verbatim, so 122's instance-admin principal relief from `OPL02` comes back;
- it drops the `platform.` policy and every 123 definer;
- it lists the holders granted after 123, which exist only in
  `role_assignments`, to be re-granted in `instance_admins` by hand if they
  must survive.

It leaves the role tables, the audit rows and the OCCUPIES edges in place:
that is history, and only a forward fix changes it.

### A lineage stays in its owner group (migration 153) — deploy order and rollback

Once the operator binding is armed, an application session may not leave a
CURRENT claim naming `supersedes` in a different owner group than that
predecessor: at the insert, at a re-open, or when `supersedes` is first set
on a claim that stays current. It is refused `OPL02`, which the
`operator_link_enforcement` valve never relieves. Privileged sessions, the
supersede act (which inherits the predecessor's group), retired rows (the
dedup and consolidate acts) and an unarmed database are unchanged. The rule
and its reason are in `docs/tenancy.md` ("A lineage stays in its owner
group").

1. **Preconditions.** Migration 123 applied. No binary change is needed: the
   refusal is `OPL02`, which every surface already maps.
2. **Migrate 153** (`epigraph-migrate`, migration DSN): one `CREATE OR
   REPLACE` of the claims binding trigger function. It changes no write on
   an unarmed database. It may apply before or after any lower-numbered
   migration that does not re-body that function (sqlx applies every
   embedded, unapplied migration in version order).
3. **Before arming, census the dangling successors** that 153 does not
   revisit (read-only):

   ```sql
   SELECT (p.owner_group_id = '00000000-0000-0000-0000-000000000000') AS world_pred,
          (s.owner_group_id IS DISTINCT FROM p.owner_group_id) AS cross_group,
          count(*)
     FROM claims s JOIN claims p ON p.id = s.supersedes
    WHERE COALESCE(s.is_current, true) AND COALESCE(p.is_current, true)
      AND s.id <> p.id
    GROUP BY 1, 2;
   ```

   (`00000000-0000-0000-0000-000000000000` is the world group's id, a schema
   constant.) What blocks is ANOTHER CURRENT successor of a CURRENT
   predecessor, in any group. 123's inherited-author rule needs "no other
   current successor", and that rule is the only one that admits a supersede
   restating a claim under its unbound or retired-linked author, the
   custodial supersede of a corpus claim included (refused `OPL01`
   otherwise).
   - The `world_pred` rows are custodial edits that would be refused once
     armed. Revise or retire each such successor on the maintenance DSN
     first.
   - The other rows include benign pairs: a same-author first `supersedes`
     within one group needs no inherited rule.
   - A current successor of an already-retired predecessor blocks nothing.
   - The `cross_group` rows are the shape 153 refuses. Migration 153's header
     carries that subset's count alone.
4. **Before arming, confirm the world group has no live writer.** 153
   compares groups only, so a writer of the world group could still attach a
   current successor to a corpus claim in that group, with the same effect.
   The world group has no memberships by design, but nothing enforces it.
   Expect 0 rows:

   ```sql
   SELECT agent_id, role FROM group_memberships
    WHERE group_id = '00000000-0000-0000-0000-000000000000'
      AND revoked_at IS NULL AND role IN ('writer', 'admin');
   ```

   A row is a stop for arming until it is revoked or ruled on.

**Migration 185** builds on 153: once armed, a supersession is bound on its
ACTOR, not on the author its successor inherits. It has no ordering
constraint against the binaries, and it changes no write while the database
is unarmed. Before applying it, check that

```sql
SELECT md5(prosrc) FROM pg_proc
 WHERE oid = to_regprocedure('public.epigraph_claims_require_operator_binding()');
```

prints `292b24b3dfb6b342f6f60d7868666236` (153's body; the value is pinned in
185's precondition). Over any other body, 185 refuses with `55000`, changes
nothing, and stops the migration run.

**Rollback.** `docs/runbooks/153-undo.sql` on the migration DSN, in one
transaction: it restores 123's body of the function and re-asserts its owner.
Run it before `123-undo.sql`. If migration 185 is applied, run
`docs/runbooks/185-undo.sql` first: it restores 153's body of the same
function.

### Agent identities and the attestor login (migrations 161, 162, 163, 166, 179, 180)

Migration 161 lets a host register an agent identity, declare its
succession ("X succeeds Y in group G, with these prompt files") and record
the prompt files it ran. The database links X to Y's operator only if Y is
live-linked, and a container can never declare a parent.

**The trust boundary is a database role.** Session settings such as
`epigraph.principal_id` can be SET by any login, and agent containers hold an
application DSN, so registration is gated on the connection's ROLE:

* `epigraph_identity_attestor` is created by 161 as `NOLOGIN`, a member of
  nothing. Give it LOGIN and a password out of band:
  `ALTER ROLE epigraph_identity_attestor LOGIN PASSWORD '<secret>';`. Its
  privileges are USAGE on schema `public`, EXECUTE on
  `epigraph_register_agent_identity`, a `SECURITY DEFINER` owned by
  `epigraph_maintenance` whose EXECUTE is revoked from PUBLIC, from
  `epigraph_app` and from its owner, and, from migration 166, EXECUTE on
  `epigraph_role_agent_may_run(uuid)`. No API route registers.
* **Check it** at any time, on the maintenance DSN:
  `SELECT public.epigraph_identity_attestor_faults();`. It must return `{}`.
  It lists any elevated attribute, any membership of the attestor's own, and
  any other non-superuser role that can act as it. The migration raises on
  any fault if the role already exists.
* **If migration 161 could not create the role** (no CREATEROLE), it says so
  and skips the attestor grant. Create the role and grant it, as a superuser
  or the owner:

  ```sql
  CREATE ROLE epigraph_identity_attestor NOLOGIN;   -- a member of nothing
  GRANT USAGE ON SCHEMA public TO epigraph_identity_attestor;
  GRANT EXECUTE ON FUNCTION public.epigraph_register_agent_identity(
      bytea, uuid, text, text, text, bytea, jsonb) TO epigraph_identity_attestor;
  REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity(
      bytea, uuid, text, text, text, bytea, jsonb) FROM epigraph_maintenance;
  SELECT public.epigraph_identity_attestor_faults();   -- must be {}
  ```

* **Migration 166's grant, out of band, for the same case.** When the
  attestor is created (or re-created) after migration 166 ran, also run:

  ```sql
  GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_may_run(uuid)
      TO epigraph_identity_attestor;
  ```

  Without it the host's "may this agent run?" question is denied (`42501`).

Migrations 162 and 163 make retiring an agent key close its validity window.
Undo each by re-running 161's `CREATE OR REPLACE FUNCTION
public.epigraph_agent_key_set_status` block verbatim (not 118's, which has no
attested-type gate). Windows closed in between stay closed.

**Separate signing keys.** A host can register an identity key and give the
agent process a different, active `signing` key of that agent:
`--agent-identity-pubkey` / `EPIGRAPH_AGENT_IDENTITY_PUBKEY` with
`EPIGRAPH_AGENT_SIGNING_KEY` (environment only, never the command line),
stdio only. `epigraph-mcp-full` refuses to serve unless the signing key is an
ACTIVE `signing` key of the agent the identity key names.

**Role-attached agents (migration 166).** An agent attached to a role runs
only while a human holds the role. An application write whose acting agent
has a live attachment is refused `ROL01` unless, for every live attachment,
the role has a live human holder and the agent's live-linked human is that
holder. That also refuses an agent still linked to the previous holder after
a handover: grant the role back to its human, or detach the agent and attach
an identity linked to the new holder. `epigraph-mcp-full` asks the same question
at boot, on every transport, and refuses to start on `may_run = false`.
Attachments are written by a maintenance session
(`epigraph_attach_agent_to_role` / `epigraph_detach_agent_from_role`, or a
direct statement that meets the same guards) and by the identity
registration. Order: REGISTER, THEN ATTACH. Attaching an identity before the
host first registers it makes that registration abort `AID09`, and the
identity stays refused. An operator link counts the same way. The database
enforces the rule against a writer that does not choose its own principal
(the API, which stamps the authenticated viewer). A container that holds the
application DSN directly can stamp another identity of the same human; the
migration's header states that limit in full.

**Group bindings that admit only attached agents (migration 179).**
`define-group-role` and `bind-group-role` take
`--agent-mode holder_only|registered_agents|attached_agents`. 179 checks the
md5 of the three 165 function bodies it re-states, and refuses with `55000`
(nothing changed) over any other body.

**Legacy fleet parents (migration 180).** Registration accepts a legacy
fleet identity as a parent (`AID03`). `epigraph_record_legacy_succession(child,
parent, group_folder, reason)` (maintenance-only, audited) records, after the
fact, a succession that an `AID03` refusal skipped. Take the
(child, parent, folder) triple from the host's refusal alert, and run the
record before the legacy links retire. 180 checks the md5 of 166's
registration body and refuses with `55000` over any other.

**Rollback.** `docs/runbooks/180-undo.sql` before `166-undo.sql`.
`166-undo.sql` restores 165's writer-scope body, 123's attribution body and
161's registration body. Roll back first any `epigraph-mcp` built against
166, because it calls `epigraph_role_agent_may_run` at boot and refuses to
start without it. 161's own undo is a statement list in its header (section
8 of the file). It ends with `DROP ROLE epigraph_identity_attestor`, which is
cluster-wide: run that only once no database uses the role. Linked agents
keep their links.

### Keyless team groups and role-derived membership (migrations 164, 165)

A team group is a visibility boundary, not an encryption one. It is created
and administered only through maintenance verbs:

```
epigraph-operator create-group --kind team --name "<name>" --admin <registered human's agent> --reason <text> [--apply]
epigraph-operator group-member add|remove|set-role ...        # see --help
epigraph-operator define-group-role --key role:<key> --description <text> --group <id> \
    --member-role reader|writer [--agent-mode ...] --reason <text> [--apply]
epigraph-operator bind-group-role --role <key> --group <id> --member-role reader|writer [--agent-mode ...] --reason <text> [--apply]
epigraph-operator end-group-role-binding --binding <id> --reason <text> [--apply]
epigraph-operator group-roster --group <id> [--at <RFC3339>]
```

Without `--apply`, each verb's writes and audit row roll back.
`define-group-role` and `bind-group-role` bind a NON-ELEVATING catalog role to
a group. Every registered human holding a live assignment of the role is then
a member, computed and never written, and the membership lapses at the
assignment's end. A role that elevates or reads the audit trail is refused
(`GRB01`). The member verbs refuse the last live admin's removal or demotion.
The rules are in `docs/tenancy.md` ("Keyless team groups", "Group membership
that follows a role"). Each migration's undo is a statement list in its
header. Those undos were exercised on throwaway databases only.

### `epigraph-operator restrict-claims` — the audited admin privatization act (no migration)

This verb moves listed PUBLIC claims into a target group with
`visibility = 'group'`, together with every row that follows them: evidence,
reasoning traces, BBAs, versions, challenges, frame assignments, fragments,
and every edge with the claim as an endpoint, other writers' rows included.
`reown-reverse` reverses it exactly. It runs on the maintenance DSN like the
other operator verbs, and like `reown-claims` it needs a SUPERUSER DSN (its
readability probe switches the session to the application role). Module doc:
`crates/epigraph-cli/src/operator/restrict.rs`.

```bash
# dry run: plan, held claims with reasons, per-table counts, a sample, ENFORCED/UNENFORCED
epigraph-operator restrict-claims --claims-file ids.txt --target-group <group> \
    --operator <person> --manifest-out restrict-1.jsonl
# apply: repeat the dry run's eligible count back
epigraph-operator restrict-claims ... --manifest-out restrict-1.jsonl --apply \
    --confirm-count <N> --ruling "<decision>" --reason "<why>" [--accept-unenforced]
# undo (several manifests: pass them all; applied newest first)
epigraph-operator reown-reverse --manifest restrict-1.jsonl [--apply]
```

- **Eligible**: public and world-owned (`--allow-non-world-owner` admits other
  public owners). The target must be an existing `active` group, not world or
  seed, administered by `--operator`. A claim whose move would make another
  group's row readable to the target's members (for example an edge declared
  `('group', H)`) is HELD, not widened. Pinned evidence is left as it is.
- **Enforcement**: the run detects legacy permissive read policies (and row
  security disabled) on every table it touches. `--apply` refuses while any
  exist unless `--accept-unenforced`. The report and the audit row then say
  UNENFORCED, because an application session can still read the moved rows.
- **Manifest**: the header comes before the first batch, and each batch's
  prior tuples (owner, visibility, co-owner, `writer_owned`) are fsynced
  before its write. A manifest is never overwritten: a resumed run takes a
  new path, and moved claims count as done. `--max-batches` bounds one run.
- **Audit**: one `security_events` row per applied run
  (`privatization.cli_restrict`) and per reversed manifest
  (`privatization.cli_restrict_reverse`), attributed to `--operator`. It is
  written in the first batch transaction that changes anything. It carries
  the ruling, the reason, the target, the planned counts, the operator login
  and process, the SHA-256 of the id file and of the manifest header (the
  whole manifest on reverse), and ENFORCED/UNENFORCED.
- **Reverse** restores every recorded row and edge to its own recorded tuple,
  never to a meet recomputed from its endpoints (an edge declared group
  between public claims stays group). An edge whose other moved endpoint is
  held keeps its narrow meet until that endpoint is reversed. The
  declassification interlock is armed transaction-locally around the one
  claims UPDATE, for claims recorded as originally public only.
- **Nodes stay; links narrow.** The claim's own dependent rows (evidence,
  traces, BBAs, beliefs, versions, challenges, triples, revocations) and its
  LINK rows (edges, cluster / frame / neighbourhood assignments, entity
  mentions, provenance links) narrow. A node at the other end (another claim
  or its evidence, a frame, a cluster, an entity) is never written. A
  harvester fragment narrows only if every claim it is the provenance of is
  restricted into the target; otherwise it keeps its tuple. The
  classification is `restrict::TABLE_ROLES`, and an unclassified table is
  refused.
- **Edges with an evidence endpoint** (claim→evidence, evidence→evidence)
  are not re-met by the tenancy trigger, so the tool narrows them itself: an
  edge is no more visible than its least visible endpoint. Each takes the
  meet of its endpoints (the same tuple a claim-endpoint edge gets) unless it
  is already at least as narrow. Each is recorded and restored like every
  other edge. The plan counts them (`EVIDENCE-ENDPOINT-EDGES`).
- **Not covered**: `claims.updated_at` is stamped by its trigger on apply and
  on reverse.

### `epigraph-operator regroup-claims` — move group-private claims between groups (no migration)

This verb moves listed claims that are `('group', <source>)` to
`('group', <target>)`, together with every row that follows only them, keeping
`group` visibility. It is for claims an earlier act put in the wrong group:
`restrict-claims` moves only public claims, and reversing the earlier act
first would make the claims public for a while and, on a linked graph, can
leave a shared edge public while its other end stays private. Nothing this
verb does makes a row public. `reown-reverse` reverses it exactly. It needs a
SUPERUSER DSN, like `restrict-claims`. Module doc:
`crates/epigraph-cli/src/operator/regroup.rs`.

```bash
# dry run: plan, every held claim with its reason code, every co-owned edge and
# source-node edge, a sample
epigraph-operator regroup-claims --claims-file ids.txt --source-group <group> \
    --target-group <group> --operator <person> --manifest-out regroup-1.jsonl
# apply: repeat the dry run's eligible count back
epigraph-operator regroup-claims ... --manifest-out regroup-1.jsonl --apply \
    --confirm-count <N> --ruling "<decision>" --reason "<why>"
# undo (several manifests: pass them all; applied newest first)
epigraph-operator reown-reverse --manifest regroup-1.jsonl [--apply]
```

- **Who**: `--operator` must be a registered human operator and a live admin
  of both groups. The target must be an active `team` or `community` group,
  or the operator's OWN personal group (the group carrying
  `did:epigraph:personal:<operator>`, created by the operator). Another
  person's personal group is refused, and so is the personal group of an
  agent the operator operates, even when the operator administers it: that
  group is the agent's, and the ownership model moves an operated agent's
  claims out of it (`reown-linked`), never into it. The source is held to
  the same rule: an active `team` or `community` group, or the operator's own
  personal group. Another person's personal group and an operated agent's
  are refused as `--source-group` even when the operator administers them,
  so their claims never leave them through this verb, into the operator's own
  group or into a team (`reown-workflows`' private move applies the same
  rule). Neither group may be the world or seed group, and they must differ.
- **Eligible**: a claim that is `('group', <source>)` and not sealed. A claim
  already `('group', <target>)` counts as done, so a re-run resumes. A public
  claim (`public-claim`) and another group's claim (`not-in-source`) are held,
  and so is a sealed claim (`sealed`): one with a `claim_encryption` row, or
  with a `claim_version_encryption` row on one of its versions (the version
  row would follow the claim away from the group that keys it). The `HELD`
  line names the table.
- **Held whole, never partly moved**: a claim carrying a public row
  (`public-row`), a row owned by a third group (`third-group`), sealed
  evidence (`sealed-evidence`: an `evidence_encryption` row, whose ciphertext
  is keyed to the group that sealed it), a sealed edge the move would
  re-tuple (`sealed-edge`: an `edge_encryption` row; the line names the edge
  and its key group), pinned evidence (`pinned`), or an edge whose new meet
  would drop a group its current tuple requires (`edge-would-widen`). The
  plan applies these checks too, so its eligible count is the number
  `--confirm-count` repeats. Ciphertext is never re-keyed by a move, and it
  never leaves the group it is keyed to, whether the target is a team or the
  operator's personal group. Each batch repeats the checks under its locks,
  with its claims, their evidence and their edges taken `FOR UPDATE` before
  it reads the seal tables, so a seal that lands after the dry run holds too.
- **Edges** take the EXACT meet of their endpoints: the INSERT rule applied
  to what each endpoint is.
  - An edge whose other end is a claim or evidence that stays in the source
    becomes co-owned by both groups, so only a member of both reads it. Every
    such edge is printed (`CO-OWNED-EDGE`) and counted. Edges with an evidence
    endpoint get the same meet, which the tool writes itself because the
    trigger does not re-meet them.
  - An edge whose other end is a NODE with its own tenancy (the `NODE-TYPES`
    line lists them; at head a workflow, frame, context, perspective,
    community or reasoning trace) is met with the node's own tuple. The
    trigger and `epigraph_node_tenancy` count such a node as public, so left
    alone an `executes` edge from a source-private workflow would go to the
    target alone: source-only members would lose it, and target-only members
    would gain an edge naming a workflow they cannot read. The tool writes the
    exact meet instead (co-owned by the node's group and the target) and
    prints every edge to a group-private node that is not the target's
    (`SOURCE-NODE-EDGE`, with the node, and a `source-node edges` count). An
    edge to a public node, or to one in the target, goes to the target alone.
    An edge to a moving claim's reasoning trace is also read through the
    trace, so the batch that moves the trace re-meets it whichever batch
    moves its other end, and an edge from a claim outside the run to a moving
    trace takes the exact meet as well (co-owned, `CO-OWNED-EDGE`; a public
    one holds the claim, `public-row`).
    A later act that re-tenants the claim again (another regroup, a
    restriction, the privatization pipeline's re-meet) puts such an edge back
    on the trigger's meet.
- **Locks**: each batch, dry runs included, holds `SHARE ROW EXCLUSIVE` on
  `edges`, `harvester_fragments` and the derived tables with no key to claims
  (`LOCKED-PER-BATCH`), so an edge or fragment inserted on a moving claim
  while the batch runs either lands before the batch reads its rows or is
  stamped after the move. Every write to those tables on the instance waits
  for the batch; keep `--batch-size` small on a busy instance.
- **Left as they are**: an outsider's challenge (it is the challenger's; it
  is readable with its claim) and a fragment shared with a claim that stays.
- **Invariants per batch**: the row census, every row's end state, and
  readability measured as an unstamped session (unchanged) and as a session
  reading only the source and only the target (each must match the tenancy
  model before and after). A table without enforced row security is refused.
- **Audit**: one `security_events` row per applied run
  (`privatization.cli_regroup`) and per reversed manifest
  (`privatization.cli_regroup_reverse`).
- **Exit**: `--apply` exits 3 when any listed claim was held or the moved
  count differs from `--confirm-count`.
- **Reverse** is a compare-and-swap per claim. A claim something moved since,
  a row written after the act, a neighbour that moved since, a claim, claim
  version or evidence row sealed since, a sealed edge the reversal would
  change (the run held every sealed edge it would have re-tupled, so such an
  edge was sealed after it), or an edge whose recorded tuple would be wider
  than the exact meet of its endpoints after the restore (an endpoint the
  neighbour watch does not cover moved: another claim's evidence, a node)
  holds the claim (exit 3). An
  edge stays on the meet of its current endpoints until every endpoint the
  manifest moved is back, then takes its recorded tuple. An edge to a
  group-private node that is not in the source (one in the target or one of
  a third group) was already wider than that node before the act, so its
  reversal holds the claim rather than write the wider tuple back: such a
  claim cannot be reversed by this tool. The dry run and the apply predict
  this for every edge and print each one (`IRREVERSIBLE-EDGE`, naming the
  claim, and an `irreversible edges` count with the number of claims).
- **Authority for its first use** (the 17 legacy workflow claims an earlier
  restriction put in the wrong team group): two operator rulings, both of
  2026-11-11. "Do both along with the 25 mixed lineage move" decides the
  move; "Build a regroup-claims verb" authorizes this tool to carry it out.
  The apply's `--ruling` text cites both. Before applying, read the dry run's
  `SOURCE-NODE-EDGE` lines: each is an edge from a group-private workflow (or
  other node) to one of the claims, and it stays co-owned with that node's
  group. Compare the count with the `executes` edges measured on production
  from source-group workflow rows to the listed claims; any other line is a
  reason to stop. Then read the `irreversible edges` count: every
  `IRREVERSIBLE-EDGE` line names a claim the act could not undo (an edge from
  a target-group or third-group workflow, or another node, to it). A count
  above zero is a reason to stop unless the decision accepts those claims as
  not reversible.

### `epigraph-operator reown-workflows --from-visibility group` — move group-private lineages to another group (no migration)

`reown-workflows` moves public lineages (`('public', <source>)`) into a team,
or narrows them in place. With `--from-visibility group` it instead moves
lineages that are ALREADY group-private, `('group', <source>)`, whole to
`('group', <target>)`: every generation, the plan claims they execute (and
their step lineages), every row those carry, and the plan edges. Nothing
becomes public. It needs a SUPERUSER DSN, like `regroup-claims`. Module doc:
`crates/epigraph-cli/src/operator/reown_workflows.rs` ("A private move").

```bash
# dry run: plan, held lineages, LEFT-CLAIM / SHARED-SPLIT / CO-OWNED-EDGE lines,
# ELIGIBLE-WORKFLOW-ROWS
epigraph-operator reown-workflows --canonical-names-file lineages.txt \
    --from-group <source group> --target-group <target group> --operator <person> \
    --from-visibility group --visibility group --manifest-out private-move-1.jsonl
# apply: repeat ELIGIBLE-WORKFLOW-ROWS back
epigraph-operator reown-workflows ... --manifest-out private-move-1.jsonl --apply \
    --confirm-count <N> --ruling "<decision>" --reason "<why>"
# undo (several manifests: pass them all; applied newest first)
epigraph-operator reown-reverse --manifest private-move-1.jsonl [--apply]
```

- **Who**: the source is `--from-group` or, without it, the operator's
  personal group. The rows are private, so the source is held to the same
  rule as the target: an active `team` or `community` group the operator is a
  live admin of, or the OWN personal group of an operator who is a registered
  human operator. Another person's personal group and an operated agent's are
  refused as `--from-group` even when the operator administers them, and an
  operated agent passed as `--operator` cannot move its own group's rows. The target must be another group that
  passes the same rule (the one `regroup-claims` applies). `--visibility
  group` is required and `--catch-up` is refused.
- **Public input is refused**: a public generation holds its lineage
  (`PublicInput`). An unshared public plan claim, or a public row a moving
  claim carries, holds its lineage as a hand-off, and an `--apply` then exits
  3: moving the rest would split the plan. Narrow such a plan in place first
  (the public act, `--visibility group` with the target equal to the source).
- **Left where it is, reported**: a plan claim shared with a lineage the list
  omits (`LEFT-CLAIM ... SHARED`, and `SHARED-SPLIT` when that lineage is the
  source's private one: list both in one run), or owned by another group.
  An edge from a moved row to one that stays in its group becomes co-owned by
  both groups, readable only by a member of both (`CO-OWNED-EDGE`).
- **Held whole**: a private row a third group owns, an edge whose new tuple
  would drop a group its current one requires, an edge to a group-private
  frame, context, perspective, community or reasoning trace that does not move
  (the edges trigger counts such a node as public, so the edge would go to the
  target naming a node the target cannot read), and a SEALED row: a plan claim
  with a `claim_encryption` row or a sealed version
  (`claim_version_encryption`), evidence of one with an `evidence_encryption`
  row, or a moving edge with an `edge_encryption` row. A move does not re-key
  ciphertext, and ciphertext never leaves the group it is keyed to, so the
  `HELD-LINEAGE` line reads `<claim|evidence|edge> <id> is sealed (<table>,
  keyed to group <group>)` and an `--apply` exits 3. Each batch re-plans under
  its locks, so a seal that lands after the dry run holds too.
- **Invariants per batch**: the public act's (every row's end state, the row
  census, the unstamped view, the atlas epoch), plus what a session reading
  ONLY the source and one reading ONLY the target read among the batch's rows,
  before and after, each against the tenancy model.
- **Reverse**: as for the public act (all of a manifest or nothing; refused
  when the plan changed or grew since, or when a moved claim, claim version,
  evidence row or edge was sealed since: ciphertext keyed to the target never
  goes back to the source).

#### Moving a pinned (scheduled) pipeline

A client that runs pinned workflows reads each generation's plan through
`GET /api/v1/workflows/:id/plan` with its OWN reader principal's token. The
read is viewer-scoped: it answers 404 when that principal can see none of the
generation's `executes` edges, and `hidden_count` counts every plan claim it
cannot read. After the move every row of the plan is owned by the target
group, so that reader principal needs a live membership of the TARGET group;
its membership of the source no longer reads anything of the plan. A client
that also checks each plan item's owner group against the group its pin
records refuses the plan from the moment the move commits until its pins
record the target. A non-member principal the client uses to prove that
outsiders see nothing must NOT be a member of the target.

Operator ruling, 2026-11-12: the pinned procurement pipeline moves, private,
from the team group that runs it to the consultancy team group. In the steps
below `<source>` is the team group that holds the pipeline now and `<target>`
is the consultancy team group. The operator must be a live admin of both, and
both must be active `team` or `community` groups (see **Who** above).

0. Build the lineage list from what the client has pinned, not from memory:
   every pinned root and every child generation a root names. A root that
   names its children only in its own content (no `executes` or `variant_of`
   edge between them) does not join them in the plan, so a child missing
   from the list stays in the source and the root's check refuses it at the
   next fire. If the client binds ONE owner group per schedule owner, every
   pinned lineage of that owner must be in this one act: re-pointing the
   owner's group breaks any of its pins left behind. `--confirm-count` is
   the dry run's `ELIGIBLE-WORKFLOW-ROWS` (generations, not lineages).
1. Before the move, add the reader principal's agent to the target group
   (`epigraph-operator group-member add --group <target> --agent <reader agent>
   --role <role per operator ruling> --reason "<why>" --apply`). The role is
   the operator's ruling, not this runbook's: the target group's membership
   policy may admit new members as writers only, and an operated agent is a
   member only where its operator writes. Check the non-member principal is not in the
   target (`epigraph-operator group-roster --group <target>`). If the client
   publishes new generations, its publishing agent needs a writer membership
   of the target too.
2. Dry run the move (`--from-group <source> --target-group <target>
   --from-visibility group --visibility group`). Stop on any `HELD-LINEAGE`,
   `LEFT-CLAIM` or `SHARED-SPLIT` line for the pipeline's lineages, and on a
   sealed hold in particular (a `HELD-LINEAGE` line reading `... is sealed
   (claim_encryption | claim_version_encryption | evidence_encryption |
   edge_encryption, keyed to group <source>)`): a claim left in the source
   keeps the source as its owner, so an owner-group check refuses the plan,
   and the reader would still need the source; a sealed row's lineage cannot
   move with this tool (it does not re-key ciphertext) and needs its own
   ruling.
3. Pause the client's pinned schedules for these lineages (or pick a window
   with no fire), then apply with the dry run's count.
4. Verify a plan fetch AS the reader principal for each pinned generation:
   200, `hidden_count` 0, every item's `owner_group_id` the target and
   `visibility` `group`. The same fetch as the non-member principal: 404.
5. Change the pins' recorded owner group to the target in the client's
   configuration, have the client verify the pins live, install them, and
   resume the schedules.
6. Undo: `reown-reverse` the manifest, then restore the pins' previous owner
   group.

`reown-claims --claims-file <f> --operator <person> --derived <mode>
--manifest-out <path> [--apply]` moves listed claims into the operator's
personal group. `hide-evidence` hides and pins selected evidence on the
operator's claims; it needs a SUPERUSER DSN for `--apply`, like
`reown-claims`, and `--apply` also requires `--manifest-out <new file>`.
Both are reversed by `reown-reverse`.

### `backfill_evidence_type` — legacy BBA typing (no migration, operator-gated)

Every BBA write path stores the canonical `mass_functions.evidence_type`.
Rows written before that are NULL, so `effective_source_strength` uses their
stored `source_strength` (or 0.5) instead of `[evidence_type_weights]`, and
the perspective lens never sees them. This binary types the rows whose stored
provenance determines their type, and leaves every other row NULL, counted
per writer (`combination_method`) and reason. Rules and reasons:
`crates/epigraph-cli/src/evidence_type_backfill.rs`.

- **Authority**: `MAINTENANCE_DATABASE_URL` must be set (the fallback to
  `DATABASE_URL` is refused), and its login must bypass row security.
- **`--calibration <path>` is required**, and must be the `calibration.toml`
  the API and MCP servers load. The report echoes it. A file that does not
  load, or has no `[evidence_type_weights]`, is refused.
- **Dry run by default.** `--apply` writes `evidence_type` only, only on rows
  still untyped, one transaction per `--batch` (default 1000). A re-run
  writes nothing on rows already typed. On a live database it also decides
  the rows written untyped since, by the same rules, so it can type some of
  them (for example a REST input sent without a type on a claim that declares
  one). Run the re-apply right after the apply and expect `written` near 0;
  any rows it does write were created after the first apply started.
  `--max-batches N` bounds a run. Pass the report's `last_id` as `--after` to
  continue.
- **Never typed**:
  - cached combination rows (the predicate the combine-input readers
    exclude);
  - unlabelled agent-less rows that share their (claim, frame) with another
    BBA;
  - `error_derived` / `prior` / `truth_value_seed`;
  - rows whose masses already carry their weight
    (`masses_already_weighted`: agent-less, perspective-less `discount`
    inputs, and lone unlabelled agent-less rows on `research_validity` /
    `paper_validity_*`);
  - other rows labelled with a combination-rule name in any case
    (`combination_labelled_input`);
  - test and backlog rows, and propagated BBAs;
  - linked `observation` / `testimony` / `computation` / `document` tags;
  - declared aliases, and rows with a deciding methodology.
- **Counted, not applied: `openstax_agent_name_only`.** OpenStax extractor
  rows have only their agent's name to go on. Typing them `logical` would
  move them from 0.3 to 0.85, and that needs its own operator decision.
- **Beliefs**: typing changes the weight each typed row contributes (the
  calibrated weight of its type, times the locality factor) and nothing else.
  Cached beliefs are NOT recomputed: run the belief recompute after an apply.

### `epigraph-operator delete-frames`

`delete-frames --ids-file <f> [--companion-claims-file <f>] --reason <text>
[--apply --confirm-delete <N>]` removes an explicit list of test or probe
`frames` rows, with the rows that cascade from them. It refuses any frame
that a real claim or another row still depends on, and records one
`operator.frames_deleted` audit row. Exit 3 means at least one listed frame
was refused, and then nothing is written under `--apply`. It runs on a
NOSUPERUSER maintenance login from migration 158 on. A `delete-frames`
built for migration 194 purges retracted BBAs through the audited purge
definer (`epigraph_purge_mass_functions`), so install it AFTER 194 is
applied.

### The operator CLI at a glance

Every verb runs on `EPIGRAPH_OPERATOR_MAINTENANCE_DSN`. Writes are audited,
and without `--apply` they roll back. `epigraph-operator <verb> --help` gives
the flags.

| Area | Verbs |
|---|---|
| Humans and links | `register-human-operator`, `revoke-human-operator`, `link`, `retire-link`, `link-retired`, `link-legacy-authors`, `arm-operator-binding`, `register-system-agent`, `allow-author-binding-client`, `revoke-author-binding-client` |
| Ownership | `reown-linked`, `reown-claims`, `hide-evidence`, `restrict-claims`, `reown-reverse` |
| Roles and custodians | `grant-role`, `end-role-assignment`, `list-role-assignments`, `custodial-supersede` |
| Groups | `create-group`, `group-member add\|remove\|set-role`, `define-group-role`, `bind-group-role`, `end-group-role-binding`, `group-roster` |
| Passkeys and elevation | `passkey-enroll`, `list-passkeys`, `revoke-passkey`, `end-elevation`, `list-elevations`, `verify-confirmations` |
| OAuth clients and scopes | `grant-client-scope`, `revoke-client-scope`, `suspend-client`, `revoke-client`, `sweep-dcr-clients`, `list-dcr-clients`, `arm-admin-scopes`, `disarm-admin-scopes` |
| Data hygiene | `delete-frames` |

## 10. Elevation (migrations 124–132)

Elevation is time-boxed, passkey-confirmed, read-only access for a custodian
to rows outside their own groups. Every elevated read is recorded in a log
that the people whose rows were read can see. The model is in
`docs/tenancy.md` ("Elevation"). The subsections below give each
migration's deploy order and rollback, then the order across the whole stack.

### Passkeys (migration 124) — deploy order and rollback

A registered human's WebAuthn passkeys (`person_authenticators`) and the
maintenance enrollment tickets that admit them (`passkey_enrollments`). This
is storage only: nothing reads a passkey for authority until the elevation
ceremony is deployed, and nothing serves the enrollment page until the API
that runs the WebAuthn ceremony is deployed with a relying party configured
(`EPIGRAPH_WEBAUTHN_RP_ID` and `EPIGRAPH_WEBAUTHN_ORIGIN`, section 3).

1. **Migrate 124** (`epigraph-migrate`, migration DSN). Two new tables, their
   triggers and policies, and new functions. Nothing existing changes, and
   there is no backfill. Binaries built before it are unaffected.
2. **Deploy** `epigraph-operator` and `epigraph-tenancy-backfill` built from
   the same commit. `verify` then checks the 124 definers' owner and grants.
3. **Enroll**, once the enrollment ceremony is deployed:
   `epigraph-operator passkey-enroll --person <the human's own agent> --reason
   <text> [--label <device>] --apply` on the maintenance DSN prints a ticket,
   live for 15 minutes, and its ceremony path, `/elevate/enroll/<id>`. The
   human opens it under the public base URL, on the device that holds the
   authenticator. `list-passkeys` shows the result. For a lost device:
   `revoke-passkey --id <passkey> --reason <text> --apply` (audited; final).
   For a stolen or otherwise suspect device, add `--compromised` (migration
   200; "Two revoke modes" in that section).

The default attestation policy requires a verified attestation that chains
to a CA in `EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE`, from an authenticator
model on the `EPIGRAPH_WEBAUTHN_AAGUIDS` allowlist.
`EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION` accepts software
authenticators. It is for tests and development only, and a request binary
refuses to start with it on a database armed for operator binding.

Two settings widen that policy; see "Android hardware keys and a synced
second passkey (migration 200)" below.

**Rollback.** First roll back every binary that calls a 124 function
(`epigraph-operator`, any `epigraph-api` that serves the enrollment ceremony,
`epigraph-tenancy-backfill`). Then run `docs/runbooks/124-undo.sql` on the
migration DSN, in one transaction. It reports how many passkeys and tickets
it drops, then drops both tables and every 124 function. The
`platform.passkey_*` audit rows stay (history), and so does 124's
`_sqlx_migrations` row. Re-introducing passkeys is a new migration, and every
human then enrolls again.

### Android hardware keys and a synced second passkey (migration 200) — settings, cost, operator steps, rollback

**The rule, on an armed database.**
- A person's first passkey is always hardware-attested.
- A passkey anchors a later unattested passkey only if it is hardware-attested
  AND still trusted under the configuration the API runs at that moment.
- A synced passkey never anchors, directly or through any chain of acts.

**Why.** `webauthn-rs` checks an authenticator model (AAGUID) only for
`packed` and `tpm` attestation. An Android phone's hardware-backed key
attests in the `android-key` format, which names no model, so it verifies
only under a root trusted for every key it attests. The allowlist's roots
admit only their listed models, so an Android key chaining to a configured
Google root is refused there with "The attestation CA that was trusted
limits the aaguids allowed, but this device does not have an aaguid".

**`EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE`** holds those roots, kept apart
from the allowlist. A registration is checked against the allowlist first,
unchanged. Only when the allowlist refuses it is it checked against the
Android roots alone. A registration that verifies that way is accepted only
when all of these hold:
- the format is `android-key`;
- the credential is device-bound and the user is verified;
- the attestation itself puts the key in hardware. The leaf certificate's
  KeyDescription must give both `attestationSecurityLevel` and
  `keyMintSecurityLevel` as TrustedEnvironment (1) or StrongBox (2). The
  key's `purpose` (SIGN) and `origin` (GENERATED) must be in the
  hardware-enforced list.
  - The library accepts security level 0 (Software), so this check is the
    API's.
  - Google also publishes a software attestation root. Its statements say
    Software, and they are refused.
  - The pinned library refuses StrongBox (level 2) outright, so a
    StrongBox-only key cannot register until the library parses it.
- only the leaf carries a KeyDescription. A chain with a second one, which
  would be an attacker's certificate extending a genuine chain, is refused;
- no certificate of the chain, the root included, is on the attestation
  status list (next item).

The passkey is recorded with format `android-key` and the nil AAGUID. A
`packed` certificate chaining to a Google root is refused.

**`EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE`** is REQUIRED with the Android
roots. It is a local copy of Google's attestation status list:
- the URL is <https://android.googleapis.com/attestation/status>;
- the format is `{"entries": {"<serial>": {"status":
  "REVOKED"|"SUSPENDED", ...}}}`. Google's schema says the key is the serial
  in lowercase hex, but the published list keys its 64-bit serials in
  DECIMAL and its 128-bit ones in hex (measured 2026-11-06: 981 of 1,771
  keys were 17-20 decimal digits). The API therefore looks each certificate
  up in both forms.

Google lists the serial numbers of attestation certificates it has revoked or
suspended, for example leaked device keys. The library loads no CRL and no
status list, so the API reads this file itself. It never fetches it, and no
request reaches the network.

The policy:
- **At boot.** The roots without the file, or a file that is unreadable or
  is not a status list, are a boot error (exit 1). The file alone, without
  the roots, is also a boot error. A file that is valid but stale never
  blocks boot; it refuses Android enrollments and anchors only.
- **At every use.** The file is re-read at every Android enrollment and at
  every use of an Android passkey as an anchor. A refreshed file takes
  effect without a restart.
- **Any listed serial refuses.** A certificate of the chain listed with any
  status (`REVOKED` or `SUSPENDED`) refuses the enrollment or the anchor.
- **Older than 48 hours refuses (fail closed).** The age is the file's
  modification time. A file older than that refuses, until it is refreshed:
  - every Android enrollment, on BOTH ceremonies. The anchored ceremony
    refuses an Android key whose chain, hardware rules and device binding
    pass but whose standing cannot be checked; it does NOT record it `none`.
    The refusal names the list and says to refresh it, and the API logs it
    at WARN (`passkey.anchor`, "its attestation status list cannot be
    checked");
  - every Android anchor;
  - every OTHER anchor whose lineage holds an Android passkey, a security key
    included, even when that Android passkey is revoked (a person whose first
    passkey was a phone, for example). The API logs those as
    `refusal=lineage_not_attested`, and their enrollments fall back to the
    attested ceremony, which refuses a synced passkey at the finish.

  A missing or unreadable file, and one dated more than 5 minutes in the
  future, are refused the same way. Android passkeys still ASSERT (elevate)
  while the file is stale.

Fetching and refreshing the file is an operator job outside the API. A job
that fails leaves the old file in place, and nothing in the API refuses until
the file is 48 hours old. Without an alert, the first sign would be a refused
enrollment. Install BOTH of the following, because each catches what the other
cannot: a failing run alerts at once, and a job that stopped running (a
disabled timer never fails) is caught by its age.

**1. The refresh job.** It exits non-zero and prints one line on any failure:
a failed fetch, a download that fails the API's parse rule (for example one
non-hex key upstream), or a failed replace. Paths are placeholders:

```bash
#!/usr/bin/env bash
# refresh-android-attestation-status: replace the API's copy of Google's
# attestation status list. Exit 0 only when the file was replaced.
set -euo pipefail
STATUS=/path/readable/by/the/api/android-attestation-status.json
URL=https://android.googleapis.com/attestation/status
TMP="$STATUS.tmp"
fail() { echo "ANDROID-STATUS REFRESH FAILED: $*" >&2; rm -f "$TMP"; exit 1; }
curl -fsS --max-time 30 -o "$TMP" "$URL" \
  || fail "the fetch of $URL failed (curl exit $?); the old file is kept"
jq -e '(.entries | type == "object")
       and (.entries | to_entries
            | all((.key | test("^[0-9a-fA-F]+$")) and (.value.status | type == "string")))' \
   "$TMP" >/dev/null \
  || fail "the download does not pass the API's parse rule; the old file is kept"
mv -f "$TMP" "$STATUS" || fail "could not replace $STATUS"
echo "android attestation status list refreshed: $(jq '.entries | length' "$STATUS") entries"
```

Run it from a systemd timer at least daily (every 6 hours leaves room for a
failed run before the 24-hour warning), as a user that can write the file's
directory, with an alert on failure:

```ini
# android-status-refresh.service
[Unit]
Description=Refresh the Android attestation status list
OnFailure=android-status-alert@%n.service

[Service]
Type=oneshot
User=<a user that can write the file's directory>
ExecStart=/usr/local/bin/refresh-android-attestation-status

# android-status-refresh.timer
[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

`android-status-alert@.service` is your alert: a oneshot whose `ExecStart`
sends the failing unit's name (`%i`) and its last journal lines through a mail
or chat path whose delivery you have verified end to end. An alert nobody
receives is no alert.

**2. The age check.** It exits 1 and prints one line unless the file exists,
is readable, is at most 24 hours old, is not dated in the future, and passes
the API's parse rule:

```bash
#!/usr/bin/env bash
# check-android-attestation-status: exit 1 with one line unless the API's copy
# of the attestation status list is present, fresh (<= 24h) and well-formed.
set -uo pipefail
STATUS=/path/readable/by/the/api/android-attestation-status.json
MAX_AGE_H=24
bad() { echo "ANDROID-STATUS CHECK FAILED: $*"; exit 1; }
[ -r "$STATUS" ] || bad "$STATUS is missing or unreadable; every Android enrollment and anchor is refused"
age_s=$(( $(date +%s) - $(stat -c %Y "$STATUS") ))
[ "$age_s" -ge -300 ] || bad "$STATUS is dated in the future; the API refuses it"
[ "$age_s" -le $(( MAX_AGE_H * 3600 )) ] \
  || bad "$STATUS is $(( age_s / 3600 ))h old (over ${MAX_AGE_H}h; refused at 48h): the refresh job has stopped or is failing"
jq -e '(.entries | type == "object")
       and (.entries | to_entries
            | all((.key | test("^[0-9a-fA-F]+$")) and (.value.status | type == "string")))' \
   "$STATUS" >/dev/null 2>&1 \
  || bad "$STATUS does not pass the API's parse rule; the API exits 1 at its next restart"
echo "android attestation status list OK: $(( age_s / 3600 ))h old, $(jq '.entries | length' "$STATUS") entries"
```

Run it hourly from your monitoring (or from its own timer with the same
`OnFailure=` alert), and alert on a non-zero exit.

**What the API logs.** These thresholds are constants, not settings.
- **At boot**, after `passkey relying party configured`: the line `Android
  attestation status list` with `path=`, `age_hours=` and `entries=` (INFO).
  Past 24 hours the same facts are a WARN ("older than 24h: its refresh job
  has missed a run"). A file that cannot be read is a WARN too. None of these
  blocks boot.
- **At every use** (an Android enrollment, an Android anchor, an Android
  passkey on a lineage) past 24 hours: a WARN (target
  `passkey.android_status`, `age_hours=`). The file is still used.
- **Past 48 hours:** refused, as above.

The `jq` check in both scripts is the API's own parse rule (an `entries`
object, every key hex digits, every entry a string `status`). A download that
fails it never replaces the good file. The API exits 1 at boot on a file that
does not parse, so a bad file left in place would take the whole API down at
the next restart. The `mv` replaces the file atomically, so a partial download
is never read.
Never use `curl -R`, `cp -a` or `rsync -t` for this step. Each keeps an older
modification time, and a file that looks stale refuses every Android anchor
even though its content is new.

**`EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY`** (default off) lets a
person add a passkey that carries no attestation, such as a password
manager's synced passkey. It is anchored by a passkey they already hold:
- **The first passkey is always attested.** A person's first passkey comes
  from a maintenance enrollment, which has no act, so it always runs the
  attested ceremony. The setting therefore never lets a maintenance-DSN
  holder plant a first key, and it is served on an armed database. The
  software flag stays refused there.
- **A later passkey may be unattested.** It comes from a confirmed
  `passkey.register` act. Its enrollment takes the anchored path when the
  passkey that confirmed the act (the anchor) passes all of these checks:
  - it is the same person's;
  - it is live;
  - it is HARDWARE-ATTESTED UNDER THE CONFIGURATION THE API RUNS NOW. The
    API re-verifies the certificate chain stored with the anchor's
    credential against today's roots, never the columns its registration
    wrote:
    - `packed`/`tpm`: an allowlist root that still admits its model;
    - `android-key`: an Android root, plus the TEE/StrongBox rule and the
      status list above.

    The row's recorded format, AAGUID and backup-eligible flag must also
    agree with that credential. The anchor's certificate validity periods are
    checked NOW, as at registration, so an anchor whose chain has expired
    anchors nothing.
  - every passkey on its LINEAGE passes the same check, with one
    difference: its certificates' VALIDITY PERIODS are checked at the moment
    it confirmed the act its successor was enrolled on, not now. The lineage
    is the passkey that confirmed the act the anchor was itself enrolled on,
    then that passkey's own confirmer, and so on, back to the person's first,
    maintenance-enrolled passkey. A lineage that does not reach the first
    passkey within 32 steps anchors nothing.
    - **As of now** for every ancestor: the roots and the allowlist
      configured today, the Android hardware rules, and today's status list
      (which must be fresh). A certificate revoked on the status list breaks
      the lineage, whenever it was listed.
    - **As of its confirmation** for every ancestor: each certificate of its
      stored chain, and the root, must have been valid then. The time is the
      act's `asserted_at`, which the database sets at the assertion. An
      ancestor whose chain expired AFTER it confirmed still counts, so a
      first passkey's expiry does not stop the person's later hardware keys
      anchoring.
    - **A revoked passkey** on the lineage is still checked, and being
      revoked (`revoke-passkey`) does not disqualify it: it authorized its
      successor while it was live. So a backup key enrolled on an act a lost
      phone confirmed still anchors after the phone is revoked.
    - **The consequence of expiry.** A passkey whose chain has expired can
      still elevate and confirm acts. It no longer anchors. A passkey
      enrolled on an act it confirmed after the expiry never anchors either:
      its lineage holds a chain that was not valid at that confirmation. To
      recover, confirm the next `passkey.register` act with a passkey whose
      chain is still valid. If none is left, revoke every passkey of the
      person and enroll a first passkey again (`passkey-enroll` without
      `--act`, which 130 allows only once the person has no live passkey).
      How long real Android chains stay valid was not measured. Remotely
      provisioned intermediates may be short-lived; the API log names the
      certificate and its window (`reason=... was not valid at ...`).
- **The confirmation is re-verified.** The API re-verifies the act's
  recorded confirmation before taking the anchored path: the act's own
  challenge, the anchor's stored public key and the credential. The
  database cannot verify a signature, so a confirmation written with
  fabricated evidence anchors nothing.
- **Which path a ceremony takes.** The decision is made from the database
  rows at both the challenge and the finish, never from the stored ceremony
  state. Otherwise the act's enrollment is attested, exactly as with the
  setting off. The API log says why an anchor was refused (`refusal=` and
  `reason=`).
- **What the anchored ceremony records.** It ASKS for attestation
  (`direct`; a browser would otherwise strip a hardware key's statement) but
  needs none, and records the passkey one of two ways, or refuses it:
  - **`none`** for a synced passkey, or for any key whose attestation is not
    trusted under the configuration the API runs now: self attestation, a
    model not on the allowlist, a root that is not configured, or an Android
    key that fails the Android rules (a software-level key, `purpose` or
    `origin` only software-enforced, a KeyDescription outside the leaf, a
    backup-eligible credential) or has a certificate on a CURRENT status
    list. Such an attestation is dropped, as a browser drops it when asked
    for none, and logged at INFO. The passkey holds only through its anchor:
    it never anchors a further one, and it is revoked with its anchor.
  - **Attested** for a hardware key whose attestation IS trusted now (an
    allowlisted model, or an Android key under the Android roots, rules and
    status list). It is recorded exactly as the attested ceremony would
    record it (its format and model), stands on its own, may anchor in turn,
    and is NOT revoked with its anchor.
  - **Refused** for an Android key whose chain is trusted but whose standing
    cannot be checked, because the status list is older than 48 hours,
    missing, unreadable or malformed. It is not recorded `none` (that would
    hide the outage and give a backup that dies with its anchor). Refresh the
    list, then retry the enrollment link within its 15 minutes; after that,
    propose and confirm a new `passkey.register` act.

  So a backup hardware key for a lost phone can be enrolled with the setting
  on. Check `list-passkeys` afterwards: it must show the backup's format
  (`packed`, `tpm` or `android-key`), not `none`. A backup recorded `none`
  (its user declined the browser's prompt to share the key's make and model,
  or its model is not allowlisted) is revoked with the phone; enroll it again
  and allow the prompt, or enroll it with the setting off, which refuses an
  untrusted key outright.
  - A statement the WebAuthn library cannot verify at all is refused before
    this choice is made, as on the attested path: a StrongBox-level Android
    key, an unsupported format, and the one-in-64 Android key with a leading
    zero byte in a coordinate (retry). Before this change the browser
    stripped those to `none`.
  - The anchored ceremony does not ask the authenticator to enforce the
    credential protection policy as the attested one does. User verification
    is still required at registration and at every assertion.
- **The response says which act anchored it.** The enrollment finish
  answers `anchored_by` with that act's id for a passkey recorded `none` on
  the anchored path. It is `null` on the attested path and for a passkey the
  anchored path recorded attested.
- **No completion on a revoked anchor.** Migration 200's insert guard records
  a passkey enrolled on an act only while the passkey that confirmed the act
  is live. It reads that passkey under a share lock, so a revoke and a
  completion that race are serialised. This applies to every act enrollment,
  attested ones included.
- **Revoking an anchor revokes what it anchored.** `revoke-passkey` on a
  passkey also revokes, in the same transaction, every live `none` passkey
  enrolled on an act it confirmed. On an armed database those are exactly
  the passkeys it anchored. They are stamped with the same login and the
  reason `anchor <id> revoked: <reason>`. An attested passkey enrolled on
  such an act stays live: it stands on its own attestation. That includes a
  backup hardware key the anchored ceremony recorded attested, and excludes
  one it recorded `none` (see above). This is the default, LOST-device mode.
- **Two revoke modes: lost or compromised.** Every `platform.passkey_revoked`
  audit row records which one revoked it, as `mode` (`lost` or
  `compromised`).
  - **Lost** (the default: `revoke-passkey --id <passkey> --reason <text>
    --apply`). Use it when the device is gone but nobody else can use it: it
    was lost, broken, or wiped. It revokes the passkey and the `none`
    passkeys it anchored, as above. Attested keys enrolled on acts it
    confirmed stay live, so the person keeps working with them.
    *Example:* a phone falls into a lake. Revoke it as lost. The person's
    backup security key, enrolled on an act the phone confirmed, keeps
    elevating, and confirms the `passkey.register` act for the next phone.
  - **Compromised** (`revoke-passkey --id <passkey> --reason <text>
    --compromised --apply`). Use it when someone else may have used the
    device or its passkey: stolen, unlocked out of the person's sight, or
    otherwise suspect. Whoever held it could have confirmed the
    `passkey.register` acts that enrolled further keys. It revokes the
    passkey and every passkey whose anchor lineage passes through it: each
    passkey enrolled on an act it confirmed, each enrolled on an act one of
    those confirmed, and so on, attested ones included. It never touches
    another person's passkeys. Every elevation any of them confirmed ends
    (`passkey_revoked`), and every unexecuted act they confirmed is voided,
    as for any revoke. It first locks the person's passkeys, so an
    enrollment completing at that moment on one of their acts is waited
    for and then revoked with the rest, and one that starts later is
    refused. It prints one line per passkey reached (`depth=` 0 for the
    passkey named) and, without `--apply`, rolls everything back.
    It also works on a passkey already revoked: revoked passkeys are walked
    through, not revoked again, and anything still live below them is
    revoked. Afterwards the person enrolls a replacement on a
    `passkey.register` act confirmed with a passkey still live (one not
    enrolled through the compromised one), or, if none is left, through
    `passkey-enroll` without `--act` (the bootstrap).
    *Example:* a phone is stolen while unlocked. Revoke it as compromised.
    The backup security key enrolled on the phone's act is revoked too,
    because the thief could have enrolled it, and so is any key enrolled
    through that one. If the phone was first revoked as lost and only
    later found to be stolen, run the compromised revoke on it then: it
    sweeps what the lost revoke left.

**What remains, exactly.**
- **The anchor confirms an act, not a credential.** The anchor's
  confirmation commits to "register a passkey for this person, with this
  label and reason". It does not commit to WHICH credential. Whoever first
  opens the 15-minute `/elevate/enroll/<id>` link registers their own key.
  That can be the maintenance-DSN holder who opened the enrollment, or anyone
  the link reaches. On the attested path they would need an allowlisted or
  Android hardware key. On the anchored path they need no hardware at all.
  The remaining guarantee:
  - an anchored passkey is registered only for the act's person;
  - only on an act that person confirmed with a live hardware-attested
    passkey;
  - only within 15 minutes of the enrollment's opening;
  - only once per act.

  Hand the link only to the person, on the device that will hold the
  passkey. Check `list-passkeys` after each anchored enrollment.
- **Chains of acts.** A synced passkey can still confirm a `passkey.register`
  act. That act's enrollment runs the ATTESTED ceremony, so only a genuine
  hardware key registers on it. That hardware key never anchors, because
  its lineage holds the synced passkey. So the password-manager account
  cannot mint an anchor, through any number of acts.
- **Not re-checked at use, for `packed`/`tpm`:** that the anchor's stored
  certificate chain was the one that attested its stored key. That
  certificate is the authenticator model's, and the attestation signature
  that bound it to the key is not stored. The API's ceremony verified it when
  it wrote the row, but the row has other writers:
  - the maintenance DSN;
  - a holder of the REQUEST DSN with a live enrollment id. They can call
    124's `epigraph_complete_passkey_enrollment` directly, with a key, a
    stored credential and the format, AAGUID and backup-eligible columns of
    their choosing.

  Such a holder can already plant any key on that enrollment, and it elevates
  as the person (the enrollment-link threat above). What a planted `packed`
  or `tpm` row adds, when it pairs a genuine, public model certificate chain
  with the planter's own key:
  - it passes the anchor check, so it anchors later passkeys (on acts it
    confirms, each opened by the operator's `passkey-enroll --act`);
  - it counts as hardware on a lineage (its genuine chain also passes the
    validity window);
  - recorded as non-`none`, it is NOT revoked with its anchor. The cascade
    deliberately spares attested rows, including a backup hardware key.

  An `android-key` row cannot be planted this way: its leaf certificate must
  certify the credential's key, which must then assert, and the API checks
  both at every use. Re-deriving the columns in the database would not close
  it, because the stored credential is as freely chosen as the columns, and
  the API already demands that they agree. Storing the attestation statement
  and re-verifying its signature at use would close it; that is not done.
  Hand enrollment links only to their person, and check `list-passkeys`.

**The accepted cost.** Once a synced passkey is registered, an elevation (and
every admin-act confirmation) is only as strong as the password-manager
account that holds it: whoever controls that account can elevate as the
person. Revoking the synced passkey (`epigraph-operator revoke-passkey`)
ends that, and ends any elevation it confirmed. So does revoking its anchor,
which revokes it.

**Operator steps.**

1. **Migrate 200** (`epigraph-migrate`, migration DSN). It adds the
   enrollment page's reader of an act enrollment's anchor and its lineage,
   the act-confirmer insert guard, the anchored-revoke cascade and the
   compromised revoke. It re-states ONE earlier body: 124's passkey audit
   trigger function, whose revoke rows gain `mode`. Then deploy
   `epigraph-tenancy-backfill` and `epigraph-operator` from the same commit;
   `verify` checks the four functions' owner, the reader's grant to
   `epigraph_app` and that `epigraph_app` cannot call the compromised
   revoke. The guard and the cascade apply whatever the settings say.
2. **The status list.** Install the refresh job and its timer with the
   `OnFailure=` alert, and the age check under your monitoring (both above).
   Run the job once, then run the age check: it must print `android
   attestation status list OK`. Trigger the alert once (for example, run the
   alert unit by hand) and confirm it arrives. Set
   `EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE` to the file.
3. **The Android roots.** Write Google's hardware attestation root
   certificates to a PEM file the API unit can read (one or more
   `-----BEGIN CERTIFICATE-----` blocks). Google publishes them in the
   Android key attestation documentation, and as a JSON array at
   <https://android.googleapis.com/attestation/root>. Do NOT include Google's
   software attestation root. Set `EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE` to
   that file.
   **The CA-file overlap hazard.** An earlier configuration may have
   allowlisted Android: a Google root in
   `EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE` with an Android AAGUID in
   `EPIGRAPH_WEBAUTHN_AAGUIDS`. Remove that root and that AAGUID IN THE SAME
   CHANGE: a root in both files stops the server at boot (exit 1). Keep the
   allowlist for security keys, or unset BOTH of its variables when no
   security-key model remains, to accept Android keys only.
4. **The anchored setting** (only if a synced second passkey is wanted): set
   `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY=1`.
5. **Restart the API.** The boot line `passkey relying party configured`
   shows `software_attestation=false` and `synced_anchored=true|false`, and
   the next line, `Android attestation status list`, shows the file's
   `age_hours=` and `entries=` (a WARN past 24 hours). A configuration error
   exits 1 with the variable named.
6. **First passkey**, on the phone: `epigraph-operator passkey-enroll
   --person <agent> --reason <text> [--label <device>] --apply`, then open
   the printed `/elevate/enroll/<id>` path on the phone. `list-passkeys`
   shows it as `android-key`.
   - A first passkey must be device-bound. A synced passkey offered by the
     phone (its password manager's) is refused with "not truly bound to
     hardware" or "this one is backup-eligible", whatever either setting
     says. Choose the device's own key.
   - A phone whose attestation is software-level is refused with "not
     attested as hardware-backed". So is one with a certificate on the
     status list ("is REVOKED" / "is SUSPENDED"). A stale status file
     refuses with "older than the 48h maximum", a missing one with "cannot
     be read"; both add "refused until the operator refreshes it". The same
     holds for an Android backup on the anchored ceremony.
   - About one Android key in 64 is refused by the WebAuthn library with
     "The COSEKey contains invalid ECDSA X/Y coordinate data" (a coordinate
     with a leading zero byte). A retry creates a new key and passes.
7. **Second (synced) passkey.**
   1. Elevate with the phone.
   2. Propose `passkey.register` with
      `{"person": <agent>, "label": <name>, "reason": <text>}`
      (`POST /api/v1/admin/acts`).
   3. Confirm it at `/elevate/act/<id>` WITH THE PHONE (a confirmation by a
      synced passkey anchors nothing).
   4. Run `epigraph-operator passkey-enroll --person <agent> --reason
      <same text> --label <same name> --act <id> --apply`.
   5. Open the printed path, yourself, in the browser where the password
      manager runs.
   The finish answers `anchored_by`. If the enrollment ran the attested
   ceremony instead, the API log says why (`refusal=`, `reason=`).

**Rollback.**
- **The anchored setting.** Unset `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY`
  and restart; later passkeys are attested again. A synced passkey registered
  meanwhile stays live until `revoke-passkey` on it or on its anchor.
- **The Android roots.** Unsetting `EPIGRAPH_WEBAUTHN_ANDROID_KEY_CA_FILE`
  (and with it `EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE`) stops new Android
  enrollments. It also stops, at once, because anchors and their lineages are
  re-verified against the current roots:
  - every Android passkey ANCHORING;
  - every other anchor whose LINEAGE holds an Android passkey, revoked or
    not: for example a security key enrolled on an act a phone confirmed, or
    any later key of a person whose first passkey was a phone. The API logs
    them as `refusal=lineage_not_attested`, and their enrollments run the
    attested ceremony instead.

  Registered Android passkeys keep asserting. The same holds for an AAGUID
  removed from the allowlist or a root replaced: every anchor whose own chain
  or lineage depends on it stops anchoring. Synced passkeys already anchored
  stay live; revoke them, or their anchors, to remove them.
- **Migration 200.** Run `docs/runbooks/200-undo.sql` on the migration DSN,
  only after no unit runs with the anchored setting on and `epigraph-operator`
  is rolled back to a build without `--compromised`. It drops the reader, the
  insert guard, the cascade and the compromised revoke, and restores 124's
  audit body (later revoke rows carry no `mode`). After the undo, revoking
  an anchor no longer revokes what it anchored.

### Elevation tickets and sessions (migration 125) — deploy order and rollback

The database half of elevation:
- `elevation_tickets`: a request to elevate, asserted once by a passkey
  ceremony;
- `elevation_sessions`: a confirmed, read-only elevation of at most 15
  minutes, bound to one refresh family of the human and to the live
  assignment of an `elevates` role;
- `epigraph_is_elevated()`.

It is INERT on its own. No session is live until migration 132 opens 125's
gate (`epigraph_elevated_access_ready()`, which ships answering false) AND the
serving build declares that it writes the log (see "two keys" in the 126
section).

1. **Migrate 125** (`epigraph-migrate`, migration DSN), after 124. Two new
   tables, their triggers and policies, new functions, and five new AFTER
   UPDATE triggers on existing tables (`role_assignments`, `human_operators`,
   `refresh_tokens`, `oauth_clients`, `person_authenticators`). They end a
   live elevation when:
   - its assignment is revoked;
   - its holder's registration is revoked;
   - its refresh family is revoked for any reason but a rotation (reuse,
     RFC 7009, a denied refresh, a client-wide revoke);
   - its client leaves `active`;
   - the passkey that confirmed it is revoked. `epigraph-operator
     revoke-passkey` is therefore also a way to end a live elevation that the
     passkey opened.

   To end sessions without taking anything else away, run `epigraph-operator
   end-elevation (--session <id> | --person <agent>) --reason <text> --apply`
   on the maintenance DSN. Each end is audited as `platform.elevation_ended`,
   with the reason as `operator_reason`. `epigraph-operator list-elevations
   [--person <agent>] [--live]` finds them. There is no backfill, and nothing
   existing changes shape. Binaries built before it are unaffected (they call
   none of it).
2. **Deploy** `epigraph-tenancy-backfill` built from the same commit. `verify`
   then checks the 125 definers' owner and grants. It FAILS while a
   non-superuser member of `epigraph_maintenance` may CREATE in schema
   `public`, for example through the PUBLIC grant that a cluster upgraded
   from before PostgreSQL 15 keeps. Run the `REVOKE` it prints.

**Rollback.** First roll back every binary that calls a 125 function: any
`epigraph-api` serving the elevation ceremony or the elevate grant, and every
binary that resolves an elevated viewer. Undo first any later migration whose
row policies read `epigraph_is_elevated()`; `docs/runbooks/125-undo.sql`
refuses while one does. Then run `docs/runbooks/125-undo.sql` on the
migration DSN, in one transaction. It reports how many tickets and sessions
it drops (live sessions counted), and drops the five end triggers, both
tables and every 125 function. The `platform.elevat*` audit rows stay
(history), and so does 125's `_sqlx_migrations` row. Re-introducing
elevation is a new migration. **Run 125-undo before 124-undo**: 125's tables
reference `person_authenticators`, so 124-undo cannot run while they exist.

### The elevated viewer (no migration) — the five session settings, deploy order and rollback

Two binaries RESOLVE an elevated viewer: `epigraph-api`, for a token carrying
an elevation claim (minted only by the elevate grant), and
`epigraph-mcp-full`, the same over HTTP and never over stdio.
- An elevated viewer is built only after migration 125's
  `epigraph_elevation_live` answers for a live session of that principal on
  that refresh family.
- It reads with the always-true fragment on the APPLICATION role, so until a
  migration adds row policies that read `epigraph_is_elevated()`, it reads
  exactly what an ordinary viewer reads.
- It writes nothing: `begin_as` refuses it, with HTTP 403
  `ELEVATED READ-ONLY` or MCP `INVALID_REQUEST`.

**A unit on a privileged DSN never elevates.** Migration 125 answers "no live
session" in these cases:
- to a login that skips row security (a superuser or a BYPASSRLS role);
- to a member of `epigraph_maintenance`;
- to a connection that RUNS AS a superuser or BYPASSRLS role through a role
  switch (`SET ROLE`, a DSN's `options=-c role=...`, or a per-login
  `ALTER ROLE <login> SET role`).

Such a unit serves every elevated token with the principal's ordinary scoped
viewer. The boot posture checks (`epigraph_bypass()`, the row-security
probe) read the LOGIN only, so they do not flag a role switch. Elevation
refuses one anyway, and a request DSN should carry no role switch at all.
That holds whether or not the operator binding is armed: without it, the
always-true elevated fragment, on a login no row policy narrows, would read
and decide writes on every tenant's rows. Elevation is therefore only ever
served by a unit on the application-role DSN.

Every `ScopedPool` binary stamps FIVE session settings per checkout and
clears all five on release: the tenancy three plus `epigraph.elevation_id`
and `epigraph.family_id`, which are EMPTY for every viewer that is not
elevated (section 6). That covers the API, both MCP transports,
`decompose_claims`, the operator and maintenance CLIs, and the job drain.
Only a binary that RECORDS every elevated access declares the per-access
recorder (`epigraph.access_recorder`; see "two keys" in the 126 section, and
the 127 section). `epigraph-api` declares it, through its response layer.
`epigraph-mcp-full` declares it on its HTTP transport (`--listen`), through
its tool-call wrapper. Every other binary listed here, and the MCP server on
stdio, never elevates a request on any database.

1. **Migrate 125 first** (above). A binary built with the elevated viewer, on
   a database without 125, still serves: a failed liveness check is logged
   and the request is served UNELEVATED.
2. **Deploy** the binaries in any order. Binaries built before the elevated
   viewer stamp three settings and never elevate. The two other settings read
   empty to them, which means "not elevated".
3. **Connector mode stays OFF.** `epigraph-mcp-full` elevates a request with
   no elevation claim (a connector-mode session found by its family) only
   when `EPIGRAPH_MCP_CONNECTOR_ELEVATION=on`. Leave it unset: the
   connector's refresh-family scope is an open operator question, and until
   it is decided only the CLI elevate path elevates. Any other value leaves
   it off.

**Rollback.** Redeploy the previous binaries; there is no data to undo. Roll
these binaries back BEFORE running `125-undo.sql`.

### The elevated read arms (migration 126) — deploy order, lock plan and rollback

Migration 126 gives every owner-isolated table (and the agent, group, derived
and edge tables) an elevated READ arm and an elevated WRITE refusal: a
PERMISSIVE `<t>_elevated_read` and RESTRICTIVE `<t>_elevated_no_insert` /
`_update` / `_delete`, all `TO epigraph_app` and all reading
`epigraph_is_elevated()`. The two audit tables get the read arm only, and the
retired (T-DROP) tables get the refusals only. This is the migration that
lets an elevated session read other people's rows, and it also makes the
database, not only `begin_as`, refuse that session's writes. For every
session that is not elevated nothing changes: the arm is false and every
refusal is true.

**Known limit (forged confirmations).** The database cannot verify a
WebAuthn signature, so a holder of the application DSN can forge an
elevation confirmation. For most rows that reads nothing the DSN could not
already read by stamping a principal and a group, but an elevated read arm
also admits rows no stamp reaches (for example a `recall_events` row whose
agent was deleted). Before the first real elevation, run the offline
confirmation verifier, and confirm that only the request units hold the
application DSN.

**THE GATE: no elevation session is live until the per-access elevation log
ships, and the database enforces it.** 126 is what lets an elevated session
read other people's private rows. The design requires every such read to be
recorded, fail-closed (a response whose access cannot be recorded is not
sent), in a log the SUBJECT can read ("an administrator read your group's
rows at T, for reason R"). That log is migration 127.
- `epigraph-migrate` (the supported path) applies every embedded migration
  up to the binary's head, in version order, and takes no target, so a
  prose "hold 126" could not keep 126 off a database.
- Migration 125 therefore holds the line itself.
  `epigraph_elevated_access_ready()` ships answering `false` and is part of
  the one liveness test. Before 132, no session is elevated,
  `epigraph_elevation_live` answers no session, and the grant-mode
  redemption refuses, whatever was applied. A ceremony still confirms and
  audits its session (`platform.elevated`); the session just never reads.
- Only a migration opens the gate, by replacing that function with its own
  readiness test. That migration is 132.
- There is no operator switch, and the function must not be replaced by
  hand.

What stops a hand replacement is NOT ownership alone. Replacing a function
takes CREATE on its schema AND its ownership. The application role owns
nothing, but the gate (and every elevation definer) is owned by
`epigraph_maintenance`, so a member of it has the ownership half. The barrier
for the maintenance DSN is therefore that it is a NON-superuser member of
`epigraph_maintenance` holding no CREATE on schema `public`. PostgreSQL 15
and later grant PUBLIC no CREATE there, but a cluster upgraded from an older
default keeps the old grant, and a superuser passes every check. Before the
first real elevation, `epigraph-tenancy-backfill verify` must pass (it fails
while a non-superuser maintenance role may CREATE in `public`, and names the
`REVOKE`), and the maintenance DSN must not be the superuser.

**AND THE SERVING BUILD MUST RECORD: two keys, not one.** The gate is opened
by a migration, but the log is written by the binaries (the API's response
layer and the MCP tool-call wrapper). A database function cannot tell
whether the process serving a request writes the log.
- So 125 also requires each connection to DECLARE the recorder: the session
  setting `epigraph.access_recorder` = `on`, stamped once per connection by a
  build that records. `epigraph_is_elevated()` and `epigraph_elevation_live`
  answer "not elevated" without it.
- Only a recording build declares it (see the 127 section for which
  binaries). A unit rolled back to, or left on, a build without the log
  therefore never elevates, even on a database whose gate is open. The API
  and MCP units need not be upgraded in lockstep.
- The grant-mode redemption does not check the declaration: a token it
  mints elevates nothing until a declaring unit resolves it.
- What the two keys do NOT cover: a holder of the application DSN can set
  any session setting (see "Known limit" above). Behind a transaction-mode
  pooler the per-connection declaration does not survive, so elevation fails
  closed there.

1. **Deploy the elevated-viewer binaries first** (the section above), and
   migrate 125 before them. Without them nothing stamps an elevation, so the
   arms do nothing. Before 132 no session is elevated at all, on any unit,
   so 126 widens nothing in either order. Once both keys open, a session on a
   unit without 126 reads only its own groups, and a unit on a privileged DSN
   still never elevates. Neither order is unsafe: what keeps 126 from
   widening a read before the per-access log is the enforced gate above.
2. **Migrate 126** (`epigraph-migrate`, migration DSN) under the lock plan.
   `CREATE POLICY` takes ACCESS EXCLUSIVE on its table, so it waits for every
   open reader of that table. The file arms ONE table per committed block
   with a 3 s lock timeout (about 35 tables, in the order the file lists
   them).
   - Stop the timers and confirm that no transaction is older than a few
     seconds (`SELECT max(now() - xact_start) FROM pg_stat_activity WHERE
     state <> 'idle'`), outside the backup windows.
   - PostgreSQL prints `WARNING: there is no transaction in progress` once
     per table. That is expected.
   - A lock timeout (SQLSTATE `55P03`) fails the migration at one table, with
     the tables before it armed and NO `_sqlx_migrations` row. Re-run the
     migration: it is idempotent and resumes. An API booting with
     `EPIGRAPH_MIGRATE_ON_BOOT` set would retry it too, but prefer the
     explicit `epigraph-migrate` run, under the lock plan.

**Rollback.** No binary names these policies, so nothing must be rolled back
first. Run `docs/runbooks/126-undo.sql` on the migration DSN. It uses the
same per-table, resumable form, with one `WARNING` per table under `psql`.
Its `_sqlx_migrations` row stays, and re-arming is a new migration. **Run
126-undo before 125-undo**: 125-undo refuses while any policy reads
`epigraph_is_elevated()`. Undoing 126 while a session is live narrows that
session's reads back to its own groups, and leaves its write refusal to
`begin_as` alone.

### The elevated-access log (migration 127) — deploy order and rollback

Migration 127 adds `elevated_access`, the per-access log of elevated reads,
and its recorder `epigraph_record_elevated_access`. There is one row per
elevated request, holding:
- the session, the person, the role assignment and the session's reason;
- the route or tool;
- the request's ids and filters, and the response's row count;
- the owner groups of the private rows the response named that the reader
  could not read unelevated.

The database decides the groups; the serving process only hands over the
ids its response named. A live ADMIN member of a named group reads the row,
and holders of a `reads_audit` role read the whole log through
`epigraph_elevated_access_audit`. The log is append-only for every login.

**Operator-hidden evidence.** An elevated session that reads claims may read
their evidence, including rows hidden with `epigraph-operator hide-evidence`.
This is an interim rule, to be revisited before a second person is invited.
Every such read is recorded against the hidden row's owning group (the hiding
operator's), whose admin sees it in the log.

**It does NOT open the gate.** 125's gate waits on more than the log: 125's
header lists the conditions under "OPENING IT WAITS ON MORE THAN THE
RECORDER". One of them is the API's refusal of elevated non-GET requests,
described below. After 127 and before 132, no session is live on any
database, and every recorder call is refused (`ELV07`) because no connection
is elevated.

1. **Migrate 127** (`epigraph-migrate`, migration DSN), after 126. One new
   table (FORCE row security; the application role reads only), its two
   guard triggers and two policies, and five new functions. Nothing existing
   changes. Binaries built before it are unaffected (they call none of it).
2. **Deploy** `epigraph-tenancy-backfill` built from the same commit.
   `verify` checks the 127 definers' owner and grants.
3. **Deploy the recording binaries** after 127, in any order. The gate keeps
   every session not live until 132.
   - `epigraph-api` RECORDS. Its authenticated router carries a route layer
     for every request whose viewer resolved ELEVATED:
     - it buffers the response (at most 64 MiB) and collects every id it
       names;
     - it calls the recorder on its own transaction, stamped with that
       elevation, BEFORE the response leaves. If recording fails, the client
       gets a 500 and none of the body;
     - its pool is built by `ScopedPool::connect_recording_elevated_access`,
       so its connections declare the recorder;
     - the viewer extractor refuses an elevated viewer to any request the
       layer does not wrap. The two elevation routes (open a ticket, end an
       elevation) act as the person, not as the elevation, so they are never
       recorded;
     - a token without an elevation claim pays nothing.
   - `epigraph-mcp-full` RECORDS on its HTTP transport (`--listen`):
     - for a request that may be elevated, `call_tool` resolves the viewer
       once, at dispatch;
     - if the viewer is elevated, the tool's result (or its error) is
       recorded before it is returned, and a recording failure replaces it
       with an internal error;
     - if it is not elevated, the token's claim and family are stripped
       before the tool runs;
     - its HTTP pool is built by `connect_recording_elevated_access`. On
       stdio (no token, never elevated) it keeps the non-declaring pool.

     Two known limits. The MCP read tools read on the unstamped pool, so an
     elevated MCP read is not widened by the arms yet (it is still recorded).
     And a FEDERATED tool is proxied under the caller's token before the
     wrapper, so its reads are the extension's to record.
   - A build without the recorder declares nothing and never elevates: it
     would serve an elevated token unelevated.

**Rollback.** Roll back first every binary that records (the builds that
declare the recorder). Without the recorder function they refuse every
elevated request, which is safe but noisy. Then run
`docs/runbooks/127-undo.sql` on the migration DSN, in one transaction. It
copies every log row into `security_events` as a `platform.elevated_access`
event, so the subjects' record outlives the table, then drops the table and
every 127 function. Its `_sqlx_migrations` row stays: re-introducing the log
is a new migration. **Run 127-undo before 126-undo and 125-undo**, because
the log's rows name 125's sessions.

### The admin-scope arming switch (migration 128) — shipped unarmed

Migration 128 adds `admin_scope_enforcement`, a single row that says whether
the admin-only scopes (`claims:admin`, `clients:admin`, `entity-types:write`,
`groups:admin`, `instance:admin`) are STANDING authority (unarmed, the
shipped state) or reachable only through elevation (armed). Applying it
changes no mint, route or CLI outcome, because everything reads the switch
and finds it unarmed.

1. **Migrate 128** (`epigraph-migrate`, migration DSN), after 127. One new
   table, with no row security: the application role reads only, and the
   maintenance role may change `armed` and `reason` only. Its guard and audit
   triggers, and five functions (two of them the triggers'). Nothing existing
   changes. Binaries built before it never read it, and a binary built with
   it reads a database WITHOUT it as unarmed, so the deploy order between the
   two is free.
2. **Deploy** `epigraph-tenancy-backfill` built from the same commit.
   `verify` checks the 128 definers' owner and grants.
3. **Deploy** `epigraph-api`, in any order with the migration. Its token
   endpoint builds every token's scopes through ONE mint chokepoint
   (`oauth::scopes::grantable`). That covers the authorization-code
   exchange, the refresh grant, client credentials (agent and service), an
   external provider's assertion grant, the browser redirect exchange and the
   elevate grant.
   - When a token would carry an admin-only scope, the chokepoint reads the
     switch. Unarmed, the scope is kept and one
     `oauth.admin_scope_would_strip` event is recorded (per client per hour).
     Armed, the scope is stripped.
   - A database without 128 counts as unarmed. A switch the application role
     cannot read strips (fail closed).
   - The elevate grant is unaffected either way (read scopes plus
     `platform:admin`). A token without an admin-only scope never reads the
     switch.
   - The paths that hand scopes OUT follow the same switch. Client approval
     refuses an admin-only scope (403) while the switch is armed or cannot be
     read, and never grants `platform:admin`; from migration 188 on, approval
     is maintenance-only (section 8). Registration (`POST /oauth/register`),
     which grants a fixed set whatever it is asked, refuses (400) a request
     that names an admin-only scope while armed.

**Every change is audited.** Arming and disarming are maintenance acts with a
reason. Each writes one `platform.admin_scopes_armed` or
`platform.admin_scopes_disarmed` security event, whether it came from the
setter (`epigraph_set_admin_scope_enforcement`) or from a direct UPDATE on
the maintenance DSN. No login can insert the row again or delete it.

**Arming is NOT part of the deploy.** It is a separate operator step. Do it
after the consumers that rely on a standing admin scope have moved off it,
and after the would-strip measurement (`oauth.admin_scope_would_strip`
events, at most one per client per hour, written while unarmed) has read zero
for a soak window. `epigraph-operator arm-admin-scopes --reason TEXT` on the
maintenance DSN prints the switch and what would change, and `--apply` arms.
While armed, `epigraph-operator grant-client-scope` refuses too
(`revoke-client-scope` still works).

**Rollback.** Disarming is the first rollback and needs no DDL:
`epigraph-operator disarm-admin-scopes --reason TEXT --apply`. To remove the
switch itself, run `docs/runbooks/128-undo.sql` on the migration DSN, in one
transaction. If the switch is armed, it first disarms it through the table's
own audit (reason `128-undo`), then drops the table and every 128 function.
The events stay. Run it AFTER `129-undo.sql` (129's policies call
`epigraph_admin_scopes_armed()`, so 128-undo refuses while they exist) and
before 127-undo.

A disarm is reversible for the refresh chains minted while armed. A chain
stores its CONSENTED scopes (`oauth::scopes::chain_scopes`), not the
chokepoint's output, so an admin-only scope stripped from the access token
at the first mint comes back at the chain's first refresh after the disarm.
A chain minted by a binary that stored the stripped set stays without it.
Its holder re-consents: a new authorization-code grant, or a fresh
`client_credentials` grant for a service or agent.

### The standing admin read arms follow the switch (migration 129)

Migration 129 rewrites the four read policies that carry a STANDING
instance-admin arm: `security_events_read`, `privatization_audit_read`,
`privatization_plans_read` and `privatization_plan_items_read`. The arm that
answered `epigraph_is_instance_admin(principal)` (a live custodian
assignment, 123) answers `CASE WHEN epigraph_admin_scopes_armed() THEN
epigraph_is_elevated() ELSE epigraph_is_instance_admin(principal) END`.
Every other conjunct is unchanged, the plans' group-admin conjunct included.
Unarmed, every read is exactly as before. Armed, a custodian reads the whole
actor log, and the plans and audit of the groups it administers, only while
ELEVATED. Arming stays one row change (`arm-admin-scopes --apply`), never
policy DDL.

1. **Migrate 129** (`epigraph-migrate`, migration DSN), after 128. It is
   policy DDL on `security_events` (busy) and the three privatization tables,
   in ONE transaction with a 3 s `lock_timeout`. Apply it outside the backup
   windows, with the timers stopped and no transaction older than a few
   seconds (the 126 lock plan, smaller). A lock timeout rolls the whole file
   back; re-run it. Older binaries are unaffected (the policies are the
   database's), so the order against the binaries is free.

**Rollback.** `docs/runbooks/129-undo.sql` on the migration DSN, in one
transaction, recreates the four bodies exactly as 083 and 087 left them. Run
it BEFORE `128-undo.sql`. If migration 169 is applied, run
`docs/runbooks/169-undo.sql` before it (169 recreates `security_events_read`
again). On an ARMED database 129-undo returns the standing custodian reads at
once; disarm first if that is not intended.

### An elevated token writes through no API route (no migration)

`epigraph-api` refuses every request whose token CARRIES an elevation claim
(`elv`, minted only by the elevate grant), before routing reaches the
handler. The exceptions are the methods `GET`, `HEAD` and `OPTIONS`, and the
routes on `middleware::elevated_access::ELEVATED_NON_GET_ALLOWLIST`:
- the two elevation routes (open a ticket, end an elevation), which act as
  the person;
- the POST routes that only read: `/api/v1/search/semantic`,
  `/api/v1/graph/query`, `/api/v1/triples/query` and
  `/api/v1/embeddings/neighborhood-density`.

The refusal is 403 `ELEVATED READ-ONLY`. It names `epigraph-operator` on the
maintenance DSN as the place where admin writes (client approval, entity
types, privatization acts) run while elevated. The check is keyed on the
claim, not on a live session: an elevate-grant token is read-only for its
whole life. So a write route that checks no scope and writes on the unscoped
pool (`assess`, `refine_frame`, `submit_evidence`) never runs for one, and
the check costs no database round trip. Nothing changes for a token without
the claim.

This is the API half of the recorder gate's opening conditions (125's
header). The gate itself stays CLOSED until migration 132.

Deploy: with `epigraph-api`, in any order; no migration. Rollback: the
previous binary.

### The admin-scope check chokepoint (no migration)

Every scope check follows migration 128's switch. That means
`epigraph_auth::AuthContext::has_scope`, which `check_scopes`, the API's
`RequireScope*` extractors and the MCP server's `SCOPE_MAP` gate all go
through. The API's bearer middleware and the MCP server's dispatch read the
switch for every authenticated request, through a per-process cache. The
cache lasts 10 s. A database without 128 reads unarmed. A switch that cannot
be read counts as armed for that request, and the error is not cached.

- **Unarmed**: every scope counts as the token says.
- **Armed**: an admin-only scope (`claims:admin`, `clients:admin`,
  `entity-types:write`, `groups:admin`, `instance:admin`) counts only on an
  ELEVATED request. A token minted before arming that still carries one is
  treated as lacking it at once (no re-mint needed), on REST and on MCP.
  Since elevation refuses every write, the admin WRITE surfaces (client
  approval, entity-type registration, the privatization acts, the MCP admin
  tools) are maintenance-CLI-only once armed.
- **The MCP `--allow-unauthenticated-http` listener**: its injected context
  carries `claims:admin` (when its scope map lists it). Armed, that scope is
  absent there too, so the listener's admin tools refuse. That is expected:
  arming ends standing admin authority everywhere.
- `platform:admin` (the elevate grant's scope) counts only while its
  elevation is live.

Deploy: with `epigraph-api` and the MCP binaries, in any order; no
migration. A binary without the chokepoint ignores the switch for checks
(the mint still strips while armed), so arm only after every request unit
runs a build with it. Rollback: disarm (`disarm-admin-scopes --apply`), then
the previous binaries.

### MCP `sudo` / `unsudo`, and who the tool list shows them to (no migration)

`epigraph-mcp-full` serves two tools over its HTTP transport:

- **`sudo(reason)`** opens a CONNECTOR-mode elevation ticket for the calling
  token's own principal, client and refresh family, and returns ONLY the
  ceremony page's URL (`<EPIGRAPH_PUBLIC_BASE_URL>/elevate/<ticket>`). The
  person opens it on the device that holds their passkey. Once confirmed,
  every later request on that refresh family resolves elevated (read-only,
  recorded) for at most 15 minutes. No token, secret or session id is
  returned, and the token endpoint never redeems a connector ticket.
- **`unsudo()`** ends that family's live elevation at once
  (`ended_reason = 'unsudo'`).

Who may use them is decided by the database (migration 125's ticket
definer): a registered human holding a live assignment of an elevating role,
with a live passkey, on a live family of its own human client. Agents never
can, and over stdio both tools refuse.

**Connector mode is OFF by default.** `sudo` is served only when
`EPIGRAPH_MCP_CONNECTOR_ELEVATION=on` (see "The elevated viewer"). Otherwise
it refuses and names the CLI elevate path, which is the served path:
`POST /api/v1/elevation/tickets`, the ceremony, then
`grant_type=urn:epigraph:grant:elevate` at `/oauth/token`. `unsudo` is served
either way, because ending only narrows. `sudo` also needs
**`EPIGRAPH_PUBLIC_BASE_URL`** in the MCP server's environment (the API's
public origin, where the ceremony page is served); unset, `sudo` refuses.

**The tool list is per caller.** `tools/list` and the `list_mcp_tools` tool
give the same answer:

- `sudo` is listed over HTTP only to a principal that holds a live elevating
  role, and only while connector mode is on. `unsudo` is listed to such a
  principal. The check is one subject-bound database read, made only for a
  human client's token that names its principal. stdio lists neither.
- An admin-only-scoped tool is listed only where the scope gate would admit
  it (`AuthContext::has_scope`). Unarmed, that is a token carrying the scope.
  Armed, it is only an elevated request.
- `GET /api/v1/mcp/tools` (REST) applies the same admin-tool rule and never
  lists `sudo`/`unsudo`. The API cannot see an MCP listener's connector
  switch; an MCP connection lists them to a holder itself.

Deploy: `epigraph-mcp-full` (HTTP units, and fleet and stdio images) and
`epigraph-api`, in any order; no migration. Leave
`EPIGRAPH_MCP_CONNECTOR_ELEVATION` unset until the connector's refresh-family
scope is decided. Rollback: the previous binaries. An open connector ticket
expires in 5 minutes. A live connector session ends at its expiry (at most 15
minutes), or at once with `epigraph-operator end-elevation` on the
maintenance DSN.

### Pending admin acts (migration 130) — the confirmation requirement, deploy order and rollback

A custodial write by a person who holds a passkey is bound to that person's
passkey assertion over the write's exact arguments:
1. an elevated session PROPOSES the act;
2. a passkey of its proposer CONFIRMS it, through a ceremony over the act's
   content;
3. the maintenance verb EXECUTES it with `--act <id>`, consuming it in the
   write's own transaction.

The rule lives in the table guards, so a direct maintenance statement meets
it too.

**What it means for the maintenance verbs (`ELV10`).** Once the acting
person holds a LIVE passkey, the verb without `--act` is refused:

- `grant-role` whose `--granted-by` holds a passkey;
- `end-role-assignment` while ANY live custodian holds a passkey (an end
  names no actor, so a confirmation is required whenever one is available);
- `custodial-supersede` whose `--actor` holds a passkey;
- `passkey-enroll` of a person who already holds a passkey (a further
  passkey comes from a confirmed `passkey.register` act of that person).

**The bootstrap.** No grantor, or a grantor with no passkey, writes
unconfirmed. Every `platform.role_granted` / `role_ended` / `custodial_act`
row says `confirmation` (`none` or `passkey`, with the act and its
elevation). The privatization custodial acts have no act kind yet and record
without one.

**With `--act`**, each verb rebuilds the act's arguments from its own flags.
It refuses before writing (exit 1, the act unspent) when the act is not that
act: another kind, not confirmed, executed already, expired (an act lives 30
minutes), other arguments, or another actor. A dry run spends nothing.

**The break-glass.** `epigraph-operator revoke-passkey` (audited) of a lost
or suspect passkey lifts the requirement for its holder, and voids every
unexecuted act it confirmed. For a suspect passkey use `--compromised`
(migration 200), which also revokes every passkey enrolled through it. Proposing an act needs a LIVE elevation, and no
elevation is live until migration 132 opens the recorder gate. The act API
that proposes and confirms is migration 131. Until both are deployed, a
custodian who holds a passkey makes these writes only after revoking it.

1. **Migrate 130** (`epigraph-migrate`, migration DSN): one transaction,
   `lock_timeout` 3s. It adds a table, a nullable column on
   `role_assignments` (metadata only, no rewrite), new functions, and new
   bodies for 123's role-assignment guards and audit, 123's custodial-act
   recorder (the six-parameter form becomes a wrapper) and 124's enrollment
   guard. Retry on a lock timeout.
2. **Deploy** `epigraph-operator` and `epigraph-tenancy-backfill` from the
   same commit. `verify` then checks the 130 definers' owner and grants. Older
   binaries keep working, except where `ELV10` applies.

**Rollback.** Roll back the `epigraph-operator` that passes `--act` first.
Then run `docs/runbooks/130-undo.sql` on the migration DSN, in one
transaction, BEFORE `129-undo.sql` and before `123-undo.sql` (130 adds
act-taking overloads of 123's definers). It archives every act as a
`platform.admin_act_archived` event, restores 123's and 124's bodies byte for
byte (every `ELV10` requirement goes with them), and drops the act table and
every 130 function. The `revoke_act_id` column, and the act ids that earlier
writes recorded, stay.

### Proposing and confirming admin acts (migration 131) — the act API, deploy order and rollback

The request path's half of migration 130: an elevated person PROPOSES an act
and CONFIRMS it with their passkey, and the maintenance CLI executes it.

- `POST /api/v1/admin/acts` `{kind, args, reason}` proposes the act as the
  caller.
  - Only an ELEVATED request may (a grant-mode elevated token); the database
    refuses any other with 403.
  - It is the ONE non-GET route an elevated token may write through. It
    writes only the act (an authority record the passkey must still
    confirm), through 130's elevation-gated definer, and the request is
    recorded in the elevated-access log like every elevated request.
  - The answer is the act id, its confirmation path and the URL on the
    relying party's origin. It answers 503 when no relying party is
    configured.
- `GET /api/v1/admin/acts?mine` returns the caller's OWN acts, newest first,
  with each step's outcome (migration 131's reader). Never anyone else's, and
  never the ceremony state or the evidence.
- `/elevate/act/<id>` (page), `/elevate/act/<id>/challenge` and
  `/elevate/act/<id>/assert` are the confirmation. They are anonymous by
  design, like the elevation page: the act id and the proposer's passkey are
  the credentials.
  - The page shows the STORED arguments, their digest, and the
    `epigraph-operator <verb> --act <id>` command that executes the act.
  - The WebAuthn challenge commits to the act: its id, its stored arguments
    digest, and a stored server nonce. A stored ceremony that does not is
    refused before any assertion is looked at.
  - Only the proposer's live passkeys confirm.
- MCP `propose_admin_act` (HTTP only) is listed and served only to an
  ELEVATED request. It answers only the confirmation URL under
  `EPIGRAPH_PUBLIC_BASE_URL`, and refuses when that is unset. A grant-mode
  elevation reaches it with the connector switch OFF.

Nothing is visible to an operator until the recorder gate opens (132): no
elevation is live before it, so nothing can be proposed. A confirmed act is
executed as the previous section describes.

1. **Migrate 131** (`epigraph-migrate`, migration DSN): one transaction,
   `lock_timeout` 3s, ONE new function (no table, no policy, no earlier
   body). Before the API that calls it.
2. **Deploy** `epigraph-api` (the routes) and the HTTP MCP units (the tool;
   set `EPIGRAPH_PUBLIC_BASE_URL` on them, as for `sudo`), and
   `epigraph-tenancy-backfill` from the same commit (`verify` checks the
   reader's owner and grant). Older binaries serve none of the routes or the
   tool.

**Rollback.** Roll back `epigraph-api` and the MCP units first (newest
first). Then run `docs/runbooks/131-undo.sql` on the migration DSN, BEFORE
`130-undo.sql`. The reader's `LANGUAGE sql` body records no dependency on
130's table, so 130-undo alone would leave it behind. The acts stay
(130-undo archives them).

### The offline confirmation verifier (no migration) — `epigraph-operator verify-confirmations`

The database cannot verify a WebAuthn signature. The definers that confirm
an elevation ticket (125) and an admin act (130) record what the API says it
verified, with the evidence. So a holder of the application DSN can forge a
confirmation through those definers, and a holder of the maintenance DSN can
write the rows directly. That cannot be prevented in this design; this verb
makes it DETECTABLE.

Run `epigraph-operator verify-confirmations [--since <RFC3339>] [--json]` on
the maintenance DSN, with `EPIGRAPH_WEBAUTHN_RP_ID` and
`EPIGRAPH_WEBAUTHN_ORIGIN` set to the values the API's ceremonies ran under.
It refuses to run without them (exit 1).
- For every CONFIRMED ticket and act, it re-verifies the stored evidence
  against the confirming passkey's stored public key, the rp id and the
  origin.
- It checks that the evidence's challenge is the row's own. An act's
  challenge is recomputed from the act id, its stored arguments digest and
  its stored nonce.
- It checks that the passkey is the person's, and that a device-bound
  passkey did not assert as backup-eligible.
- Across rows, it flags a challenge asserted more than once (a replayed
  evidence object), and an elevation session that no confirmed ticket opened
  (a session written directly).
- Refused assertions are counted, not verified.

- Exit 0: everything checked verifies. Exit 2: at least one finding. Each
  finding is printed and recorded ONCE as a `platform.confirmation_unverified`
  security event attributed to the person; a re-run reports it again and
  records nothing more. Exit 1: no relying party configured, or a failure.
- A wrong `EPIGRAPH_WEBAUTHN_ORIGIN` or `_RP_ID` makes every genuine
  confirmation fail (`assertion_does_not_verify`) and records a row for each.
  Check the two values against the API's before the first run.
- On a database without migration 130 the acts are skipped and the
  elevations are verified.

When to run it: before the FIRST real elevation (together with the check
that only the request units hold the application DSN, a precondition of
opening the recorder gate), after every admin session, and on a timer. A
finding means a confirmation nobody's passkey made. End the person's
elevations (`end-elevation --person`), treat the application or maintenance
DSN as compromised, and rotate it.

Deploy: `epigraph-operator` from the same commit; nothing else. Rollback:
the previous binary (the recorded findings stay).

### Opening elevation (migration 132) — the preconditions, deploy order and rollback

Migration 132 is the ONE migration of the elevation stack that opens
migration 125's recorder gate (`epigraph_elevated_access_ready()`). Its body
is a readiness test: true while the per-access recorder (127's
`elevated_access` table and `epigraph_record_elevated_access`) is installed.
Every earlier migration of the stack ships the gate closed, so on a database
below 132 a confirmed ceremony opens a session that is never live.

From 132 on, a session is live only when ALL of these hold, re-checked on
every statement:
- the serving connection DECLARES the recorder. Only the recording builds
  do: the API `server` and the HTTP MCP units. A unit on an older build never
  elevates;
- the login is the application role, never a privileged login or a role
  switch;
- the person is a registered human holding a live assignment of an
  elevating role;
- the session's passkey is unrevoked, and its refresh family and human
  client are live;
- it has not expired (at most 15 minutes) and has not been ended.

**`epigraph-migrate` applies every embedded migration up to the build's head,
and so does `EPIGRAPH_MIGRATE_ON_BOOT`.** Deploying ANY build that embeds 132
opens the gate at its migrate step. A fresh install at the current head
therefore has the gate open from the start, and widens nothing until a
person holds both a passkey and an elevating assignment and completes a
ceremony. So the preconditions below come BEFORE the deploy that carries
132, or, on a fresh install, before the first passkey is enrolled:

1. `epigraph-operator verify-confirmations` (with the API's relying-party
   values) exits 0 on the target database.
2. Only the request units hold the application DSN. Check this on the host:
   the offline verifier detects a confirmation forged through that DSN, but
   it cannot stop one.
3. `epigraph-tenancy-backfill verify` passes, and the maintenance DSN is not
   the superuser. `verify` fails while a maintenance role, or PUBLIC, may
   CREATE in schema `public`, which is what would let a maintenance statement
   replace the gate.
4. Every request unit runs on the application role, with no role switch in
   its DSN (`options=-c role=...`) and no per-login default role.
5. Connector mode stays OFF: leave `EPIGRAPH_MCP_CONNECTOR_ELEVATION` unset
   until the connector's refresh-family scope has been measured and decided.
   The served path is the CLI / console elevate grant.

Applying 132 with no passkey enrolled and no elevating assignment held widens
nothing: a session needs both, and a ceremony.

1. **Migrate 132** (`epigraph-migrate`, migration DSN): one transaction,
   `lock_timeout` 3s, one function body. No table, policy or grant changes
   (`CREATE OR REPLACE` keeps the owner and the ACL).
2. **Deploy** nothing new for it: the recording builds are the ones the 127
   section already deployed.

**Rollback.** Run `docs/runbooks/132-undo.sql` on the migration DSN FIRST,
before every other elevation undo. It restores 125's `SELECT false`, so every
session stops being live at its next statement. No binary needs rolling back
first: a recording build on a gate-closed database serves every request
unelevated. Taking 127 back out also closes the gate by itself (the readiness
test reads the recorder), but run 132-undo first anyway.

### The elevation stack as a whole (migrations 124-132) — order, undo order, arming

The sections above hold the detail; this is the order across them. Record
each deployed commit as you go.

**Upgrading a database below 124.**

1. Migrate 124 (passkeys and enrollment tickets) and 125 (elevation tickets
   and sessions; inert, because the gate is closed).
2. Deploy the binaries that understand elevation: `epigraph-api`, the HTTP
   and fleet/stdio `epigraph-mcp` units, the maintenance CLIs
   (`epigraph-operator`, `epigraph-tenancy-backfill`), and `drain_jobs`.
   Older binaries stamp no elevation pair and never elevate.
3. Migrate 126 (the elevated read arms and write refusals) under its lock
   plan: timers stopped, no long transaction, outside backup windows.
4. Migrate 127 (the elevated-access log) and deploy the RECORDING builds (API
   server, HTTP MCP units). Then migrate 128 (the admin-scope switch, shipped
   UNARMED) and 129 (the standing admin arms follow the switch, under the
   lock plan), with the builds that read the switch.
5. Migrate 130 (pending admin acts) with the CLIs that take `--act`, then 131
   (a person reads their own acts) before the API and MCP builds that serve
   the act routes and tool.
6. Meet the preconditions in "Opening elevation (migration 132)", then deploy
   the build that carries 132. Its migrate step opens the gate.

**Then, on any database (fresh or upgraded):**

7. Enroll the operator's passkey (`epigraph-operator passkey-enroll`, then
   the ceremony on the operator's device at the relying party's host).
   Elevate once through the CLI path, read one row of another group, and
   confirm that its `elevated_access` row exists. Run `verify-confirmations`
   after every admin session and on a timer.

**Arming the admin-scope chokepoints** is a separate, later step. Do it only
after every request unit runs a build with the check chokepoint, and the
`oauth.admin_scope_would_strip` events have read zero for a soak window: run
`epigraph-operator arm-admin-scopes --reason TEXT --apply`. Once armed,
standing admin-only scopes count for nothing on an unelevated request, and no
grant mints them. Admin reads need an elevation, and admin writes are
maintenance-CLI acts. The rollback is `disarm-admin-scopes --reason TEXT
--apply`, with no DDL.

**Undo order.** Disarm first (if armed). Roll back the binaries, newest
first. Then run the undo scripts in reverse: `200-undo.sql` (if 200 is
applied; its reader and triggers read 124's and 130's tables), `132-undo.sql`, `131-undo.sql`,
`130-undo.sql`, `129-undo.sql` (after `169-undo.sql`, if 169 is applied),
`128-undo.sql`, `127-undo.sql` (which archives the log into
`security_events` first), `126-undo.sql`, `125-undo.sql`, `124-undo.sql`.
Each script's header names the binaries that must be rolled back before it.
`epigraph-operator revoke-passkey` is the break-glass that returns a passkey
holder to the bootstrap path without any undo.

## 11. Upgrade notes by migration

A fresh database applies every migration in one `epigraph-migrate` run, and
none of the orderings below arise. They matter when you **upgrade** a
database whose head is below the migration named. Find your database's head
(`SELECT max(version) FROM _sqlx_migrations WHERE success`), and read every
entry above it before you deploy.

The general rule, unless an entry says otherwise: migrate with
`epigraph-migrate` first, then deploy the binaries built from the same
commit. Where a migration's header gives a binding order, it is repeated
here. Each migration's header is authoritative and holds its full undo.

| Migration | When upgrading across it |
|---|---|
| 060 | A database provisioned outside the public migration series needs the reconcile runbooks first ([section 13](#databases-provisioned-outside-the-public-migration-series)). |
| 062–066 | 062 locks 25 tables in one transaction; 063–066 are `-- no-transaction` index builds ([section 4](#4-database-migrations)). After the tenancy backfill, `REINDEX INDEX CONCURRENTLY idx_claims_world_owned` ([section 6](#6-session-settings-and-connection-poolers)). |
| 074, 075, 076 | Binaries first, then a 24-hour zero-counter soak, then three separate migrate steps ([section 13](#upgrading-across-074075076-tenancy-required)). |
| 079 | The FORCE kill switch is `docs/runbooks/079-undo.sql`, run from the tree you roll back to ([section 5](#5-the-maintenance-dsn-and-the-maintenance-timers)). |
| 084 | Drops `public.ownership`. Run the backfill's transcription and `verify` with the release that still has them, then apply ([section 13](#retiring-the-ownership-table-084)). |
| 122 | [Operator binding (migration 122) — deploy order](#operator-binding-migration-122--deploy-order). |
| 123 | [The custodian role](#the-custodian-role-migration-123--deploy-order-and-rollback). Register every human first. |
| 124–132 | [The elevation stack](#the-elevation-stack-as-a-whole-migrations-124-132--order-undo-order-arming). Deploying any build that embeds 132 opens the elevation gate. |
| 140 | Migrate before (or with) the API ([section 8](#refresh-scope-migration-140--a-refresh-never-widens-a-chain)). Decide what to do with chains widened under 118. |
| 141 | Apply with or before the API and MCP binaries that read the access-token denylist. A current binary on a database without it refuses every authenticated request. Undo only after rolling the binaries back. |
| 144 | Install the `epigraph-cli reembed` that filters `is_current` BEFORE applying. An older reembed run after 144 raises `23514` on the first retired row and aborts. No reembed run may be in flight while it applies. |
| 148 | Register the workflow-ingest system agent before arming and before rotating its key, once every API and MCP binary is at or above 148 (the operator binding section, step 8). |
| 149 | The author-binding allowlist. No behaviour changes while the registry is empty. Undo: `docs/runbooks/149-undo.sql`, after rolling back the operator CLI and the MCP binaries built against it. Every allowlisted client's agent becomes unbound. |
| 150 | Drops `uq_claims_content_hash_agent` (`IF EXISTS`; a no-op where it is already absent). `ACCESS EXCLUSIVE` on `claims` for an instant under `lock_timeout = '3s'`: on a timeout, re-run in a quiet window. Undo only on a database with no duplicate `(content_hash, agent_id)` rows; `scripts/audit_claims_content_hash_agent.py` counts them, read-only. |
| 153 | [A lineage stays in its owner group](#a-lineage-stays-in-its-owner-group-migration-153--deploy-order-and-rollback): census before arming. |
| 154 | Seeds and verifies the canonical `claim_validity` frame. It refuses if a frame with another id holds the name. Its header gives the undo, which applies only where this file inserted the row and nothing references it yet. |
| 158 | Grants the maintenance role DELETE on `frames`, so `delete-frames` runs on a NOSUPERUSER maintenance login. Undo: `REVOKE DELETE ON public.frames FROM epigraph_maintenance;`. |
| 159 | A never-populated community group is bootstrapped by a maintenance session only. No rows change. Undo: re-run 106's `CREATE OR REPLACE FUNCTION public.epigraph_community_add_member`, which re-opens the bootstrap to every actor. A later re-statement of that function must start from 159's body. |
| 161–163 | Agent identity registration and the attestor role ([section 9](#agent-identities-and-the-attestor-login-migrations-161-162-163-166-179-180)). Without CREATEROLE, create and grant the attestor by hand. |
| 164, 165 | Keyless team groups and role-derived membership. Maintenance verbs only; undos in the headers ([section 9](#keyless-team-groups-and-role-derived-membership-migrations-164-165)). |
| 166 | Role-attached agents. Register identities before attaching them. Give an attestor created after 166 its EXECUTE on `epigraph_role_agent_may_run(uuid)` by hand. Undo after rolling back `epigraph-mcp` (`docs/runbooks/166-undo.sql`, after `180-undo.sql`). |
| 168 | An outsider's challenge is owned by the outsider. Apply BEFORE a binary built with it serves: that binary admits an outsider in its preflight, and without the attach rule the INSERT is refused (MCP "refused after the writer check", HTTP 403). An older binary on a migrated database keeps working. Short `challenges` locks under `lock_timeout`. Undo: in its header, after deciding what to do with any outsider-owned row. |
| 169 | Applied-cascade audit rows are read by instance admins only. Policy DDL on `security_events`: one transaction, 3 s `lock_timeout`, rerunnable. Older binaries keep working. Undo: `docs/runbooks/169-undo.sql`, BEFORE `129-undo.sql`. |
| 170 | A challenge's resolution columns change only through `epigraph_resolve_challenge`. Independent of the binaries. Undo: drop the four triggers and the guard function (its header). |
| 171 | **Binaries FIRST** (the API, `epigraph-mcp-full`, and `drain_jobs`, which runs the hosted jobs), then this migration. A binary built before it names `ON CONFLICT (content_hash, claim_id)` and fails `42P10` once the key is gone. No seal or unseal may be in flight while it applies. From the binary deploy on, a same-owner, byte-identical evidence write on a claim that already holds that body is refused as a duplicate (HTTP 400; the MCP evidence-writing tools return an error and roll the whole submission back). Undo only on a database with no duplicate `(content_hash, claim_id)` rows; the count query is in its header. |
| 172 | The refresh-rotation definer resolves its built-ins in `pg_catalog`. Undo: re-run 140's `CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_rotate` block. |
| 173 | `harvester_sources` and `harvester_audit_reports` come under tenancy and FORCE. Apply before, or with, the API binary that lists both tables in `FORCE_PROTECTED_SET`: that binary refuses to serve where they exist un-FORCEd. An older binary on a migrated database is unaffected. Undo in its header, including removing both names from `079-undo.sql`. |
| 174 | Migrate BEFORE the API ([section 8](#refresh-grant-hardening-migration-174--confidential-clients-authenticate-on-refresh-a-chain-is-bound-to-its-connector-app)). |
| 175 | **Binding order; getting it wrong damages data silently** ([below](#migration-175-one-spelling-for-the-case-folded-edge-relationships)). |
| 176 | Caller-reachable refusals carry a refusal code (`AGK01`, `AAR01`–`AAR12`, `TEN01`–`TEN02`, `GRM01`–`GRM06`, `PRV01`). Each function is re-stated with only its `RAISE` text changed and the SQLSTATE kept, so callers that branch on the SQLSTATE behave the same. |
| 179 | Group-role bindings that admit only attached agents. A precondition refuses (`55000`, nothing changed) unless the three 165 bodies it re-states are 165's, by md5 of `prosrc`. Undo: end every `attached_agents` binding first; the statements are in its header. |
| 180 | Legacy fleet parents for registration. A precondition checks 166's registration body by md5 (`55000` otherwise). Undo: `docs/runbooks/180-undo.sql`, before `166-undo.sql`. |
| 181 | A group admin marks the group's re-key obligation through a narrow definer, which member removal calls. Undo: drop the function, and revert the repository to its direct `UPDATE groups`. |
| 183 | `workflows` rows carry tenancy (`owner_group_id`, `visibility`, NOT NULL, no default), backfilled from each plan's declared tenancy, with row security ENABLEd and FORCEd. A writer must name both columns (`workflows_require_tenancy`). Re-tenanting a workflow row is a maintenance act. |
| 184 | Retract one BBA without deleting it. One transaction holding ACCESS EXCLUSIVE on `mass_functions` from the first `ALTER TABLE` to the commit, including one sequential scan to add the CHECK. Measure the row count before the window. Apply BEFORE a binary with the matching readers serves (it selects `retracted_at`). An older binary keeps working. Undo only while no row is retracted (its header). |
| 185 | Once armed, a supersession is bound on its actor. A precondition refuses (`55000`) unless the function body is 153's (md5 `292b24b3dfb6b342f6f60d7868666236`). No order against the binaries. Undo: `185-undo.sql` before `153-undo.sql`. |
| 186 | The maintenance role may DELETE from `recall_events` and `events`, for `prune_recall_events`. No ordering. Undo: `REVOKE DELETE ON public.recall_events, public.events FROM epigraph_maintenance;`. |
| 188 | Client approval becomes a maintenance act. Apply with or after the binary built with it: an older binary on 188 answers the approve route with 500 (`42501`), and the newer binary answers 501 either way. Undo: re-grant EXECUTE on `epigraph_oauth_client_approve(uuid, text[], uuid)` to `epigraph_app`. |
| 189 | `events` is append-only for the application role (UPDATE, DELETE and TRUNCATE revoked). After 186; no order against the binaries. Undo in its header. |
| 190 | Every `SECURITY DEFINER` lists `pg_temp` last on its `search_path`. A precondition (`55000`) checks six function bodies by md5, and a postcondition refuses if any definer still lacks the trailing `pg_temp`. The undo, a re-run of six bodies and a path reset on 23 definers, is in its header. |
| 191 | The `retire-link` verb, and an audit row for every flip of `operator_links.retired`. Retired links stay retired after an undo. |
| 193 | Apply BEFORE a binary whose `cache_owner_frame_for_claim` calls `epigraph_claim_is_compound` serves; without it every owner lookup errors (`42883`). An older binary ignores it. Undo only after rolling the binary back. |
| 194 | **Binding order.** Migrate 194 only after every binary that can delete `mass_functions` rows on a privileged connection runs the release that keeps retracted rows on those paths. A binary still on an older build deletes a retracted row, the guard refuses it, and the whole administrative cascade aborts and is replayed for ever. Install a `delete-frames` built for 194 after the migrate. A precondition refuses (`55000`) unless `epigraph_cascade_delete_edge_bbas(uuid[], text)` has 117's body (md5 `39f3eacd53e7717a323759ec91b5c2c0`) and its `proconfig` is `search_path=pg_catalog, public` or `search_path=pg_catalog, public, pg_temp`. Check first with `SELECT md5(prosrc), proconfig FROM pg_proc WHERE oid = to_regprocedure('public.epigraph_cascade_delete_edge_bbas(uuid[], text)')`. Undo: `docs/runbooks/194-undo.sql`. |

The md5 values above are copied from the migrations' own preconditions. They
are properties of the public function bodies, not of any deployment.

### Migration 175: one spelling for the case-folded edge relationships

175 makes `supports`, `contradicts`, `corroborates` and `refutes`
spelling-blind in the schema (`edge_to_factor_type` and the matcher's unique
index), and the writers store the lower-case spelling. If a binary built with
this change writes against a database WITHOUT 175, then every matcher
`corroborates` edge written in that gap:
- gets NO belief-propagation factor, permanently (`edges_auto_factor` is
  AFTER INSERT only, and nothing backfills);
- falls outside 090's unique index predicate.

A `decompose_claims --retarget --apply` against an API without the change
POSTs lower-case `contradicts` and gets 400.

1. **Apply 175 first**, with `epigraph-migrate`, and confirm that the marker's
   `db_head` is at or above 175. 175's header says "Only epigraph-api applies
   migrations (at boot)". That describes builds where the API migrated at
   boot. At this tree, `epigraph-migrate` applies migrations, and the API does
   only with `EPIGRAPH_MIGRATE_ON_BOOT` set. The requirement is the same:
   175 is on the database before any writer built with the change runs.
2. **Then** deploy the writers: the API, `epigraph-mcp-full`, `drain_jobs`
   (which runs the job handlers 175's header calls `epigraph-jobs`) and
   `decompose_claims`.
3. **Then**, optionally, fold legacy rows with
   `docs/runbooks/edge-relationship-casefold.sql`: on the migration DSN, in
   a quiet window, after a fresh full backup. Its undo is
   `edge-relationship-casefold-undo.sql`, which restores from the backup table
   the fold wrote.

**Precondition** (read-only, expected zero rows). A pair holding both
spellings of an in-force matcher edge fails the index CREATE, and the
migration fails:

```sql
SELECT LEAST(source_id,target_id) AS a, GREATEST(source_id,target_id) AS b,
       lower(relationship::text) AS rel, count(*)
  FROM public.edges
 WHERE lower(relationship::text) IN ('corroborates','contradicts')
   AND source_type = 'claim' AND target_type = 'claim'
   AND properties->>'source' = 'cross_source_matcher'
   AND valid_to IS NULL
 GROUP BY 1,2,3
HAVING count(*) > 1;
```

Undo: re-run 011's `edge_to_factor_type` body and 090's index statement.
Both files are unchanged and re-runnable. A factor backfill for `corroborates`
/ `refutes` edges that have no factors row is a separate decision, not part
of 175.

## 12. Undo scripts and rollback order

There is no `sqlx migrate revert` in this tree, and `migrations/` holds no
`.down.sql` files. The undo for a migration is either a script under
`docs/runbooks/` or a statement list in the migration's own header. Run
undos on the migration DSN, in one transaction unless the script says
otherwise. Before each one, roll back the binaries its header names. A
`_sqlx_migrations` row usually stays after an undo, so re-introducing the
change is a new migration.

| Script | Undoes | Run it before | Notes |
|---|---|---|---|
| `070-undo.sql` | 070 and 071 (tenancy triggers, the ownership shim) | — | |
| `074-undo.sql` | 074 | — | 074 is a one-way door. Read this before applying 074 to anything you cannot rebuild. |
| `079-undo.sql` | FORCE on every protected relation (the kill switch) | — | Run the copy from the tree you are rolling back to, and finish with its VERIFY query. A stale copy leaves a partially FORCEd set, and the API then refuses to boot. |
| `084-undo.sql` | 084 (recreates the EMPTY shape of `ownership` only) | — | 084 is a one-way door. |
| `185-undo.sql` | 185 (restores 153's body) | `153-undo.sql` | |
| `153-undo.sql` | 153 (restores 123's body) | `123-undo.sql` | |
| `180-undo.sql` | 180 (restores 166's registration body) | `166-undo.sql` | Removes 180's guard on the registration's role-attachment copy too. |
| `166-undo.sql` | 166 | — | Roll back every `epigraph-mcp` built against 166 first. |
| `169-undo.sql` | 169 | `129-undo.sql` | |
| `149-undo.sql` | 149 | removing 122's functions | Every allowlisted client's agent becomes unbound (`OPL01` once armed). |
| `132-undo.sql` | 132 (closes the elevation gate) | every other elevation undo | |
| `131-undo.sql` | 131 | `130-undo.sql` | |
| `130-undo.sql` | 130 (archives the acts) | `129-undo.sql`, `123-undo.sql` | |
| `129-undo.sql` | 129 | `128-undo.sql` | Returns standing custodian reads at once on an armed database. |
| `128-undo.sql` | 128 (disarms through its own audit first) | `127-undo.sql` | |
| `127-undo.sql` | 127 (archives the log into `security_events`) | `126-undo.sql`, `125-undo.sql` | |
| `126-undo.sql` | 126 (per table, resumable) | `125-undo.sql` | |
| `125-undo.sql` | 125 | `124-undo.sql` | Refuses while any policy reads `epigraph_is_elevated()`. |
| `124-undo.sql` | 124 | — | Every human enrolls again afterwards. |
| `123-undo.sql` | 123 | — | Lists the holders granted after 123, to re-grant by hand. |
| `194-undo.sql` | 194 | — | A `delete-frames` built for 194 then fails on a frame that holds a retracted row ("function does not exist"), with nothing written. |
| `edge-relationship-casefold-undo.sql` | the case-fold data runbook | — | Does not undo 175, and does not need to. |

Chains to keep in order:

- **185 → 153 → 123**, with **130** (and 131 before it) also before 123.
- **180 → 166.**
- **169 → 129 → 128 → 127.**
- **The elevation stack:** 132 → 131 → 130 → 129 → 128 → 127 → 126 → 125 → 124.
- Disarm the admin-scope switch before any of it, and roll back the binaries
  (newest first) before the scripts.

Two scripts under `docs/runbooks/` are not undos:
`060-pre-reconcile.sql` and `001-restore-missing-tables.sql` are legacy
pre-migrate steps (section 13).

## 13. Legacy one-time procedures

Nothing in this section applies to a database created by `epigraph-migrate`
from empty. Each subsection says which databases it is for.

### Databases tracked under a private repository's numbering (the 2026-05-05 reconcile)

**For:** a database whose `_sqlx_migrations` was tracking a private
repository's migration numbering (rows 1–98 and 100–106) before 2026-05-05.
The public repository numbers its files differently, starting at 001.
Running the public migrator against such a database would see "no public
migrations applied" and try to re-run `001_initial_schema.sql` against a
populated database, which fails.

`ops/reconcile_2026_05_05.sql` truncates `_sqlx_migrations` and re-inserts
rows 1–26 with the sha384 checksums of the public files. After that,
`epigraph-migrate` sees a clean tracking state and applies only the later
migrations.

1. `pg_dump -Fc "$DATABASE_URL" > epigraph_pre_reconcile_$(date -I).dump`
2. `psql "$DATABASE_URL" -f ops/reconcile_2026_05_05.sql`
3. Run `epigraph-migrate` (on the migration DSN). It applies everything after
   026.
4. Restart the API.

**If the reconcile goes wrong.** If a checksum mismatch surfaces on the next
`epigraph-migrate` run, restore the pre-reconcile dump before retrying:

1. Stop the API.
2. `pg_restore --clean --if-exists -d "$DATABASE_URL" epigraph_pre_reconcile_*.dump`
3. Compare `sha384sum migrations/NNN_*.sql` with the values recorded in
   `ops/reconcile_2026_05_05.sql`, before you retry step 2.
4. Start the API only once the tracking table is consistent.

The reconcile lives outside `migrations/`, under `ops/`, so that
`sqlx::migrate!("../../migrations")` does not pick it up. sqlx's filename
parser splits on `_` and treats every file in the migrations directory as a
candidate. A leading-underscore name like `_reconcile.sql` produces an empty
version string, which is a hard parse error, not a skip. Under `ops/`, the
embedded migrator never sees it, and it is run by hand exactly once.

### Databases provisioned outside the public migration series

**For:** a database whose schema was created by some other means (an
enterprise provisioning path, for example) and whose `_sqlx_migrations`
claims early migrations that never ran.

- `docs/runbooks/060-pre-reconcile.sql` brings such a database to the shape
  migration 060 expects, without losing the rows already in it. It must run
  between 059 and 060. Read its header.
- `docs/runbooks/001-restore-missing-tables.sql` creates, empty, the eight
  tables that `001_initial_schema.sql` defines but that such a database
  lacks. On such a database, `_sqlx_migrations` claims 001 was applied (its
  row was inserted by hand, with `execution_time = 0`), so sqlx never creates
  them, and later migrations then ALTER tables that do not exist. Run it
  immediately before `epigraph-migrate`, after `060-pre-reconcile.sql`.

A shared test database that was not migrated `001 → head` from empty cannot
be migrated forward in place either: 060 fails closed on its pre-060 tables.
Create a fresh `*_test` database instead (`CLAUDE.md`, "Test database").

### Before the router allowlist: every active client needs an `agent_id`

**For:** upgrading a database whose OAuth clients were issued before clients
received an agent identity at their first token. Measure first:

```sql
SELECT count(*) FILTER (WHERE agent_id IS NOT NULL)::float
       / NULLIF(count(*), 0)
FROM oauth_clients WHERE status = 'active';
```

It must read 1.0. `oauth_clients.agent_id` is what the JWT's `agent_id` claim
is copied from. A null `agent_id` is an immediate write outage on the primary
write path (`POST /api/v1/claims` and `POST /claims` answer 401
`invalid_token`), and every read route that takes a viewer refuses it too.
Below 1.0, back-fill first, or re-mint the affected clients through
`/oauth/token`. Find them in the logs by the event
`visibility.viewer.rejected{reason="no_agent_id", route, client_id}`: grep
for it (for example on `route=/api/v1/hypothesis`) for one retention window
before you roll, and re-mint whatever `client_id` appears.

### Upgrading across 074/075/076 (tenancy required)

**For:** a database below migration 074. These three migrations make tenancy
REQUIRED: they drop the column defaults, arm the triggers and validate the
constraints. **They do not ship in the same deploy step as the code.** This
is the largest single outage risk in the tenancy series.

1. Deploy the binaries that carry the patched `INSERT INTO claims` call
   sites, with 074/075/076 **not applied**.
2. Watch `epigraph_tenancy_undeclared_writes` (scraped from
   `EPIGRAPH_METRICS_ADDR`) **stay flat at zero for 24 hours across every
   tier-A table**.

   **Falsify the counter FIRST, before the 24 hours start.** Zero and unwired
   look identical on a dashboard. After 074 no test exercises the
   trigger→counter link any more: 074's `CREATE OR REPLACE` removes migration
   070 arm (a)'s counting limb, so the link only exists on a pre-074 database.
   That is exactly the database you are standing on at this step, and the
   only place it can still be demonstrated. On a canary, perform ONE
   deliberate undeclared insert as the application role, and confirm that the
   series increments and appears in the scrape. Then reset the observation
   window. A gate whose instrument was never proved live is not a gate.
3. Run `epigraph-tenancy-backfill verify` before step 4. Its exit code is
   the guard, and it prints the offending ids. Then run
   `REINDEX INDEX CONCURRENTLY idx_claims_world_owned` (migration 066's header
   requires it after the backfill; it is not an optimisation).
4. Apply 074, then 075, then 076, as **three separate steps**. 075 and 076
   are split so that `claims`'s `VALIDATE CONSTRAINT` scan does not hold
   `SHARE UPDATE EXCLUSIVE` for the sum of every other table's.

Skipping step 2 is the failure: older pods still run
`ClaimRepository::create` without the tenancy columns, and **every claim
write raises `23502` the instant 074 commits**.

074 is a **one-way door**. Its undo script is `docs/runbooks/074-undo.sql`;
read it before applying 074 to anything you cannot rebuild.

### Retiring the ownership table (084)

**For:** a database below migration 084 that still has `public.ownership`.

The read path does not consult `ownership`; the tenancy columns are the sole
source of truth. Migration 084 DROPS `public.ownership`. Its second
pre-flight refuses to run while any non-public row lacks a
`tenancy_transcription_log` entry. The release that ships 084 also retires
the backfill's transcription pass and the two `verify` checks that cleared
exactly that condition. That is safe only because the pre-flight proves the
condition is already met. So:

1. run `epigraph-tenancy-backfill run` to completion with a build that STILL
   HAS the transcription pass, before you deploy the binaries that ship 084;
2. confirm that `epigraph-tenancy-backfill verify` exits 0;
3. then apply 084.

If 084's pre-flight raises, do not work around it.
`refusing to DROP ownership: N non-public row(s) were never transcribed`
means those nodes' declarations never reached a visibility column, and
dropping them would silently widen the nodes.
`... N quarantined encryption_key_id row(s) are untriaged` means rows naming
an encryption key that no longer resolves. Both are operator action items.

084 is a **one-way door**, and `sqlx migrate revert` does not exist in this
tree. `docs/runbooks/084-undo.sql` recreates the EMPTY SHAPE only; read it
before applying 084 to anything you cannot rebuild.

With `ownership` gone, the routes that read or wrote it do not exist:
`GET /api/v1/ownership/:node_id`, `POST /api/v1/ownership`,
`PUT /api/v1/ownership/:node_id`, `GET /api/v1/agents/:id/owned-nodes`, and
the MCP tools `assign_ownership`, `update_partition` and `get_ownership`.
Callers get **404**, not 401. Tenancy is stamped at INSERT by migration 070's
inherit trigger and by 074's per-table `_require_tenancy` guards.

### `recall_events` rows written before self-scoping

**For:** a database with `recall_events` rows written before recall events
were self-scoped (section 7). Those rows carry `visibility = 'public'`, from
migration 062's column default and from `epigraph-tenancy-backfill`'s
`recall_events` pass. The read predicate's middle disjunct admits every one
of them to every authenticated reader, and no migration restamps them:

* the narrowing applies to rows written since, so the historical log stays
  instance-wide until it ages out;
* `prune_recall_events` (`RecallEventRepository::prune_older_than`,
  `RECALL_EVENTS_RETENTION_DAYS`, default 90) is what retires those rows, so **confirm that the retention prune is scheduled and
  running** rather than assuming it.

A one-off reconciliation (set `visibility = 'group'` where `agent_id IS NOT
NULL` and `owner_group_id` already names that agent's personal group) is
recorded as an outstanding operator decision in `docs/tenancy/progress.json`.
Do not improvise it against a live database without that entry's context.

## 14. Troubleshooting

| Symptom (exact text where the code emits one) | Cause and fix |
|---|---|
| `ERROR: MAINTENANCE_DATABASE_URL is set; a request-serving process never holds the maintenance DSN (operator decision D9). ...` | The API or an MCP unit has the maintenance DSN in its environment (an EnvironmentFile, `.env`, or an MCP client's env block). Remove it. |
| `FATAL: EPIGRAPH_JWT_SECRET is empty. ...` / `... is N bytes; minimum is 32` / `... is the committed dev literal; refusing to start in production` | Set a real secret of at least 32 bytes. `EPIGRAPH_ALLOW_INSECURE_SECRET=1` is for development and CI only. |
| `failed to build providers registry: "providers.toml not found at ..."` | Create `providers.toml` (empty is valid) or set `EPIGRAPH_PROVIDERS_CONFIG`. The template is `providers.toml.example`. |
| `failed to build providers registry: "provider '...': auto_provision is enabled with no allowed_emails/allowed_domains ..."` | Populate the allowlists, or set `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`. `EPIGRAPH_ENV` unset counts as production. |
| `failed to build providers registry: ... env var GOOGLE_CLIENT_ID not set` | A configured provider names environment variables that are unset. |
| `EPIGRAPH_RESOURCE_METADATA_URL is unusable; refusing to start` | The value cannot go in an HTTP header. |
| A passkey configuration error at boot (`ERROR: ...`), or `passkeys not configured (EPIGRAPH_WEBAUTHN_RP_ID / _ORIGIN unset): the enrollment ceremony answers 503` | Set both `EPIGRAPH_WEBAUTHN_RP_ID` and `EPIGRAPH_WEBAUTHN_ORIGIN`, or neither. |
| `FATAL: session GUCs do not survive between statements on one pooled connection. ...` | A transaction-mode pooler. Use a session-mode endpoint, or `EPIGRAPH_SESSION_GUC_MODE=transaction` (section 6). |
| `Failed to load entity_types registry cache` | The database is not migrated. Run `epigraph-migrate`. |
| `refusing to serve: tenancy triggers are not armed` | A require-tenancy trigger is missing or disabled. The database is not at head, or a trigger was disabled by hand. |
| `refusing to serve: RLS posture assertion failed` | The API connects as `epigraph_app` and a protected table is not FORCEd. Typically this is a partial FORCE after an older `079-undo.sql`, or a table migrated in without FORCE (see 173). |
| `operator binding NOT ENFORCED for the writer on this privileged DSN: ...`, then `ERROR: refusing to start: ...` | A request unit on a privileged DSN against an armed database. Point it at the `epigraph_app` login. |
| `ERROR: stopping: ...` from a running unit | The same, found by the periodic re-check (`EPIGRAPH_REQUEST_UNIT_RECHECK_SECS`) after the database was armed. |
| `operator binding is NOT ARMED on this database: ...` (WARN) | Expected until you arm (section 9). |
| `migration 122 (operator binding) is not applied to this database; claim writes through default declarations fail closed until it is` | Run `epigraph-migrate`. |
| `migrations: FAILED: REFUSING: the database has N applied migration version(s) this binary does not embed: ...` | A stale binary (section 4). Deploy the newer build, or `--allow-db-ahead` for a deliberate rollback. |
| `migrations: FAILED: sqlx::migrate failed: ...` | Often an edited applied migration (a checksum mismatch), or a precondition `RAISE` (`55000` from the md5 preconditions, 074/075/084's pre-flights). Read the message, and the migration's header. |
| `epigraph-migrate` exits 0 and applies nothing, but your migration is missing | A stale binary from a shared target directory (section 4). |
| `Failed to bind the internal metrics listener; metrics will not be scrapeable. The API continues to serve.` | Another process holds `EPIGRAPH_METRICS_ADDR`. Give each instance its own. |
| `ERROR: drain_jobs: ...` | `drain_jobs` could not start: the maintenance DSN is unset, names another database, or does not satisfy `epigraph_bypass()`. |
| `42501 permission denied for function epigraph_live_memberships` | A login outside `epigraph_app` / `epigraph_maintenance` resolved a viewer. Use the maintenance login. |
| Elevated tokens read nothing extra | Expected before migration 132, on a unit without the recorder declaration, on a privileged DSN, behind a transaction-mode pooler, or with a DSN role switch (section 10). |
| The MCP server prints `Generated new agent keypair` | No declared identity. Set `--agent-key` / `EPIGRAPH_MCP_AGENT_KEY` or `--agent-model` with a prompt or prompt hash. |
| MCP `embeddings disabled (no API key)` / `could not embed the query` | No `OPENAI_API_KEY` for the MCP server. Flat `recall` still works lexically. |
| A burst of 400s from `POST /api/v1/webhooks` | Look for `Refusing webhook registration: target host failed egress vetting`, and check the API host's resolver first (section 7). |

## Change log

Newest first. The 2026-11-04 entry describes this revision. The older
entries are rebuilt from `git log --follow docs/deploy.md`, grouped by the
change they belong to. Each group gives example commits, and where commits
reached `main` through a merge, the PR is given as "landed via #N".

- **2026-11-04, this revision** (PR #764): rewrote the runbook for an
  operator new to the project, checked against `main` at 5fcd75087. The
  per-PR changelog structure is replaced by current-behaviour sections,
  conditional upgrade notes and a legacy appendix. Procedures, census
  queries, lock plans and rollback orders are carried over.
  - **Added:**
    - a process and login inventory (section 1);
    - a from-scratch production install (section 2);
    - a configuration reference per binary (section 3);
    - agent identity, the attestor login and role-attached agents (161, 166,
      179, 180);
    - team groups (164, 165), `delete-frames`, `retire-link`, the client and
      DCR verbs, and an operator CLI index;
    - upgrade notes for migrations 141–194;
    - an undo-script index naming `149-`, `166-`, `169-`, `180-` and
      `194-undo.sql`, the case-fold pair, and the two legacy pre-migrate
      runbooks;
    - a troubleshooting table;
    - per scheduled job: the database variables it needs (`DATABASE_URL`
      and `MAINTENANCE_DATABASE_URL`), `embed_backfill`'s `OPENAI_API_KEY` /
      `--allow-mock`, and which jobs take an advisory lock;
    - the five operator verbs that need a superuser DSN, including
      `hide-evidence --apply`;
    - that `epigraph-migrate`'s fallback WARN shows only when `RUST_LOG`
      enables `warn`, the values each on/off switch accepts, and the readers of
      `EPIGRAPH_API`, `EPIGRAPH_API_URL` and `EPIGRAPH_TOKEN`.
  - **Corrected:**
    - the anonymous surface is 25 paths, not 13;
    - checkouts stamp five session settings, not three;
    - the API holds no job pool or maintenance pool;
    - the job statement timeout applies to `drain_jobs`;
    - the count of scripts with a hardcoded DSN ("twelve") is replaced by
      a grep that lists them;
    - the migrate marker example is head 194, and the gap list is complete;
    - reclassification is possible through `restrict-claims`;
    - 175's "only epigraph-api applies migrations" is restated for
      `epigraph-migrate`;
    - the cross-worktree rebuild no longer mixes `--bin` with whole-package
      builds.
  - **Removed:** host paths, unit and container names, and internal ruling,
    plan and backlog labels, from the body. The old section titles, some of
    which carry such labels, are quoted below only so readers can trace where
    each section went. Strings the code emits, the refusal codes, and
    the md5 and world-group schema constants are kept verbatim.
  - **Moved:** the 2026-05-05 reconcile, the pre-074 ordering, the 084
    ownership retirement and the `agent_id` precondition now sit in section 13
    as conditional procedures. The registration-only webhook check described
    with the router inversion (superseded by the egress guard) now lives only
    in this log.
  - **Where earlier sections went:**
    - "Database migrations" → section 4;
    - "Cross-worktree binary caching" → section 4, "Stale binaries from a
      shared target directory";
    - "If the reconcile goes wrong" and "Why the reconcile is needed" →
      section 13;
    - "PR-02" §1 (`bootstrap_clients`) and §2 (`EPIGRAPH_ENV`) → section 8;
    - "PR-03" §0 → section 13;
    - "PR-03" §1–§1e, the metrics listener, `EPIGRAPH_RESOURCE_METADATA_URL`,
      `EPIGRAPH_AGENT_ID` and `EPIGRAPH_REQUIRE_SIGNATURES` → section 7;
    - "PR-04" §1 and §1b → section 6;
    - §1c-bis (`MAINTENANCE_DATABASE_URL`) and §1c-ter (roles) → sections 1,
      2 and 5;
    - §1d (group deletion), §2 (no-transaction) and §3 (062 locks) →
      section 4;
    - §4 and "Deploy ordering for 074/075/076" → sections 4 and 13;
    - "`tenancy/fix-security-track`" §1a–§1d → section 7;
    - "Webhook egress guard" → section 7;
    - "Batch OA1" → section 8;
    - "Refresh scope (migration 140)" and "Refresh-grant hardening (migration
      174)" → section 8;
    - the operator binding, custodian, lineage, restrict-claims and
      `backfill_evidence_type` sections → section 9, with headings kept;
    - the elevation sections (124–132) → section 10, with headings kept.
- 2026-11-03 0614f36e3 (landed via #761): a `recompute_claim_belief
  --snapshot` wave file, with compare-and-swap restore.
- 2026-11-01..02 b90e5deef, 15f14dafd, eab65f5ac, 4c2618716, 21a358ce0
  (landed via #750):
  - OAuth client approval becomes a maintenance act (migration 188);
  - the `unmark_duplicate` CLI is named wherever an un-mark is refused;
  - a custodial supersede records a cascade deferral;
  - `epigraph_app` LOGIN is allowed once armed, and no migration may grant
    LOGIN.
- 2026-10-27 5e9c77085, c46a95add (landed via #727): migration 185's
  pre-deploy body check, and its undo placed before 153's.
- 2026-10-26 3ba0411a6, 216e07ff3, ed4c3b7c9, a0e231c74, d7320e7e5 (landed
  via #720): refresh-grant hardening (migration 174):
  - confidential clients authenticate on refresh;
  - a chain is bound to its connector app;
  - `invalid_scope` for stripped scopes;
  - the consented scopes are stored.
- 2026-10-23 61b9fecb2 (landed via #680): rewrote the migration-140 census
  and stated the revoke window.
- 2026-10-20 b24e0a21d, b6feed797, 1e0917810, 20d514f0d, 6c16320a4 (landed
  via #640): documented the `backfill_evidence_type` run, and that
  `decompose_claims --as-agent` needs no maintenance DSN.
- 2026-10-13 fe0c51a17 (#598), 7eaf6d526, 513195914 (landed via #603):
  documented `epigraph-operator restrict-claims`: its guards, audit,
  reversal, evidence-endpoint edges and table classification.
- 2026-10-12 ed7bdfcdc (landed via #590): `embed_backfill` also fills
  `workflows.goal_embedding`.
- 2026-10-12 0e643a406, b682dfbf1 (landed via #569): a lineage stays in its
  owner group (migration 153), with the census and the world-group check
  before arming.
- 2026-10-10 f5120fa69, 1d0618625, 47a8aa63a (landed via #560):
  `POST /api/v1/claims/batch` persists its claims, and the `group_id` advice
  for public items.
- 2026-10-09 4dfc8ee49 (landed via #554): the system-agent registry and its
  deploy order.
- 2026-10-01..05 (landed via #539; 44 commits, for example 1324a9751,
  c49a62563, ebf6ddfab, 17bf228dc, fb670a27b, d550e92b6, 94db1eabe,
  45f2598c5, 05d42233f, 482cedf81, 46623d7f0, 718fa0d7a, f9afcd02a,
  13a00e288, 3b246d31c, 3387413f4, ee84c4c7e):
  - the custodian role (123) and its undo;
  - request units refuse a privileged DSN on an armed database;
  - passkeys (124), elevation tickets and sessions (125), and the elevated
    viewer;
  - the elevated read arms (126) and the elevated-access log (127);
  - the admin-scope switch (128/129), read-only elevated tokens, and the
    admin-scope chokepoint;
  - MCP `sudo`/`unsudo`;
  - pending and confirmed admin acts (130/131), and the offline confirmation
    verifier;
  - opening elevation (132), and the stack's deploy, undo and arming order;
  - refresh scope (140).
- 2026-09-30..10-01 (landed via #525; 13 commits, for example c4c7570e3,
  bd49ccb55, 17309e6bb, 5381ec9dc, bf03682c8, 518e6f556):
  - the operator binding (migration 122) deploy order;
  - the explicit `--legacy-owner` decision;
  - `register-human-operator --client`;
  - the rollback of 122's functions.
- 2026-09-29 d26cdaa8c (landed via #524): `ADM02` on the MCP server-stamp
  borrow without a live client grant.
- 2026-09-28 (landed via #523; 8 commits, for example 4f322b0d1, 37dbdee98,
  42bf03de8, f973ec339, 6d47ad3dd):
  - the maintenance DSN becomes timer-and-CLI only;
  - `EPIGRAPH_DISABLE_JOBS` dropped;
  - own-claim authority for supersede and dedup, and the audited
    `grant-client-scope` / `revoke-client-scope`.
- 2026-09-26 20c7013de, 737d2242b, 6676234c5 (landed via #510): the webhook
  egress guard:
  - names are resolved, and every delivery is re-vetted and pinned;
  - it superseded the registration-only check, which judged IP literals and
    RFC 6761 loopback names at registration only, accepted any other name
    unresolved, and grandfathered stored rows.
- 2026-09-24..25 7bf77cfa0, a2795348f (landed via #505): the MCP maintenance
  tools gated on `claims:admin` and a maintenance DSN. Later replaced by the
  MOVED answer.
- 2026-09-24 c7064b090, fc515c3dd, 054fbbd01, b0b327387 (landed via #500):
  - the `epigraph-migrate` head report;
  - the db-ahead refusal and its opt-out;
  - the migration lock held across the checks.
- 2026-08-26..09-19 (landed via #485; 14 commits, for example 4f324088a,
  642909771, 8c70e5aff, 1e310bce3, 68b8a8b12, 9cf5389c3, f41d87303,
  3de44d566, 38f180aff, 40969da54, 80bae0a31, 61b2d7c40, 8c2220b1c): the
  multi-user tenancy rollout:
  - the group tables;
  - the router inversion to an anonymous allowlist;
  - tenancy columns and `ScopedPool`;
  - redaction removed;
  - a maintenance DSN for background writers;
  - tenancy required (074–076);
  - row-level security (077–079);
  - privatization plans;
  - ownership retired (084);
  - the security-track behaviour changes.
- 2026-05-28 71e92f52e (#204): the cross-worktree binary caching foot-gun and
  its pre-flight check.
- 2026-05-05 bdcf2048a, 39d1fd0a5, f9b05de97 (#80): the one-shot
  `_sqlx_migrations` reconcile runbook, the reconcile moved to `ops/`, and the
  migration immutability warning.

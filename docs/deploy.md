# Deploy runbook

## Database migrations

Applied by the `epigraph-migrate` binary, run explicitly — as an
`ExecStartPre=` on `epigraph-api.service` or by hand — **before** the API
starts. The API binary does *not* migrate at boot unless
`EPIGRAPH_MIGRATE_ON_BOOT=1` (also accepts `true`/`yes`, case-insensitively and
ignoring surrounding whitespace) is set in its environment; migrations
074/075/084 are designed to `RAISE` when their tenancy preconditions do not
hold, and the server call site `.expect()`s, so an unattended boot-time apply
turns a precondition failure into a crash loop. Any other value — including
`0`, `false` and the empty string — skips.

The first deploy after 2026-05-05 also requires a one-shot reconcile of
`_sqlx_migrations`:

1. `pg_dump -Fc $DATABASE_URL > epigraph_pre_reconcile_$(date -I).dump`
2. `psql $DATABASE_URL -f ops/reconcile_2026_05_05.sql`
3. `cargo run -p epigraph-api --bin epigraph-migrate`  (applies 015–026)
4. Restart `epigraph-api.service`.

Subsequent deploys: run `cargo run -p epigraph-api --bin epigraph-migrate`
(or let `ExecStartPre=` do it), then restart `epigraph-api.service`.

### Cross-worktree binary caching (foot-gun)

`/home/jeremy/.cargo-target` is the shared cargo target across every worktree
on the deploy host. `sqlx::migrate!("../../migrations")` is a proc-macro that
embeds the migration file list **at compile time**, resolved relative to the
crate being compiled. If a different worktree previously built `server` or
`epigraph-mcp-full` at an older revision, the linker can reuse the cached
artifact and you end up installing a binary whose embedded migration list
predates the worktree you think you're building from.

Symptoms on deploy — watch the `epigraph-migrate` run, not the server; since
the API stopped migrating at boot it emits `EPIGRAPH_MIGRATE_ON_BOOT unset —
skipping migrations` and says nothing at all about migration state:

* `epigraph-migrate` exits 0 and applies nothing.
* `_sqlx_migrations` is missing the migration version your branch added.
* `information_schema.columns` confirms the new column doesn't exist.
* Health check passes (the binary doesn't crash — it just doesn't know about
  the new migration).

If you observe that pattern, do:

```bash
cd /home/jeremy/<your-deploy-worktree>
cargo clean -p epigraph-api -p epigraph-db
CARGO_INCREMENTAL=0 cargo build --release \
    -p epigraph-api -p epigraph-mcp -p epigraph-cli --bin recompute_claim_belief
sudo -n systemctl stop epigraph-mcp-http epigraph-api
sudo -n install -m 0755 /home/jeremy/.cargo-target/release/server /usr/local/bin/epigraph-api
sudo -n install -m 0755 /home/jeremy/.cargo-target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp
sudo -n install -m 0755 /home/jeremy/.cargo-target/release/recompute_claim_belief /usr/local/bin/epigraph-recompute-belief
sudo -n systemctl start epigraph-api && sleep 4 && sudo -n systemctl start epigraph-mcp-http
docker exec epigraph-postgres psql -U epigraph -d epigraph -c \
    "SELECT version FROM _sqlx_migrations ORDER BY version DESC LIMIT 5;"
```

The `cargo clean -p epigraph-api -p epigraph-db` step is what evicts the
stale cached artifact. The two crates are the ones that actually call
`sqlx::migrate!()` (and re-export it); other crates that depend on them
get rebuilt as a side effect.

Pre-deploy verification (do this BEFORE `systemctl stop`, while the old
binary is still serving):

```bash
strings /home/jeremy/.cargo-target/release/server \
    | grep -E '<expected_new_migration_filename>' || \
        echo "STOP: new migration not embedded — cargo clean + rebuild before deploy"
```

`strings` finds the migration filename as a string literal in the binary's
sqlx metadata. If grep is silent, the build is stale; do not install.

### If the reconcile goes wrong

If a checksum mismatch surfaces on the next `epigraph-migrate` run (or at API
startup), restore the pre-reconcile dump before retrying:

1. `systemctl stop epigraph-api`
2. `pg_restore --clean --if-exists -d "$DATABASE_URL" epigraph_pre_reconcile_*.dump`
3. Investigate the diff between `sha384sum migrations/NNN_*.sql` and the values
   recorded in `ops/reconcile_2026_05_05.sql` before retrying step 2 of the
   runbook above.
4. `systemctl start epigraph-api` only after the tracking table is consistent.

### Why the reconcile is needed

Prior to 2026-05-05, prod's `_sqlx_migrations` table was tracking the
internal-repo migration numbering (rows 1–98, 100–106). The public repo's
migration files use a different numbering (001–026). Running
`sqlx migrate run --source ./migrations` against the public repo would see
"no public migrations applied" and try to re-run `001_initial_schema.sql`
against a populated DB — which fails.

`ops/reconcile_2026_05_05.sql` truncates `_sqlx_migrations` and
re-inserts rows 1–26 with the sha384 checksums of the public-repo files,
so subsequent calls to `sqlx::migrate!()` (or the `epigraph-migrate`
binary) see a clean tracking state and only apply genuinely-new migrations
(027+) going forward.

The reconcile lives outside `migrations/` (under `ops/`) so that
`sqlx::migrate!("../../migrations")` does not pick it up. sqlx 0.7's
filename parser splits on `_` with `splitn(2, '_')` and treats every
file in the migrations directory as a candidate; a leading-underscore
name like `_reconcile.sql` produces an empty version string and is a
hard parse error, not a skip. Keeping the file under `ops/` avoids
that entirely — the embedded migrator never sees it, and it is run
by hand exactly once.

## PR-02 (multi-user tenancy) — required rollout steps

PR-02 changes two things that a plain `git pull && restart` does **not** carry
over. Both fail closed, so the symptom is 403s and a refused boot, not silent
degradation — but both need an operator action.

### 1. Re-run `bootstrap_clients` to widen the canonical scopes

`POST /api/v1/groups` now requires `groups:write`, and
`POST`/`DELETE /api/v1/groups/:id/members` now require `groups:admin`. Both are
new entries in `epigraph_core::canonical_scopes`, and `oauth_clients.granted_scopes`
is persisted per client at registration — so an instance bootstrapped before this
release keeps its old arrays and 403s on all three routes, `epigraph-admin`
included. No migration can fix this: the rows are data, not schema.

```bash
cargo run -p epigraph-cli --bin bootstrap_clients -- \
  --legal-entity-name "<same as before>" --legal-contact-email "<same as before>"
```

It is convergent as of PR-02: an existing canonical client has its
`allowed_scopes`/`granted_scopes` rewritten to `scopes_for(<name>)` and is
reported `EXISTS: … scopes=RECONCILED`. Non-canonical clients are untouched.
Externally provisioned humans get theirs from `default_scopes` in
`providers.toml`; if yours still says `groups:manage` (a scope that never
existed), change it to `groups:write` — see `providers.toml.example`.

### 2. Set `EPIGRAPH_ENV`

`EPIGRAPH_ENV` is introduced by PR-02 and is therefore **unset everywhere
today**, so **unset is treated as production**. With a provider whose
`allowed_emails` and `allowed_domains` are both empty, `auto_provision = true`,
and no `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`, the server now **refuses to boot**.

That is the intended discovery mechanism: PR-02 also makes
`provision_external_user_client` and the refresh-token gate deny by default, so
an instance that booted in that posture would 403 every already-provisioned
Google identity on its next refresh, with nothing in the logs naming the cause.

Choose one before deploying:

* populate `allowed_emails` / `allowed_domains` in `providers.toml` (recommended);
* or set `EPIGRAPH_ALLOW_ALL_IDENTITIES=true` to declare that any identity the
  IdP authenticates may have an account here (the pre-PR-02 behaviour, now said
  out loud);
* dev/CI only: set `EPIGRAPH_ENV` to `development` / `dev` / `test` / `testing` /
  `local` / `ci` to downgrade the abort to a warning.

Existing external clients are re-checked against the allowlist on **refresh**
too, so removing an address stops that client renewing.

## PR-03 (router inversion) — BREAKING, and deploy-coordinated

PR-03 inverts the HTTP router from an anonymous-by-default surface to an
allowlist. This is the largest behavioural change in the tenancy series and
**two of its five steps are operator actions, not code**. Read all of it before
deploying.

### 0. Precondition — do not deploy this until it reads 1.0

```sql
SELECT count(*) FILTER (WHERE agent_id IS NOT NULL)::float
       / NULLIF(count(*), 0)
FROM oauth_clients WHERE status = 'active';
```

Every active OAuth client must have a non-null `agent_id`. PR-02 populates it
for newly issued clients (`ensure_for_client`), but rows that predate PR-02 may
still be null, and `oauth_clients.agent_id` is what the JWT's `agent_id` claim
is copied from.

**A null `agent_id` breaks writes in THIS release, not in a later one.**
`POST /api/v1/claims` and `POST /claims` refuse such a token with 401
`invalid_token` as of PR-03: the handler used to fall back to a `[0u8; 32]`
author key, and that fallback is deleted. Read a "PR-07" in the paragraph below
as "and then it gets worse", not as "so this is not yet my problem" — deploying
at less than 1.0 coverage is an immediate write outage on the primary write
path.

The read paths follow when PR-07 attaches `ViewerExtractor`; a null `agent_id`
is also already the reason a client cannot administer a group.

If this query returns anything below 1.0, back-fill first. Deploying without
measuring it is a self-inflicted outage.

### 1. BREAKING — 105 previously anonymous routes now require a Bearer token

Everything that returns claim content, claim-derived structure, ACLs,
embeddings or aggregates moved from the `public` router to `protected`. The
notable ones: `GET /claims`, `GET /claims/:id`, `GET /api/v1/claims`,
`GET /agents`, `GET /lineage/:claim_id`, `POST /api/v1/search/semantic`,
**`GET /api/v1/query/rag`**, **`GET /api/v1/search/evidence`**,
`GET /api/v1/admin/stats`, `GET /api/v1/themes/:id/embeddings`,
`GET /api/v1/ownership/:node_id`, `GET /api/v1/events`, all `/api/v1/graph/*`,
all `/frames/*`, all `/belief*`, and every `/api/v1/perspectives*`,
`/communities*`, `/contexts*`, `/workflows*`, `/methods*` and `/tasks*` read.

**The RAG and evidence-search public-access guarantees are revoked.** Announce
this; anything scraping those two endpoints anonymously stops working the
moment this deploys.

#### One route needs more than a token

| Route | Was | Now | Failure if you get it wrong |
|---|---|---|---|
| `GET /api/v1/claims/needing-embeddings` | anonymous | requires the **`claims:admin`** scope | **403**, not 401 — a token with `claims:read` is refused |

Everything else in the list above needs only a valid Bearer token with the
scope it already needed. This one is singled out because it is a maintenance
worklist: it enumerates claim ids *and* raw content corpus-wide, ordered by an
internal invariant (which rows the embedder has not reached), which is an
operator's backfill queue rather than a query a reader would ask. If you run a
backfill job against this endpoint, widen its token's scopes to include
`claims:admin` in the same window as this deploy.

The complete anonymous surface afterwards is 13 paths:

| Path | Why |
|---|---|
| `GET /health` | stateless; load balancers cannot mint a token |
| `GET /api/v1/openapi.json` | a client cannot read the schema that tells it how to authenticate if reading the schema requires authentication |
| the 11 `/oauth/*` and `/.well-known/*` endpoints | discovery and token issuance must precede authentication |

Enforced by `crates/epigraph-api/tests/public_router_allowlist.rs`, which fails
the build if a fourteenth appears.

Refused requests carry an RFC 6750 challenge:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource", error="invalid_token"
```

### 2. REQUIRED ACTION — `/metrics` moved to a separate internal listener

`/metrics` is **no longer on the application port at all**. It is served by a
second listener bound from `EPIGRAPH_METRICS_ADDR`, default `127.0.0.1:9090`.

**Update the Prometheus scrape target in the same window as this deploy**, or
monitoring goes dark at exactly the moment 105 routes start returning 401 —
which is the worst possible time to be blind.

```ini
# epigraph-api.service
Environment=EPIGRAPH_METRICS_ADDR=127.0.0.1:9090
```

Binding to loopback means a scraper must be on the host or in the same network
namespace; widen it deliberately (e.g. `0.0.0.0:9090` inside a private network)
if yours is not. A bind failure on this listener logs an error and lets the API
keep serving — losing metrics must not take the API down — so check the log line
`Internal metrics listener started` rather than assuming.

**If you run two instances side by side with `EPIGRAPH_PORT`, set
`EPIGRAPH_METRICS_ADDR` on the second one too.** The metrics port has no
equivalent of `EPIGRAPH_PORT`'s per-instance default, so the second instance
tries to bind the same `127.0.0.1:9090`, fails, logs
`Failed to bind the internal metrics listener`, and serves the API with no
metrics — which is easy to miss precisely because the API itself is fine.

The listener is spawned before the TLS branch, so it works under both
`EPIGRAPH_TLS_CERT`/`EPIGRAPH_TLS_KEY` and plain HTTP.

### 3. New: `EPIGRAPH_RESOURCE_METADATA_URL`, and the process refuses to boot on a bad value

Defaults to `${EPIGRAPH_PUBLIC_BASE_URL}/.well-known/oauth-protected-resource`,
which is the document this deployment already serves, so most deployments need
nothing. Set it only when the metadata document is fronted by a different host.

A value that cannot be embedded in an HTTP header (control characters,
non-ASCII, an embedded newline) makes the process `exit(1)` at boot rather than
silently dropping the challenge from every 401. Same fail-fast shape as
`epigraph-mcp`'s `--resource-metadata-url`.

### 4. New: `EPIGRAPH_AGENT_ID` for the in-repo Python helpers

`scripts/_api_client.py::mint_bearer_token` now defaults its `agent_id` claim
from `EPIGRAPH_AGENT_ID`. It always *emitted* the claim; it never had a value to
put in it, so it was always null — the exact token shape the API refuses.

There is deliberately no default: `agent_id` names the principal whose group
membership decides what the token can read, and defaulting it would hand every
script one identity's view of the corpus by accident.

`scripts/_api_client.py::EpiGraphClient` **exits at construction** when neither
an explicit `agent_id=` nor `EPIGRAPH_AGENT_ID` is available, rather than
minting a principal-less token and dying on an opaque 401 at the first request.
That covers `anchor_papers_to_themes.py`, `classify_paper_document_type.py`,
`update_theme_workflow_steps.py` and `lib/nli_stance.py`. The lower-level
`mint_bearer_token` is deliberately *not* guarded — a caller exercising the 401
path is a legitimate use of a raw token helper.

`scripts/reconcile_backlog_labels.py` (the daily reconciler named in
`CLAUDE.md`), `scripts/cleanup_backlog_labels.py` and
`scripts/maintain_themes.py` now **exit** when `EPIGRAPH_TOKEN` is unset. They
previously degraded to no `Authorization` header, which used to mean "read-only
mode" and now means "401 on the first request". The `dekg` CLI likewise
requires `--token` / `EPIGRAPH_TOKEN`.

### 5. `EPIGRAPH_REQUIRE_SIGNATURES` — unchanged name, narrower meaning

The env var is unchanged. The Rust config field behind it was renamed
`ApiConfig::require_packet_signatures`, and it now gates **only** payload-level
Ed25519 packet signatures on `POST /api/v1/submit/packet`.

The request-signing middleware (`middleware::require_signature`, the
`X-Signature` / `X-Public-Key` / `X-Timestamp` headers) is **deleted**. It was
unreachable through either `create_router`, so no live behaviour changes — but
it was the only writer of `SecurityEvent::signature_verification` and
`auth_attempt` rows into `security_events`. Any dashboard reading those two
event types will read empty from now on.

The `require_signatures` field in the `GET /api/v1/admin/stats` response body is
**unchanged on the wire** (pinned by `#[serde(rename)]`), so nothing that parses
that response needs updating.

### Known gap, filed rather than hidden

`GET /api/v1/openapi.json` will under-report authentication. utoipa's
`security(...)` annotations are per-operation and the 105 moved read operations
carry none, so the schema advertises them as requiring nothing. The document
itself is still anonymous, which is correct. Annotating them is a follow-up.

---

## PR-04 (tenancy columns, ScopedPool) — new env var, and the repo's first `-- no-transaction` migrations

Migrations `062`–`067`. Nothing in PR-04 changes an HTTP response: it widens 25
tables with two columns that need no table rewrite, creates the world and seed
groups, adds **five** partial indexes — four built `CONCURRENTLY` in `063`–`066`
plus `idx_agents_default_group`, an ordinary `CREATE INDEX` inside `062` — and
creates the five session/bypass SQL functions the RLS policies will read from
PR-17 onward. RLS is **not** enabled by this PR.

### 1. New: `EPIGRAPH_SESSION_GUC_MODE`

| Value | Meaning |
|---|---|
| *unset* (default), or anything other than `transaction` | `session` — the fast path |
| `transaction` | every scoped read runs inside a transaction |

Tenancy context reaches the database as three session GUCs —
`epigraph.group_ids`, `epigraph.writable_group_ids`, `epigraph.principal_id` —
stamped once at connection checkout by `ScopedPool::acquire_as`, in one extra
statement and no transaction.

**Behind a transaction-mode pooler that mechanism silently does not work.** A
`set_config(..., is_local = false)` on one statement is not visible to the next,
so from PR-17 on every RLS policy would collapse to `visibility = 'public'` and
`epigraph_principal_id()` would be NULL. That is a *fail-closed* failure: no
errors, no 500s, just permanently empty result sets that look like data loss.

**The boot probe.** `bin/server.rs` therefore runs
`ScopedPool::probe_session_gucs()` immediately after the pool connects, before
anything else. It:

1. acquires a connection and stamps a sentinel UUID into all three tenancy GUCs
   — through the *same* `set_config` triple the request path uses, not a scratch
   GUC;
2. reads all three back **as a second statement on the same handle** — they must
   still carry the sentinel;
3. releases the connection, acquires again, and asserts all three are now empty
   — which proves the `after_release` scrub is running, because step 1 is what
   put values there.

Step 3 is written that way on purpose. An earlier draft stamped a scratch
`epigraph.probe` GUC in step 1 and then checked the *tenancy* GUCs in step 3;
since nothing had ever set those, they read empty whether or not the scrub was
installed, and the check could not fail. Stamping the real three is what makes
the boot control non-vacuous.

If step 2 fails the process **refuses to serve**, with:

```
FATAL: session GUCs do not survive between statements on one pooled connection.
This deployment is behind a transaction-mode pooler. Set
EPIGRAPH_SESSION_GUC_MODE=transaction to switch every read to begin_as, or
point DATABASE_URL at a session-mode endpoint.
```

**When to set `transaction`.** pgbouncer with `pool_mode = transaction`, or RDS
Proxy without session pinning, in front of `DATABASE_URL`. Setting it skips the
probe (a `WARN` is logged saying so) and every scoped read runs inside
`ScopedPool::begin_as`. **Measured cost: two extra round trips per read**
(`BEGIN` and `COMMIT`). Prefer pointing `DATABASE_URL` at a session-mode
endpoint if one exists; the fallback is supported, not recommended.

A typo (`EPIGRAPH_SESSION_GUC_MODE=tranaction`) selects `session` and the probe
then proves whether that was right. Failing over to the slow mode on a typo
would hide the misconfiguration behind a permanent latency cost nobody
attributes.

**Not exercised in this repo's CI:** the *refusal* half. There is no
pgbouncer-in-transaction-mode fixture available here, so the pooler's behaviour
is reasoned about but not measured. Verify it against staging before relying on
it in production. What *is* covered: the verdict itself is a pure function
(`pool.rs::probe_verdict`) with unit tests pinning that a lost stamp is
diagnosed as a pooler and names `EPIGRAPH_SESSION_GUC_MODE=transaction`, that a
carried-over stamp is diagnosed as a dead scrub, and that an all-empty
observation is reported as the former rather than the latter.

### 1b. The release scrub costs one extra round trip on **every** connection

`after_release` runs the `set_config` triple on every release from the API pool,
including the ~100 % of requests that stamp nothing until PR-06 lands. Measured
on this loopback cluster (3000 sequential statements through `psql`):
`SELECT 1` 0.15–0.19 s, the scrub triple 0.19–0.20 s — i.e. **≈55 µs per
release**, of which the triple itself is ~13 µs and the rest is the round trip.
Over a real network hop the round trip dominates, so budget one extra p50 RTT
per released connection. It is not made conditional: a scrub that only runs when
someone remembered to set a flag is not a security control.

### 1c. Obligations this PR hands to PR-15 and PR-16

* **PR-15** — `ScopedPool::unscoped_for_maintenance` currently draws from the
  *application* pool. Harmless until RLS is enabled, unsound after: a bypass
  viewer emits no predicate but the policy still filters, so it reads zero rows.
  Repoint it at `MAINTENANCE_DATABASE_URL` **before PR-17**.
* **PR-15** — the background `job_pool` (`bin/server.rs`) is a second pool on the
  same database built with bare `PgPoolOptions`, so it has **no scrub**. Route it
  through `ScopedPool` (keeping its `after_connect` `statement_timeout` hook)
  before anything can stamp a job connection.
* **PR-16** — after the backfill, `REINDEX INDEX CONCURRENTLY
  idx_claims_world_owned;`. That index is corpus-sized when `066` builds it
  (`owner_group_id` defaults to the world group, so the partial predicate
  matches every row) and the backfill empties it without reclaiming the pages.

### 1d. Deleting a group is a maintenance-window operation

Migration `062` adds 25 `owner_group_id → groups(id)` foreign keys, all
`ON DELETE RESTRICT`, and **none of them is indexed**. The partial indexes in
`063`–`065` lead on `owner_group_id` but predicate on `visibility`, and the RI
check for a RESTRICT parent delete is an unqualified `owner_group_id = $1`
lookup, so none of them can serve it.

`DELETE FROM groups` is blocked outright by migration `060`'s trigger. Its
documented escape hatch —

```sql
SET LOCAL epigraph.allow_group_delete = 'yes';
```

— therefore costs **25 sequential scans, one of them on `claims`**, inside the
deleting transaction with row locks held throughout. Take it in a maintenance
window. An online deprovisioning path must first add plain `(owner_group_id)`
indexes on the tables it touches.

### 2. Migrations 063–066 are the repo's first `-- no-transaction` migrations

They run `CREATE INDEX CONCURRENTLY`. Consequences an operator must know:

* **They hold no `ACCESS EXCLUSIVE` lock** — that is why they are concurrent.
  Writes to `claims`, `evidence` and `edges` continue throughout.
* **sqlx cannot roll them back.** There is no enclosing transaction, and the
  `_sqlx_migrations` bookkeeping is not atomic with the DDL. A failure leaves an
  **INVALID index** behind and no migration row.
* **One statement per file, deliberately.** sqlx sends a whole migration file as
  one simple query; PostgreSQL wraps a multi-statement simple query in an
  implicit transaction block; `CREATE INDEX CONCURRENTLY` inside one fails with
  SQLSTATE 25001. Do not merge 063–066 back into one file — a test fails if you
  do. Full explanation in `migrations/README.md`.

**Detection:**

```sql
SELECT c.relname FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
 WHERE NOT i.indisvalid;
```

**Recovery** — drop the leftover, then re-run the migration (`IF NOT EXISTS`
means re-running is safe, but it will *not* rebuild an index that already exists
in an invalid state):

```sql
DROP INDEX CONCURRENTLY <name>;
```

**Window.** `CREATE INDEX CONCURRENTLY` waits for every transaction older than
itself in the same database. The background job pool's `statement_timeout`
defaults to **45 minutes** (`EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS`), so one long
clustering job can stall these migrations for that long. `SET LOCAL
lock_timeout` in a `-- no-transaction` file is *legal* but useless — outside a
transaction block it is a silent no-op with a `WARNING`, and it would not bound
this wait even if it took effect. Run them during a quiet window, or check
first:

```sql
SELECT max(now() - xact_start) FROM pg_stat_activity
 WHERE state <> 'idle' AND datname = current_database();
```

### 3. Migration 062 rewrites no table, but it locks 25 of them

`ADD COLUMN ... NOT NULL DEFAULT ...` is metadata-only on PostgreSQL 11+, so
widening `claims` does not rewrite the table. Measured against a 5,000,000-row /
1028 MB clone of `claims` on PostgreSQL 16.2: the two-column `ADD COLUMN` took
**3.5 ms** and the `NOT VALID` CHECK **3.6 ms**, with `pg_relation_size`
identical before and after. Every constraint it adds is `NOT VALID`: new rows
are checked, existing rows are not scanned. Validation is migration 075's job,
after the backfill.

**That is duration, not locks.** Each `ALTER TABLE` still takes `ACCESS
EXCLUSIVE`, and sqlx runs the whole file in one transaction, so a lock is held
until `COMMIT` — by the last table this migration holds `ACCESS EXCLUSIVE` on
**25 tables simultaneously**, `claims` among them. `SET LOCAL lock_timeout =
'3s'` bounds how long each `ALTER TABLE` *waits*, not how long the transaction
*holds*; and while one is queued behind a long-running reader it blocks every
new query on that table for up to 3 s. Worst case on a busy cluster is a series
of rolling 3-second stalls ending in a rollback and a restart from table 1. Run
it in a quiet window, expect to retry, and pre-check with the `pg_stat_activity`
query above.

The `DEFAULT 'public'` and `DEFAULT <world group>` are **transition artifacts**
and are dropped by migration 074. Do not build anything that relies on them.

If 062 aborts on its `lock_timeout`, sqlx records no row and the fix is simply
to re-run it: the whole file is `IF NOT EXISTS` / catalog-guarded and applies
cleanly a second time.

### 4. `epigraph-migrate` is still the supported migration path

Unchanged from PR-01. The api binary runs migrations only when
`EPIGRAPH_MIGRATE_ON_BOOT` is set; `ExecStartPre=` running `epigraph-migrate` is
the supported path, and it honours `-- no-transaction` (the flag is propagated
into the compile-time `migrate!()` literal).

# Deploy runbook

## Database migrations

Applied automatically by the API binary on startup. The first deploy after
2026-05-05 also requires a one-shot reconcile of `_sqlx_migrations`:

1. `pg_dump -Fc $DATABASE_URL > epigraph_pre_reconcile_$(date -I).dump`
2. `psql $DATABASE_URL -f ops/reconcile_2026_05_05.sql`
3. `cargo run -p epigraph-api --bin epigraph-migrate`  (applies 015–026)
4. Restart `epigraph-api.service`.

Subsequent deploys: just restart; `sqlx::migrate!()` runs at boot.

### Cross-worktree binary caching (foot-gun)

`/home/jeremy/.cargo-target` is the shared cargo target across every worktree
on the deploy host. `sqlx::migrate!("../../migrations")` is a proc-macro that
embeds the migration file list **at compile time**, resolved relative to the
crate being compiled. If a different worktree previously built `server` or
`epigraph-mcp-full` at an older revision, the linker can reuse the cached
artifact and you end up installing a binary whose embedded migration list
predates the worktree you think you're building from.

Symptoms on deploy:

* `systemctl restart epigraph-api` succeeds and reports `Migrations up to date`.
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

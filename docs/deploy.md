# Deploy runbook

## Database migrations

Applied automatically by the API binary on startup. The first deploy after
2026-05-05 also requires a one-shot reconcile of `_sqlx_migrations`:

1. `pg_dump -Fc $DATABASE_URL > epigraph_pre_reconcile_$(date -I).dump`
2. `psql $DATABASE_URL -f ops/reconcile_2026_05_05.sql`
3. `cargo run -p epigraph-api --bin epigraph-migrate`  (applies 015–026)
4. Restart `epigraph-api.service`.

Subsequent deploys: just restart; `sqlx::migrate!()` runs at boot.

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

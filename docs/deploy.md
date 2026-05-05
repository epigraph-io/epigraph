# Deploy runbook

## Database migrations

Applied automatically by the API binary on startup. The first deploy after
2026-05-05 also requires a one-shot reconcile of `_sqlx_migrations`:

1. `pg_dump -Fc $DATABASE_URL > epigraph_pre_reconcile_$(date -I).dump`
2. `psql $DATABASE_URL -f migrations/_reconcile_2026_05_05.sql`
3. `cargo run -p epigraph-api --bin epigraph-migrate`  (applies 015–026)
4. Restart `epigraph-api.service`.

Subsequent deploys: just restart; `sqlx::migrate!()` runs at boot.

### Why the reconcile is needed

Prior to 2026-05-05, prod's `_sqlx_migrations` table was tracking the
internal-repo migration numbering (rows 1–98, 100–106). The public repo's
migration files use a different numbering (001–026). Running
`sqlx migrate run --source ./migrations` against the public repo would see
"no public migrations applied" and try to re-run `001_initial_schema.sql`
against a populated DB — which fails.

`migrations/_reconcile_2026_05_05.sql` truncates `_sqlx_migrations` and
re-inserts rows 1–26 with the sha384 checksums of the public-repo files,
so subsequent calls to `sqlx::migrate!()` (or the `epigraph-migrate`
binary) see a clean tracking state and only apply genuinely-new migrations
(027+) going forward.

The leading underscore in the filename (`_reconcile_...`) is significant:
`sqlx::migrate!` only picks up files matching `NNN_NAME.sql`, so the
reconcile file is invisible to the embedded migrator and is run by hand
exactly once.

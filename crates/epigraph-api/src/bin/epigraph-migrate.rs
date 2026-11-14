//! Apply pending SQL migrations and exit. Suitable for ExecStartPre= in
//! systemd units, or for ops dry-runs (with sqlx-cli for plan visibility).
//!
//! The bin requires the `db` feature (see Cargo.toml `required-features`).
//! When `cargo clippy --workspace` runs without `db` activated, this body
//! compiles out and `main` becomes a no-op so the build still succeeds.

#[cfg(feature = "db")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    // MIGRATION_DATABASE_URL, falling back to DATABASE_URL with a WARN.
    //
    // The migrator needs DDL privilege on every tier-A table -- from PR-16 on
    // it drops column defaults and creates 23 triggers -- and that is a
    // strictly stronger role than either `epigraph_app` (which after migration
    // 074 cannot so much as `ALTER TABLE ... SET DEFAULT`) or
    // `epigraph_maintenance` (which holds SELECT/INSERT/UPDATE and no DDL at
    // all, per migration 070's grant block).
    //
    // The fallback is deliberate and is why this is a WARN and not a refusal:
    // every existing invoker -- `.github/workflows/ci.yml`, `docs/deploy.md`'s
    // `ExecStartPre=`, `README.md` -- sets only `DATABASE_URL`, and a hard
    // requirement here would turn a deploy into an outage on the first restart
    // after this ships. `ci.yml` is updated in the same PR to set both, so CI
    // exercises the new variable; the fallback exists for the operator who has
    // not split the credentials yet.
    //
    // The rule is `epigraph_api::migrate::select_migration_dsn`, shared with
    // the server's EPIGRAPH_MIGRATE_ON_BOOT path; a blank value is unset.
    let dsn = epigraph_api::migrate::migration_dsn_from_env().unwrap_or_else(|e| panic!("{e}"));
    if dsn.fell_back() {
        tracing::warn!("{}", epigraph_api::migrate::MIGRATION_DSN_FALLBACK_WARNING);
    }
    let var = dsn.var;
    tracing::info!(dsn_var = var, "resolved migration DSN");
    // Log the host but not credentials.
    let host_hint = dsn.url.split('@').nth(1).unwrap_or("<unknown>");
    tracing::info!(host = host_hint, "Connecting to PostgreSQL");
    // DDL privilege, so not a maintenance constructor: the pool is built by
    // `migrate::connect_migration_pool`, the one exempt construction site
    // (see its doc and `crates/epigraph-db/tests/no_unmaintained_dsn.rs`).
    let pool = epigraph_api::migrate::connect_migration_pool(&dsn)
        .await
        .unwrap_or_else(|e| panic!("connecting to the migration database ({var}) failed: {e}"));
    // Issue #492: a database AHEAD of this binary's embedded migration set is
    // refused unless the operator opts in, by flag or by env. Either spelling
    // suffices; both are named in the refusal text.
    let opts = epigraph_api::migrate::MigrateOptions {
        allow_db_ahead: std::env::args()
            .skip(1)
            .any(|a| a == epigraph_api::migrate::ALLOW_DB_AHEAD_FLAG)
            || epigraph_api::migrate::MigrateOptions::from_env().allow_db_ahead,
    };
    tracing::info!(
        binary_head = epigraph_api::migrate::embedded_migration_versions()
            .last()
            .copied(),
        allow_db_ahead = opts.allow_db_ahead,
        "Applying migrations"
    );
    let report = match epigraph_api::run_migrations(&pool, opts).await {
        Ok(r) => r,
        Err(e) => {
            // Nonzero exit and NO `migrations: ok` marker: ops scripts key on
            // that string, so it must never appear on a refusal.
            tracing::error!(error = %e, "migrations FAILED");
            eprintln!("migrations: FAILED: {e}");
            std::process::exit(1);
        }
    };
    // `run_migrations` returns `db_ahead` only when the opt-in was given (a
    // strict run is refused instead), but the claim below is about the opt-in,
    // so it is keyed on the opt-in rather than inferred from the report.
    if report.db_ahead && opts.allow_db_ahead {
        eprintln!(
            "WARNING: the database has applied migration version(s) {:?} that this binary \
             does not embed (database head {}, binary head {}); proceeding because the \
             rollback opt-in is set",
            report.ahead, report.db_head, report.binary_head
        );
    }
    // Backlog e30316ae: the kernel needs pgvector >= 0.8.0 and nothing checked
    // it. Checked after migrating (001 creates the extension on a fresh
    // database) and before the `migrations: ok` marker, so a refused run never
    // prints it. This binary only: the server does not refuse to boot on it.
    let pgvector = match epigraph_api::migrate::check_pgvector_version(&pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "pgvector version check FAILED");
            eprintln!("migrations: FAILED: migrations were applied, but {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(pgvector = %pgvector, "pgvector version ok");
    tracing::info!(
        db_head_before = report.db_head_before,
        db_head = report.db_head,
        binary_head = report.binary_head,
        applied = report.applied_this_run,
        db_ahead = report.db_ahead,
        "migrations: ok"
    );
    // Stdout marker for ops scripts: the line still STARTS with
    // `migrations: ok`, so an existing `grep 'migrations: ok'` keeps matching,
    // and it now carries both heads so the marker says what "ok" means.
    println!("migrations: ok {report}");
}

#[cfg(not(feature = "db"))]
fn main() {
    eprintln!("epigraph-migrate requires the `db` feature");
    std::process::exit(1);
}

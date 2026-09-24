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
    let (url, var) = match std::env::var("MIGRATION_DATABASE_URL") {
        Ok(u) => (u, "MIGRATION_DATABASE_URL"),
        Err(_) => {
            let u = std::env::var("DATABASE_URL")
                .expect("MIGRATION_DATABASE_URL or DATABASE_URL environment variable required");
            tracing::warn!(
                "MIGRATION_DATABASE_URL is unset; falling back to DATABASE_URL. Migrations \
                 need DDL privilege, which the application role must not have -- see \
                 docs/deploy.md."
            );
            (u, "DATABASE_URL")
        }
    };
    tracing::info!(dsn_var = var, "resolved migration DSN");
    // Log the host but not credentials.
    let host_hint = url.split('@').nth(1).unwrap_or("<unknown>");
    tracing::info!(host = host_hint, "Connecting to PostgreSQL");
    // MAINTENANCE-DSN-EXEMPT: the migrator needs DDL privilege, which is a
    // different and strictly stronger role than `epigraph_maintenance` — a
    // maintenance DSN here would be the WRONG credential, not a safer one.
    //
    // PR-16 wired `MIGRATION_DATABASE_URL` above, and the exemption STAYS.
    // `no_unmaintained_dsn.rs` is keyed on POOL CONSTRUCTION, not on which
    // environment variable supplies the URL — its own module doc says so at
    // length, with two measured reasons. Swapping the variable while keeping
    // `PgPool::connect` therefore changes nothing this lint can see, and
    // `the_exemption_set_is_exactly_what_was_reviewed` asserts an exempt file
    // STILL builds an unmaintained pool, so deleting the entry is what would
    // turn CI red. Removing it requires routing this binary through a
    // maintenance-style constructor, which the reason above argues against.
    // Pinned with this reason in `crates/epigraph-db/tests/no_unmaintained_dsn.rs`.
    let pool = epigraph_db::PgPool::connect(&url)
        .await
        .expect("PgPool::connect to DATABASE_URL failed");
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
    if report.db_ahead {
        eprintln!(
            "WARNING: database schema head {} is AHEAD of this binary's head {}; proceeding \
             because the rollback opt-in is set",
            report.db_head, report.binary_head
        );
    }
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

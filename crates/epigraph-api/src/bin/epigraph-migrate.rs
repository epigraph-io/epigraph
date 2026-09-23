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
    tracing::info!("Applying migrations");
    epigraph_api::run_migrations(&pool)
        .await
        .expect("sqlx::migrate failed — refusing to leave DB in a half-migrated state");
    tracing::info!("migrations: ok");
    println!("migrations: ok"); // keep stdout marker for ops scripts that grep for it
}

#[cfg(not(feature = "db"))]
fn main() {
    eprintln!("epigraph-migrate requires the `db` feature");
    std::process::exit(1);
}

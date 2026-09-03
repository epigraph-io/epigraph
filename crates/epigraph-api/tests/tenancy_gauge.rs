//! The `epigraph_tenancy_undeclared_writes` gauge — PR-12's export of the
//! instrument plan §9.2's week-11b gate reads.
//!
//! # Why this file exists
//!
//! Everything else in PR-12 was verified by executing it: the trigger arms
//! against a live database, the backfill binary end to end. The gauge was the
//! one deliverable whose only evidence was `cargo build`, and "it compiles" is
//! not evidence that a metric reaches a scrape.
//!
//! The gate before migration 074 (PR-16) turns migration 070 arm (a)'s warning
//! into a hard `23502` is that this series is **flat at zero for 24 hours
//! across every tier-A table**. A gauge that silently exports nothing would let
//! that gate read as satisfied while the counter climbed.
//!
//! This drives the sampler's exact composition — repo read → `Family`
//! `get_or_create` → `.set()` → registry encode — against real rows. What it
//! does NOT cover is the `tokio::spawn` + `interval` wrapper in
//! `bin/server.rs`, which has no logic beyond the loop.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::metrics::Metrics;
use epigraph_api::tenancy_gauge::TenancyGaugeSampler;
use prometheus_client::encoding::text::encode;
use sqlx::PgPool;

/// One sampler pass through THE PRODUCTION SAMPLER.
///
/// An earlier revision of this file re-implemented the loop body inline and
/// called it "byte-identical in composition". It was not a copy for long, and
/// worse, every test built a FRESH `Metrics`, so nothing here could observe the
/// one property that actually matters across passes: whether a series that
/// disappears from the query goes to zero or keeps its last value. The tests
/// below now share one sampler and one `Metrics` where that is the point.
async fn sample_once(sampler: &mut TenancyGaugeSampler, metrics: &Metrics, pool: &PgPool) {
    sampler
        .sample(pool, metrics)
        .await
        .expect("read undeclared writes");
}

fn scrape(metrics: &Metrics) -> String {
    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).expect("encode registry");
    buf
}

/// The labelled series lines only.
///
/// A registered `Family` always emits its `# HELP` / `# TYPE` header even when
/// it holds no series, so "does the scrape mention the metric name" cannot
/// distinguish "no undeclared writes" from "the sampler never ran". Counting
/// SERIES lines can.
fn series_lines(body: &str) -> Vec<&str> {
    body.lines()
        .filter(|l| l.starts_with("epigraph_tenancy_undeclared_writes{"))
        .collect()
}

/// An undeclared write reaches the scrape, labelled by table.
///
/// The claim is inserted through the REAL trigger — arm (a) is what increments
/// `tenancy_undeclared_writes` — rather than by writing the counter table
/// directly, so this also proves the two halves are connected.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_write_reaches_the_prometheus_scrape(pool: PgPool) {
    let metrics = Metrics::new();
    let mut sampler = TenancyGaugeSampler::new();

    // Before: the series does not exist, because no undeclared write has
    // happened. A gauge that reported zero here would be indistinguishable from
    // one that never samples.
    sample_once(&mut sampler, &metrics, &pool).await;
    assert!(
        series_lines(&scrape(&metrics)).is_empty(),
        "with no undeclared writes there must be no SERIES — the family's \
         HELP/TYPE header is always emitted, so only the labelled lines \
         distinguish this from a sampler that never ran"
    );

    // An undeclared INSERT — no tenancy columns named, exactly what an unpatched
    // production call site does. Migration 070 arm (a) counts it.
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES (gen_random_uuid(), 'undeclared', $1, 0.8, $2, true)",
    )
    .bind(vec![5u8; 32])
    .bind(agent)
    .execute(&pool)
    .await
    .expect("undeclared insert");

    sample_once(&mut sampler, &metrics, &pool).await;
    let body = scrape(&metrics);

    assert!(
        body.contains(r#"epigraph_tenancy_undeclared_writes{table_name="claims"} 1"#),
        "the scrape must carry the per-table series the week-11b gate reads; got:\n{body}"
    );
    assert!(
        body.contains("# TYPE epigraph_tenancy_undeclared_writes gauge"),
        "it must be exported as a GAUGE — the value is SAMPLED from a table this \
         process does not increment, so it can legitimately go down, and a \
         counter would make a decrease look like a restart; got:\n{body}"
    );
}

/// The gauge tracks the table DOWNWARD as well as upward.
///
/// This is why it is a `Gauge` and not a `Counter`, and it is the property the
/// 24-hour "flat at zero" gate actually depends on: after the write paths are
/// fixed, a new `day` row resets the count and the series must follow it down.
#[sqlx::test(migrations = "../../migrations")]
async fn the_gauge_follows_the_table_down_not_only_up(pool: PgPool) {
    let metrics = Metrics::new();
    let mut sampler = TenancyGaugeSampler::new();

    sqlx::query(
        "INSERT INTO tenancy_undeclared_writes (table_name, day, n, last_seen) \
         VALUES ('claims', current_date, 42, now())",
    )
    .execute(&pool)
    .await
    .expect("seed counter");
    sample_once(&mut sampler, &metrics, &pool).await;
    assert!(scrape(&metrics).contains(r#"{table_name="claims"} 42"#));

    sqlx::query("UPDATE tenancy_undeclared_writes SET n = 0 WHERE table_name = 'claims'")
        .execute(&pool)
        .await
        .expect("reset counter");
    sample_once(&mut sampler, &metrics, &pool).await;
    let body = scrape(&metrics);
    assert!(
        body.contains(r#"epigraph_tenancy_undeclared_writes{table_name="claims"} 0"#),
        "the gauge must fall back to zero, which is the state the week-11b gate \
         waits 24 hours to see; got:\n{body}"
    );
}

/// Only TODAY's rows are exported.
///
/// The gate is "flat at zero for 24 h", not "has never been non-zero". A
/// historical row from before the write paths were fixed must not hold the
/// gauge above zero forever.
#[sqlx::test(migrations = "../../migrations")]
async fn a_historical_row_does_not_pin_the_gauge_above_zero(pool: PgPool) {
    let metrics = Metrics::new();
    let mut sampler = TenancyGaugeSampler::new();

    sqlx::query(
        "INSERT INTO tenancy_undeclared_writes (table_name, day, n, last_seen) \
         VALUES ('claims', current_date - 3, 999, now())",
    )
    .execute(&pool)
    .await
    .expect("seed historical counter");

    sample_once(&mut sampler, &metrics, &pool).await;
    assert!(
        series_lines(&scrape(&metrics)).is_empty(),
        "a three-day-old row must not be exported; the gate reads today's count"
    );
}

/// A series that disappears from today's counts goes to ZERO — it does not keep
/// its last value for the life of the process.
///
/// # Why the three tests above could not catch this
///
/// Each of them builds a fresh `Metrics`, so no series ever survives from one
/// pass to the next and "the sampler retains stale state" is unobservable. This
/// test samples TWICE against the SAME `Metrics` and the SAME sampler, with the
/// row removed in between — which is exactly the shape of the real failure:
/// `undeclared_writes_today` filters `WHERE day = current_date`, and migration
/// 070 arm (a) creates a NEW `(table_name, day)` row each day, so the day after
/// an undeclared write the query returns nothing for that table.
///
/// A sampler that only writes the rows it read would keep exporting `1` there
/// forever. That breaks plan §9.2's week-11b gate in both directions: stuck
/// high means "flat at zero for 24 h" can never pass, and an API restart clears
/// every series so the same corpus suddenly reads clean.
#[sqlx::test(migrations = "../../migrations")]
async fn a_series_whose_row_disappears_is_reset_to_zero_not_left_stale(pool: PgPool) {
    let metrics = Metrics::new();
    let mut sampler = TenancyGaugeSampler::new();

    sqlx::query(
        "INSERT INTO tenancy_undeclared_writes (table_name, day, n, last_seen) \
         VALUES ('claims', current_date, 7, now())",
    )
    .execute(&pool)
    .await
    .expect("seed counter");

    sample_once(&mut sampler, &metrics, &pool).await;
    assert!(
        scrape(&metrics).contains(r#"epigraph_tenancy_undeclared_writes{table_name="claims"} 7"#),
        "the first pass must export the row it read"
    );

    // The row rolls off — this is what a new `day` looks like to a query
    // filtered on `current_date`.
    sqlx::query("DELETE FROM tenancy_undeclared_writes WHERE table_name = 'claims'")
        .execute(&pool)
        .await
        .expect("roll the row off");

    sample_once(&mut sampler, &metrics, &pool).await;
    let body = scrape(&metrics);
    assert!(
        body.contains(r#"epigraph_tenancy_undeclared_writes{table_name="claims"} 0"#),
        "a series whose row is gone must be RESET to 0, not left at its last \
         value; the gauge would otherwise be a function of process uptime \
         rather than of the table. got:\n{body}"
    );
    assert!(
        !body.contains(r#"epigraph_tenancy_undeclared_writes{table_name="claims"} 7"#),
        "the stale value must not survive; got:\n{body}"
    );
}

/// The sampler does not invent series for tables it has never seen.
///
/// The reset above must not become "export a speculative zero for every tier-A
/// table". Migration 070 arm (a)'s trigger exists only on `claims`; migration
/// 074 (PR-16) is what widens it. A zero series for a table no trigger can
/// count would assert a coverage this release does not have, and the week-11b
/// gate would read it as evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sampler_invents_no_series_for_a_table_it_has_never_seen(pool: PgPool) {
    let metrics = Metrics::new();
    let mut sampler = TenancyGaugeSampler::new();

    sample_once(&mut sampler, &metrics, &pool).await;
    sample_once(&mut sampler, &metrics, &pool).await;

    assert!(
        series_lines(&scrape(&metrics)).is_empty(),
        "with no rows at all there must still be NO series, on any pass"
    );
}

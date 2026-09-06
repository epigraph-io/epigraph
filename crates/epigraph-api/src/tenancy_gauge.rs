//! The sampler behind `epigraph_tenancy_undeclared_writes` — PR-12's export of
//! the instrument plan §9.2's week-11b gate reads.
//!
//! # Why this is a type and not a closure inside `bin/server.rs`
//!
//! It carries state. A Prometheus `Family` only holds the series that have been
//! `get_or_create`d, and a sampler that writes only the rows its query RETURNED
//! can never take a series back down: `CorpusStatsRepository::undeclared_writes_today`
//! filters `WHERE day = current_date`, and migration 070 arm (a) creates a NEW
//! `(table_name, day)` row each day — so the day after an undeclared write the
//! query returns nothing for that table and the long-lived server keeps
//! yesterday's non-zero value **forever**.
//!
//! That is the exact failure the `current_date` filter was written to prevent,
//! reintroduced one layer up, and it breaks the gate in both directions: stuck
//! high means "flat at zero for 24 h across every tier-A table" can never pass,
//! and an API restart clears every series so the same corpus suddenly reads
//! clean. The gauge value becomes a function of process uptime rather than of
//! the table.
//!
//! [`TenancyGaugeSampler`] therefore remembers every table it has ever exported
//! and explicitly `.set(0)` on any that today's query did not return.
//!
//! # Why it is not a `prometheus_client` `Collector`
//!
//! `Collector::encode` is SYNCHRONOUS and cannot await an sqlx query, so the
//! value has to be pushed in. That is also why this file, and not `metrics.rs`,
//! is where `epigraph_db` gets named — and why the whole module is
//! `#[cfg(feature = "db")]` while `Metrics::tenancy_undeclared_writes` is
//! deliberately not.

// UNSCOPED-POOL-EXEMPT: Observability. It counts rows across the whole corpus to measure tenancy
// coverage; a viewer-scoped gauge would report one tenant's coverage and label it the fleet's.

use crate::metrics::{Metrics, TenancyTableLabel};
use sqlx::PgPool;
use std::collections::BTreeSet;

/// A stateful sampler for the `epigraph_tenancy_undeclared_writes` gauge.
///
/// One instance per process; call [`sample`](Self::sample) on a tick.
#[derive(Debug, Default)]
pub struct TenancyGaugeSampler {
    /// Every `table_name` this sampler has ever exported a series for.
    ///
    /// Not "every tier-A table": arm (a)'s trigger exists only on `claims`
    /// today, and migration 074 (PR-16) is what widens it. Exporting a
    /// speculative zero for a table no trigger can ever count would assert a
    /// coverage this release does not have.
    seen: BTreeSet<String>,
}

impl TenancyGaugeSampler {
    /// A sampler that has exported nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One sampling pass: read today's counts and reconcile the whole series
    /// set, not only the rows the query returned.
    ///
    /// # Errors
    ///
    /// Returns [`epigraph_db::DbError`] if the read fails. The caller logs and
    /// retries — a database blip must not take the API down, and a stale gauge
    /// is visible in the scrape's staleness rather than silently reading zero.
    pub async fn sample(
        &mut self,
        pool: &PgPool,
        metrics: &Metrics,
    ) -> Result<(), epigraph_db::DbError> {
        let rows = epigraph_db::CorpusStatsRepository::undeclared_writes_today(pool).await?;

        let mut present: BTreeSet<String> = BTreeSet::new();
        for (table_name, n) in rows {
            present.insert(table_name.clone());
            self.seen.insert(table_name.clone());
            metrics
                .tenancy_undeclared_writes
                .get_or_create(&TenancyTableLabel { table_name })
                .set(n);
        }

        // THE RESET. A table that has disappeared from today's counts is at
        // zero, not at whatever it last was.
        for table_name in &self.seen {
            if !present.contains(table_name) {
                metrics
                    .tenancy_undeclared_writes
                    .get_or_create(&TenancyTableLabel {
                        table_name: table_name.clone(),
                    })
                    .set(0);
            }
        }
        Ok(())
    }

    /// PR-17's canary pass: **the plan's "60-second canary health metric".**
    ///
    /// Deliberately a SECOND method on the existing sampler rather than a
    /// second tick loop. The plan asks for a 60-second canary and PR-12 already
    /// built a 60-second tick with a stateful sampler on the API pool; adding a
    /// task would double the connections held for periodic work and give an
    /// operator two intervals to keep in step.
    ///
    /// # Why this does not share `sample`'s error handling
    ///
    /// It does not return `Err`. `sample`'s caller logs and retries, which is
    /// right for a count that can go stale harmlessly. This probe's failure is
    /// itself a finding: if the canary read errors, the honest export is "I
    /// could not measure it" (`-1`), not the previous value and not zero. A
    /// stuck-at-zero canary is the single worst failure mode available here —
    /// it reports "RLS is enforcing" forever.
    ///
    /// The two series are set together and in this order so a scrape can never
    /// catch a fresh canary count beside a stale role flag, which is the pair
    /// the alert expression joins on.
    pub async fn sample_canary(&mut self, state: &crate::state::AppState, metrics: &Metrics) {
        let app_role: i64 = match sqlx::query_scalar::<_, String>("SELECT current_user::text")
            .fetch_one(&state.db_pool)
            .await
        {
            Ok(u) if u == crate::state::EXPECTED_APP_ROLE => 1,
            Ok(_) => 0,
            Err(e) => {
                tracing::warn!(error = %e, "rls canary: could not read current_user");
                -1
            }
        };
        metrics.rls_app_role.set(app_role);

        match state.rls_canary_visible().await {
            // Below migration 078 there is no table to read. Not an error, but
            // not a measurement either.
            Ok(None) => {
                metrics.rls_canary_visible.set(-1);
            }
            Ok(Some(n)) => {
                if n > 0 && app_role == 1 {
                    // The one combination that is a live security failure.
                    tracing::error!(
                        canary_rows = n,
                        "RLS CANARY VISIBLE on an epigraph_app connection: row-level security \
                         is NOT protecting this database. See docs/tenancy.md."
                    );
                }
                metrics.rls_canary_visible.set(n);
            }
            Err(e) => {
                tracing::warn!(error = %e, "rls canary probe failed; exporting -1 (unmeasured)");
                metrics.rls_canary_visible.set(-1);
            }
        }
    }
}

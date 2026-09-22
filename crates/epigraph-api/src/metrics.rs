//! Prometheus metrics for EpiGraph API
//!
//! Exposes operational counters and gauges via GET /metrics in the
//! Prometheus text format (version 0.0.4).  The registry is constructed
//! once at startup and shared via `axum::Extension<Arc<Metrics>>`.

use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Label set for [`Metrics::tenancy_undeclared_writes`]: one series per table.
///
/// A single scalar would answer "is anything undeclared" but not "which write
/// path", and the deploy gate is per-table — plan §9.2 week 11b requires
/// `tenancy_undeclared_writes` **flat at zero for 24 h across every tier-A
/// table**, which cannot be read off an aggregate.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TenancyTableLabel {
    pub table_name: String,
}

/// Application-level Prometheus metrics.
///
/// Each field is a cloned handle into the shared `registry`; incrementing the
/// handle is reflected in the registry's output automatically.
pub struct Metrics {
    pub registry: Registry,
    /// Total number of HTTP requests received (all routes, all methods).
    pub requests_total: Counter,
    /// Total number of HTTP responses with a 4xx or 5xx status code.
    pub request_errors: Counter,
    /// Total number of epistemic packets / claims submitted via POST endpoints.
    pub claims_submitted: Counter,
    /// Current number of registered agents tracked in the in-memory store.
    pub active_agents: Gauge,
    /// Undeclared tenancy writes counted by migration 070 arm (a), per table.
    ///
    /// **This is the instrument plan §9.2's week-11b gate reads**: migration
    /// 074 (PR-16) turns the arm-(a) warning into a hard `23502`, and the gate
    /// before it is that this number is flat at zero for 24 hours across every
    /// tier-A table. Without an exported series, that gate has nothing to read.
    ///
    /// It is a `Gauge`, not a `Counter`, and the distinction is load-bearing:
    /// the value is *sampled* from `tenancy_undeclared_writes.n` — a table the
    /// database owns and this process does not increment — so it can legitimately
    /// go down (a new `day` row, an operator truncating the table). A Counter
    /// would make a decrease look like a process restart to Prometheus.
    ///
    /// **The plan's *Acceptance* line asks for this gauge and says nothing about
    /// how it is fed.** `prometheus_client::collector::Collector::encode` is
    /// SYNCHRONOUS, so it cannot run an async sqlx query and a custom Collector
    /// is not an option; the value has to be pushed in by a sampler task. See
    /// `bin/server.rs`. The field itself is deliberately NOT behind
    /// `#[cfg(feature = "db")]` — it is pure `prometheus_client` and naming it
    /// under `--no-default-features` must keep compiling.
    pub tenancy_undeclared_writes: Family<TenancyTableLabel, Gauge>,

    /// PR-17's canary: how many `rls_canary` rows the API pool can see.
    ///
    /// **This is the plan's "60-second canary health metric".** Migration 078
    /// creates one row in a `FORCE`d table whose only policy is bypass-only, so
    /// on a correctly configured application connection the answer is `0` and
    /// on a connection that bypasses row security it is `1`. That single
    /// integer is the whole security posture, and there is no app-layer
    /// equivalent — you cannot assert at runtime that 85 MCP tools remembered
    /// to filter.
    ///
    /// # Read it with the companion series, not alone
    ///
    /// `1` is the CORRECT and expected value on every environment that has not
    /// yet performed plan §9.2 week 11d's credential split, because those
    /// connect as the owning superuser. Alerting on `> 0` unconditionally would
    /// page on every dev box. The alert is
    /// `epigraph_rls_canary_visible > 0 AND epigraph_rls_app_role == 1`.
    ///
    /// `-1` means the sampler could not decide: below migration 078 the table
    /// does not exist. A distinguished value rather than an absent series,
    /// because an absent series and a zero look identical in a `sum()` and this
    /// is the one number where "I could not measure it" must not read as
    /// "healthy".
    ///
    /// Registered on the INTERNAL listener like everything else here
    /// (`progress.json::decisions_taken.Q1_metrics` = "separate internal
    /// listener"); `/metrics` is not on the application router.
    pub rls_canary_visible: Gauge,

    /// `1` when the API pool's `current_user` is `epigraph_app`, else `0`.
    ///
    /// The companion series that makes [`Self::rls_canary_visible`] alertable,
    /// and the same staging marker
    /// `epigraph_api::state::rls_verdict` keys its refusals on. Without it an
    /// operator cannot tell "canary visible because we are pre-11d" from
    /// "canary visible because the policy was dropped" — which are a no-op and
    /// a total tenancy failure respectively.
    pub rls_app_role: Gauge,

    /// Groups that have owed a re-key for more than seven days — FINAL-PLAN
    /// §6.7 point 2's `epigraph_groups_reseal_required`.
    ///
    /// A member removal sets `groups.reseal_required_at` and marks the epoch
    /// `rotating`; only a key-holding admin can finish the job, because by
    /// §6.5.6 the server holds no group key. So the obligation is one the
    /// server can measure and cannot discharge, and an obligation nobody can
    /// see is one nobody services. Every day it goes unmet is another day the
    /// removed member's retained share reads content the group still writes.
    ///
    /// **The seven-day clause is part of the instrument, not a tuning knob.**
    /// A fresh obligation is a normal operational state; one a week old is a
    /// process failure, and a gauge without the age clause alerts on the first
    /// and so gets muted before it can report the second.
    ///
    /// **In this release the series is monotone non-decreasing, and a reader
    /// deciding whether the alert is actionable needs to know that.** Nothing
    /// clears `groups.reseal_required_at`: rotation deliberately does not
    /// (§6.7 point 3 gives the clearing to the re-seal handler, when the last
    /// `claim_encryption` row has actually moved) and that handler is not
    /// built. So read this as "groups that have EVER incurred an unrotated
    /// removal older than 7 days", not "groups currently owing one" — a group
    /// stays counted after its admin has done everything the system asks. The
    /// gauge is still worth having in that form, but an alert wired to it will
    /// not clear on remediation, which is a property of the deferred design and
    /// not of the sampler.
    ///
    /// A `Gauge`, and sampled rather than incremented: the value is a `count(*)`
    /// the database owns, and it falls whenever the underlying count does.
    /// Fed by `tenancy_gauge::TenancyGaugeSampler::sample_reseal_required` for
    /// the same reason as its neighbours — `Collector::encode` is synchronous
    /// and cannot await sqlx. Seeded to -1 ("not yet sampled"), because 0 is
    /// the healthy value and publishing it before the first tick would report a
    /// clean instance nobody has looked at.
    ///
    /// Deliberately NOT behind `#[cfg(feature = "db")]`: this field is pure
    /// `prometheus_client`, and naming it under `--no-default-features` must
    /// keep compiling.
    pub groups_reseal_required: Gauge,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let requests_total: Counter = Counter::default();
        registry.register(
            "epigraph_requests_total",
            "Total HTTP requests",
            requests_total.clone(),
        );

        let request_errors: Counter = Counter::default();
        registry.register(
            "epigraph_request_errors_total",
            "Total HTTP errors",
            request_errors.clone(),
        );

        let claims_submitted: Counter = Counter::default();
        registry.register(
            "epigraph_claims_submitted_total",
            "Total claims submitted",
            claims_submitted.clone(),
        );

        let active_agents: Gauge = Gauge::default();
        registry.register(
            "epigraph_active_agents",
            "Number of active agents",
            active_agents.clone(),
        );

        let tenancy_undeclared_writes = Family::<TenancyTableLabel, Gauge>::default();
        registry.register(
            "epigraph_tenancy_undeclared_writes",
            "Undeclared tenancy writes counted by migration 070 arm (a), by table",
            tenancy_undeclared_writes.clone(),
        );

        // Seeded to -1, not 0. Until the first sampler tick this process has
        // not measured anything, and 0 is the HEALTHY value — publishing it
        // before the probe has run would report "RLS is enforcing" on a
        // database nobody has looked at yet.
        let rls_canary_visible: Gauge = Gauge::default();
        rls_canary_visible.set(-1);
        registry.register(
            "epigraph_rls_canary_visible",
            "rls_canary rows visible on the API pool: 0 healthy under the app role, \
             1 on a bypassing connection, -1 not yet sampled or below migration 078",
            rls_canary_visible.clone(),
        );

        let rls_app_role: Gauge = Gauge::default();
        rls_app_role.set(-1);
        registry.register(
            "epigraph_rls_app_role",
            "1 when the API pool connects as epigraph_app, 0 otherwise, -1 not yet sampled",
            rls_app_role.clone(),
        );

        let groups_reseal_required: Gauge = Gauge::default();
        groups_reseal_required.set(-1);
        registry.register(
            "epigraph_groups_reseal_required",
            "Groups whose reseal_required_at is non-NULL and older than 7 days, \
             -1 not yet sampled",
            groups_reseal_required.clone(),
        );

        Self {
            registry,
            requests_total,
            request_errors,
            claims_submitted,
            active_agents,
            tenancy_undeclared_writes,
            rls_canary_visible,
            rls_app_role,
            groups_reseal_required,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler for `GET /metrics`.
///
/// Returns the full Prometheus text exposition in the standard wire format.
///
/// # Where this is served from
///
/// **Not** from the application router. PR-03 removed `/metrics` from both
/// `create_router` variants: with the router inverted to an anonymous
/// allowlist, the only two remaining choices for a public `/metrics` were to
/// leave a corpus-shaped operational surface open to the internet, or to make
/// scrapers carry an OAuth token. Neither is what a metrics endpoint should be.
///
/// It is served instead by a **separate internal listener** bound in
/// `bin/server.rs` from `EPIGRAPH_METRICS_ADDR` (default `127.0.0.1:9090`),
/// which carries no application routes, no rate limiter, and no body limit.
/// Reaching it requires being on the host or inside the network namespace.
///
/// Deploy consequence: the Prometheus scrape target must be updated in the same
/// window as this change, or monitoring goes dark.
pub async fn metrics_handler(
    axum::extract::Extension(metrics): axum::extract::Extension<Arc<Metrics>>,
) -> impl axum::response::IntoResponse {
    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
}

/// The internal metrics router: exactly one route, `GET /metrics`.
///
/// Kept here rather than inline in `bin/server.rs` so that the exposition
/// surface is described in one place, and so a future change to it (an
/// additional `/metrics/health`, a scrape token) has an obvious home.
///
/// The `Arc<Metrics>` is supplied as an `Extension` because `metrics_handler`
/// already takes it that way on the application router, where `bin/server.rs`
/// still layers it. Keeping one handler signature means the two cannot drift.
pub fn metrics_router(metrics: Arc<Metrics>) -> axum::Router {
    axum::Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .layer(axum::Extension(metrics))
}

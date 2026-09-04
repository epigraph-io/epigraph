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

        Self {
            registry,
            requests_total,
            request_errors,
            claims_submitted,
            active_agents,
            tenancy_undeclared_writes,
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

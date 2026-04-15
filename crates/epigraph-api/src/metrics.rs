//! Prometheus metrics for EpiGraph API
//!
//! Exposes operational counters and gauges via GET /metrics in the
//! Prometheus text format (version 0.0.4).  The registry is constructed
//! once at startup and shared via `axum::Extension<Arc<Metrics>>`.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;

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

        Self {
            registry,
            requests_total,
            request_errors,
            claims_submitted,
            active_agents,
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
/// No authentication is required — scrapers (Prometheus, Grafana Agent) hit
/// this endpoint directly.
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

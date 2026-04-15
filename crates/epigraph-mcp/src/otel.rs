//! OpenTelemetry integration — instruments MCP tool calls and bridges
//! completed spans into EpiGraph evidence records.
//!
//! Two layers:
//! 1. **Infrastructure telemetry**: every MCP tool call becomes an OTEL span
//!    exported to a collector (Jaeger, etc.) for operational dashboards.
//! 2. **Epistemic telemetry**: completed spans on write operations create
//!    `EvidenceType::Telemetry` records linked to the claims they operated on,
//!    providing cryptographically-signed provenance.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// Initialize the OTEL tracer provider with OTLP gRPC export.
///
/// Respects standard OTEL env vars:
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` (default: `http://localhost:4317`)
/// - `OTEL_SERVICE_NAME` (default: `epigraph-mcp`)
///
/// Returns the provider (caller must hold it and call `shutdown()` on exit).
pub fn init_tracer_provider() -> Result<SdkTracerProvider, Box<dyn std::error::Error>> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}

/// Build a tracing subscriber that bridges `tracing` spans to OTEL
/// and also logs to stderr (preserving stdout for MCP JSON-RPC).
///
/// Call this *instead of* the plain `tracing_subscriber::fmt().init()`.
pub fn init_telemetry(
    provider: &SdkTracerProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    let tracer = provider.tracer("epigraph-mcp");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr) // stdout reserved for JSON-RPC
        .with_target(true);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "epigraph_mcp=info".parse().unwrap());

    let subscriber = Registry::default()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer);

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}

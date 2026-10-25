//! Log subscriber for the `epigraph-mcp` binary.
//!
//! The binary logs to stderr (stdout is reserved for MCP JSON-RPC in stdio
//! mode) under the operator's `RUST_LOG`, falling back to
//! [`DEFAULT_DIRECTIVES`] when it is unset or does not parse.
//!
//! On top of that filter sits a hard cap: every `rmcp*` target is held at
//! INFO, whatever `RUST_LOG` says. rmcp's service loop logs each inbound
//! request (`received request`) and each tool result (`response message ...
//! CallToolResult(..)`) at DEBUG with the full body, which carries claim
//! content the caller was entitled to read (including group-private rows).
//! A debug-level `RUST_LOG` must not copy those bodies into the journal.
//!
//! The cap is a separate layer rather than an `rmcp=info` directive appended
//! to the `EnvFilter`: an `EnvFilter` lets a more specific directive
//! (`rmcp::service=debug`) beat a broader one, and lets a span directive
//! (`[serve_inner]=debug`) enable every target inside that span before any
//! target directive is consulted. A layered `Targets` filter is ANDed with
//! the `EnvFilter`, so neither form can lift the cap.
//!
//! Local debugging can lift the cap explicitly with
//! [`PAYLOAD_LOGGING_ENV`]`=1`; [`init_stderr`] then logs a WARN at boot.
//!
//! Known residual: the cap is a level cap, so rmcp lines logged at INFO or
//! WARN still pass with their payload. In rmcp 2.2 these are
//! `received notification` (INFO, `?notification`) in the service loop and
//! `Received unexpected message` (WARN, `?notification` / `?message`) on the
//! client side, which this binary hits as a federation client. They carry
//! MCP notifications and stray messages, not tool results. They are far
//! rarer than the per-call DEBUG dump and are not capped here.
//!
//! `otel.rs::init_telemetry` (not compiled today) builds its own subscriber
//! without this cap. Anything that wires it up must layer the same cap.

use tracing::Subscriber;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Filter used when `RUST_LOG` is unset or unparseable.
///
/// `tenancy=info` so the default filter carries the D9 boot line (target
/// `tenancy.maintenance`), which is what an operator greps the journal for
/// after a deploy.
pub const DEFAULT_DIRECTIVES: &str = "epigraph_mcp=info,tenancy=info";

/// Target prefix capped at INFO (covers `rmcp::service`, `rmcp::transport::*`).
pub const RMCP_TARGET: &str = "rmcp";

/// Opt-in that lifts the rmcp cap, for local debugging only.
pub const PAYLOAD_LOGGING_ENV: &str = "EPIGRAPH_MCP_LOG_PAYLOADS";

/// Does the value of [`PAYLOAD_LOGGING_ENV`] opt in to payload logging?
/// Only an explicit `1` / `true` (any case) does; unset, empty, `0` and
/// anything else keep the cap.
#[must_use]
pub fn payload_logging_opted_in(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        let v = v.trim();
        v == "1" || v.eq_ignore_ascii_case("true")
    })
}

/// The binary's subscriber: `rust_log` (or [`DEFAULT_DIRECTIVES`]) as an
/// `EnvFilter`, the rmcp INFO cap unless `log_payloads`, formatted to
/// `writer`. [`init_stderr`] installs it with `std::io::stderr`; tests pass
/// a capture buffer, so they exercise this exact construction.
pub fn subscriber<W>(
    rust_log: Option<&str>,
    log_payloads: bool,
    writer: W,
) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let env_filter = rust_log
        .and_then(|directives| EnvFilter::try_new(directives).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_DIRECTIVES));
    // The cap's default is the EnvFilter's own ceiling, not TRACE: the
    // subscriber's max-level hint (hence `LevelFilter::current()` and the
    // `log` bridge's max level) is the max over both layers, and the cap must
    // only narrow `RUST_LOG`, never widen what callsites are evaluated.
    let hint = env_filter.max_level_hint().unwrap_or(LevelFilter::TRACE);
    let cap = Targets::new().with_default(hint);
    let cap = if log_payloads {
        cap
    } else {
        cap.with_target(RMCP_TARGET, LevelFilter::INFO)
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(writer)
        .finish()
        .with(cap)
}

/// Install [`subscriber`] as the global default, reading `RUST_LOG` and
/// [`PAYLOAD_LOGGING_ENV`] from the environment and writing to stderr.
pub fn init_stderr() {
    let log_payloads = payload_logging_opted_in(std::env::var(PAYLOAD_LOGGING_ENV).ok().as_deref());
    subscriber(
        std::env::var("RUST_LOG").ok().as_deref(),
        log_payloads,
        std::io::stderr,
    )
    .init();
    if log_payloads {
        tracing::warn!(
            target: "epigraph_mcp",
            "{PAYLOAD_LOGGING_ENV} is set: rmcp DEBUG logging is uncapped and writes MCP \
             request and tool-result bodies to the log; never set it on a shared host"
        );
    }
}

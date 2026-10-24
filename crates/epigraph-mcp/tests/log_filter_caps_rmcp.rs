//! The `epigraph-mcp` binary's log subscriber must never write rmcp's DEBUG
//! request / tool-result bodies, whatever `RUST_LOG` says.
//!
//! rmcp's service loop logs `received request` and `response message ...
//! CallToolResult(..)` at DEBUG with the whole body inside a `serve_inner`
//! span. These tests drive the REAL [`log_filter::subscriber`] (the exact
//! construction `main` installs, with a capture buffer in place of stderr)
//! and emit events on rmcp's targets the way rmcp does.

use std::io;
use std::sync::{Arc, Mutex};

use epigraph_mcp::log_filter;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `emit` under the binary's subscriber built from `rust_log` /
/// `log_payloads`, returning everything it wrote.
fn captured(rust_log: Option<&str>, log_payloads: bool, emit: impl FnOnce()) -> String {
    let buf = Capture::default();
    let sub = log_filter::subscriber(rust_log, log_payloads, buf.clone());
    tracing::subscriber::with_default(sub, emit);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

/// rmcp-shaped events: body-carrying DEBUG/TRACE lines inside the
/// `serve_inner` span, plus one INFO lifecycle line that must survive.
fn emit_rmcp() {
    let span = tracing::info_span!(target: "rmcp::service", "serve_inner");
    let _entered = span.enter();
    tracing::debug!(target: "rmcp::service", "response message SECRET-RESPONSE-BODY");
    tracing::debug!(target: "rmcp::service", "received request SECRET-REQUEST-BODY");
    tracing::trace!(target: "rmcp::service", "new event SECRET-TRACE-BODY");
    tracing::debug!(
        target: "rmcp::transport::streamable_http_server",
        "SECRET-TRANSPORT-BODY"
    );
    tracing::info!(target: "rmcp::service", "serve finished KEEP-RMCP-INFO");
}

/// Every operator `RUST_LOG` shape that would let rmcp DEBUG through an
/// `EnvFilter`: global levels, a specific rmcp target that beats a broad
/// `rmcp=` directive, and a span directive that bypasses target directives.
const UNSAFE_RUST_LOGS: &[&str] = &[
    "debug",
    "trace",
    "rmcp::service=debug",
    "rmcp=trace,epigraph_mcp=debug",
    "rmcp::transport=trace,rmcp::service=trace",
    "[serve_inner]=debug",
    "info,[serve_inner]=trace",
];

#[test]
fn rmcp_bodies_never_logged_under_any_rust_log() {
    let leaked: Vec<(&str, String)> = UNSAFE_RUST_LOGS
        .iter()
        .map(|raw| (*raw, captured(Some(raw), false, emit_rmcp)))
        .filter(|(_, out)| out.contains("SECRET-"))
        .collect();
    assert!(
        leaked.is_empty(),
        "{} of {} RUST_LOG values let an rmcp DEBUG/TRACE body into the log: {:#?}",
        leaked.len(),
        UNSAFE_RUST_LOGS.len(),
        leaked
    );
}

#[test]
fn cap_is_info_not_off_and_own_debug_survives() {
    let out = captured(Some("debug"), false, || {
        emit_rmcp();
        tracing::debug!(target: "epigraph_mcp", "KEEP-OWN-DEBUG");
    });
    assert!(
        out.contains("KEEP-RMCP-INFO"),
        "rmcp INFO lifecycle lines must still be logged:\n{out}"
    );
    assert!(
        out.contains("KEEP-OWN-DEBUG"),
        "RUST_LOG=debug must still enable epigraph_mcp DEBUG:\n{out}"
    );
}

#[test]
fn default_filter_keeps_tenancy_boot_line_and_hides_debug() {
    let out = captured(None, false, || {
        tracing::info!(target: "tenancy.maintenance", "KEEP-TENANCY-BOOT");
        tracing::info!(target: "epigraph_mcp", "KEEP-OWN-INFO");
        tracing::debug!(target: "epigraph_mcp", "HIDDEN-OWN-DEBUG");
    });
    assert!(out.contains("KEEP-TENANCY-BOOT"), "{out}");
    assert!(out.contains("KEEP-OWN-INFO"), "{out}");
    assert!(!out.contains("HIDDEN-OWN-DEBUG"), "{out}");
}

/// The positive `KEEP-TENANCY-BOOT` assertion is what this test pins. A
/// lossy fallback (an empty filter) would drop that INFO line. The `SECRET-`
/// check is belt and braces: the default filter excludes rmcp with or
/// without the cap.
#[test]
fn unparseable_rust_log_falls_back_to_default() {
    let out = captured(Some("rmcp=notalevel"), false, || {
        tracing::info!(target: "tenancy.maintenance", "KEEP-TENANCY-BOOT");
        emit_rmcp();
    });
    assert!(out.contains("KEEP-TENANCY-BOOT"), "{out}");
    assert!(!out.contains("SECRET-"), "{out}");
}

#[test]
fn explicit_opt_in_lifts_the_cap() {
    let out = captured(Some("rmcp=debug"), true, emit_rmcp);
    assert!(
        out.contains("SECRET-RESPONSE-BODY"),
        "the payload opt-in must actually enable rmcp DEBUG:\n{out}"
    );
}

#[test]
fn payload_opt_in_requires_an_explicit_value() {
    for on in ["1", "true", "TRUE", " true "] {
        assert!(log_filter::payload_logging_opted_in(Some(on)), "{on:?}");
    }
    for off in ["", "0", "false", "yes", "debug"] {
        assert!(!log_filter::payload_logging_opted_in(Some(off)), "{off:?}");
    }
    assert!(!log_filter::payload_logging_opted_in(None));
}

/// The cap must not raise the process-wide max level above what `RUST_LOG`
/// asks for. `LevelFilter::current()` (and the `log`-crate bridge's max level,
/// set from it at init) is the subscriber's `max_level_hint`, and a layered
/// filter's hint is the max of its layers' hints. A cap whose default is TRACE
/// would make every disabled `debug!` / `trace!` callsite in every dependency
/// build its record before being rejected.
#[test]
fn cap_does_not_raise_the_max_level_hint() {
    use tracing::level_filters::LevelFilter;
    use tracing::Subscriber;

    for (rust_log, ceiling) in [
        (None, LevelFilter::INFO),
        (Some("warn"), LevelFilter::INFO),
        (Some("debug"), LevelFilter::DEBUG),
        (Some("[serve_inner]=debug"), LevelFilter::DEBUG),
    ] {
        let hint = log_filter::subscriber(rust_log, false, io::sink).max_level_hint();
        assert!(
            hint.is_some_and(|h| h <= ceiling),
            "RUST_LOG={rust_log:?}: max_level_hint {hint:?} exceeds {ceiling:?}"
        );
    }
}

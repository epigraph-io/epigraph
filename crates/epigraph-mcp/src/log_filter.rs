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
//! The level cap does not cover rmcp lines logged at INFO or above, and
//! several of those carry peer-supplied data in a field (backlog e6ed6cc9).
//! In rmcp 3.9:
//!
//! - `received notification` (INFO, `?notification`) in the service loop, on
//!   every notification a peer sends;
//! - `cancelled` (INFO, `reason`), on both sides of the service loop, when a
//!   `notifications/cancelled` cancels a call in flight: `reason` is the
//!   peer's free text, copied from its message;
//! - `Received unexpected message` (WARN, `?notification` / `?message`) in
//!   the client handshake, which this binary runs as a federation client of
//!   every extension.
//!
//! A third layer drops every rmcp event that carries such a field
//! ([`carries_rmcp_payload`]), at any level. It matches on the callsite's
//! field NAMES (metadata), so the decision is made once per callsite and no
//! payload is formatted to make it. The match fails closed: a dropped line is
//! lost whole, not redacted. That also drops rmcp's `rejected peer request`
//! (WARN, `message = %error.message`), whose second `message` field matches
//! the `?message` rule; in rmcp 3.9 that text is a fixed constant, so only
//! visibility is lost, and the rule is kept so a later rmcp that puts the
//! request into it cannot leak.
//!
//! Local debugging can lift both the cap and the drop explicitly with
//! [`PAYLOAD_LOGGING_ENV`]`=1`; [`init_stderr`] then logs a WARN at boot.
//!
//! Known residuals (not dropped; the filter sees field names, so data
//! formatted into a line's TEXT or into a field not named above passes):
//!
//! - `response error` (WARN, `?error`) logs the `ErrorData` a tool answered
//!   with, whose message a tool may build from the caller's input;
//! - `Service initialized as server` (INFO, `?peer_info`) logs the caller's
//!   `initialize` parameters (its self-reported client name, version and
//!   capabilities);
//! - `worker quit with fatal: {error}` (ERROR) formats a transport error into
//!   the text; a session worker's `UnexpectedEvent` error carries the whole
//!   event, which can hold a client message, and a streamable-HTTP client's
//!   `UnexpectedServerResponse` carries the extension's response body. Not
//!   traced to a peer-triggerable path.
//!
//! This is the binary's only subscriber: `tests/one_log_subscriber.rs` fails
//! on any other file under `src/` that builds or installs one, so a second
//! subscriber cannot skip the cap.

use tracing::{Metadata, Subscriber};
use tracing_subscriber::filter::{filter_fn, LevelFilter, Targets};
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

/// Field names rmcp logs a whole MCP message, or a peer's free text, under.
/// An rmcp event with one of these fields is dropped (see
/// [`carries_rmcp_payload`]). `reason` is the `cancelled` line's copy of a
/// `notifications/cancelled` reason.
pub const RMCP_PAYLOAD_FIELDS: &[&str] = &["notification", "request", "result", "params", "reason"];

/// Is `target` one of rmcp's (`rmcp` or `rmcp::…`)? Not `rmcp_foo`.
fn is_rmcp_target(target: &str) -> bool {
    target == RMCP_TARGET
        || target
            .strip_prefix(RMCP_TARGET)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// Does this callsite log an MCP message as a field: an rmcp EVENT with a
/// field named in [`RMCP_PAYLOAD_FIELDS`], or with a second `message` field?
///
/// The second test is for `warn!(?message, "Received unexpected message")`:
/// the format string is the event's `message` field, and `?message` adds
/// another field of the same name, which holds the payload. An event with a
/// format string and no `?message` has exactly one.
#[must_use]
pub fn carries_rmcp_payload(meta: &Metadata<'_>) -> bool {
    if !meta.is_event() || !is_rmcp_target(meta.target()) {
        return false;
    }
    let fields = meta.fields();
    fields
        .iter()
        .any(|f| RMCP_PAYLOAD_FIELDS.contains(&f.name()))
        || fields.iter().filter(|f| f.name() == "message").count() > 1
}

/// Opt-in that lifts the rmcp cap and the payload drop, for local debugging
/// only.
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
/// `EnvFilter`, the rmcp INFO cap and the rmcp payload drop unless
/// `log_payloads`, formatted to
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
    // Same ceiling as the cap, for the same reason: `filter_fn` alone reports
    // no hint, which a layered subscriber reads as "any level". A `FilterFn`
    // must then enable nothing above its hint, hence the level test.
    let drop_payloads = filter_fn(move |meta| {
        *meta.level() <= hint && (log_payloads || !carries_rmcp_payload(meta))
    })
    .with_max_level_hint(hint);
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(writer)
        .finish()
        .with(cap)
        .with(drop_payloads)
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
            "{PAYLOAD_LOGGING_ENV} is set: rmcp logging is uncapped and writes MCP \
             requests, notifications and tool-result bodies to the log; never set it on a \
             shared host"
        );
    }
}

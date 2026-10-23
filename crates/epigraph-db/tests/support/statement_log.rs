//! Capture every statement sqlx executes while one future runs.
//!
//! sqlx's `QueryLogger` emits one `tracing` event per executed statement, on
//! target `sqlx::query`, carrying the statement text (`summary`, plus
//! `db.statement` when the summary elides it) and `rows_returned`. This module
//! installs a minimal subscriber for the duration of ONE future and records
//! those events, so a test can assert how many statements a code path ran and
//! how many rows each one returned.
//!
//! # Why a hand-rolled `Subscriber`
//!
//! `tracing` is already a normal dependency of every crate that includes this
//! file, so the capture needs no new dev-dependency and no `Cargo.lock` change.
//! `tracing-subscriber` would be one more edge in the lock file for ~60 lines.
//!
//! # What it sees, and what it does not
//!
//! The subscriber is attached with `WithSubscriber`, so it is the default only
//! while the wrapped future is being polled. A statement run by a task the
//! pool SPAWNS (connection return, background maintenance) is not captured.
//! That is what a footprint test wants: the statements the request itself
//! issued on its connection. It also means two captures in one test never see
//! each other's statements.
//!
//! Included with `#[path]`, never linked: it lives under `tests/support/` so
//! cargo does not auto-discover it as a test target of its own.

#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing::span::{Attributes, Id, Record};
use tracing::{Dispatch, Event, Metadata, Subscriber};

/// The target sqlx logs every executed statement on.
const SQLX_QUERY_TARGET: &str = "sqlx::query";

/// One executed statement, as sqlx reported it.
#[derive(Debug, Clone, Default)]
pub struct Statement {
    /// sqlx's first-four-words summary (the whole statement when it is short).
    pub summary: String,
    /// The full statement text when sqlx elided it from `summary`, else empty.
    pub db_statement: String,
    /// Rows the statement returned to the client.
    pub rows_returned: u64,
}

impl Statement {
    /// The statement text: the full SQL when sqlx recorded it, else the summary.
    pub fn text(&self) -> &str {
        let full = self.db_statement.trim();
        if full.is_empty() {
            self.summary.trim()
        } else {
            full
        }
    }

    /// Whitespace-collapsed [`Self::text`], so a needle is matched without
    /// caring how the SQL literal was indented.
    pub fn normalized(&self) -> String {
        self.text().split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

struct Capture {
    next_span: AtomicU64,
    log: Arc<Mutex<Vec<Statement>>>,
}

#[derive(Default)]
struct StatementVisitor(Statement);

impl Visit for StatementVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.0.summary = value.to_string(),
            "db.statement" => self.0.db_statement = value.to_string(),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "rows_returned" {
            self.0.rows_returned = value;
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "rows_returned" {
            self.0.rows_returned = value.max(0) as u64;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `summary` / `db.statement` arrive as `String`s, which `tracing`
        // records through `record_str`; this arm only catches a future sqlx
        // that switches them to `Debug`, without the surrounding quotes.
        match field.name() {
            "summary" if self.0.summary.is_empty() => {
                self.0.summary = format!("{value:?}").trim_matches('"').to_string()
            }
            "db.statement" if self.0.db_statement.is_empty() => {
                self.0.db_statement = format!("{value:?}").trim_matches('"').to_string()
            }
            _ => {}
        }
    }
}

impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // Only sqlx's statement events. Spans (`#[instrument]` on the repo
        // functions) are disabled, so `new_span` is never asked for one.
        metadata.target() == SQLX_QUERY_TARGET
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        // Never 0: `Id::from_u64(0)` panics.
        Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != SQLX_QUERY_TARGET {
            return;
        }
        let mut visitor = StatementVisitor::default();
        event.record(&mut visitor);
        self.log.lock().expect("statement log").push(visitor.0);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Run `fut` and return its output together with every statement sqlx
/// executed while it was being polled, in execution order.
pub async fn capture<F: Future>(fut: F) -> (F::Output, Vec<Statement>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let dispatch = Dispatch::new(Capture {
        next_span: AtomicU64::new(1),
        log: Arc::clone(&log),
    });
    let out = fut.with_subscriber(dispatch).await;
    let statements = std::mem::take(&mut *log.lock().expect("statement log"));
    (out, statements)
}

/// The captured statements' texts, one per line, for an assertion message.
pub fn describe(statements: &[Statement]) -> String {
    statements
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let text = s.normalized();
            let short: String = text.chars().take(120).collect();
            format!("  {i:>3}: rows={} {short}", s.rows_returned)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

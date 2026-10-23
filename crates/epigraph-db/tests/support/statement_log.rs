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
//! # Why a GLOBAL subscriber, routed per future
//!
//! `tracing` caches each callsite's `Interest` process-wide, and computes it
//! the first time the callsite runs, against whichever dispatcher is the
//! default ON THE THREAD THAT RAN IT. sqlx's per-statement `event!` only runs
//! once its `enabled!` check passes, so with a scoped (`WithSubscriber`)
//! capture, a parallel test thread could be the first to reach that `event!`
//! and cache `never` for it, silently emptying every later capture. Measured:
//! that is exactly what happened under `--test-threads=2`.
//!
//! So ONE global subscriber is installed (once per test binary) and is
//! interested in `sqlx::query` events from every thread; it appends each
//! event to the capture that is active on the current thread, if any. A
//! capture is active only while its own future is being polled.
//!
//! # What it sees, and what it does not
//!
//! A statement run by a task the pool SPAWNS (connection return, background
//! maintenance) is polled outside the captured future and is not captured.
//! That is what a footprint test wants: the statements the call itself issued.
//! Two captures never see each other's statements, on one thread or on many.
//!
//! The global subscriber records nothing else and emits nothing, so it does
//! not change what any other test observes. If a test binary already set a
//! different global subscriber, [`capture`] panics rather than return an
//! empty, vacuous log.
//!
//! Included with `#[path]`, never linked: it lives under `tests/support/` so
//! cargo does not auto-discover it as a test target of its own.

#![allow(dead_code)]

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

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

type Log = Arc<Mutex<Vec<Statement>>>;

thread_local! {
    /// The capture whose future is being polled on this thread, if any.
    static ACTIVE: RefCell<Option<Log>> = const { RefCell::new(None) };
}

/// The process-wide subscriber: interested in `sqlx::query` events only, and
/// routes each one to the capture active on the emitting thread.
struct Router {
    next_span: AtomicU64,
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

impl Subscriber for Router {
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
        ACTIVE.with(|active| {
            if let Some(log) = active.borrow().as_ref() {
                let mut visitor = StatementVisitor::default();
                event.record(&mut visitor);
                log.lock().expect("statement log").push(visitor.0);
            }
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Install [`Router`] as the global default, once per test binary.
fn install_router() {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    let ok = *INSTALLED.get_or_init(|| {
        let ok = tracing::subscriber::set_global_default(Router {
            next_span: AtomicU64::new(1),
        })
        .is_ok();
        // A callsite first reached by another thread between the dispatcher's
        // registration and the global being marked set could have cached
        // `never`; recompute every cached interest now that it is set.
        tracing::callsite::rebuild_interest_cache();
        ok
    });
    assert!(
        ok,
        "statement_log needs to be the global tracing subscriber, and this test \
         binary already installed another one; a capture here would be empty"
    );
}

/// Makes `log` the active capture on the current thread for each poll of
/// `inner`, restoring whatever was active before.
struct Capturing<F> {
    inner: Pin<Box<F>>,
    log: Log,
}

impl<F: Future> Future for Capturing<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let previous = ACTIVE.with(|a| a.replace(Some(Arc::clone(&this.log))));
        let out = this.inner.as_mut().poll(cx);
        ACTIVE.with(|a| *a.borrow_mut() = previous);
        out
    }
}

/// Run `fut` and return its output together with every statement sqlx
/// executed while it was being polled, in execution order.
pub async fn capture<F: Future>(fut: F) -> (F::Output, Vec<Statement>) {
    install_router();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let out = Capturing {
        inner: Box::pin(fut),
        log: Arc::clone(&log),
    }
    .await;
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

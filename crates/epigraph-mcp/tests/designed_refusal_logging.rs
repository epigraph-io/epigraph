//! A CODED database refusal (a migration's `RAISE EXCEPTION 'GRM05: ...'`)
//! that leaves the MCP server through `internal_error` is logged, with the
//! database's DETAIL, the way the HTTP mapper logs it (backlog 365e0749).
//!
//! The reply to the caller is the refusal's MESSAGE only, as before: DETAIL is
//! what the reply withholds (migration 176 moved disclosure-sensitive text
//! there), so the server log is the only place an operator can read it. Before
//! this, `internal_error` returned the designed text before its log line and
//! the refusal never reached the MCP journal at all.
//!
//! This arm needs a real `PgDatabaseError` (DETAIL is read by downcasting to
//! it), so it raises one on the test database rather than faking the trait.

use std::io::Write;
use std::sync::{Arc, Mutex};

use epigraph_mcp::errors::internal_error;
use sqlx::postgres::PgPoolOptions;

/// A `MakeWriter` that appends every log line to one shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Run `f` with every event it emits captured; return what was logged.
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, sink.text())
}

#[tokio::test]
async fn a_coded_database_refusal_is_logged_with_its_detail_and_sent_without_it() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect");
    const DETAIL: &str = "withheld-detail-marker-6c0b";
    let raised = sqlx::query(&format!(
        "DO $$ BEGIN RAISE EXCEPTION 'GRM05: the roster refused this change' \
         USING DETAIL = '{DETAIL}', ERRCODE = '42501'; END $$"
    ))
    .execute(&pool)
    .await
    .expect_err("the DO block raises");
    let db_error = epigraph_db::DbError::from(raised);

    let (e, logs) = logged(|| internal_error(db_error));

    assert_eq!(
        e.message, "GRM05: the roster refused this change",
        "the caller reads the refusal's message, exactly"
    );
    assert!(
        !e.message.contains(DETAIL),
        "DETAIL stays out of the reply: {e:?}"
    );
    assert!(
        logs.contains("the database refused the request"),
        "the refusal leaves a log line: {logs}"
    );
    assert!(
        logs.contains(DETAIL),
        "the log line carries the database's DETAIL (db_detail): {logs}"
    );
    assert!(
        logs.contains("GRM05: the roster refused this change"),
        "the log line carries the refusal's message (detail): {logs}"
    );
    assert!(logs.contains("WARN"), "logged at warn: {logs}");

    // The fields are the HTTP mapper's, by NAME, on the refusal's own line,
    // under the MCP journal's target: renaming `db_detail` or `detail`, or
    // dropping the target, is a regression.
    let line = logs
        .lines()
        .find(|l| l.contains("the database refused the request"))
        .expect("the refusal's line");
    for field in [
        "WARN",
        "mcp.internal_error",
        "detail=GRM05: the roster refused this change",
        &format!("db_detail=Some(\"{DETAIL}\")"),
    ] {
        assert!(
            line.contains(field),
            "the refusal's line carries `{field}`: {line}"
        );
    }
}

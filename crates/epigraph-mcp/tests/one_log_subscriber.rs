//! `log_filter` is the only place in `epigraph-mcp`'s source that builds or
//! installs a `tracing` subscriber (backlog e6ed6cc9).
//!
//! Its subscriber holds rmcp at INFO and drops the rmcp lines that carry an
//! MCP message as a field. A second subscriber built elsewhere would carry
//! neither: the unwired `otel.rs::init_telemetry` built its own
//! `Registry` + `EnvFilter` + fmt layer with no cap, so wiring it up would
//! have put rmcp's request and tool-result bodies back in the journal. This
//! scan fails on any source file other than `src/log_filter.rs` that names
//! `tracing_subscriber` or installs a dispatcher, compiled or not, so such a
//! file cannot sit in the tree waiting to be wired up.

use std::path::{Path, PathBuf};

/// What building or installing a subscriber needs. A file that only emits
/// events (`tracing::info!`) names none of these.
const SUBSCRIBER_MARKERS: &[&str] = &[
    "tracing_subscriber",
    "set_global_default",
    "subscriber::set_default",
    "subscriber::with_default",
];

/// The one file allowed to: it builds the capped subscriber.
const LOG_FILTER: &str = "log_filter.rs";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn only_log_filter_builds_a_subscriber() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let log_filter = src.join(LOG_FILTER);
    assert!(
        files.contains(&log_filter),
        "CALIBRATION: the scan walks src/ and finds {LOG_FILTER}"
    );
    let log_filter_text = std::fs::read_to_string(&log_filter).expect("read log_filter.rs");
    assert!(
        log_filter_text.contains("tracing_subscriber"),
        "CALIBRATION: the marker matches the file that does build the subscriber"
    );

    let offenders: Vec<String> = files
        .iter()
        .filter(|path| **path != log_filter)
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).expect("read source file");
            let hits: Vec<&str> = SUBSCRIBER_MARKERS
                .iter()
                .copied()
                .filter(|marker| text.contains(marker))
                .collect();
            (!hits.is_empty()).then(|| {
                format!(
                    "{}: {}",
                    path.strip_prefix(&src).unwrap_or(path).display(),
                    hits.join(", ")
                )
            })
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "only src/{LOG_FILTER} may build or install a tracing subscriber (any other one \
         lacks the rmcp cap and payload drop); layer log_filter's filters instead:\n{}",
        offenders.join("\n")
    );
}

//! `bridge_component` — bridge a single disconnected component into the
//! giant connected component via LLM-validated semantic edges.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md.

#![allow(dead_code)] // Filled in by Phase 7 Task 4.

use uuid::Uuid;

const USAGE: &str = r#"
bridge-component — bridge a single disconnected component into the giant CC

USAGE:
  bridge-component <component-id> [OPTIONS]

OPTIONS:
  --target <ID>              Target component (default: giant)
  --min-similarity <FLOAT>   Cosine similarity threshold [default: 0.50]
  --top-k <N>                Per-source-atom top-K matches [default: 50]
  --batch-size <N>           Pairs per LLM call [default: 10]
  --provider <NAME>          LLM provider [default: claude-cli]
  --model <NAME>             Model override
  --dry-run                  Default. Reports candidates + LLM eval; creates no edges.
  --apply                    Commit edges (overrides --dry-run).
  --keep-tables              Don't drop the temp candidates table on exit.
  --report-out <PATH>        Write JSON report to file (else stdout)
  -h, --help                 Show this message
"#;

#[derive(Debug)]
struct Args {
    component_id: Uuid,
    target: Option<Uuid>,
    min_similarity: f64,
    top_k: u32,
    batch_size: usize,
    provider: String,
    model: Option<String>,
    apply: bool,
    keep_tables: bool,
    report_out: Option<String>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    eprintln!("bridge-component: stub (Phase 7 Task 4 will fill this in)");
    std::process::exit(1);
}

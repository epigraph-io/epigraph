//! `bridge_sweep` — bridge multiple disconnected components into the
//! giant connected component, with spine-destination report.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md.

#![allow(dead_code)] // Filled in by Phase 7 Task 5.

use uuid::Uuid;

const USAGE: &str = r#"
bridge-sweep — bridge multiple disconnected components into the giant CC

USAGE:
  bridge-sweep [--components <UUID,UUID,...> | --all] [OPTIONS]

OPTIONS:
  --components <LIST>        Explicit component UUIDs (mutually exclusive with --all)
  --all                      Sweep all components ≥ --min-component-size
  --min-component-size <N>   Only used with --all [default: 30]
  --target <ID>              Target component (default: giant)
  --min-similarity <FLOAT>   [default: 0.50]
  --top-k <N>                Per-source-atom [default: 50]
  --batch-size <N>           [default: 10]
  --provider <NAME>          [default: claude-cli]
  --model <NAME>             Model override
  --dry-run                  Default.
  --apply                    Commit edges (overrides --dry-run).
  --keep-tables              Don't drop temp candidate tables on exit.
  --report-out <PATH>        JSON report path (else stdout).
  -h, --help
"#;

#[derive(Debug)]
struct Args {
    components: Option<Vec<Uuid>>, // None when --all is set
    all: bool,
    min_component_size: u32,
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
    eprintln!("bridge-sweep: stub (Phase 7 Task 5 will fill this in)");
    std::process::exit(1);
}

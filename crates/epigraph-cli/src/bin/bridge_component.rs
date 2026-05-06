//! `bridge_component` — bridge a single disconnected component into the
//! giant connected component via LLM-validated semantic edges.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::bridge::candidates::{build_candidate_table, drop_candidate_table};
use epigraph_cli::bridge::components::{compute_components, ComponentSummary};
use epigraph_cli::rerank::{rerank_candidates_table, RerankConfig};

const USAGE: &str = r#"
bridge-component — bridge a single disconnected component into the giant CC

USAGE:
  bridge-component <component-id> [OPTIONS]

OPTIONS:
  --target <ID>              Target component (default: giant — largest by size)
  --min-similarity <FLOAT>   Cosine threshold [default: 0.50]
  --top-k <N>                Per-source-atom [default: 50]
  --batch-size <N>           Pairs per LLM call [default: 10]
  --provider <NAME>          LLM provider [default: epigraph (auto-detect)]
  --model <NAME>             Model override
  --dry-run                  Default. Reports candidates + LLM eval; creates no edges.
  --apply                    Commit edges (overrides --dry-run).
  --keep-tables              Don't drop the temp candidates table on exit.
  --report-out <PATH>        JSON report path (else stdout)
  --limit <N>                Cap LLM evaluations
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
    limit: Option<i64>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let argv: Vec<String> = std::env::args().collect();
        let mut positional: Vec<String> = vec![];

        let mut min_similarity = 0.50;
        let mut top_k = 50_u32;
        let mut batch_size = 10_usize;
        let mut provider = "epigraph".to_string();
        let mut model = None;
        let mut apply = false;
        let mut keep_tables = false;
        let mut target = None;
        let mut report_out = None;
        let mut limit = None;

        let mut i = 1;
        while i < argv.len() {
            match argv[i].as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                "--target" => {
                    i += 1;
                    target = Some(parse_uuid(&argv, i, "--target")?);
                }
                "--min-similarity" => {
                    i += 1;
                    min_similarity = parse_f64(&argv, i, "--min-similarity")?;
                }
                "--top-k" => {
                    i += 1;
                    top_k = parse_u32(&argv, i, "--top-k")?;
                }
                "--batch-size" => {
                    i += 1;
                    batch_size = parse_usize(&argv, i, "--batch-size")?;
                }
                "--provider" => {
                    i += 1;
                    provider = parse_string(&argv, i, "--provider")?;
                }
                "--model" => {
                    i += 1;
                    model = Some(parse_string(&argv, i, "--model")?);
                }
                "--dry-run" => { /* default */ }
                "--apply" => {
                    apply = true;
                }
                "--keep-tables" => {
                    keep_tables = true;
                }
                "--report-out" => {
                    i += 1;
                    report_out = Some(parse_string(&argv, i, "--report-out")?);
                }
                "--limit" => {
                    i += 1;
                    limit = Some(parse_i64(&argv, i, "--limit")?);
                }
                arg if arg.starts_with("--") => {
                    return Err(format!("Unknown flag: {arg}\n{USAGE}"));
                }
                arg => positional.push(arg.to_string()),
            }
            i += 1;
        }

        let component_id = match positional.as_slice() {
            [s] => Uuid::parse_str(s).map_err(|_| format!("invalid <component-id> UUID: {s}"))?,
            _ => {
                return Err(format!(
                    "expected exactly one <component-id>; got {}\n{USAGE}",
                    positional.len()
                ))
            }
        };

        Ok(Args {
            component_id,
            target,
            min_similarity,
            top_k,
            batch_size,
            provider,
            model,
            apply,
            keep_tables,
            report_out,
            limit,
        })
    }
}

fn parse_uuid(argv: &[String], i: usize, name: &str) -> Result<Uuid, String> {
    let v = argv
        .get(i)
        .ok_or_else(|| format!("{name} requires a value"))?;
    Uuid::parse_str(v).map_err(|_| format!("{name} expects a UUID, got: {v}"))
}
fn parse_f64(argv: &[String], i: usize, name: &str) -> Result<f64, String> {
    let v = argv
        .get(i)
        .ok_or_else(|| format!("{name} requires a value"))?;
    v.parse::<f64>()
        .map_err(|_| format!("{name} expects a float, got: {v}"))
}
fn parse_u32(argv: &[String], i: usize, name: &str) -> Result<u32, String> {
    let v = argv
        .get(i)
        .ok_or_else(|| format!("{name} requires a value"))?;
    v.parse::<u32>()
        .map_err(|_| format!("{name} expects a u32, got: {v}"))
}
fn parse_usize(argv: &[String], i: usize, name: &str) -> Result<usize, String> {
    let v = argv
        .get(i)
        .ok_or_else(|| format!("{name} requires a value"))?;
    v.parse::<usize>()
        .map_err(|_| format!("{name} expects a usize, got: {v}"))
}
fn parse_i64(argv: &[String], i: usize, name: &str) -> Result<i64, String> {
    let v = argv
        .get(i)
        .ok_or_else(|| format!("{name} requires a value"))?;
    v.parse::<i64>()
        .map_err(|_| format!("{name} expects an integer, got: {v}"))
}
fn parse_string(argv: &[String], i: usize, name: &str) -> Result<String, String> {
    argv.get(i)
        .ok_or_else(|| format!("{name} requires a value"))
        .cloned()
}

fn locate_component(components: &[ComponentSummary], target: &Uuid) -> Option<usize> {
    components
        .iter()
        .position(|c| c.component_id == *target || c.claim_ids.contains(target))
}

async fn level3_atoms_in_component(
    pool: &PgPool,
    component: &ComponentSummary,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM claims WHERE id = ANY($1) AND (properties->>'level')::int = 3 AND embedding IS NOT NULL",
    )
    .bind(&component.claim_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let args = match Args::parse() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("ERROR: DATABASE_URL must be set");
        std::process::exit(1);
    });

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to connect to PostgreSQL: {e}");
            std::process::exit(1);
        });

    let started = std::time::Instant::now();
    let summary = run_pipeline(&pool, &args).await;

    let report = match summary {
        Ok(r) => r,
        Err(msg) => {
            eprintln!("ERROR: {msg}");
            std::process::exit(1);
        }
    };

    let json = serde_json::to_string_pretty(&report).expect("report serialization");
    if let Some(ref path) = args.report_out {
        std::fs::write(path, &json).unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to write report to {path}: {e}");
            std::process::exit(1);
        });
        eprintln!("Wrote report to {path}");
    } else {
        println!("{json}");
    }

    let elapsed = started.elapsed();
    eprintln!("Done in {:.2}s", elapsed.as_secs_f64());
}

#[derive(serde::Serialize)]
struct Report {
    component_id: Uuid,
    target_component_id: Uuid,
    component_size: usize,
    target_size: usize,
    candidates_table: String,
    candidates_count: usize,
    rerank: Option<RerankReport>,
    duration_ms: u128,
    apply: bool,
}

#[derive(serde::Serialize)]
struct RerankReport {
    candidates_evaluated: usize,
    llm_accepted: usize,
    edges_created: usize,
    duration_ms: u128,
}

async fn run_pipeline(pool: &PgPool, args: &Args) -> Result<Report, String> {
    let started = std::time::Instant::now();

    let components = compute_components(pool)
        .await
        .map_err(|e| format!("compute_components: {e}"))?;
    if components.is_empty() {
        return Err("no claims in graph".to_string());
    }

    // Default target = giant = largest component (compute_components returns
    // sorted by size descending).
    let target_id = match args.target {
        Some(t) => t,
        None => components.first().expect("non-empty").component_id,
    };

    let component_idx = locate_component(&components, &args.component_id)
        .ok_or_else(|| format!("component not found: {}", args.component_id))?;
    let target_idx = locate_component(&components, &target_id)
        .ok_or_else(|| format!("target component not found: {target_id}"))?;
    if component_idx == target_idx {
        return Err(format!(
            "component {} IS the target {} — nothing to bridge",
            args.component_id, target_id,
        ));
    }

    let component = &components[component_idx];
    let target = &components[target_idx];

    let source_atoms = level3_atoms_in_component(pool, component)
        .await
        .map_err(|e| format!("source atoms: {e}"))?;
    let target_atoms = level3_atoms_in_component(pool, target)
        .await
        .map_err(|e| format!("target atoms: {e}"))?;

    if source_atoms.is_empty() {
        return Err("source component has no level-3 atoms with embeddings".to_string());
    }
    if target_atoms.is_empty() {
        return Err("target component has no level-3 atoms with embeddings".to_string());
    }

    let table_name = format!("bridge_sweep_{}_candidates", Uuid::new_v4().simple());

    let candidates_count = build_candidate_table(
        pool,
        &table_name,
        &source_atoms,
        &target_atoms,
        args.min_similarity,
        args.top_k,
    )
    .await
    .map_err(|e| format!("build_candidate_table: {e}"))?;

    let rerank = if candidates_count > 0 {
        let config = RerankConfig {
            min_similarity: args.min_similarity,
            batch_size: args.batch_size,
            provider: args.provider.clone(),
            model: args.model.clone(),
            dry_run: !args.apply,
            limit: args.limit,
            verbose: false, // bridge_component owns its own progress logging
        };
        match rerank_candidates_table(pool, &table_name, &config).await {
            Ok(s) => Some(RerankReport {
                candidates_evaluated: s.candidates_evaluated,
                llm_accepted: s.llm_accepted,
                edges_created: s.edges_created,
                duration_ms: s.duration_ms,
            }),
            Err(e) => return Err(format!("rerank: {e}")),
        }
    } else {
        None
    };

    if !args.keep_tables {
        let _ = drop_candidate_table(pool, &table_name).await; // best-effort
    }

    Ok(Report {
        component_id: component.component_id,
        target_component_id: target.component_id,
        component_size: component.size,
        target_size: target.size,
        candidates_table: table_name,
        candidates_count,
        rerank,
        duration_ms: started.elapsed().as_millis(),
        apply: args.apply,
    })
}

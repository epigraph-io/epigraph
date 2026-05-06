//! `bridge_sweep` — bridge multiple disconnected components into the
//! giant connected component, with spine-destination report.
//!
//! Pipeline parallels `bridge_component` but iterates a set of source
//! components and emits one combined JSON report. Per-component errors are
//! captured into the report and do not abort the sweep.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::bridge::candidates::{build_candidate_table, drop_candidate_table};
use epigraph_cli::bridge::components::{compute_components, ComponentSummary};
use epigraph_cli::bridge::spine::{compute_spine_destination, SpineUmbrella};
use epigraph_cli::rerank::{rerank_candidates_table, RerankConfig};

const USAGE: &str = r#"
bridge-sweep — bridge multiple disconnected components into the giant CC

USAGE:
  bridge-sweep [--components <UUID,UUID,...> | --all] [OPTIONS]

OPTIONS:
  --components <LIST>        Explicit component UUIDs (mutex with --all)
  --all                      Sweep all components ≥ --min-component-size, excluding target
  --min-component-size <N>   Only with --all [default: 30]
  --target <ID>              Target component (default: giant — largest)
  --min-similarity <FLOAT>   [default: 0.50]
  --top-k <N>                Per-source-atom [default: 50]
  --batch-size <N>           [default: 10]
  --provider <NAME>          [default: claude-cli]
  --model <NAME>             Model override
  --dry-run                  Default.
  --apply                    Commit edges (overrides --dry-run).
  --keep-tables              Don't drop temp candidate tables on exit.
  --report-out <PATH>        JSON report path (else stdout).
  --limit <N>                Per-component LLM evaluation cap.
  -h, --help
"#;

#[derive(Debug)]
struct Args {
    /// Explicit set of component UUIDs to bridge. Mutually exclusive with `all`.
    components: Option<Vec<Uuid>>,
    /// Sweep all components ≥ `min_component_size`, excluding the target.
    all: bool,
    min_component_size: usize,
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

        let mut components: Option<Vec<Uuid>> = None;
        let mut all = false;
        let mut min_component_size = 30_usize;
        let mut target: Option<Uuid> = None;
        let mut min_similarity = 0.50_f64;
        let mut top_k = 50_u32;
        let mut batch_size = 10_usize;
        let mut provider = "claude-cli".to_string();
        let mut model: Option<String> = None;
        let mut apply = false;
        let mut keep_tables = false;
        let mut report_out: Option<String> = None;
        let mut limit: Option<i64> = None;

        let mut i = 1;
        while i < argv.len() {
            match argv[i].as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                "--components" => {
                    i += 1;
                    let v = argv
                        .get(i)
                        .ok_or_else(|| "--components requires a value".to_string())?;
                    let parsed: Result<Vec<Uuid>, _> = v
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(Uuid::parse_str)
                        .collect();
                    let ids = parsed.map_err(|e| {
                        format!("--components expects comma-separated UUIDs; parse error: {e}")
                    })?;
                    if ids.is_empty() {
                        return Err("--components requires at least one UUID".into());
                    }
                    components = Some(ids);
                }
                "--all" => {
                    all = true;
                }
                "--min-component-size" => {
                    i += 1;
                    min_component_size = parse_usize(&argv, i, "--min-component-size")?;
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
                arg => {
                    return Err(format!("Unexpected positional argument: {arg}\n{USAGE}"));
                }
            }
            i += 1;
        }

        // Mutex / required.
        match (components.is_some(), all) {
            (true, true) => {
                return Err("--components and --all are mutually exclusive\n".to_string() + USAGE)
            }
            (false, false) => {
                return Err("must specify --components <LIST> or --all\n".to_string() + USAGE)
            }
            _ => {}
        }

        Ok(Args {
            components,
            all,
            min_component_size,
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
    let report_result = run_sweep(&pool, &args).await;

    let report = match report_result {
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
    eprintln!(
        "Done in {:.2}s ({} components processed)",
        elapsed.as_secs_f64(),
        report.components.len()
    );
}

#[derive(serde::Serialize)]
struct SweepReport {
    sweep_id: Uuid,
    started_at: String,
    target_component_id: Uuid,
    target_size: usize,
    apply: bool,
    config: SweepConfigSummary,
    components: Vec<ComponentReport>,
    duration_ms: u128,
}

#[derive(serde::Serialize)]
struct SweepConfigSummary {
    min_similarity: f64,
    top_k: u32,
    min_component_size: u32,
    provider: String,
    model: Option<String>,
    limit: Option<i64>,
}

#[derive(serde::Serialize)]
struct ComponentReport {
    component_id: Uuid,
    size: usize,
    candidates_table: String,
    candidates_count: usize,
    spine_top_umbrellas: Vec<SpineUmbrella>,
    rerank: Option<RerankReport>,
    error: Option<String>,
    duration_ms: u128,
}

#[derive(serde::Serialize)]
struct RerankReport {
    candidates_evaluated: usize,
    llm_accepted: usize,
    edges_created: usize,
    duration_ms: u128,
}

async fn run_sweep(pool: &PgPool, args: &Args) -> Result<SweepReport, String> {
    let started = std::time::Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let sweep_id = Uuid::new_v4();

    let components = compute_components(pool)
        .await
        .map_err(|e| format!("compute_components: {e}"))?;
    if components.is_empty() {
        return Err("no claims in graph".to_string());
    }

    // Default target = giant = first (compute_components returns sorted desc by size).
    let target_id = match args.target {
        Some(t) => t,
        None => components.first().expect("non-empty").component_id,
    };
    let target_idx = locate_component(&components, &target_id)
        .ok_or_else(|| format!("target component not found: {target_id}"))?;
    let target = &components[target_idx];

    // Resolve sweep set.
    let sweep_indices: Vec<usize> = if args.all {
        components
            .iter()
            .enumerate()
            .filter(|(idx, c)| *idx != target_idx && c.size >= args.min_component_size)
            .map(|(idx, _)| idx)
            .collect()
    } else {
        // --components: each UUID must locate a component; error if any fail.
        let ids = args
            .components
            .as_ref()
            .expect("Args::parse enforces components|all");
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let idx = locate_component(&components, id)
                .ok_or_else(|| format!("component not found: {id}"))?;
            // Defensive: skip self-bridges. A duplicate inside --components is
            // accepted but only processed once below.
            if idx != target_idx && !out.contains(&idx) {
                out.push(idx);
            }
        }
        out
    };

    let total = sweep_indices.len();
    let mut component_reports: Vec<ComponentReport> = Vec::with_capacity(total);

    for (n, &comp_idx) in sweep_indices.iter().enumerate() {
        let component = &components[comp_idx];
        let table_name = format!(
            "bridge_sweep_{}_c{}_candidates",
            sweep_id.simple(),
            comp_idx
        );
        let comp_started = std::time::Instant::now();

        eprintln!(
            "[{n}/{total}] component {} (size={}) → table={}",
            component.component_id,
            component.size,
            table_name,
            n = n + 1,
            total = total,
        );

        let block =
            process_component(pool, args, component, target, &table_name, comp_started).await;
        component_reports.push(block);
    }

    Ok(SweepReport {
        sweep_id,
        started_at,
        target_component_id: target.component_id,
        target_size: target.size,
        apply: args.apply,
        config: SweepConfigSummary {
            min_similarity: args.min_similarity,
            top_k: args.top_k,
            min_component_size: args.min_component_size as u32,
            provider: args.provider.clone(),
            model: args.model.clone(),
            limit: args.limit,
        },
        components: component_reports,
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Run the candidate-build → spine → rerank pipeline for one component.
/// Errors are captured into `ComponentReport.error` so the sweep continues.
async fn process_component(
    pool: &PgPool,
    args: &Args,
    component: &ComponentSummary,
    target: &ComponentSummary,
    table_name: &str,
    started: std::time::Instant,
) -> ComponentReport {
    // Step 1: pull source / target atoms.
    let source_atoms = match level3_atoms_in_component(pool, component).await {
        Ok(v) if v.is_empty() => {
            return ComponentReport {
                component_id: component.component_id,
                size: component.size,
                candidates_table: table_name.to_string(),
                candidates_count: 0,
                spine_top_umbrellas: Vec::new(),
                rerank: None,
                error: Some("source component has no level-3 atoms with embeddings".into()),
                duration_ms: started.elapsed().as_millis(),
            }
        }
        Ok(v) => v,
        Err(e) => {
            return ComponentReport {
                component_id: component.component_id,
                size: component.size,
                candidates_table: table_name.to_string(),
                candidates_count: 0,
                spine_top_umbrellas: Vec::new(),
                rerank: None,
                error: Some(format!("source atoms: {e}")),
                duration_ms: started.elapsed().as_millis(),
            }
        }
    };

    let target_atoms = match level3_atoms_in_component(pool, target).await {
        Ok(v) if v.is_empty() => {
            return ComponentReport {
                component_id: component.component_id,
                size: component.size,
                candidates_table: table_name.to_string(),
                candidates_count: 0,
                spine_top_umbrellas: Vec::new(),
                rerank: None,
                error: Some("target component has no level-3 atoms with embeddings".into()),
                duration_ms: started.elapsed().as_millis(),
            }
        }
        Ok(v) => v,
        Err(e) => {
            return ComponentReport {
                component_id: component.component_id,
                size: component.size,
                candidates_table: table_name.to_string(),
                candidates_count: 0,
                spine_top_umbrellas: Vec::new(),
                rerank: None,
                error: Some(format!("target atoms: {e}")),
                duration_ms: started.elapsed().as_millis(),
            }
        }
    };

    // Step 2: build candidate table.
    let candidates_count = match build_candidate_table(
        pool,
        table_name,
        &source_atoms,
        &target_atoms,
        args.min_similarity,
        args.top_k,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            return ComponentReport {
                component_id: component.component_id,
                size: component.size,
                candidates_table: table_name.to_string(),
                candidates_count: 0,
                spine_top_umbrellas: Vec::new(),
                rerank: None,
                error: Some(format!("build_candidate_table: {e}")),
                duration_ms: started.elapsed().as_millis(),
            }
        }
    };

    // Step 3: spine BEFORE the LLM step (graph-health diagnostic).
    let spine = match compute_spine_destination(pool, table_name, 5).await {
        Ok(v) => v,
        Err(e) => {
            // Record the error but continue to the rerank step — spine is a
            // diagnostic, not a precondition.
            eprintln!(
                "WARN: compute_spine_destination for {} failed: {e}",
                component.component_id
            );
            Vec::new()
        }
    };

    // Step 4: rerank if there are candidates.
    let rerank = if candidates_count > 0 {
        let config = RerankConfig {
            min_similarity: args.min_similarity,
            batch_size: args.batch_size,
            provider: args.provider.clone(),
            model: args.model.clone(),
            dry_run: !args.apply,
            limit: args.limit,
            verbose: false,
        };
        match rerank_candidates_table(pool, table_name, &config).await {
            Ok(s) => Some(RerankReport {
                candidates_evaluated: s.candidates_evaluated,
                llm_accepted: s.llm_accepted,
                edges_created: s.edges_created,
                duration_ms: s.duration_ms,
            }),
            Err(e) => {
                if !args.keep_tables {
                    let _ = drop_candidate_table(pool, table_name).await;
                }
                return ComponentReport {
                    component_id: component.component_id,
                    size: component.size,
                    candidates_table: table_name.to_string(),
                    candidates_count,
                    spine_top_umbrellas: spine,
                    rerank: None,
                    error: Some(format!("rerank: {e}")),
                    duration_ms: started.elapsed().as_millis(),
                };
            }
        }
    } else {
        None
    };

    // Step 5: drop temp table unless --keep-tables.
    if !args.keep_tables {
        let _ = drop_candidate_table(pool, table_name).await; // best-effort
    }

    ComponentReport {
        component_id: component.component_id,
        size: component.size,
        candidates_table: table_name.to_string(),
        candidates_count,
        spine_top_umbrellas: spine,
        rerank,
        error: None,
        duration_ms: started.elapsed().as_millis(),
    }
}

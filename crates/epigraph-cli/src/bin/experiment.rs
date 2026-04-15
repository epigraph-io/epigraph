//! Experiment lifecycle CLI.
//!
//! experiment create <hypothesis_id> --agent-id UUID [--method-ids id1,id2]
//! experiment design <hypothesis_id> [--llm]
//! experiment search-methods <hypothesis_id> [--gap "description"]
//! experiment start <experiment_id>
//! experiment submit <experiment_id> <results.json>
//! experiment add <result_id> <measurements.json>
//! experiment analyze <result_id> --direction supports|refutes [--scope "limitation1,limitation2"]

use clap::{Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "experiment", about = "Manage experimental lifecycle")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new experiment for a hypothesis
    Create {
        /// Hypothesis claim UUID
        hypothesis_id: Uuid,
        /// Agent UUID
        #[arg(long, env = "EPIGRAPH_AGENT_ID")]
        agent_id: Uuid,
        /// Method UUIDs (comma-separated)
        #[arg(long, value_delimiter = ',')]
        method_ids: Vec<Uuid>,
        /// Protocol description
        #[arg(long)]
        protocol: Option<String>,
    },
    /// Show experiment design with methods and evidence scores
    Design {
        /// Hypothesis claim UUID
        hypothesis_id: Uuid,
        /// Use LLM for full protocol generation (delegates to protocol_gen)
        #[arg(long)]
        llm: bool,
        /// Output path for LLM-generated protocol
        #[arg(long, default_value = "docs/protocols/generated-protocol.md")]
        output: String,
    },
    /// Search web for method evidence to fill gaps
    SearchMethods {
        /// Hypothesis claim UUID
        hypothesis_id: Uuid,
        /// Search for a specific gap
        #[arg(long)]
        gap: Option<String>,
    },
    /// Start an experiment (set status to running)
    Start {
        /// Experiment UUID
        experiment_id: Uuid,
    },
    /// Submit results for an experiment
    Submit {
        /// Experiment UUID
        experiment_id: Uuid,
        /// Path to results JSON file
        results_file: String,
    },
    /// Add measurements to an existing result
    Add {
        /// Experiment result UUID
        result_id: Uuid,
        /// Path to measurements JSON file
        measurements_file: String,
    },
    /// Analyze results and build mass function
    Analyze {
        /// Experiment result UUID
        result_id: Uuid,
        /// Evidence direction
        #[arg(long)]
        direction: String,
        /// Agent UUID
        #[arg(long, env = "EPIGRAPH_AGENT_ID")]
        agent_id: Uuid,
        /// Scope limitations (comma-separated)
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
        /// Expected value for effect size calculation
        #[arg(long)]
        expected_value: Option<f64>,
    },
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let pool = epigraph_cli::db_connect().await?;

    match cli.command {
        Command::Create {
            hypothesis_id,
            agent_id,
            method_ids,
            protocol,
        } => {
            let method_ids_opt = if method_ids.is_empty() {
                None
            } else {
                Some(method_ids)
            };
            let exp_id = epigraph_db::ExperimentRepository::create(
                &pool,
                hypothesis_id,
                agent_id,
                method_ids_opt.as_deref(),
                protocol.as_deref(),
                None,
            )
            .await?;

            // Create tests_hypothesis edge (matches API behavior)
            sqlx::query(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'experiment', $2, 'claim', 'tests_hypothesis', '{}')",
            ).bind(exp_id).bind(hypothesis_id).execute(&pool).await.ok();

            println!("Experiment created: {exp_id}");
            Ok(())
        }
        Command::Design {
            hypothesis_id,
            llm,
            output,
        } => {
            if llm {
                // Delegate to protocol_gen binary
                let status = tokio::process::Command::new("protocol_gen")
                    .arg(hypothesis_id.to_string())
                    .arg("--output")
                    .arg(&output)
                    .status()
                    .await
                    .map_err(|e| format!("Failed to run protocol_gen: {e}"))?;
                if !status.success() {
                    return Err("protocol_gen failed".into());
                }
            } else {
                design_skeleton(&pool, hypothesis_id).await?;
            }
            Ok(())
        }
        Command::SearchMethods { hypothesis_id, gap } => {
            // Delegate to method_search binary
            let mut cmd = tokio::process::Command::new("method_search");
            cmd.arg(hypothesis_id.to_string());
            if let Some(g) = &gap {
                cmd.arg("--gap").arg(g);
            }
            let status = cmd
                .status()
                .await
                .map_err(|e| format!("Failed to run method_search: {e}"))?;
            if !status.success() {
                return Err("method_search reported remaining gaps".into());
            }
            Ok(())
        }
        Command::Start { experiment_id } => {
            // update_status already sets started_at when status = "running"
            epigraph_db::ExperimentRepository::update_status(&pool, experiment_id, "running")
                .await?;
            println!("Experiment {experiment_id} started");
            Ok(())
        }
        Command::Submit {
            experiment_id,
            results_file,
        } => submit_results(&pool, experiment_id, &results_file).await,
        Command::Add {
            result_id,
            measurements_file,
        } => add_measurements(&pool, result_id, &measurements_file).await,
        Command::Analyze {
            result_id,
            direction,
            agent_id,
            scope,
            expected_value,
        } => {
            analyze(
                &pool,
                result_id,
                &direction,
                agent_id,
                &scope,
                expected_value,
            )
            .await
        }
    }
}

async fn design_skeleton(
    pool: &sqlx::PgPool,
    hypothesis_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let (statement,): (String,) = sqlx::query_as("SELECT content FROM claims WHERE id = $1")
        .bind(hypothesis_id)
        .fetch_one(pool)
        .await?;

    let experiments =
        epigraph_db::ExperimentRepository::get_for_hypothesis(pool, hypothesis_id).await?;

    println!("Hypothesis: {statement}");
    println!("Experiments: {}\n", experiments.len());

    for exp in &experiments {
        println!("Experiment: {} (status: {})", exp.id, exp.status);
        if let Some(method_ids) = &exp.method_ids {
            for mid in method_ids {
                if let Some(method) = epigraph_db::MethodRepository::get(pool, *mid).await? {
                    let evidence =
                        epigraph_db::MethodRepository::get_evidence_strength(pool, method.id)
                            .await
                            .ok();
                    let score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);
                    let gap = if score < 0.3 { " [GAP]" } else { "" };
                    println!(
                        "  Method: {} ({}){}",
                        method.name, method.technique_type, gap
                    );
                    println!(
                        "    Evidence: {score:.3} ({} source claims)",
                        method.source_claim_ids.len()
                    );
                    if let Some(conditions) = &method.typical_conditions {
                        println!("    Conditions: {conditions}");
                    }
                }
            }
        }
        println!();
    }

    if experiments.is_empty() {
        println!("No experiments designed yet. Use the API to design an experiment first.");
    }

    Ok(())
}

async fn submit_results(
    pool: &sqlx::PgPool,
    experiment_id: Uuid,
    results_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(results_file)
        .map_err(|e| format!("Cannot read {results_file}: {e}"))?;
    let results: serde_json::Value = serde_json::from_str(&file_content)
        .map_err(|e| format!("Invalid JSON in {results_file}: {e}"))?;

    let data_source = results
        .get("data_source")
        .and_then(|v| v.as_str())
        .unwrap_or("manual");

    let measurements = results
        .get("measurements")
        .and_then(|v| v.as_array())
        .ok_or("results.json must contain 'measurements' array")?;

    let result_id = epigraph_db::ExperimentResultRepository::create(
        pool,
        experiment_id,
        data_source,
        &serde_json::json!(measurements),
        measurements.len() as i32,
    )
    .await?;

    // Create result_of edge (matches API behavior)
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'experiment_result', $2, 'experiment', 'result_of', '{}')",
    )
    .bind(result_id)
    .bind(experiment_id)
    .execute(pool)
    .await
    .ok();

    // Update experiment status to collecting
    epigraph_db::ExperimentRepository::update_status(pool, experiment_id, "collecting")
        .await
        .ok();

    println!("Result submitted: {result_id}");
    println!("Measurements: {}", measurements.len());
    Ok(())
}

async fn add_measurements(
    pool: &sqlx::PgPool,
    result_id: Uuid,
    measurements_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(measurements_file)
        .map_err(|e| format!("Cannot read {measurements_file}: {e}"))?;
    let new_measurements: Vec<serde_json::Value> = serde_json::from_str(&file_content)
        .map_err(|e| format!("Invalid JSON array in {measurements_file}: {e}"))?;

    // Append to existing raw_measurements
    sqlx::query(
        r#"
        UPDATE experiment_results
        SET raw_measurements = raw_measurements || $2::jsonb,
            measurement_count = measurement_count + $3
        WHERE id = $1
        "#,
    )
    .bind(result_id)
    .bind(serde_json::json!(new_measurements))
    .bind(new_measurements.len() as i32)
    .execute(pool)
    .await?;

    println!(
        "Added {} measurements to result {result_id}",
        new_measurements.len()
    );
    Ok(())
}

async fn analyze(
    pool: &sqlx::PgPool,
    result_id: Uuid,
    direction: &str,
    agent_id: Uuid,
    scope_strs: &[String],
    expected_value: Option<f64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use epigraph_engine::{build_error_mass, ErrorBudget, EvidenceDirection, ScopeLimitation};

    // Load result and experiment
    let result = epigraph_db::ExperimentResultRepository::get(pool, result_id)
        .await?
        .ok_or(format!("Result {result_id} not found"))?;
    let experiment = epigraph_db::ExperimentRepository::get(pool, result.experiment_id)
        .await?
        .ok_or(format!("Experiment {} not found", result.experiment_id))?;

    // Parse measurements
    let raw_measurements: Vec<serde_json::Value> =
        serde_json::from_value(result.raw_measurements.clone())?;

    // Circularity guard: check sources are grounded (same logic as API route)
    for m in &raw_measurements {
        if let Some(source_id) = m.get("source").and_then(|v| v.as_str()) {
            if let Ok(src_uuid) = source_id.parse::<Uuid>() {
                // Reject self-referencing measurement (source == hypothesis)
                if src_uuid == experiment.hypothesis_id {
                    return Err(format!(
                        "Measurement source {src_uuid} is the hypothesis itself — circular"
                    )
                    .into());
                }
                // Use same grounding check as API: ClaimRepository::has_grounded_evidence
                let grounded = epigraph_db::ClaimRepository::has_grounded_evidence(pool, src_uuid)
                    .await
                    .unwrap_or(false);
                if !grounded {
                    return Err(format!(
                        "Measurement source {src_uuid} lacks grounded evidence \
                         (no paper, experimental data, or analysis provenance). \
                         Claim-to-claim propagation is not sufficient evidence."
                    )
                    .into());
                }
            }
        }
    }

    // Aggregate errors
    let expected = expected_value.unwrap_or(0.0);
    let (random_err, systematic_err, effect_size) = aggregate_errors(&raw_measurements, expected);

    // Parse scope limitations
    let scope_lims: Vec<ScopeLimitation> = scope_strs
        .iter()
        .map(|s| match s.as_str() {
            "single_temperature_point" => ScopeLimitation::SingleTemperaturePoint,
            "single_material_system" => ScopeLimitation::SingleMaterialSystem,
            "non_standard_environment" => ScopeLimitation::NonStandardEnvironment,
            "small_sample_size" => ScopeLimitation::SmallSampleSize,
            "proxy_measurement" => ScopeLimitation::ProxyMeasurement,
            _ => ScopeLimitation::Custom(0.05),
        })
        .collect();

    let dir = if direction == "supports" {
        EvidenceDirection::Supports
    } else {
        EvidenceDirection::Refutes
    };

    let budget = ErrorBudget {
        random_error: random_err,
        systematic_error: systematic_err,
        scope_limitations: scope_lims,
        effect_size,
        direction: dir,
    };

    let mass_result = build_error_mass(&budget)?;

    // Create analysis node
    let analysis_id: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO analyses (analysis_type, method_description, inference_path, agent_id, properties)
        VALUES ('automated', 'Error-derived mass function from experimental measurements',
                'novel', $1, $2)
        RETURNING id
        "#,
    )
    .bind(agent_id)
    .bind(serde_json::json!({
        "scope_limitations": scope_strs.iter().map(|s| serde_json::json!({"type": s})).collect::<Vec<_>>(),
        "error_budget": {
            "random_contribution": random_err,
            "systematic_contribution": systematic_err,
            "m_supported": if direction == "supports" { mass_result.m_evidence } else { 0.0 },
            "m_unsupported": if direction == "refutes" { mass_result.m_evidence } else { 0.0 },
            "m_frame_ignorance": mass_result.m_frame_ignorance,
            "m_open_world": mass_result.m_open_world,
        },
        "supports_hypothesis": direction == "supports",
    }))
    .fetch_one(pool)
    .await?;

    // Create edges
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'analysis', $2, 'experiment_result', 'analyzes', '{}')",
    ).bind(analysis_id.0).bind(result_id).execute(pool).await?;

    sqlx::query(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'analysis', $2, 'claim', 'provides_evidence', $3)
        "#,
    )
    .bind(analysis_id.0)
    .bind(experiment.hypothesis_id)
    .bind(serde_json::json!({
        "direction": direction,
        "precision_ratio": mass_result.precision_ratio,
        "evidence_strength": mass_result.evidence_strength,
    }))
    .execute(pool)
    .await?;

    // Submit mass function
    let frame_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(pool)
            .await?;

    let masses_json = mass_result.mass_function.masses_to_json();
    epigraph_db::MassFunctionRepository::store(
        pool,
        experiment.hypothesis_id,
        frame_id.0,
        Some(agent_id),
        &masses_json,
        None,
        Some("error_derived"),
    )
    .await?;

    // Update statuses
    epigraph_db::ExperimentResultRepository::update_status(pool, result_id, "complete")
        .await
        .ok();
    epigraph_db::ExperimentRepository::update_status(pool, result.experiment_id, "complete")
        .await
        .ok();

    println!("Analysis created: {}", analysis_id.0);
    println!("Hypothesis: {}", experiment.hypothesis_id);
    println!("Direction: {direction}");
    println!("Evidence strength: {:.4}", mass_result.evidence_strength);
    println!("Precision ratio: {:.4}", mass_result.precision_ratio);

    Ok(())
}

/// Aggregate errors from measurement array (same logic as experiment_loop.rs).
fn aggregate_errors(measurements: &[serde_json::Value], expected_value: f64) -> (f64, f64, f64) {
    if measurements.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let mut random_sum_sq = 0.0;
    let mut systematic_sum_sq = 0.0;
    let mut effect_sum = 0.0;
    let mut count = 0.0;

    for m in measurements {
        let random = m
            .get("random_error")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let systematic = m
            .get("systematic_error")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let n_avg = m
            .get("n_averaged")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0)
            .max(1.0);
        let value = m.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);

        let effective_random = random / n_avg.sqrt();
        random_sum_sq += effective_random.powi(2);
        systematic_sum_sq += systematic.powi(2);
        effect_sum += (value - expected_value).abs();
        count += 1.0;
    }

    let random_rms = (random_sum_sq / count).sqrt();
    let systematic_rms = (systematic_sum_sq / count).sqrt();
    let effect_size = effect_sum / count;

    (random_rms, systematic_rms, effect_size)
}

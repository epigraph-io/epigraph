//! Hypothesis lifecycle CLI.
//!
//! hypothesis create "statement" [--search-radius 0.3] [--agent-id UUID]
//! hypothesis status <id>
//! hypothesis promote <id>

use clap::{Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "hypothesis", about = "Manage epistemic hypotheses")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new hypothesis claim with VOI assessment
    Create {
        /// Hypothesis statement
        statement: String,
        /// Semantic search radius for neighborhood
        #[arg(long, default_value = "0.3")]
        search_radius: f64,
        /// Agent UUID
        #[arg(long, env = "EPIGRAPH_AGENT_ID")]
        agent_id: Uuid,
        /// Optional research question
        #[arg(long)]
        research_question: Option<String>,
    },
    /// Show hypothesis status and promotion readiness
    Status {
        /// Hypothesis claim UUID
        id: Uuid,
    },
    /// Promote hypothesis to research_validity frame
    Promote {
        /// Hypothesis claim UUID
        id: Uuid,
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
            statement,
            search_radius,
            agent_id,
            research_question,
        } => {
            create(
                &pool,
                &statement,
                search_radius,
                agent_id,
                research_question.as_deref(),
            )
            .await
        }
        Command::Status { id } => status(&pool, id).await,
        Command::Promote { id } => promote(&pool, id).await,
    }
}

async fn create(
    pool: &sqlx::PgPool,
    statement: &str,
    search_radius: f64,
    agent_id: Uuid,
    research_question: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Embed the hypothesis
    let embedder = epigraph_cli::embedding_service()
        .ok_or("OPENAI_API_KEY not set — embeddings required for hypothesis creation")?;
    let embedding = embedder
        .generate(statement)
        .await
        .map_err(|e| format!("Embedding failed: {e}"))?;

    // 2. Create claim
    let content_hash = epigraph_crypto::ContentHasher::hash(statement.as_bytes());
    let embedding_str = format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    let claim_id: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties, embedding)
        VALUES ($1, $2, $3, 0.5, ARRAY['hypothesis'], $4, $5::vector)
        RETURNING id
        "#,
    )
    .bind(statement)
    .bind(content_hash.as_slice())
    .bind(agent_id)
    .bind(serde_json::json!({
        "hypothesis_status": "active",
        "research_question": research_question,
        "search_radius": search_radius,
    }))
    .bind(&embedding_str)
    .fetch_one(pool)
    .await?;

    // 3. Add to hypothesis_assessment frame
    let frame_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("hypothesis_assessment frame not found: {e}"))?;

    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim_id.0)
    .bind(frame_id.0)
    .execute(pool)
    .await?;

    // 4. Compute VOI
    #[allow(clippy::type_complexity)]
    let neighbors: Vec<(Uuid, Option<f64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        r#"
        SELECT c.id, c.belief, c.plausibility,
               1 - (c.embedding <=> $1::vector) AS similarity
        FROM claims c
        WHERE c.embedding IS NOT NULL
          AND c.id != $2
          AND 1 - (c.embedding <=> $1::vector) >= $3
          AND EXISTS (
              SELECT 1 FROM edges e
              WHERE e.target_id = c.id AND e.target_type = 'claim'
                AND e.source_type IN ('paper', 'evidence', 'analysis')
                AND e.relationship IN ('asserts', 'SUPPORTS', 'concludes', 'provides_evidence')
          )
        ORDER BY similarity DESC LIMIT 50
        "#,
    )
    .bind(&embedding_str)
    .bind(claim_id.0)
    .bind(search_radius)
    .fetch_all(pool)
    .await?;

    let voi_neighbors: Vec<epigraph_engine::Neighbor> = neighbors
        .iter()
        .map(|(_, b, p, s)| epigraph_engine::Neighbor {
            belief: b.unwrap_or(0.0),
            plausibility: p.unwrap_or(1.0),
            similarity: s.unwrap_or(0.0),
        })
        .collect();

    let voi = epigraph_engine::compute_voi(&voi_neighbors);

    // 5. Cache VOI
    sqlx::query("UPDATE claims SET properties = properties || $2 WHERE id = $1")
        .bind(claim_id.0)
        .bind(serde_json::json!({"voi_score": voi.score}))
        .execute(pool)
        .await
        .ok();

    // 6. Submit vacuous prior
    let vacuous_masses = serde_json::json!({"0,1": 1.0});
    epigraph_db::MassFunctionRepository::store(
        pool,
        claim_id.0,
        frame_id.0,
        Some(agent_id),
        &vacuous_masses,
        None,
        Some("prior"),
    )
    .await?;

    println!("Hypothesis created: {}", claim_id.0);
    println!("VOI score: {:.3}", voi.score);
    println!("Grounded neighbors: {}", neighbors.len());

    Ok(())
}

async fn status(pool: &sqlx::PgPool, id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    // Load claim
    let (content, properties): (String, serde_json::Value) =
        sqlx::query_as("SELECT content, properties FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|_| format!("Hypothesis {id} not found"))?;

    // Experiments
    let experiments = epigraph_db::ExperimentRepository::get_for_hypothesis(pool, id).await?;
    let completed_with_analysis =
        epigraph_db::ExperimentRepository::count_completed_with_analysis(pool, id)
            .await
            .unwrap_or(0);

    // Mass functions
    let frame_id: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_optional(pool)
            .await?;

    let (bel_supported, bel_unsupported) = if let Some((fid,)) = frame_id {
        let mass_rows = epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, id, fid)
            .await
            .unwrap_or_default();
        if let Some(latest) = mass_rows.last() {
            (
                latest
                    .masses
                    .get("0")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                latest
                    .masses
                    .get("1")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
            )
        } else {
            (0.0, 0.0)
        }
    } else {
        (0.0, 0.0)
    };

    // Scope check
    let has_scope: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM analyses a
            JOIN edges e ON e.source_id = a.id AND e.source_type = 'analysis'
                        AND e.target_id = $1 AND e.target_type = 'claim'
                        AND e.relationship = 'provides_evidence'
            WHERE a.properties->>'scope_limitations' IS NOT NULL
              AND a.properties->'scope_limitations' != '[]'::jsonb
        )
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or((false,));

    let promotion_input = epigraph_engine::PromotionInput {
        bel_supported,
        bel_unsupported,
        completed_experiments_with_analysis: completed_with_analysis as usize,
        has_explicit_scope: has_scope.0,
    };
    let promotion = epigraph_engine::evaluate_promotion(&promotion_input);

    let status_str = properties
        .get("hypothesis_status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("Hypothesis: {id}");
    println!("Status: {status_str}");
    println!("Statement: {content}");
    println!("\nBelief:");
    println!("  Supported:   {bel_supported:.4}");
    println!("  Unsupported: {bel_unsupported:.4}");
    println!(
        "\nExperiments: {} total, {} with analysis",
        experiments.len(),
        completed_with_analysis
    );
    println!(
        "\nPromotion: {}",
        if promotion.ready {
            "READY"
        } else {
            "NOT READY"
        }
    );
    if !promotion.failures.is_empty() {
        println!("Failures:");
        for f in &promotion.failures {
            println!("  - {f:?}");
        }
    }

    Ok(())
}

async fn promote(pool: &sqlx::PgPool, id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    // Re-check gate (inline the logic from status)
    let completed_with_analysis =
        epigraph_db::ExperimentRepository::count_completed_with_analysis(pool, id)
            .await
            .unwrap_or(0);

    let hyp_frame: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(pool)
            .await?;

    let mass_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, id, hyp_frame.0).await?;
    let (bel_supported, bel_unsupported) = if let Some(latest) = mass_rows.last() {
        (
            latest
                .masses
                .get("0")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
            latest
                .masses
                .get("1")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
        )
    } else {
        (0.0, 0.0)
    };

    let has_scope: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM analyses a
            JOIN edges e ON e.source_id = a.id AND e.source_type = 'analysis'
                        AND e.target_id = $1 AND e.target_type = 'claim'
                        AND e.relationship = 'provides_evidence'
            WHERE a.properties->>'scope_limitations' IS NOT NULL
              AND a.properties->'scope_limitations' != '[]'::jsonb
        )
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or((false,));

    let promotion_input = epigraph_engine::PromotionInput {
        bel_supported,
        bel_unsupported,
        completed_experiments_with_analysis: completed_with_analysis as usize,
        has_explicit_scope: has_scope.0,
    };
    let promotion = epigraph_engine::evaluate_promotion(&promotion_input);

    if !promotion.ready {
        return Err(format!(
            "Hypothesis not ready for promotion: {:?}",
            promotion.failures
        )
        .into());
    }

    // Execute promotion transaction
    let rv_frame: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'research_validity'")
            .fetch_one(pool)
            .await?;

    let mut tx = pool.begin().await?;

    // Copy mass function
    if let Some(latest) = mass_rows.last() {
        sqlx::query(
            r#"
            INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (claim_id, frame_id, source_agent_id, perspective_id) DO UPDATE
            SET masses = EXCLUDED.masses, conflict_k = EXCLUDED.conflict_k, created_at = NOW()
            "#,
        )
        .bind(id).bind(rv_frame.0).bind(latest.source_agent_id)
        .bind(&latest.masses).bind(latest.conflict_k).bind(latest.combination_method.as_deref())
        .execute(&mut *tx).await?;
    }

    // Add to research_validity frame
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING")
        .bind(id).bind(rv_frame.0).execute(&mut *tx).await?;

    // Move factors
    sqlx::query("UPDATE factors SET frame_id = $3 WHERE frame_id = $1 AND $2 = ANY(variable_ids)")
        .bind(hyp_frame.0)
        .bind(id)
        .bind(rv_frame.0)
        .execute(&mut *tx)
        .await?;

    // Update status
    sqlx::query("UPDATE claims SET properties = properties || '{\"hypothesis_status\": \"promoted\"}' WHERE id = $1")
        .bind(id).execute(&mut *tx).await?;

    tx.commit().await?;

    println!("Hypothesis {id} promoted to research_validity");
    println!("Research validity frame: {}", rv_frame.0);

    Ok(())
}

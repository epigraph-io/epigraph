//! DEKG CLI — command-line interface for Dempster-Shafer knowledge graph operations
//!
//! Wraps the `EpiGraph` REST API with ergonomic CLI commands for frames, beliefs,
//! divergence, conflict analysis, evidence submission, and entity management.
//!
//! Usage:
//!   `dekg frame list`
//!   `dekg belief show <claim_id>`
//!   `dekg divergence report --threshold 0.3`
//!   `dekg evidence submit <content> --frame <id> --mass '{"0": 0.7, "0,1": 0.3}'`

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

// =============================================================================
// CLI STRUCTURE
// =============================================================================

#[derive(Parser)]
#[command(
    name = "dekg",
    about = "DEKG CLI — Dempster-Shafer Knowledge Graph operations"
)]
struct Cli {
    /// Base URL of the `EpiGraph` API (or set `EPIGRAPH_API_URL`)
    #[arg(
        long,
        env = "EPIGRAPH_API_URL",
        default_value = "http://localhost:3000"
    )]
    api_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Frame management
    Frame {
        #[command(subcommand)]
        action: FrameCmd,
    },
    /// Belief interval queries
    Belief {
        #[command(subcommand)]
        action: BeliefCmd,
    },
    /// DS vs Bayesian divergence
    Divergence {
        #[command(subcommand)]
        action: DivergenceCmd,
    },
    /// Conflict analysis
    Conflict {
        #[command(subcommand)]
        action: ConflictCmd,
    },
    /// Evidence submission
    Evidence {
        #[command(subcommand)]
        action: EvidenceCmd,
    },
    /// Agent management
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// Perspective management
    Perspective {
        #[command(subcommand)]
        action: PerspectiveCmd,
    },
    /// Community management
    Community {
        #[command(subcommand)]
        action: CommunityCmd,
    },
    /// Migration tooling (connects directly to DB via DATABASE_URL)
    Migrate {
        #[command(subcommand)]
        action: MigrateCmd,
    },
}

// =============================================================================
// FRAME COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum FrameCmd {
    /// List all frames
    List {
        #[arg(long, default_value = "50")]
        limit: i64,
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Show a specific frame
    Show { id: Uuid },
    /// Create a new frame
    Create {
        name: String,
        /// Comma-separated hypothesis names
        #[arg(long, value_delimiter = ',')]
        hypotheses: Vec<String>,
        #[arg(long)]
        description: Option<String>,
    },
}

// =============================================================================
// BELIEF COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum BeliefCmd {
    /// Show belief interval for a claim
    Show { claim_id: Uuid },
    /// Show scoped belief for a claim
    Scoped {
        claim_id: Uuid,
        #[arg(long, default_value = "global")]
        scope: String,
        #[arg(long)]
        scope_id: Option<Uuid>,
    },
    /// Compare all scopes for a claim
    Compare { claim_id: Uuid },
    /// List claims in a frame sorted by ignorance
    Ignorance {
        frame_id: Uuid,
        #[arg(long, default_value = "50")]
        limit: i64,
    },
}

// =============================================================================
// DIVERGENCE COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum DivergenceCmd {
    /// Show top divergent claims
    Report {
        #[arg(long, default_value = "10")]
        limit: i64,
    },
    /// Show divergence for a specific claim
    Show { claim_id: Uuid },
}

// =============================================================================
// CONFLICT COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum ConflictCmd {
    /// List frames sorted by conflict level
    List {
        #[arg(long, default_value = "50")]
        limit: i64,
    },
    /// Show conflict detail for a frame
    Show { frame_id: Uuid },
}

// =============================================================================
// EVIDENCE COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum EvidenceCmd {
    /// Submit mass function evidence
    Submit {
        /// Claim ID to submit evidence for
        claim_id: Uuid,
        /// Frame ID
        #[arg(long)]
        frame: Uuid,
        /// Mass assignments as JSON (e.g. '{"0": 0.7, "0,1": 0.3}')
        #[arg(long)]
        mass: String,
        /// Agent ID
        #[arg(long)]
        agent_id: Option<Uuid>,
        /// Reliability discount [0, 1]
        #[arg(long, default_value = "1.0")]
        reliability: f64,
    },
    /// List claims in a frame
    List {
        frame_id: Uuid,
        #[arg(long, default_value = "50")]
        limit: i64,
    },
}

// =============================================================================
// AGENT COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum AgentCmd {
    /// List all agents
    List,
    /// Create a new agent
    Create {
        name: String,
        #[arg(long, default_value = "human")]
        agent_type: String,
    },
}

// =============================================================================
// PERSPECTIVE COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum PerspectiveCmd {
    /// List perspectives for an agent
    List {
        #[arg(long)]
        agent_id: Uuid,
    },
    /// Create a new perspective
    Create {
        name: String,
        #[arg(long)]
        agent_id: Uuid,
        #[arg(long)]
        perspective_type: Option<String>,
    },
}

// =============================================================================
// COMMUNITY COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum CommunityCmd {
    /// List all communities
    List,
    /// Create a new community
    Create {
        name: String,
        #[arg(long, default_value = "open")]
        governance: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// Show scoped belief for a community
    Beliefs {
        community_id: Uuid,
        #[arg(long)]
        claim_id: Uuid,
    },
}

// =============================================================================
// MIGRATE COMMANDS
// =============================================================================

#[derive(Subcommand)]
enum MigrateCmd {
    /// Validate DB integrity: Bel <= Pl, mass sums ≈ 1.0, frames have hypotheses
    Validate {
        /// Database URL (overrides DATABASE_URL env var)
        #[arg(long, env = "DATABASE_URL")]
        db_url: String,
    },
    /// Re-create mass functions from truth_value for claims without BBAs
    BootstrapMasses {
        /// Database URL (overrides DATABASE_URL env var)
        #[arg(long, env = "DATABASE_URL")]
        db_url: String,
        /// Confidence scaling factor for mass assignment
        #[arg(long, default_value = "0.7")]
        confidence_scale: f64,
    },
    /// Report agent statistics
    ExtractAgents {
        /// Database URL (overrides DATABASE_URL env var)
        #[arg(long, env = "DATABASE_URL")]
        db_url: String,
    },
    /// Backfill edges from FK references (perspectives, community members, mass functions)
    MaterializeEdges {
        /// Database URL (overrides DATABASE_URL env var)
        #[arg(long, env = "DATABASE_URL")]
        db_url: String,
        /// Dry run: report what would be created without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Auto-create frames by clustering claim embeddings (k-means via linfa)
    CreateFrames {
        /// Database URL (overrides DATABASE_URL env var)
        #[arg(long, env = "DATABASE_URL")]
        db_url: String,
        /// Minimum k for k-means search
        #[arg(long, default_value = "2")]
        k_min: usize,
        /// Maximum k for k-means search
        #[arg(long, default_value = "10")]
        k_max: usize,
        /// Minimum claims per cluster to create a frame
        #[arg(long, default_value = "3")]
        min_claims: usize,
        /// Dry run: report what would be created without writing
        #[arg(long)]
        dry_run: bool,
    },
}

// =============================================================================
// RESPONSE TYPES (minimal, for deserialization)
// =============================================================================

#[derive(Deserialize)]
struct FrameResponse {
    id: Uuid,
    name: String,
    #[allow(dead_code)]
    description: Option<String>,
    hypotheses: Vec<String>,
    #[allow(dead_code)]
    parent_frame_id: Option<Uuid>,
    is_refinable: bool,
    #[allow(dead_code)]
    created_at: String,
}

#[derive(Deserialize)]
struct BeliefResponse {
    claim_id: Uuid,
    belief: Option<f64>,
    plausibility: Option<f64>,
    ignorance: Option<f64>,
    #[allow(dead_code)]
    mass_on_conflict: Option<f64>,
    pignistic_prob: Option<f64>,
    mass_function_count: i64,
}

#[derive(Deserialize)]
struct DivergenceResponseItem {
    #[allow(dead_code)]
    id: Uuid,
    claim_id: Uuid,
    #[allow(dead_code)]
    frame_id: Uuid,
    pignistic_prob: f64,
    bayesian_posterior: f64,
    kl_divergence: f64,
    #[allow(dead_code)]
    computed_at: String,
}

#[derive(Deserialize)]
struct FrameConflictResponse {
    frame_id: Uuid,
    source_count: i64,
    avg_conflict_k: Option<f64>,
    max_conflict_k: Option<f64>,
}

#[derive(Deserialize)]
struct ScopedBeliefEntry {
    scope_type: String,
    scope_id: Option<Uuid>,
    belief: f64,
    plausibility: f64,
    ignorance: f64,
    #[allow(dead_code)]
    mass_on_conflict: f64,
    pignistic_prob: Option<f64>,
    #[allow(dead_code)]
    conflict_k: Option<f64>,
    #[allow(dead_code)]
    strategy_used: Option<String>,
    #[allow(dead_code)]
    computed_at: String,
}

#[derive(Deserialize)]
struct AllScopesResponse {
    claim_id: Uuid,
    scopes: Vec<ScopedBeliefEntry>,
}

#[derive(Deserialize)]
struct FrameClaimRow {
    claim_id: Uuid,
    content: String,
    #[allow(dead_code)]
    hypothesis_index: Option<i32>,
    belief: Option<f64>,
    plausibility: Option<f64>,
    ignorance: Option<f64>,
}

#[derive(Deserialize)]
struct EvidenceSubmissionResponse {
    mass_function_id: Uuid,
    updated_belief: f64,
    updated_plausibility: f64,
    pignistic_prob: Option<f64>,
    #[allow(dead_code)]
    bayesian_posterior: Option<f64>,
    total_sources: i64,
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();
    let base = cli.api_url.trim_end_matches('/');

    match cli.command {
        Commands::Frame { action } => handle_frame(&client, base, action).await,
        Commands::Belief { action } => handle_belief(&client, base, action).await,
        Commands::Divergence { action } => handle_divergence(&client, base, action).await,
        Commands::Conflict { action } => handle_conflict(&client, base, action).await,
        Commands::Evidence { action } => handle_evidence(&client, base, action).await,
        Commands::Agent { action } => handle_agent(&client, base, action).await,
        Commands::Perspective { action } => handle_perspective(&client, base, action).await,
        Commands::Community { action } => handle_community(&client, base, action).await,
        Commands::Migrate { action } => handle_migrate(action).await,
    }
}

// =============================================================================
// HANDLERS
// =============================================================================

async fn handle_frame(client: &Client, base: &str, action: FrameCmd) -> Result<()> {
    match action {
        FrameCmd::List { limit, offset } => {
            let url = format!("{base}/api/v1/frames?limit={limit}&offset={offset}");
            let frames: Vec<FrameResponse> = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse frames response")?;

            println!("{:<36}  {:<30}  {:<5}  Hypotheses", "ID", "Name", "Refs?");
            println!("{}", "-".repeat(90));
            for f in &frames {
                let refinable = if f.is_refinable { "yes" } else { "no" };
                println!(
                    "{:<36}  {:<30}  {:<5}  {}",
                    f.id,
                    f.name,
                    refinable,
                    f.hypotheses.join(", ")
                );
            }
            println!("\n{} frame(s) returned", frames.len());
        }
        FrameCmd::Show { id } => {
            let url = format!("{base}/api/v1/frames/{id}");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse frame response")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        FrameCmd::Create {
            name,
            hypotheses,
            description,
        } => {
            let url = format!("{base}/api/v1/frames");
            let body = serde_json::json!({
                "name": name,
                "hypotheses": hypotheses,
                "description": description,
            });
            let resp: serde_json::Value = client
                .post(&url)
                .json(&body)
                .send()
                .await?
                .json()
                .await
                .context("Failed to create frame")?;
            println!("Frame created:");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn handle_belief(client: &Client, base: &str, action: BeliefCmd) -> Result<()> {
    match action {
        BeliefCmd::Show { claim_id } => {
            let url = format!("{base}/api/v1/claims/{claim_id}/belief");
            let resp: BeliefResponse = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse belief response")?;

            println!("Claim: {}", resp.claim_id);
            println!("  Belief:       {}", fmt_opt(resp.belief));
            println!("  Plausibility: {}", fmt_opt(resp.plausibility));
            println!("  Ignorance:    {}", fmt_opt(resp.ignorance));
            println!("  BetP:         {}", fmt_opt(resp.pignistic_prob));
            println!("  Sources:      {}", resp.mass_function_count);
        }
        BeliefCmd::Scoped {
            claim_id,
            scope,
            scope_id,
        } => {
            let mut url = format!("{base}/api/v1/claims/{claim_id}/belief/scoped?scope={scope}");
            if let Some(sid) = scope_id {
                use std::fmt::Write;
                let _ = write!(url, "&scope_id={sid}");
            }
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse scoped belief")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        BeliefCmd::Compare { claim_id } => {
            let url = format!("{base}/api/v1/claims/{claim_id}/belief/all-scopes");
            let resp: AllScopesResponse = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse all-scopes response")?;

            println!("Claim: {}", resp.claim_id);
            println!(
                "{:<12}  {:<36}  {:>6}  {:>6}  {:>6}  {:>6}",
                "Scope", "Scope ID", "Bel", "Pl", "Ign", "BetP"
            );
            println!("{}", "-".repeat(90));
            for s in &resp.scopes {
                println!(
                    "{:<12}  {:<36}  {:>6.3}  {:>6.3}  {:>6.3}  {:>6}",
                    s.scope_type,
                    s.scope_id
                        .map_or_else(|| "-".to_string(), |id| id.to_string()),
                    s.belief,
                    s.plausibility,
                    s.ignorance,
                    s.pignistic_prob
                        .map_or_else(|| "-".to_string(), |v| format!("{v:.3}")),
                );
            }
        }
        BeliefCmd::Ignorance { frame_id, limit } => {
            let url = format!(
                "{base}/api/v1/frames/{frame_id}/claims?sort_by=ignorance&order=desc&limit={limit}"
            );
            let rows: Vec<FrameClaimRow> = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse frame claims")?;

            println!(
                "{:<36}  {:>6}  {:>6}  {:>6}  Content",
                "Claim ID", "Bel", "Pl", "Ign"
            );
            println!("{}", "-".repeat(100));
            for r in &rows {
                let content_preview: String = r.content.chars().take(40).collect();
                println!(
                    "{:<36}  {:>6}  {:>6}  {:>6}  {}",
                    r.claim_id,
                    fmt_opt(r.belief),
                    fmt_opt(r.plausibility),
                    fmt_opt(r.ignorance),
                    content_preview,
                );
            }
            println!("\n{} claim(s)", rows.len());
        }
    }
    Ok(())
}

async fn handle_divergence(client: &Client, base: &str, action: DivergenceCmd) -> Result<()> {
    match action {
        DivergenceCmd::Report { limit } => {
            let url = format!("{base}/api/v1/divergence/top?limit={limit}");
            let items: Vec<DivergenceResponseItem> = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse divergence response")?;

            println!(
                "{:<36}  {:>8}  {:>8}  {:>8}",
                "Claim ID", "BetP", "Bayes", "KL"
            );
            println!("{}", "-".repeat(80));
            for d in &items {
                println!(
                    "{:<36}  {:>8.4}  {:>8.4}  {:>8.4}",
                    d.claim_id, d.pignistic_prob, d.bayesian_posterior, d.kl_divergence,
                );
            }
            println!("\n{} divergent claim(s)", items.len());
        }
        DivergenceCmd::Show { claim_id } => {
            let url = format!("{base}/api/v1/claims/{claim_id}/divergence");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse divergence")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn handle_conflict(client: &Client, base: &str, action: ConflictCmd) -> Result<()> {
    match action {
        ConflictCmd::List { limit } => {
            // Fetch frames, then check conflict for each
            let url = format!("{base}/api/v1/frames?limit={limit}");
            let frames: Vec<FrameResponse> = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse frames")?;

            println!(
                "{:<36}  {:<25}  {:>8}  {:>8}  {:>5}",
                "Frame ID", "Name", "Avg K", "Max K", "Srcs"
            );
            println!("{}", "-".repeat(90));
            for f in &frames {
                let conflict_url = format!("{base}/api/v1/frames/{}/conflict", f.id);
                if let Ok(resp) = client.get(&conflict_url).send().await {
                    if let Ok(c) = resp.json::<FrameConflictResponse>().await {
                        println!(
                            "{:<36}  {:<25}  {:>8}  {:>8}  {:>5}",
                            c.frame_id,
                            &f.name[..f.name.len().min(25)],
                            fmt_opt(c.avg_conflict_k),
                            fmt_opt(c.max_conflict_k),
                            c.source_count,
                        );
                    }
                }
            }
        }
        ConflictCmd::Show { frame_id } => {
            let url = format!("{base}/api/v1/frames/{frame_id}/conflict");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to parse conflict")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn handle_evidence(client: &Client, base: &str, action: EvidenceCmd) -> Result<()> {
    match action {
        EvidenceCmd::Submit {
            claim_id,
            frame,
            mass,
            agent_id,
            reliability,
        } => {
            let masses: std::collections::BTreeMap<String, f64> =
                serde_json::from_str(&mass).context("Invalid mass JSON")?;

            let url = format!("{base}/api/v1/frames/{frame}/evidence");
            let body = serde_json::json!({
                "claim_id": claim_id,
                "agent_id": agent_id,
                "reliability": reliability,
                "conflict_threshold": 0.3,
                "masses": masses,
            });
            let resp: EvidenceSubmissionResponse = client
                .post(&url)
                .json(&body)
                .send()
                .await?
                .json()
                .await
                .context("Failed to submit evidence")?;

            println!("Evidence submitted:");
            println!("  Mass function ID: {}", resp.mass_function_id);
            println!("  Updated belief:   {:.4}", resp.updated_belief);
            println!("  Updated Pl:       {:.4}", resp.updated_plausibility);
            println!("  BetP:             {}", fmt_opt(resp.pignistic_prob));
            println!("  Total sources:    {}", resp.total_sources);
        }
        EvidenceCmd::List { frame_id, limit } => {
            let url = format!(
                "{base}/api/v1/frames/{frame_id}/claims?sort_by=belief&order=desc&limit={limit}"
            );
            let rows: Vec<FrameClaimRow> = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to list frame claims")?;

            println!("{:<36}  {:>6}  {:>6}  Content", "Claim ID", "Bel", "Pl");
            println!("{}", "-".repeat(90));
            for r in &rows {
                let content_preview: String = r.content.chars().take(40).collect();
                println!(
                    "{:<36}  {:>6}  {:>6}  {}",
                    r.claim_id,
                    fmt_opt(r.belief),
                    fmt_opt(r.plausibility),
                    content_preview,
                );
            }
            println!("\n{} claim(s)", rows.len());
        }
    }
    Ok(())
}

async fn handle_agent(client: &Client, base: &str, action: AgentCmd) -> Result<()> {
    match action {
        AgentCmd::List => {
            let url = format!("{base}/agents");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to list agents")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        AgentCmd::Create { name, agent_type } => {
            let url = format!("{base}/agents");
            let body = serde_json::json!({
                "name": name,
                "agent_type": agent_type,
                "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
            });
            let resp: serde_json::Value = client
                .post(&url)
                .json(&body)
                .send()
                .await?
                .json()
                .await
                .context("Failed to create agent")?;
            println!("Agent created:");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn handle_perspective(client: &Client, base: &str, action: PerspectiveCmd) -> Result<()> {
    match action {
        PerspectiveCmd::List { agent_id } => {
            let url = format!("{base}/agents/{agent_id}/perspectives");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to list perspectives")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        PerspectiveCmd::Create {
            name,
            agent_id,
            perspective_type,
        } => {
            let url = format!("{base}/api/v1/perspectives");
            let body = serde_json::json!({
                "name": name,
                "owner_agent_id": agent_id,
                "perspective_type": perspective_type,
            });
            let resp: serde_json::Value = client
                .post(&url)
                .json(&body)
                .send()
                .await?
                .json()
                .await
                .context("Failed to create perspective")?;
            println!("Perspective created:");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn handle_community(client: &Client, base: &str, action: CommunityCmd) -> Result<()> {
    match action {
        CommunityCmd::List => {
            let url = format!("{base}/api/v1/communities");
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to list communities")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        CommunityCmd::Create {
            name,
            governance,
            description,
        } => {
            let url = format!("{base}/api/v1/communities");
            let body = serde_json::json!({
                "name": name,
                "governance_type": governance,
                "description": description,
            });
            let resp: serde_json::Value = client
                .post(&url)
                .json(&body)
                .send()
                .await?
                .json()
                .await
                .context("Failed to create community")?;
            println!("Community created:");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        CommunityCmd::Beliefs {
            community_id,
            claim_id,
        } => {
            let url = format!(
                "{base}/api/v1/claims/{claim_id}/belief/scoped?scope=community&scope_id={community_id}"
            );
            let resp: serde_json::Value = client
                .get(&url)
                .send()
                .await?
                .json()
                .await
                .context("Failed to get community belief")?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

// =============================================================================
// MIGRATE HANDLERS (direct DB connection)
// =============================================================================

async fn handle_migrate(action: MigrateCmd) -> Result<()> {
    match action {
        MigrateCmd::Validate { db_url } => {
            let pool = sqlx::PgPool::connect(&db_url)
                .await
                .context("Failed to connect to database")?;

            println!("Validating DB integrity...\n");

            // Check Bel <= Pl
            let bad_bel_pl: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM claims WHERE belief IS NOT NULL AND plausibility IS NOT NULL AND belief > plausibility + 0.0001"
            )
            .fetch_one(&pool)
            .await
            .context("Failed to query claims")?;
            let bel_pl_ok = bad_bel_pl.0 == 0;
            println!(
                "  Bel <= Pl check:       {} ({} violations)",
                if bel_pl_ok { "PASS" } else { "FAIL" },
                bad_bel_pl.0
            );

            // Check mass function sums ≈ 1.0
            let bad_mass: (i64,) = sqlx::query_as(
                r#"
                SELECT COUNT(*) FROM (
                    SELECT id, (
                        SELECT COALESCE(SUM((v.value)::float8), 0)
                        FROM jsonb_each_text(masses) v
                    ) as total
                    FROM mass_functions
                ) sub
                WHERE ABS(total - 1.0) > 0.01
                "#,
            )
            .fetch_one(&pool)
            .await
            .context("Failed to query mass functions")?;
            let mass_ok = bad_mass.0 == 0;
            println!(
                "  Mass sum ≈ 1.0 check:  {} ({} violations)",
                if mass_ok { "PASS" } else { "FAIL" },
                bad_mass.0
            );

            // Check frames have hypotheses
            let bad_frames: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM frames WHERE hypotheses IS NULL OR jsonb_array_length(hypotheses) = 0"
            )
            .fetch_one(&pool)
            .await
            .context("Failed to query frames")?;
            let frames_ok = bad_frames.0 == 0;
            println!(
                "  Frames have hypotheses: {} ({} violations)",
                if frames_ok { "PASS" } else { "FAIL" },
                bad_frames.0
            );

            // Summary counts
            let claim_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims")
                .fetch_one(&pool)
                .await
                .context("count claims")?;
            let mass_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mass_functions")
                .fetch_one(&pool)
                .await
                .context("count mass functions")?;
            let frame_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM frames")
                .fetch_one(&pool)
                .await
                .context("count frames")?;

            println!("\n  Totals:");
            println!("    Claims:          {}", claim_count.0);
            println!("    Mass functions:  {}", mass_count.0);
            println!("    Frames:          {}", frame_count.0);

            let all_ok = bel_pl_ok && mass_ok && frames_ok;
            println!(
                "\n  Overall: {}",
                if all_ok {
                    "ALL CHECKS PASSED"
                } else {
                    "VALIDATION FAILED"
                }
            );
            if !all_ok {
                std::process::exit(1);
            }
        }

        MigrateCmd::BootstrapMasses {
            db_url,
            confidence_scale,
        } => {
            let pool = sqlx::PgPool::connect(&db_url)
                .await
                .context("Failed to connect to database")?;

            println!("Bootstrapping mass functions (confidence_scale={confidence_scale})...\n");

            // Find claims that have a frame assignment but no mass function
            let claims_needing_bba: Vec<(Uuid, Uuid, f64)> = sqlx::query_as(
                r#"
                SELECT cf.claim_id, cf.frame_id, c.truth_value
                FROM claim_frames cf
                JOIN claims c ON c.id = cf.claim_id
                WHERE NOT EXISTS (
                    SELECT 1 FROM mass_functions mf
                    WHERE mf.claim_id = cf.claim_id AND mf.frame_id = cf.frame_id
                )
                "#,
            )
            .fetch_all(&pool)
            .await
            .context("Failed to query claims needing BBAs")?;

            if claims_needing_bba.is_empty() {
                println!("  No claims need bootstrapping. All have mass functions.");
                return Ok(());
            }

            println!(
                "  Found {} claim-frame pairs needing bootstrap",
                claims_needing_bba.len()
            );

            let mut created = 0i64;
            for (claim_id, frame_id, truth_value) in &claims_needing_bba {
                let mass_h = truth_value * confidence_scale;
                let mass_theta = 1.0 - mass_h;

                // Get hypothesis count to build proper Θ key
                let hyp_count: (i32,) = sqlx::query_as(
                    "SELECT COALESCE(jsonb_array_length(hypotheses), 2) FROM frames WHERE id = $1",
                )
                .bind(frame_id)
                .fetch_one(&pool)
                .await
                .unwrap_or((2,));

                let theta_key: String = (0..hyp_count.0)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",");

                let masses = serde_json::json!({
                    "0": mass_h,
                    theta_key: mass_theta,
                });

                sqlx::query(
                    r#"
                    INSERT INTO mass_functions (claim_id, frame_id, masses, source_type, source_label)
                    VALUES ($1, $2, $3, 'bootstrap', 'dekg migrate bootstrap-masses')
                    ON CONFLICT DO NOTHING
                    "#
                )
                .bind(claim_id)
                .bind(frame_id)
                .bind(&masses)
                .execute(&pool)
                .await
                .context("Failed to insert mass function")?;

                created += 1;
            }
            println!("  Created {} mass functions", created);
        }

        MigrateCmd::ExtractAgents { db_url } => {
            let pool = sqlx::PgPool::connect(&db_url)
                .await
                .context("Failed to connect to database")?;

            println!("Agent statistics:\n");

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents")
                .fetch_one(&pool)
                .await
                .context("count agents")?;
            let with_claims: (i64,) = sqlx::query_as(
                "SELECT COUNT(DISTINCT agent_id) FROM claims WHERE agent_id IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .context("agents with claims")?;
            let without_name: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM agents WHERE display_name IS NULL OR display_name = ''",
            )
            .fetch_one(&pool)
            .await
            .context("agents without name")?;
            let with_perspectives: (i64,) =
                sqlx::query_as("SELECT COUNT(DISTINCT owner_agent_id) FROM perspectives")
                    .fetch_one(&pool)
                    .await
                    .context("agents with perspectives")?;

            println!("  Total agents:              {}", total.0);
            println!("  Agents with claims:        {}", with_claims.0);
            println!("  Agents without display_name: {}", without_name.0);
            println!("  Agents with perspectives:  {}", with_perspectives.0);
        }

        MigrateCmd::MaterializeEdges { db_url, dry_run } => {
            let pool = sqlx::PgPool::connect(&db_url)
                .await
                .context("Failed to connect to database")?;

            println!(
                "Materializing edges from FK references{}...\n",
                if dry_run { " (DRY RUN)" } else { "" }
            );

            let mut total_created = 0i64;

            // 1. PERSPECTIVE_OF: perspective.owner_agent_id → agent
            let perspectives: Vec<(Uuid, Uuid)> = sqlx::query_as(
                r#"SELECT p.id, p.owner_agent_id
                   FROM perspectives p
                   WHERE p.owner_agent_id IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM edges e
                       WHERE e.source_id = p.id AND e.relationship = 'PERSPECTIVE_OF'
                     )"#,
            )
            .fetch_all(&pool)
            .await
            .context("query perspectives")?;
            println!("  PERSPECTIVE_OF: {} edges to create", perspectives.len());
            if !dry_run {
                for (pid, aid) in &perspectives {
                    let _ = sqlx::query(
                        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'perspective', $2, 'agent', 'PERSPECTIVE_OF', '{}') ON CONFLICT DO NOTHING"
                    ).bind(pid).bind(aid).execute(&pool).await;
                    total_created += 1;
                }
            }

            // 2. MEMBER_OF: community_members junction → edges
            let members: Vec<(Uuid, Uuid)> = sqlx::query_as(
                r#"SELECT cm.perspective_id, cm.community_id
                   FROM community_members cm
                   WHERE NOT EXISTS (
                       SELECT 1 FROM edges e
                       WHERE e.source_id = cm.perspective_id
                         AND e.target_id = cm.community_id
                         AND e.relationship = 'MEMBER_OF'
                     )"#,
            )
            .fetch_all(&pool)
            .await
            .context("query community members")?;
            println!("  MEMBER_OF: {} edges to create", members.len());
            if !dry_run {
                for (pid, cid) in &members {
                    let _ = sqlx::query(
                        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'perspective', $2, 'community', 'MEMBER_OF', '{}') ON CONFLICT DO NOTHING"
                    ).bind(pid).bind(cid).execute(&pool).await;
                    total_created += 1;
                }
            }

            // 3. CONTRIBUTES_TO: mass_functions with perspective_id → claim
            let contributions: Vec<(Uuid, Uuid)> = sqlx::query_as(
                r#"SELECT DISTINCT mf.perspective_id, mf.claim_id
                   FROM mass_functions mf
                   WHERE mf.perspective_id IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM edges e
                       WHERE e.source_id = mf.perspective_id
                         AND e.target_id = mf.claim_id
                         AND e.relationship = 'CONTRIBUTES_TO'
                     )"#,
            )
            .fetch_all(&pool)
            .await
            .context("query mass function contributions")?;
            println!("  CONTRIBUTES_TO: {} edges to create", contributions.len());
            if !dry_run {
                for (pid, cid) in &contributions {
                    let _ = sqlx::query(
                        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($1, 'perspective', $2, 'claim', 'CONTRIBUTES_TO', '{}') ON CONFLICT DO NOTHING"
                    ).bind(pid).bind(cid).execute(&pool).await;
                    total_created += 1;
                }
            }

            if dry_run {
                println!("\n  DRY RUN — no edges created");
                println!(
                    "  Would create: {} total edges",
                    perspectives.len() + members.len() + contributions.len()
                );
            } else {
                println!("\n  Created {} edges", total_created);
            }
        }

        MigrateCmd::CreateFrames {
            db_url,
            k_min,
            k_max,
            min_claims,
            dry_run,
        } => {
            use linfa::prelude::*;
            use linfa_clustering::KMeans;
            use ndarray::Array2;

            let pool = sqlx::PgPool::connect(&db_url)
                .await
                .context("Failed to connect to database")?;

            println!(
                "Auto-creating frames from claim embeddings{}...\n",
                if dry_run { " (DRY RUN)" } else { "" }
            );

            // 1. Fetch claims with embeddings
            let rows: Vec<(Uuid, String, Vec<f32>)> = sqlx::query_as(
                r#"SELECT id, content, embedding::text::float4[]
                   FROM claims
                   WHERE embedding IS NOT NULL
                   ORDER BY id"#,
            )
            .fetch_all(&pool)
            .await
            .context("Failed to fetch claim embeddings")?;

            if rows.len() < k_min {
                println!(
                    "  Only {} claims with embeddings (need at least {}). Aborting.",
                    rows.len(),
                    k_min
                );
                return Ok(());
            }

            let n_claims = rows.len();
            let dim = rows[0].2.len();
            println!("  Found {} claims with {}-dim embeddings", n_claims, dim);

            // 2. Build ndarray matrix
            let mut data = Array2::<f64>::zeros((n_claims, dim));
            for (i, (_, _, emb)) in rows.iter().enumerate() {
                for (j, &v) in emb.iter().enumerate() {
                    data[[i, j]] = f64::from(v);
                }
            }

            let dataset = linfa::DatasetBase::from(data.view());

            // 3. Search for best k using silhouette score
            let actual_k_max = k_max.min(n_claims);
            let mut best_k = k_min;
            let mut best_score = f64::NEG_INFINITY;

            println!("  Searching k in {}..={}...", k_min, actual_k_max);

            for k in k_min..=actual_k_max {
                let model = KMeans::params(k)
                    .max_n_iterations(100)
                    .tolerance(1e-4)
                    .fit(&dataset)
                    .context("k-means fit failed")?;

                let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();

                // Simple silhouette approximation: use intra-cluster variance as proxy
                let centroids = model.centroids();
                let mut total_dist = 0.0;
                for (i, label) in labels.iter().enumerate() {
                    let centroid = centroids.row(*label);
                    let point = data.row(i);
                    let dist: f64 = point
                        .iter()
                        .zip(centroid.iter())
                        .map(|(a, b)| (a - b).powi(2))
                        .sum();
                    total_dist += dist;
                }
                let score = -total_dist / n_claims as f64; // negative inertia (higher = better)

                // Penalize too many clusters (elbow heuristic)
                let penalized_score = score * (1.0 - 0.05 * k as f64);

                if penalized_score > best_score {
                    best_score = penalized_score;
                    best_k = k;
                }
            }

            println!("  Best k = {} (score: {:.4})", best_k, best_score);

            // 4. Fit final model
            let model = KMeans::params(best_k)
                .max_n_iterations(200)
                .tolerance(1e-5)
                .fit(&dataset)
                .context("Final k-means fit failed")?;

            let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();

            // 5. Create frames for each cluster
            let mut frames_created = 0;
            let mut claims_assigned = 0;

            for cluster_idx in 0..best_k {
                let cluster_claims: Vec<(usize, &Uuid, &str)> = labels
                    .iter()
                    .enumerate()
                    .filter(|(_, &l)| l == cluster_idx)
                    .map(|(i, _)| (i, &rows[i].0, rows[i].1.as_str()))
                    .collect();

                if cluster_claims.len() < min_claims {
                    println!(
                        "  Cluster {} has {} claims (< {}), skipping",
                        cluster_idx,
                        cluster_claims.len(),
                        min_claims
                    );
                    continue;
                }

                // Name from the first claim's content (truncated)
                let representative = cluster_claims[0].2;
                let frame_name = format!(
                    "Auto-frame-{}: {}",
                    cluster_idx,
                    &representative[..representative.len().min(60)]
                );

                // Generate hypothesis names from top 2-3 claims
                let hypotheses: Vec<String> = cluster_claims
                    .iter()
                    .take(3)
                    .map(|(_, _, content): &(usize, &Uuid, &str)| {
                        content[..content.len().min(80)].to_string()
                    })
                    .collect();

                if hypotheses.len() < 2 {
                    println!("  Cluster {} has < 2 hypotheses, skipping", cluster_idx);
                    continue;
                }

                if dry_run {
                    println!(
                        "  [DRY RUN] Would create frame '{}' with {} claims",
                        frame_name,
                        cluster_claims.len()
                    );
                } else {
                    // Create frame
                    let hyp_json = serde_json::to_value(&hypotheses).unwrap();
                    let frame_row: (Uuid,) = sqlx::query_as(
                        "INSERT INTO frames (name, hypotheses) VALUES ($1, $2) RETURNING id",
                    )
                    .bind(&frame_name)
                    .bind(&hyp_json)
                    .fetch_one(&pool)
                    .await
                    .context("Failed to create frame")?;

                    let frame_id = frame_row.0;
                    println!("  Created frame {} '{}'", frame_id, frame_name);

                    // Assign claims
                    for (h_idx, claim_id, _) in &cluster_claims {
                        let _ = sqlx::query(
                            "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
                        )
                        .bind(claim_id)
                        .bind(frame_id)
                        .bind(*h_idx as i32 % hypotheses.len() as i32)
                        .execute(&pool)
                        .await;
                        claims_assigned += 1;
                    }

                    frames_created += 1;
                }
            }

            if dry_run {
                println!("\n  DRY RUN — no frames created");
            } else {
                println!(
                    "\n  Created {} frames, assigned {} claims",
                    frames_created, claims_assigned
                );
            }
        }
    }
    Ok(())
}

// =============================================================================
// UTILITIES
// =============================================================================

fn fmt_opt(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_string(), |x| format!("{x:.3}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_opt_formats_value() {
        assert_eq!(fmt_opt(Some(0.75)), "0.750");
        assert_eq!(fmt_opt(None), "-");
    }

    #[test]
    fn cli_parses_frame_list() {
        let cli = Cli::try_parse_from(["dekg", "frame", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Frame {
                action: FrameCmd::List { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_belief_show() {
        let id = Uuid::new_v4();
        let cli = Cli::try_parse_from(["dekg", "belief", "show", &id.to_string()]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Belief {
                action: BeliefCmd::Show { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_divergence_report() {
        let cli = Cli::try_parse_from(["dekg", "divergence", "report", "--limit", "5"]).unwrap();
        match cli.command {
            Commands::Divergence {
                action: DivergenceCmd::Report { limit },
            } => {
                assert_eq!(limit, 5);
            }
            _ => panic!("Expected DivergenceCmd::Report"),
        }
    }

    #[test]
    fn cli_parses_evidence_submit() {
        let cid = Uuid::new_v4();
        let fid = Uuid::new_v4();
        let cli = Cli::try_parse_from([
            "dekg",
            "evidence",
            "submit",
            &cid.to_string(),
            "--frame",
            &fid.to_string(),
            "--mass",
            r#"{"0": 0.7, "0,1": 0.3}"#,
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Evidence {
                action: EvidenceCmd::Submit { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_agent_list() {
        let cli = Cli::try_parse_from(["dekg", "agent", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Agent {
                action: AgentCmd::List
            }
        ));
    }

    #[test]
    fn cli_parses_community_list() {
        let cli = Cli::try_parse_from(["dekg", "community", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Community {
                action: CommunityCmd::List
            }
        ));
    }

    #[test]
    fn cli_parses_conflict_show() {
        let fid = Uuid::new_v4();
        let cli = Cli::try_parse_from(["dekg", "conflict", "show", &fid.to_string()]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Conflict {
                action: ConflictCmd::Show { .. }
            }
        ));
    }

    #[test]
    fn cli_default_api_url() {
        let cli = Cli::try_parse_from(["dekg", "frame", "list"]).unwrap();
        assert_eq!(cli.api_url, "http://localhost:3000");
    }

    #[test]
    fn cli_custom_api_url() {
        let cli = Cli::try_parse_from([
            "dekg",
            "--api-url",
            "http://example.com:8080",
            "frame",
            "list",
        ])
        .unwrap();
        assert_eq!(cli.api_url, "http://example.com:8080");
    }

    #[test]
    fn cli_parses_migrate_validate() {
        let cli = Cli::try_parse_from([
            "dekg",
            "migrate",
            "validate",
            "--db-url",
            "postgres://localhost/test",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Migrate {
                action: MigrateCmd::Validate { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_migrate_bootstrap_masses() {
        let cli = Cli::try_parse_from([
            "dekg",
            "migrate",
            "bootstrap-masses",
            "--db-url",
            "postgres://localhost/test",
            "--confidence-scale",
            "0.8",
        ])
        .unwrap();
        match cli.command {
            Commands::Migrate {
                action:
                    MigrateCmd::BootstrapMasses {
                        confidence_scale, ..
                    },
            } => {
                assert!((confidence_scale - 0.8).abs() < f64::EPSILON);
            }
            _ => panic!("Expected BootstrapMasses"),
        }
    }

    #[test]
    fn cli_parses_migrate_extract_agents() {
        let cli = Cli::try_parse_from([
            "dekg",
            "migrate",
            "extract-agents",
            "--db-url",
            "postgres://localhost/test",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Migrate {
                action: MigrateCmd::ExtractAgents { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_community_create() {
        let cli = Cli::try_parse_from([
            "dekg",
            "community",
            "create",
            "test_community",
            "--governance",
            "closed",
            "--description",
            "A test community",
        ])
        .unwrap();
        match cli.command {
            Commands::Community {
                action:
                    CommunityCmd::Create {
                        name,
                        governance,
                        description,
                    },
            } => {
                assert_eq!(name, "test_community");
                assert_eq!(governance, "closed");
                assert_eq!(description, Some("A test community".to_string()));
            }
            _ => panic!("Expected CommunityCmd::Create"),
        }
    }
}

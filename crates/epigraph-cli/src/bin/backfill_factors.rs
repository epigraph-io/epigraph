//! Tier A factor backfill.
//!
//! Phase 1 (evidence): for each factorless claim that has eligible evidence
//! rows, calls `auto_wire_ds_update` with `confidence = 1.0` so only the
//! evidence-type weight shapes the BBA. Filters out:
//!   - untyped telemetry observations (epiclaw scheduled-task traces)
//!   - hierarchical-tree internals (level_0..2, plus malformed extraction_target
//!     strings that look like chapter-path values)
//!
//! Phase 2 (edges): for each factorless target with an incoming epistemic
//! edge (supports / corroborates / contradicts / refutes / refines / informs /
//! elaborates / specializes / generalizes / supersedes / frame_validates),
//! materializes a BBA via the existing `RestrictionKind` + `restrict_epistemic_*`
//! framework keyed by `edge.id`. Skips edges whose source is itself factorless.
//!
//! Run order matters: evidence-phase first so edge-phase sees fresh source
//! intervals.

use clap::{Parser, ValueEnum};
use epigraph_mcp::tools::ds_auto::{self, EdgeFactorOutcome};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "backfill_factors", about = "Tier A factor backfill")]
struct Cli {
    /// Which phase to run
    #[arg(long, value_enum, default_value_t = Phase::All)]
    phase: Phase,
    /// Process at most N rows in each phase (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Skip first N rows (paginate)
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Log what would be written without persisting
    #[arg(long)]
    dry_run: bool,
}

#[derive(ValueEnum, Clone, Copy, PartialEq)]
enum Phase {
    All,
    Evidence,
    Edges,
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

    if matches!(cli.phase, Phase::All | Phase::Evidence) {
        let summary = run_evidence_phase(&pool, cli.limit, cli.offset, cli.dry_run).await?;
        println!("evidence phase: {summary}");
    }
    if matches!(cli.phase, Phase::All | Phase::Edges) {
        let summary = run_edge_phase(&pool, cli.limit, cli.offset, cli.dry_run).await?;
        println!("edge phase: {summary}");
    }
    Ok(())
}

#[derive(Default)]
struct PhaseSummary {
    eligible: usize,
    wired: usize,
    skipped_source_factorless: usize,
    skipped_non_epistemic: usize,
    skipped_vacuous: usize,
    failed: usize,
}

impl std::fmt::Display for PhaseSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "eligible={} wired={} skipped_source_factorless={} skipped_non_epistemic={} skipped_vacuous={} failed={}",
            self.eligible,
            self.wired,
            self.skipped_source_factorless,
            self.skipped_non_epistemic,
            self.skipped_vacuous,
            self.failed
        )
    }
}

/// Evidence-phase eligibility: factorless claim, evidence row not telemetry,
/// not a textbook hierarchical-tree internal (L0/L1/L2 or malformed chapter
/// path), evidence has a signer.
const EVIDENCE_QUERY: &str = r#"
SELECT ev.id, ev.claim_id, ev.signer_id, ev.evidence_type::text,
       ev.properties->>'extraction_target' AS extr_tgt
FROM evidence ev
JOIN claims c ON c.id = ev.claim_id
WHERE c.is_current
  AND NOT EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = c.id)
  AND ev.signer_id IS NOT NULL
  AND NOT (
    -- telemetry: untyped observation rows
    ev.evidence_type = 'observation'
    AND ev.properties->>'type' IS NULL
    AND ev.properties->>'extraction_target' IS NULL
  )
  AND COALESCE(ev.properties->>'extraction_target','') NOT IN ('level_0','level_1','level_2')
  AND (
    ev.properties->>'extraction_target' IS NULL
    OR ev.properties->>'extraction_target' IN ('level_3')
    OR ev.properties->>'extraction_target' !~ '^level_[0-9]'
  )
ORDER BY ev.claim_id, ev.created_at
LIMIT $1 OFFSET $2
"#;

async fn run_evidence_phase(
    pool: &PgPool,
    limit: usize,
    offset: usize,
    dry_run: bool,
) -> Result<PhaseSummary, Box<dyn std::error::Error>> {
    let lim: i64 = if limit == 0 { i64::MAX } else { limit as i64 };
    let off: i64 = offset as i64;
    let rows: Vec<(Uuid, Uuid, Uuid, String, Option<String>)> = sqlx::query_as(EVIDENCE_QUERY)
        .bind(lim)
        .bind(off)
        .fetch_all(pool)
        .await?;

    // Also filter: chapter-path strings in extraction_target (e.g.
    // "Introductory Business Statistics 2e > Ch 2 > ...") are mis-tagged
    // hierarchical tree internals from older ingests.
    let eligible: Vec<_> = rows
        .into_iter()
        .filter(|(_, _, _, _, extr)| {
            extr.as_ref()
                .is_none_or(|s| s.is_empty() || s == "level_3" || !s.contains('>'))
        })
        .collect();

    let mut summary = PhaseSummary {
        eligible: eligible.len(),
        ..PhaseSummary::default()
    };
    if dry_run {
        println!(
            "DRY RUN: would wire {} evidence rows (showing first 5):",
            summary.eligible
        );
        for (eid, cid, sid, etype, extr) in eligible.iter().take(5) {
            println!("  evidence={eid} claim={cid} signer={sid} type={etype} extr={extr:?}");
        }
        return Ok(summary);
    }

    for (evidence_id, claim_id, signer_id, evidence_type, _extr) in eligible {
        let weight = load_evidence_type_weight(&evidence_type);
        match ds_auto::auto_wire_ds_update(
            pool,
            claim_id,
            signer_id,
            1.0, // confidence: only evidence-type weight shapes the BBA
            weight,
            true, // existing ingest semantics: evidence supports its claim
            Some(&evidence_type),
            Some(evidence_id),
        )
        .await
        {
            Ok(_) => summary.wired += 1,
            Err(e) => {
                tracing::warn!(claim=%claim_id, evidence=%evidence_id, "evidence wire failed: {e}");
                summary.failed += 1;
            }
        }
    }
    Ok(summary)
}

/// Edge-phase eligibility: factorless target claim, claim-to-claim edge with
/// epistemic relationship. Uses `signer_id` when present, otherwise falls back
/// to the source claim's `agent_id` (always populated) — the edge factor is
/// attributable to the source claim's author since they're asserting the
/// support/contradiction via the edge.
const EDGE_QUERY: &str = r#"
SELECT e.id, COALESCE(e.signer_id, src.agent_id) AS agent_id,
       e.source_id, e.target_id, e.relationship
FROM edges e
JOIN claims tgt ON tgt.id = e.target_id
JOIN claims src ON src.id = e.source_id
WHERE tgt.is_current AND src.is_current
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND LOWER(e.relationship) IN (
    'supports','corroborates','contradicts','refutes','refines','undercuts','rebuts',
    'elaborates','specializes','generalizes','supersedes','informs','frame_validates'
  )
  AND NOT EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = tgt.id)
ORDER BY e.target_id, e.created_at
LIMIT $1 OFFSET $2
"#;

async fn run_edge_phase(
    pool: &PgPool,
    limit: usize,
    offset: usize,
    dry_run: bool,
) -> Result<PhaseSummary, Box<dyn std::error::Error>> {
    let lim: i64 = if limit == 0 { i64::MAX } else { limit as i64 };
    let off: i64 = offset as i64;
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, String)> = sqlx::query_as(EDGE_QUERY)
        .bind(lim)
        .bind(off)
        .fetch_all(pool)
        .await?;

    let mut summary = PhaseSummary {
        eligible: rows.len(),
        ..PhaseSummary::default()
    };

    if dry_run {
        println!(
            "DRY RUN: would attempt {} edge factors (showing first 5):",
            summary.eligible
        );
        for (eid, sgn, src, tgt, rel) in rows.iter().take(5) {
            println!("  edge={eid} signer={sgn} {src} —[{rel}]→ {tgt}");
        }
        return Ok(summary);
    }

    for (edge_id, signer_id, source_id, target_id, relationship) in rows {
        match ds_auto::auto_wire_ds_for_edge(
            pool,
            edge_id,
            signer_id,
            source_id,
            target_id,
            &relationship,
        )
        .await
        {
            Ok(EdgeFactorOutcome::Wired) => summary.wired += 1,
            Ok(EdgeFactorOutcome::SourceFactorless) => summary.skipped_source_factorless += 1,
            Ok(EdgeFactorOutcome::NonEpistemic) => summary.skipped_non_epistemic += 1,
            Ok(EdgeFactorOutcome::Vacuous) => summary.skipped_vacuous += 1,
            Err(e) => {
                tracing::warn!(edge=%edge_id, target=%target_id, "edge wire failed: {e}");
                summary.failed += 1;
            }
        }
    }
    Ok(summary)
}

fn load_evidence_type_weight(evidence_type: &str) -> f64 {
    let path = std::env::var("CALIBRATION_PATH").unwrap_or_else(|_| "calibration.toml".to_string());
    epigraph_engine::calibration::CalibrationConfig::load(std::path::Path::new(&path))
        .ok()
        .map(|c| c.get_evidence_type_weight(evidence_type))
        .unwrap_or(0.7)
}

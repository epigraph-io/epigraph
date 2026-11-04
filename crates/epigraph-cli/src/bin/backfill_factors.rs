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
//!
//! Phase 3 (`--phase rewire-edges`, never part of `all`): re-derives every
//! ALREADY-wired edge-factor BBA from its source's current interval, so rows
//! written under an older BBA shape (before #401's open-world discount) are
//! rewritten. A full refresh of every edge factor it selects; see
//! `epigraph_cli::backfill_factors` for the selection rules and the paging
//! idiom (fixed `--written-before`, `--limit N`, `--offset` advanced by the
//! printed `next --offset`, done when a page makes no progress).
//!
//! Targeted rewire (`--phase rewire-edges --sources-from-waves <wave files>`,
//! R-176(2) / R-177(4) class E): only the edges sourced at the claims the
//! waves moved, then at the targets those moved, pass after pass, each under
//! the guards in `epigraph_cli::backfill_factors` (a held edge is never
//! deleted or rewritten). With `--dry-run` it PREDICTS (one READ ONLY
//! transaction; `--predict-json` writes the per-edge and per-target report).
//! The predict records its options (`epsilon`, `max_passes`, `only_changed`,
//! the accepted list's size, the wave files): the apply must reuse exactly
//! them. A real targeted run needs the accepted list (`--edges-from`) and both
//! snapshot files (`--snapshot`, `--edge-rows`). The fixed-point verify after
//! an apply is a predict over the L1 wave files AND the apply's `--snapshot`
//! file (an L1 claim the rewire refolded holds neither L1 value; the E
//! records chain onto the L1 ones), and must report nothing to rewrite. Undo
//! an apply with
//! `restore_edge_factors --edge-rows` and then `restore_belief_cache --from
//! <the --snapshot file>`.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use epigraph_cli::backfill_factors::{run_rewire_phase, RewireOptions, EDGE_QUERY};
use epigraph_cli::belief_mode_check::{enforce_build_fold_or_exit, enforce_or_exit, RunIntent};
use epigraph_cli::edge_rewire::{
    predict_targeted_rewire, run_targeted_rewire, seed_from_waves, TargetedRunOptions,
    DEFAULT_EPSILON, DEFAULT_MAX_PASSES,
};
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
    /// rewire-edges only: rewrite only edge-factor rows last written before
    /// this RFC 3339 instant (e.g. the deploy time of the new BBA shape)
    #[arg(long)]
    written_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
    /// rewire-edges, targeted: the wave files (`recompute_claim_belief
    /// --snapshot` output) whose moved claims are pass 1's sources and whose
    /// `before` values are the row-class baseline. Enables targeted mode.
    #[arg(long, num_args = 1.., value_name = "WAVE_FILE")]
    sources_from_waves: Vec<PathBuf>,
    /// rewire-edges, targeted: the accepted edge list (one edge id per line;
    /// blank and `#` lines ignored). Required for a real targeted run.
    #[arg(long)]
    edges_from: Option<PathBuf>,
    /// rewire-edges, targeted, --dry-run: write the predict report here
    /// (must not exist).
    #[arg(long)]
    predict_json: Option<PathBuf>,
    /// rewire-edges, targeted: stop after this many passes.
    #[arg(long, default_value_t = DEFAULT_MAX_PASSES)]
    max_passes: usize,
    /// rewire-edges, targeted: a target moved when bel or pl changed by more.
    #[arg(long, default_value_t = DEFAULT_EPSILON)]
    epsilon: f64,
    /// rewire-edges, targeted: leave a row alone when a fresh wire equals it.
    #[arg(long)]
    only_changed: bool,
    /// rewire-edges, targeted: run passes until one moves nothing (else one
    /// pass).
    #[arg(long)]
    until_fixed: bool,
    /// rewire-edges, targeted, real run: append the target caches' wave
    /// records here (must not exist).
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// rewire-edges, targeted, real run: append the rewritten rows' records
    /// here (must not exist).
    #[arg(long)]
    edge_rows: Option<PathBuf>,
}

/// Why a targeted invocation is refused before it touches the database, if
/// it is: a real run is always a list, with both snapshot files.
fn targeted_argv_problem(cli: &Cli) -> Option<String> {
    if cli.sources_from_waves.is_empty() {
        let targeted_only = cli.edges_from.is_some()
            || cli.predict_json.is_some()
            || cli.snapshot.is_some()
            || cli.edge_rows.is_some()
            || cli.only_changed
            || cli.until_fixed;
        return targeted_only.then(|| {
            "--edges-from, --predict-json, --snapshot, --edge-rows, --only-changed and \
             --until-fixed need targeted mode (--sources-from-waves)"
                .to_string()
        });
    }
    if cli.phase != Phase::RewireEdges {
        return Some("--sources-from-waves needs --phase rewire-edges".into());
    }
    if cli.dry_run {
        return None;
    }
    let mut missing = Vec::new();
    if cli.edges_from.is_none() {
        missing.push("--edges-from");
    }
    if cli.snapshot.is_none() {
        missing.push("--snapshot");
    }
    if cli.edge_rows.is_none() {
        missing.push("--edge-rows");
    }
    (!missing.is_empty()).then(|| {
        format!(
            "a real targeted rewire needs {} (an apply is always an accepted list, recorded)",
            missing.join(", ")
        )
    })
}

#[derive(ValueEnum, Clone, Copy, PartialEq)]
enum Phase {
    All,
    Evidence,
    Edges,
    /// Rewrite already-wired edge-factor BBAs (not part of `all`)
    RewireEdges,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Some(problem) = targeted_argv_problem(&cli) {
        eprintln!("backfill_factors: {problem}");
        std::process::exit(2);
    }
    if !cli.sources_from_waves.is_empty() {
        // A calibration that did not load would weight every row under the
        // wrong vocabulary (backlog d83b998a): a targeted run refuses.
        let problems = epigraph_engine::calibration::CalibrationConfig::startup_problems();
        if !problems.is_empty() {
            eprintln!(
                "backfill_factors: refusing a targeted rewire: {}",
                problems.join("; ")
            );
            std::process::exit(2);
        }
    }

    // Before the database: a writing run must show its belief modes match the
    // API's (SPEC §10.2). A dry run writes nothing and is exempt.
    let intent = if cli.dry_run {
        RunIntent::WritesNothing
    } else {
        RunIntent::Writes
    };
    enforce_or_exit("backfill_factors", intent, cli.allow_mode_skew).await;
    // Agreement on the flag is not enough: this build's cache writers fold only
    // the legacy way, so a writing run under another fold refuses.
    enforce_build_fold_or_exit("backfill_factors", intent);

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("backfill_factors")
        .await
        .expect("maintenance pool");
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance viewer");
    let viewer = session.viewer();
    if let Err(e) = run(cli, maint.pool().clone(), viewer).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(
    cli: Cli,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(cli.phase, Phase::All | Phase::Evidence) {
        let summary = run_evidence_phase(&pool, viewer, cli.limit, cli.offset, cli.dry_run).await?;
        println!("evidence phase: {summary}");
    }
    if matches!(cli.phase, Phase::All | Phase::Edges) {
        let summary = run_edge_phase(&pool, viewer, cli.limit, cli.offset, cli.dry_run).await?;
        println!("edge phase: {summary}");
    }
    if cli.phase == Phase::RewireEdges && !cli.sources_from_waves.is_empty() {
        return run_targeted(&cli, &pool, viewer).await;
    }
    if cli.phase == Phase::RewireEdges {
        let opts = RewireOptions {
            limit: cli.limit,
            offset: cli.offset,
            dry_run: cli.dry_run,
            written_before: cli.written_before,
        };
        let summary = run_rewire_phase(&pool, viewer, &opts).await?;
        println!("rewire-edges phase: {summary}");
        if !cli.dry_run && summary.eligible > 0 {
            // Skipped-non-epistemic and failed rows stay selected; the next
            // page must step past them or it reselects them forever.
            println!(
                "rewire-edges paging: next --offset {} (same --written-before)",
                cli.offset + summary.persisting()
            );
            if !summary.made_progress() {
                eprintln!(
                    "rewire-edges: this page rewrote or removed nothing ({} persisting rows); \
                     do not repeat it at the same --offset",
                    summary.persisting()
                );
            }
        }
    }
    Ok(())
}

fn create_new(path: &Path) -> Result<BufWriter<File>, Box<dyn std::error::Error>> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(BufWriter::new(f))
}

fn read_edge_list(path: &Path) -> Result<BTreeSet<Uuid>, Box<dyn std::error::Error>> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = BTreeSet::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.insert(
            Uuid::parse_str(t)
                .map_err(|e| format!("{} line {}: not an edge id: {e}", path.display(), i + 1))?,
        );
    }
    Ok(out)
}

/// `--phase rewire-edges --sources-from-waves ...`: predict (`--dry-run`) or
/// apply the targeted rewire.
async fn run_targeted(
    cli: &Cli,
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for p in &cli.sources_from_waves {
        let f = File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
        records.extend(
            epigraph_cli::belief_cache::read_wave(BufReader::new(f))
                .map_err(|e| format!("{}: {e}", p.display()))?,
        );
    }
    let seed = seed_from_waves(&records, cli.epsilon);
    let opts = TargetedRunOptions {
        edges: cli.edges_from.as_deref().map(read_edge_list).transpose()?,
        max_passes: if cli.until_fixed { cli.max_passes } else { 1 },
        epsilon: cli.epsilon,
        only_changed: cli.only_changed,
        ..TargetedRunOptions::default()
    };
    println!(
        "targeted rewire: {} wave record(s), {} moved source(s), accepted list: {}",
        records.len(),
        seed.moved.len(),
        opts.edges
            .as_ref()
            .map_or_else(|| "none".to_string(), |e| e.len().to_string())
    );
    if cli.dry_run {
        let mut report = predict_targeted_rewire(pool, viewer, &seed, &opts).await?;
        report.run.wave_files = cli
            .sources_from_waves
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        println!(
            "PREDICT ({}): would_rewrite={} unchanged={} held={:?} would_remove={} \
             would_vacate={} cycle_unconverged={} converged={} passes={}",
            report.seed_mode,
            report.totals.would_rewrite,
            report.totals.unchanged,
            report.totals.held,
            report.totals.would_remove,
            report.totals.would_vacate,
            report.totals.cycle_unconverged,
            report.converged,
            report.passes.len()
        );
        if let Some(path) = &cli.predict_json {
            let mut w = create_new(path)?;
            serde_json::to_writer_pretty(&mut w, &report)?;
            std::io::Write::flush(&mut w)?;
            println!("predict report: {}", path.display());
        }
        return Ok(());
    }
    let (Some(snapshot), Some(edge_rows)) = (&cli.snapshot, &cli.edge_rows) else {
        return Err("a real targeted rewire needs --snapshot and --edge-rows".into());
    };
    let mut wave_w = create_new(snapshot)?;
    let mut rows_w = create_new(edge_rows)?;
    let report = run_targeted_rewire(pool, viewer, &seed, &opts, &mut wave_w, &mut rows_w).await?;
    for p in &report.passes {
        println!(
            "pass {}: selected={} rewired={} unchanged={} held={:?} chain_boundary_held={} \
             skipped_stale={} failed={} moved_targets={}",
            p.pass,
            p.selected,
            p.rewired,
            p.unchanged,
            p.held,
            p.chain_boundary_held,
            p.skipped_stale,
            p.failed,
            p.moved_targets
        );
    }
    println!(
        "targeted rewire: rewired={} converged={} unconverged_edges={}",
        report.rewired(),
        report.converged,
        report.unconverged_edges.len()
    );
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
    viewer: &epigraph_db::visibility::Viewer,
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
        // The served calibration (`CALIBRATION_PATH`, else the compiled-in
        // copy), never a cwd file with a 0.7 fallback (backlog d83b998a).
        let weight = epigraph_engine::calibration::CalibrationConfig::cached()
            .get_evidence_type_weight(&evidence_type);
        // An operator backfill on the DSN the operator supplies — in practice a
        // superuser, where a tenancy stamp is inert. The acquire is mechanical: it
        // moves each row's wiring onto ONE connection instead of a checkout per
        // statement, which is also what makes the savepoint inside the helper
        // meaningful.
        let mut conn = match pool.acquire().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  skip: could not acquire a connection: {e}");
                continue;
            }
        };
        match ds_auto::auto_wire_ds_update(
            &mut conn,
            viewer,
            claim_id,
            signer_id,
            1.0, // confidence: only evidence-type weight shapes the BBA
            weight,
            true, // existing ingest semantics: evidence supports its claim
            Some(&evidence_type),
            Some(evidence_id),
            // No truth_value seed: a factorless claim's truth_value may already
            // be derived from the very evidence this backfills, so seeding it
            // would count that evidence twice (drain U026, operator Q3).
            false,
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

async fn run_edge_phase(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
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
        for (eid, author, src, tgt, rel) in rows.iter().take(5) {
            println!("  edge={eid} author={author} {src} —[{rel}]→ {tgt}");
        }
        return Ok(summary);
    }

    // `author`: the source claim's author (`EDGE_QUERY`, ruling R-49), never
    // the edge's signer.
    for (edge_id, author, source_id, target_id, relationship) in rows {
        let mut conn = match pool.acquire().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  skip: could not acquire a connection: {e}");
                continue;
            }
        };
        match ds_auto::auto_wire_ds_for_edge(
            &mut conn,
            viewer,
            edge_id,
            author,
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

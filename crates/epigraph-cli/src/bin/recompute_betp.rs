//! Operator binary: reviewed belief-cache WAVES over evidenced atoms
//! (cohort v2), and the accepted-vacate path (atom-level belief program,
//! SPEC §10.3 order of operations, §10.4 gates and drift decomposition, §10.5
//! residue and vacate path, §10.7 the held apply, §10.8 rollback).
//!
//! Usage:
//!
//! ```text
//! # review a wave (writes nothing; exempt from the mode check)
//! recompute_betp --dry-run --role standalone|leaf \
//!     [--target-fold legacy|aef_standalone|aef] \
//!     [--target-compound-source-edges frozen|excluded] --s0 <snapshot> \
//!     [--alpha-manifest <row ids>] [--report <file>] [--accept-vacate <list>]
//!
//! # apply a wave, or an accepted vacate list (one per run)
//! recompute_betp (--role standalone|leaf | --accept-vacate <list>) \
//!     --snapshot <wave file> --wave <name> --disk-path <path> \
//!     (--disk-check-cmd <cmd> | --no-backup-check) \
//!     [--min-free-gb N] [--projected-bytes-per-claim N] \
//!     [--batch-size N] [--pace-ms N] [--concurrency N]
//!
//! # the cohort-v1 report (#197's arms (a) and (b)), legacy fold, dry run only
//! recompute_betp --dry-run
//! ```
//!
//! **The wave cohort** (`--role`) is every current claim of that role with a
//! non-empty AEF input (P1): never a compound, a procedural claim, or a claim
//! whose only input is the ingest template. Each claim goes through the
//! single atom-cache writer, `recompute_atom_cache`, under this process's
//! `EPIGRAPH_ATOM_FOLD` (it stamps `binary_truth` and resyncs the atom's
//! existing per-scope `ds_combined_beliefs` rows from the fold).
//!
//! **A writing run** needs all of:
//! * `--role` or `--accept-vacate`, not both: a writing run with neither (the
//!   cohort-v1 apply) is refused, and a wave and a vacate batch are separate
//!   runs, each restored from its own wave file;
//! * `--snapshot <wave file>`, fresh (absent or empty, and so is its
//!   sidecar): before each commit the run appends what it found and what it
//!   wrote (`belief_cache::WaveRecord`, one `wave_at` per run from the
//!   database clock), and per-scope rows to `<wave file>.scoped.jsonl`, so
//!   `restore_belief_cache --from <wave file>` can undo exactly that run by
//!   compare-and-swap;
//! * `--wave <name>` and the disk gate (`--disk-path`, headroom
//!   `--min-free-gb`, provisional default 20, and the backup and archive
//!   health check `--disk-check-cmd`, or an explicit `--no-backup-check`),
//!   checked before EVERY batch; a failure aborts before that batch writes
//!   (exit 4). The run's modes and gate are recorded in
//!   `<wave file>.run.json`;
//! * matching belief modes: the API's `/health` (`EPIGRAPH_API`, else
//!   `EPIGRAPH_API_URL`) must report this process's modes (exit 3 otherwise);
//! * for `--role`, a fold that covers the role (`aef_standalone` or `aef`
//!   for standalones, `aef` for leaves): the wave is the reviewed AEF apply,
//!   and a legacy recompute of the cohort is the frozen cohort-v1 apply
//!   (exit 3 otherwise).
//!
//! Exit status: 0 done; 2 usage refusal; 3 mode refusal; 4 disk-gate abort;
//! 5 one or more claims failed (each rolled back; the others committed and
//! recorded); 1 any other error.
//!
//! **`--accept-vacate <list.jsonl>`** writes the explicit vacuous cache (Bel
//! 0, Pl 1, BetP .5, `binary_truth`, read back as `unproven`), in list order,
//! ONLY for listed ids, and only for those that are residue: a listed
//! compound, procedural or rule claim, superseded claim, or atom with AEF
//! input, is skipped and reported. List lines are `{"claim_id": ...}`, plus
//! `{"rule": ...}` lines naming the accepted class rule. The run copies the
//! list next to the wave file, as `<wave file>.accept-vacate.<h>.jsonl`, and
//! names its records' wave `<wave>:vacate:<h>`, where `<h>` is the first 16
//! hex digits of the list's SHA-256.
//!
//! **`--dry-run`** writes nothing and is exempt from the mode check. With
//! `--role` it prints (or writes to `--report`) one JSON line per cohort atom
//! with the drift decomposition from S0 (`--s0`, a `belief_snapshot` file)
//! under `--target-fold` and `--target-compound-source-edges` (default: this
//! process's settings), whatever the server's are; each line names both: components (0b) organic writes since S0, (0c) the clamp
//! residue, (1) the owner-rule recompute, (1') the α change (only with
//! `--alpha-manifest`, the `mass_functions` ids a type backfill set after S0;
//! else `null`), (2) the template drop, (3) the AEF row set, (3a) the
//! one-sided compound-source read, (3b) compound-source rows excluded, (3c)
//! paper-key grouping, (4) attribution. S0 plus the components is the value
//! the wave writes. With `--accept-vacate` it reports what each listed id
//! would get.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use futures::StreamExt as _;
use uuid::Uuid;

use epigraph_cli::belief_cache::read_snapshot;
use epigraph_cli::belief_mode_check::{enforce_or_exit, RunIntent, MODE_CHECK_REFUSED_EXIT};
use epigraph_cli::recompute_betp::{
    cse_str, drift_decomposition, fold_str, parse_accept_list, predict_cached_after, select_cohort,
    select_wave_cohort, vacate_listed_claim, write_wave_claim, DiskGate, DriftLine, WaveLog,
    WaveRole, DRIFT_COMPONENTS,
};
use epigraph_engine::atom_items::{AtomFoldMode, CompoundSourceEdges};
use epigraph_engine::edge_factor::{AtomCacheOutcome, AtomCacheSettings, VacateOutcome};

/// Exit status of a run the disk gate aborted.
const DISK_GATE_EXIT: i32 = 4;
/// Exit status of a usage refusal (as clap's).
const USAGE_EXIT: i32 = 2;
/// Exit status of a run in which one or more claims failed (each rolled
/// back; the others committed and recorded).
const CLAIM_ERRORS_EXIT: i32 = 5;

#[derive(Parser, Debug)]
#[command(
    name = "recompute_betp",
    about = "Reviewed belief-cache waves over evidenced atoms (cohort v2) and the accepted-vacate path"
)]
struct Cli {
    /// Write nothing: report the wave (drift decomposition), the vacate list,
    /// or, with neither, the cohort-v1 legacy preview.
    #[arg(long)]
    dry_run: bool,
    /// The wave: `standalone` or `leaf` atoms with AEF input.
    #[arg(long, value_parser = parse_role)]
    role: Option<WaveRole>,
    /// With --dry-run --role: the fold the decomposition is for, whatever the
    /// server's `EPIGRAPH_ATOM_FOLD` is (SPEC §10.3). Default: this process's.
    #[arg(long, requires = "dry_run", requires = "role", value_parser = parse_target_fold)]
    target_fold: Option<AtomFoldMode>,
    /// With --dry-run --role: the compound-source-edges setting the cohort
    /// and decomposition are for (`frozen` or `excluded`), whatever this
    /// process's `EPIGRAPH_COMPOUND_SOURCE_EDGES` is. Default: this process's.
    #[arg(long, requires = "dry_run", requires = "role", value_parser = parse_cse)]
    target_compound_source_edges: Option<CompoundSourceEdges>,
    /// With --dry-run --role: snapshot S0 (a `belief_snapshot` file), the
    /// decomposition's starting point.
    #[arg(long)]
    s0: Option<PathBuf>,
    /// With --dry-run --role: `mass_functions` ids (one per line, or JSON
    /// lines with `id`) whose `evidence_type` a backfill set after S0, so the
    /// α change (1') is separable.
    #[arg(long)]
    alpha_manifest: Option<PathBuf>,
    /// With --dry-run --role: write the decomposition here (JSON lines)
    /// instead of stdout.
    #[arg(long)]
    report: Option<PathBuf>,
    /// An operator-accepted vacate list (JSON lines, SPEC §10.5).
    #[arg(long)]
    accept_vacate: Option<PathBuf>,
    /// The wave file every write is recorded in (mandatory for a real run).
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// The wave's name, recorded with every write (mandatory for a real run).
    #[arg(long)]
    wave: Option<String>,
    /// A path on the database's data volume, for the disk gate (mandatory
    /// for a real run).
    #[arg(long)]
    disk_path: Option<PathBuf>,
    /// Free space (GB) that must remain after each batch's projected writes.
    #[arg(long, default_value_t = 20.0)]
    min_free_gb: f64,
    /// Projected write volume per claim, in bytes: WAL and archive, plus the
    /// wave file's and sidecar's records when they are on the measured volume.
    #[arg(long, default_value_t = 65_536)]
    projected_bytes_per_claim: u64,
    /// The backup and archive health check the disk gate runs before each
    /// batch (exit 0 = pass), for example `pgbackrest check` plus a backup-age
    /// test. A real run needs this or `--no-backup-check`.
    #[arg(long, conflicts_with = "no_backup_check")]
    disk_check_cmd: Option<String>,
    /// Run the disk gate on free space alone, with no backup check. A
    /// deliberate opt-out: printed, and recorded in `<wave file>.run.json`.
    #[arg(long)]
    no_backup_check: bool,
    /// Claims per batch (the disk gate runs before each).
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,
    /// Pause between batches, in milliseconds.
    #[arg(long, default_value_t = 0)]
    pace_ms: u64,
    /// Concurrency within a batch. Default 8.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Print a progress line every N claims. Default 100.
    #[arg(long, default_value_t = 100)]
    progress_every: usize,
    /// Proceed with a writing run although this process's belief modes differ
    /// from the API's `/health` report (or cannot be read). For tests and a
    /// deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
}

fn parse_target_fold(raw: &str) -> Result<AtomFoldMode, String> {
    AtomFoldMode::parse_value(raw)
        .ok_or_else(|| format!("unknown fold {raw:?}; one of legacy, aef_standalone, aef"))
}

fn parse_cse(raw: &str) -> Result<CompoundSourceEdges, String> {
    CompoundSourceEdges::parse_value(raw)
        .ok_or_else(|| format!("unknown setting {raw:?}; one of frozen, excluded"))
}

fn parse_role(raw: &str) -> Result<WaveRole, String> {
    WaveRole::parse_value(raw)
        .ok_or_else(|| format!("unknown role {raw:?}; one of standalone, leaf"))
}

/// The usage rules clap cannot express. `Err` is the refusal text.
fn validate(cli: &Cli) -> Result<(), String> {
    if cli.dry_run {
        if cli.role.is_some() && cli.s0.is_none() {
            return Err(
                "a wave dry run (--dry-run --role) needs --s0 <snapshot>: the drift \
                 decomposition is measured from snapshot S0 (SPEC §10.4), not from the \
                 served value"
                    .into(),
            );
        }
        return Ok(());
    }
    if cli.role.is_none() && cli.accept_vacate.is_none() {
        return Err(
            "a writing run needs --role <standalone|leaf> (a wave) or --accept-vacate \
             <list> (a vacate batch); the cohort-v1 apply is removed (SPEC §10.7). Use \
             --dry-run for the cohort-v1 report"
                .into(),
        );
    }
    if cli.role.is_some() && cli.accept_vacate.is_some() {
        return Err(
            "a writing run is a wave (--role) or a vacate batch (--accept-vacate), not both: \
             each is restored from its own wave file (SPEC §10.5, §10.8). Run them \
             separately, each with its own --snapshot"
                .into(),
        );
    }
    let mut missing = Vec::new();
    if cli.snapshot.is_none() {
        missing.push("--snapshot <wave file> (every write is recorded for a CAS restore)");
    }
    if cli.wave.is_none() {
        missing.push("--wave <name>");
    }
    if cli.disk_path.is_none() {
        missing.push("--disk-path <path on the data volume> (the disk gate)");
    }
    if cli.disk_check_cmd.is_none() && !cli.no_backup_check {
        missing.push(
            "--disk-check-cmd <backup and archive health check> (the disk gate's backup \
             half; --no-backup-check to opt out, recorded)",
        );
    }
    if !missing.is_empty() {
        return Err(format!(
            "a writing run needs {} (SPEC §10.7, §10.4)",
            missing.join(", ")
        ));
    }
    if let Some(wave_file) = &cli.snapshot {
        wave_file_is_fresh(wave_file)?;
    }
    for (flag, set) in [
        ("--s0", cli.s0.is_some()),
        ("--alpha-manifest", cli.alpha_manifest.is_some()),
        ("--report", cli.report.is_some()),
    ] {
        if set {
            return Err(format!("{flag} is for a wave dry run (--dry-run --role)"));
        }
    }
    Ok(())
}

/// One wave file holds one run (SPEC §10.8): a run's records are restored
/// together, so a wave file, or its scoped sidecar, that already holds
/// records is refused. An empty or absent file is fresh.
fn wave_file_is_fresh(wave_file: &std::path::Path) -> Result<(), String> {
    for path in [
        wave_file.to_path_buf(),
        epigraph_cli::belief_cache::scoped_sidecar_path(wave_file),
    ] {
        match std::fs::metadata(&path) {
            Ok(m) if m.len() > 0 => {
                return Err(format!(
                    "{} already holds records: one wave file holds one run, so a restore \
                     undoes exactly that run (SPEC §10.8). Give this run a new --snapshot",
                    path.display()
                ))
            }
            _ => {}
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Err(usage) = validate(&cli) {
        eprintln!("recompute_betp: refusing: {usage}");
        std::process::exit(USAGE_EXIT);
    }

    // Before the database: a writing run must show its belief modes match the
    // API's (SPEC §10.2). A dry run writes nothing and is exempt.
    let intent = if cli.dry_run {
        RunIntent::WritesNothing
    } else {
        RunIntent::Writes
    };
    enforce_or_exit("recompute_betp", intent, cli.allow_mode_skew).await;
    let settings = AtomCacheSettings::current();
    if !cli.dry_run {
        if let Some(role) = cli.role {
            if !role.folded_by(settings.fold) {
                eprintln!(
                    "recompute_betp: refusing a writing {role} wave under atom_fold={fold}: \
                     that fold does not fold {role} caches with the AEF, so the wave would \
                     write the legacy owner fold, which is the frozen cohort-v1 apply. A \
                     {role} wave runs under {need} (SPEC §10.3), after its dry run is \
                     reviewed.",
                    role = role.as_str(),
                    fold = fold_str(settings.fold),
                    need = if role == WaveRole::Leaf {
                        "aef"
                    } else {
                        "aef_standalone or aef"
                    },
                );
                std::process::exit(MODE_CHECK_REFUSED_EXIT);
            }
        }
    }

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not. Built AFTER clap and the checks,
    // and `session` is held for the whole run.
    let maint = epigraph_cli::MaintenancePool::connect("recompute_betp")
        .await
        .expect("maintenance pool");
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance viewer");
    let viewer = session.viewer();
    let result = if cli.dry_run {
        run_dry(&cli, maint.pool(), viewer, settings).await
    } else {
        run_real(&cli, maint.pool(), viewer, settings).await
    };
    match result {
        Ok(()) => {}
        Err(RunError::DiskGate(why)) => {
            eprintln!("recompute_betp: aborted: {why}");
            std::process::exit(DISK_GATE_EXIT);
        }
        Err(RunError::ClaimErrors(n)) => {
            eprintln!("recompute_betp: {n} claim(s) failed; see above");
            std::process::exit(CLAIM_ERRORS_EXIT);
        }
        Err(RunError::Other(e)) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

enum RunError {
    DiskGate(String),
    ClaimErrors(usize),
    Other(String),
}

impl From<String> for RunError {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// A manifest of `mass_functions` ids: one uuid per line, or JSON lines
/// with an `id` field; blank and `#` lines skipped.
fn read_row_manifest(path: &std::path::Path) -> Result<HashSet<Uuid>, String> {
    let text =
        String::from_utf8(read_file(path)?).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = HashSet::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let id = if t.starts_with('{') {
            serde_json::from_str::<serde_json::Value>(t)
                .ok()
                .and_then(|v| {
                    v.get("id")
                        .and_then(|x| x.as_str())
                        .and_then(|s| s.parse().ok())
                })
        } else {
            t.parse().ok()
        };
        out.insert(id.ok_or_else(|| format!("{} line {}: no row id", path.display(), i + 1))?);
    }
    Ok(out)
}

async fn run_dry(
    cli: &Cli,
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    settings: AtomCacheSettings,
) -> Result<(), RunError> {
    println!("DRY-RUN — no writes");
    if let Some(role) = cli.role {
        let target = cli.target_fold.unwrap_or(settings.fold);
        let s0_path = cli.s0.as_ref().expect("validated");
        let s0: std::collections::HashMap<Uuid, Option<f64>> =
            read_snapshot(std::io::Cursor::new(read_file(s0_path)?))
                .map_err(|e| format!("{}: {e}", s0_path.display()))?
                .into_iter()
                .map(|r| (r.claim_id, r.pignistic_prob))
                .collect();
        let manifest = match &cli.alpha_manifest {
            Some(p) => Some(read_row_manifest(p)?),
            None => None,
        };
        let cse = cli
            .target_compound_source_edges
            .unwrap_or(settings.compound_source_edges);
        let cohort = select_wave_cohort(pool, viewer, role, cse).await?;
        println!(
            "wave cohort: {} {} atoms with AEF input; target fold {}, compound_source_edges {}",
            cohort.len(),
            role.as_str(),
            fold_str(target),
            cse_str(cse)
        );
        let mut out: Box<dyn std::io::Write> = match &cli.report {
            Some(p) => Box::new(std::io::BufWriter::new(
                std::fs::File::create(p).map_err(|e| format!("{}: {e}", p.display()))?,
            )),
            None => Box::new(std::io::stdout()),
        };
        let mut lines: Vec<DriftLine> = Vec::with_capacity(cohort.len());
        for &claim_id in &cohort {
            let line = drift_decomposition(
                pool,
                viewer,
                claim_id,
                role,
                target,
                cse,
                s0.get(&claim_id).copied().flatten(),
                manifest.as_ref(),
            )
            .await?;
            serde_json::to_writer(&mut out, &line).map_err(|e| e.to_string())?;
            out.write_all(b"\n").map_err(|e| e.to_string())?;
            lines.push(line);
        }
        out.flush().map_err(|e| e.to_string())?;
        print_drift_summary(&lines);
    }
    if let Some(list) = &cli.accept_vacate {
        let accepted = parse_accept_list(&read_file(list)?)?;
        println!(
            "accept list: {} ids, sha256 {}, rules {:?}",
            accepted.ids.len(),
            accepted.sha256,
            accepted.rules
        );
        // The vacate's own refusal ladder, read-only.
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
        for &id in &accepted.ids {
            let refusal = epigraph_engine::edge_factor::vacate_refusal(
                &mut conn,
                viewer,
                id,
                settings.compound_source_edges,
            )
            .await?;
            let verdict = refusal.map_or("would_vacate", vacate_key);
            println!("{}", serde_json::json!({"claim_id": id, "vacate": verdict}));
        }
    }
    if cli.role.is_none() && cli.accept_vacate.is_none() {
        run_cohort_v1_report(pool, viewer).await?;
    }
    Ok(())
}

fn print_drift_summary(lines: &[DriftLine]) {
    println!(
        "drift summary over {} atoms (|component| median, max):",
        lines.len()
    );
    for key in DRIFT_COMPONENTS {
        let mut v: Vec<f64> = lines
            .iter()
            .filter_map(|l| l.components.get(key).copied().flatten())
            .map(f64::abs)
            .collect();
        if v.is_empty() {
            println!("  ({key}) not separable in this run");
            continue;
        }
        v.sort_by(f64::total_cmp);
        let movers = v.iter().filter(|x| **x > 1e-9).count();
        println!(
            "  ({key}) median {:.6} max {:.6} movers {movers}",
            v[v.len() / 2],
            v[v.len() - 1]
        );
    }
    let missing = lines.iter().filter(|l| l.s0_missing).count();
    if missing > 0 {
        println!("  {missing} atoms not in S0: their decomposition starts at the served value");
    }
}

/// The cohort-v1 report (SPEC §10.7: "dry-run report kept"): #197's arms
/// (a) and (b), each claim's cached BetP against what the legacy owner fold
/// would cache. Writes nothing.
async fn run_cohort_v1_report(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), RunError> {
    let cohort = select_cohort(pool).await.map_err(|e| e.to_string())?;
    println!("cohort v1: {} claims (legacy owner fold)", cohort.len());
    println!(
        "{:<38} {:>14} {:>16} {:>10}",
        "claim_id", "cached_before", "recomputed_after", "delta"
    );
    let (mut previewed, mut unchanged, mut skipped) = (0usize, 0usize, 0usize);
    for &claim_id in &cohort {
        let cached_before: Option<f64> =
            sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| e.to_string())?
                .flatten();
        // No owner: a recompute writes nothing for this claim (no BBA, only
        // ingest templates, or a compound).
        let Some((_, owned)) = predict_cached_after(pool, viewer, claim_id).await? else {
            skipped += 1;
            continue;
        };
        let after = owned.pignistic_prob;
        println!(
            "{:<38} {:>14} {:>16.6} {:>10}",
            claim_id,
            cached_before.map_or_else(|| "NULL".to_string(), |v| format!("{v:.6}")),
            after,
            cached_before.map_or_else(|| "n/a".to_string(), |b| format!("{:+.6}", after - b)),
        );
        previewed += 1;
        if cached_before.is_some_and(|b| (after - b).abs() < 1e-9) {
            unchanged += 1;
        }
    }
    println!(
        "dry-run summary: {previewed} claims previewed, {unchanged} unchanged, {skipped} with no \
         recomputable input (no BBA, only ingest templates, or a compound) (of {} cohort claims)",
        cohort.len()
    );
    Ok(())
}

async fn run_real(
    cli: &Cli,
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    settings: AtomCacheSettings,
) -> Result<(), RunError> {
    let wave_file = cli.snapshot.as_ref().expect("validated");
    let wave = cli.wave.as_deref().expect("validated");
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let gate = DiskGate {
        path: cli.disk_path.clone().expect("validated"),
        min_free_bytes: (cli.min_free_gb.max(0.0) * 1e9) as u64,
        projected_bytes_per_claim: cli.projected_bytes_per_claim,
        check_cmd: cli.disk_check_cmd.clone(),
    };
    // Read the accept list before anything is written, so a malformed list
    // stops the run first.
    let accepted = match &cli.accept_vacate {
        Some(p) => {
            let bytes = read_file(p)?;
            Some((parse_accept_list(&bytes)?, bytes))
        }
        None => None,
    };

    // `wave_at`: the database clock, in its own statement, before any write
    // (`belief_cache::WaveRecord::at`).
    let wave_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("wave_at: {e}"))?;
    let log = WaveLog::open(wave_file, wave, wave_at)?;
    println!(
        "wave {wave}: wave_at {wave_at}; recording to {}",
        wave_file.display()
    );
    let disk_check = match &gate.check_cmd {
        Some(cmd) => serde_json::json!({ "command": cmd }),
        None => {
            println!("disk gate: free space only, NO backup check (--no-backup-check; recorded)");
            serde_json::json!({ "command": null, "no_backup_check": true })
        }
    };
    write_run_record(
        wave_file,
        &serde_json::json!({
            "wave": wave,
            "wave_at": wave_at,
            "role": cli.role.map(WaveRole::as_str),
            "accept_vacate_sha256": accepted.as_ref().map(|(l, _)| l.sha256.clone()),
            "atom_fold": fold_str(settings.fold),
            "compound_source_edges": cse_str(settings.compound_source_edges),
            "disk_gate": {
                "path": gate.path,
                "min_free_bytes": gate.min_free_bytes,
                "projected_bytes_per_claim": gate.projected_bytes_per_claim,
                "backup_check": disk_check,
            },
        }),
    )?;

    if let Some(role) = cli.role {
        let cohort = select_wave_cohort(pool, viewer, role, settings.compound_source_edges).await?;
        println!(
            "wave cohort: {} {} atoms with AEF input; atom_fold {}, compound_source_edges {}",
            cohort.len(),
            role.as_str(),
            fold_str(settings.fold),
            cse_str(settings.compound_source_edges)
        );
        run_wave_batches(cli, pool, viewer, role, settings, &gate, &log, &cohort).await?;
    }

    if let Some((list, bytes)) = accepted {
        let copy = {
            let mut p = wave_file.as_os_str().to_owned();
            p.push(format!(".accept-vacate.{}.jsonl", &list.sha256[..16]));
            PathBuf::from(p)
        };
        std::fs::write(&copy, &bytes).map_err(|e| format!("{}: {e}", copy.display()))?;
        let vacate_wave = format!("{wave}:vacate:{}", &list.sha256[..16]);
        println!(
            "accept list: {} ids, rules {:?}, stored at {}",
            list.ids.len(),
            list.rules,
            copy.display()
        );
        run_vacate_batches(
            cli,
            pool,
            viewer,
            settings.compound_source_edges,
            &gate,
            &log,
            &vacate_wave,
            &list.ids,
        )
        .await?;
    }
    Ok(())
}

/// `<wave file>.run.json`: what the run was (its modes and its disk gate,
/// including a `--no-backup-check` opt-out), beside the records it makes.
fn write_run_record(wave_file: &std::path::Path, record: &serde_json::Value) -> Result<(), String> {
    let mut p = wave_file.as_os_str().to_owned();
    p.push(".run.json");
    let p = PathBuf::from(p);
    let text = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))
}

async fn pace(cli: &Cli, batch: usize) {
    if cli.pace_ms > 0 && batch > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(cli.pace_ms)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_wave_batches(
    cli: &Cli,
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    role: WaveRole,
    settings: AtomCacheSettings,
    gate: &DiskGate,
    log: &WaveLog,
    cohort: &[Uuid],
) -> Result<(), RunError> {
    let total = cohort.len();
    let done = AtomicUsize::new(0);
    let written = AtomicUsize::new(0);
    let scoped = AtomicUsize::new(0);
    let compound = AtomicUsize::new(0);
    let role_changed = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);
    for (i, batch) in cohort.chunks(cli.batch_size.max(1)).enumerate() {
        pace(cli, i).await;
        gate.check(batch.len())
            .map_err(|why| RunError::DiskGate(format!("before wave batch {}: {why}", i + 1)))?;
        futures::stream::iter(batch.iter().copied())
            .map(|claim_id| {
                let (done, written, scoped, compound, role_changed, errors) =
                    (&done, &written, &scoped, &compound, &role_changed, &errors);
                async move {
                    match write_wave_claim(pool, viewer, claim_id, role, settings, log).await {
                        Ok(o) => {
                            if o.changed {
                                written.fetch_add(1, Ordering::Relaxed);
                            }
                            scoped.fetch_add(o.scoped_rewritten, Ordering::Relaxed);
                            if o.outcome == Some(AtomCacheOutcome::CompoundSkipped) {
                                compound.fetch_add(1, Ordering::Relaxed);
                            }
                            if o.role_changed {
                                role_changed.fetch_add(1, Ordering::Relaxed);
                                println!("  {claim_id}: role_changed (skipped)");
                            }
                        }
                        Err(e) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                            eprintln!("  {claim_id}: {e}");
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if cli.progress_every > 0 && n.is_multiple_of(cli.progress_every) {
                        println!(
                            "  [{n}/{total}] written={} errors={}",
                            written.load(Ordering::Relaxed),
                            errors.load(Ordering::Relaxed)
                        );
                    }
                }
            })
            .buffer_unordered(cli.concurrency.max(1))
            .for_each(|()| async {})
            .await;
    }
    println!(
        "wave done: {} caches changed, {} scoped rows resynced, {} compounds skipped, {} \
         skipped as role_changed, {} errors (of {total})",
        written.load(Ordering::Relaxed),
        scoped.load(Ordering::Relaxed),
        compound.load(Ordering::Relaxed),
        role_changed.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed),
    );
    match errors.load(Ordering::Relaxed) {
        0 => Ok(()),
        n => Err(RunError::ClaimErrors(n)),
    }
}

/// The report key of a vacate outcome, shared by the run and its dry run.
const fn vacate_key(outcome: VacateOutcome) -> &'static str {
    match outcome {
        VacateOutcome::Vacated { written: true } => "vacated",
        VacateOutcome::Vacated { written: false } => "not_taken_by_cache",
        VacateOutcome::NotVisible => "skipped_not_found",
        VacateOutcome::Compound => "skipped_compound",
        VacateOutcome::NotAnAtom => "skipped_not_an_atom",
        VacateOutcome::NotCurrent => "skipped_not_current",
        VacateOutcome::HasAefInput => "skipped_has_aef_input",
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_vacate_batches(
    cli: &Cli,
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    compound_source_edges: CompoundSourceEdges,
    gate: &DiskGate,
    log: &WaveLog,
    wave: &str,
    ids: &[Uuid],
) -> Result<(), RunError> {
    let mut counts: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut errors = 0usize;
    // In list order (the list is ordered lowest recall exposure first, SPEC
    // §10.5), one claim at a time.
    for (i, batch) in ids.chunks(cli.batch_size.max(1)).enumerate() {
        pace(cli, i).await;
        gate.check(batch.len())
            .map_err(|why| RunError::DiskGate(format!("before vacate batch {}: {why}", i + 1)))?;
        for &claim_id in batch {
            match vacate_listed_claim(pool, viewer, claim_id, compound_source_edges, log, wave)
                .await
            {
                Ok(o) => {
                    let key = vacate_key(o);
                    *counts.entry(key).or_default() += 1;
                    if key != "vacated" {
                        println!("  {claim_id}: {key}");
                    }
                }
                Err(e) => {
                    errors += 1;
                    eprintln!("  {claim_id}: {e}");
                }
            }
        }
    }
    println!(
        "vacate done: {counts:?}, {errors} errors (of {})",
        ids.len()
    );
    match errors {
        0 => Ok(()),
        n => Err(RunError::ClaimErrors(n)),
    }
}

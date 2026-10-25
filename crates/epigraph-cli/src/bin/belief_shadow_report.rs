//! `belief_shadow_report`: what every claim serves today beside what it
//! would serve under the atom fold and the per-viewer compound derivation,
//! plus the statistics the atom-level belief cutover is reviewed on (SPEC
//! §1.3, §3.2, §7.1, §8, §10.4). See `epigraph_cli::shadow_report`.
//!
//! It writes nothing to the database: every read runs on one session set
//! `default_transaction_read_only`. It writes files only, under
//! `--out/<UTC stamp, to the microsecond>/<viewer>/` (directories mode 0700;
//! a run never writes into an existing stamped directory):
//!
//! * `claims.jsonl`: one line per claim the viewer can read;
//! * `summary.json`: the corpus statistics;
//! * `replay_progressive.jsonl`, `replay_strict.jsonl`: one line per recall
//!   event replayed.
//!
//! The report carries claim ids and values, so `--out` belongs in the
//! operator's private report directory, never in a repository.
//!
//! Usage:
//!     belief_shadow_report --out <dir> [--viewer both|maintenance|anonymous]
//!         [--days 30] [--target-fold aef|aef_standalone] [--claims <ids file>]
//!         [--owner-preview] [--s0 <snapshot.jsonl>]
//!         [--graph-view-exposure <jsonl>]

use std::collections::HashMap;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use uuid::Uuid;

use epigraph_cli::shadow_report::{run_report_on, ClaimLine, ReportOptions, Scope, Summary};
use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_engine::atom_items::AtomFoldMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ViewerArg {
    /// The maintenance viewer (corpus statistics) and then the anonymous
    /// viewer (the public floor).
    Both,
    /// The maintenance viewer only.
    Maintenance,
    /// The anonymous viewer only.
    Anonymous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FoldArg {
    /// Every atom folds under the AEF.
    Aef,
    /// Standalones fold under the AEF; leaves keep today's value.
    AefStandalone,
}

#[derive(Parser, Debug)]
#[command(
    name = "belief_shadow_report",
    about = "Report served belief beside the atom fold and derived compound values; writes nothing to the database"
)]
struct Cli {
    /// Directory the report is written under (a UTC-stamped subdirectory is
    /// created in it).
    #[arg(long)]
    out: PathBuf,
    /// Which viewer(s) to compute claim values as.
    #[arg(long, value_enum, default_value_t = ViewerArg::Both)]
    viewer: ViewerArg,
    /// Recall events of the last N days are replayed and counted as
    /// exposure.
    #[arg(long, default_value_t = 30)]
    days: i64,
    /// The atom fold the candidate is read under.
    #[arg(long, value_enum, default_value_t = FoldArg::Aef)]
    target_fold: FoldArg,
    /// Limit the report to the claim ids in this file (one per line).
    #[arg(long)]
    claims: Option<PathBuf>,
    /// Claims per page.
    #[arg(long, default_value_t = 500)]
    page_size: usize,
    /// How many top movers and rank moves to list.
    #[arg(long, default_value_t = 100)]
    top: usize,
    /// A compound moving more than this many places counts as a rank move.
    #[arg(long, default_value_t = 100)]
    rank_threshold: usize,
    /// The conflict set's threshold on K.
    #[arg(long, default_value_t = 0.3)]
    conflict_min_k: f64,
    /// The sheaf cohomology's consistency threshold.
    #[arg(long, default_value_t = 0.05)]
    sheaf_threshold: f64,
    /// Compute the owner-rule recompute stage of each atom's drift
    /// decomposition (several reads per atom).
    #[arg(long)]
    owner_preview: bool,
    /// A belief snapshot (JSONL with `claim_id` and `pignistic_prob`): the
    /// start of each atom's drift decomposition.
    #[arg(long)]
    s0: Option<PathBuf>,
    /// Graph-view exposure measured elsewhere (JSONL with `claim_id` and
    /// `count`); without it the graph-view weights are reported null.
    #[arg(long)]
    graph_view_exposure: Option<PathBuf>,
}

fn read_lines(path: &Path) -> Result<Vec<String>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::io::BufReader::new(f)
        .lines()
        .map(|l| l.map_err(|e| format!("{}: {e}", path.display())))
        .filter(|l| l.as_ref().map_or(true, |l| !l.trim().is_empty()))
        .collect()
}

fn read_ids(path: &Path) -> Result<Vec<Uuid>, String> {
    read_lines(path)?
        .iter()
        .map(|l| Uuid::parse_str(l.trim()).map_err(|e| format!("{}: {l:?}: {e}", path.display())))
        .collect()
}

/// `claim_id` and one numeric field of each JSONL line; a line whose field
/// is null or absent is skipped.
fn read_keyed(path: &Path, field: &str) -> Result<Vec<(Uuid, f64)>, String> {
    let mut out = Vec::new();
    for l in read_lines(path)? {
        let v: serde_json::Value =
            serde_json::from_str(&l).map_err(|e| format!("{}: {e}", path.display()))?;
        let id = v
            .get("claim_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| format!("{}: a line has no claim_id", path.display()))?;
        if let Some(x) = v.get(field).and_then(serde_json::Value::as_f64) {
            out.push((id, x));
        }
    }
    Ok(out)
}

fn private_dir(path: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Create `path` (mode 0700), failing if it exists.
fn new_private_dir(path: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn writer(path: &Path) -> Result<BufWriter<std::fs::File>, String> {
    std::fs::File::create(path)
        .map(BufWriter::new)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn write_json_line<T: serde::Serialize>(w: &mut impl Write, v: &T) -> Result<(), String> {
    serde_json::to_writer(&mut *w, v).map_err(|e| e.to_string())?;
    w.write_all(b"\n").map_err(|e| e.to_string())
}

async fn run_one(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    events: &Viewer,
    opts: &ReportOptions,
    dir: &Path,
) -> Result<Summary, String> {
    private_dir(dir)?;
    let mut claims = writer(&dir.join("claims.jsonl"))?;
    let summary = run_report_on(conn, viewer, events, opts, |line: &ClaimLine| {
        write_json_line(&mut claims, line)
    })
    .await?;
    claims.flush().map_err(|e| e.to_string())?;
    for (name, replay) in [
        ("replay_progressive.jsonl", &summary.replay.progressive),
        ("replay_strict.jsonl", &summary.replay.strict),
    ] {
        let mut w = writer(&dir.join(name))?;
        for e in &replay.per_event {
            write_json_line(&mut w, e)?;
        }
        w.flush().map_err(|e| e.to_string())?;
    }
    let mut w = writer(&dir.join("summary.json"))?;
    serde_json::to_writer_pretty(&mut w, &summary).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    Ok(summary)
}

fn headline(label: &str, s: &Summary) {
    println!(
        "{label}: {} claims; residue {}; vacate {} atoms / {} compounds / {} spines; \
         fold mismatch {}/{} ({}); \
         compound confirmed set {} (progressive) / {} (strict); \
         gate loss {} (progressive) / {} (strict) over {} events",
        s.claims,
        s.residue,
        s.vacate.atoms,
        s.vacate.compounds,
        s.vacate.spines,
        s.fold_mismatch.mismatched,
        s.fold_mismatch.p1_atoms,
        if s.fold_mismatch.measures_floor {
            "the floor-viewer measure"
        } else {
            "not the floor-viewer measure"
        },
        s.compound_confirmed_set.progressive,
        s.compound_confirmed_set.strict,
        s.replay.progressive.lost,
        s.replay.strict.lost,
        s.replay.strict.events,
    );
    if !s.compound_statistics_valid {
        println!(
            "{label}: the compound statistics read leaf folds this target fold does not serve; \
             they do not describe this wave"
        );
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let since = chrono::Utc::now() - chrono::Duration::days(cli.days.max(0));
    let scope = match &cli.claims {
        Some(p) => Scope::Ids(read_ids(p)?),
        None => Scope::All,
    };
    let mut opts = ReportOptions::new(scope, since);
    opts.target_fold = match cli.target_fold {
        FoldArg::Aef => AtomFoldMode::Aef,
        FoldArg::AefStandalone => AtomFoldMode::AefStandalone,
    };
    opts.page_size = cli.page_size;
    opts.top = cli.top;
    opts.rank_threshold = cli.rank_threshold;
    opts.conflict_min_k = cli.conflict_min_k;
    opts.sheaf_threshold = cli.sheaf_threshold;
    opts.owner_preview = cli.owner_preview;
    if let Some(p) = &cli.s0 {
        opts.s0 = Some(read_keyed(p, "pignistic_prob")?.into_iter().collect());
    }
    if let Some(p) = &cli.graph_view_exposure {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let m: HashMap<Uuid, u64> = read_keyed(p, "count")?
            .into_iter()
            .map(|(id, c)| (id, c.max(0.0) as u64))
            .collect();
        opts.graph_view_exposure = Some(m);
    }

    // A fresh directory per run: microseconds in the stamp, and created
    // without `recursive`, so an existing one is refused rather than written
    // into.
    private_dir(&cli.out)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.6fZ").to_string();
    let root = cli.out.join(stamp);
    new_private_dir(&root)?;

    // Built after clap has parsed, so an argv error reads as one. The
    // maintenance session is held for the whole run, and every read runs on
    // its own connection: the bypass viewer is spent where it was issued.
    let maint = epigraph_cli::MaintenancePool::connect("belief_shadow_report")
        .await
        .map_err(|e| e.to_string())?;
    let mut session = maint
        .viewer(SystemReason::BeliefRecomputation)
        .await
        .map_err(|e| e.to_string())?;
    let (conn, maint_viewer) = session.split();

    if matches!(cli.viewer, ViewerArg::Both | ViewerArg::Maintenance) {
        let s = run_one(
            conn,
            maint_viewer,
            maint_viewer,
            &opts,
            &root.join("maintenance"),
        )
        .await?;
        headline("maintenance", &s);
    }
    if matches!(cli.viewer, ViewerArg::Both | ViewerArg::Anonymous) {
        // The nil principal: a real viewer with no group, which reads the
        // public corpus only (SPEC §8 T2, the floor viewer of a public claim).
        let anonymous = Viewer::resolve(maint.pool(), Uuid::nil())
            .await
            .map_err(|e| format!("anonymous viewer: {e}"))?;
        let s = run_one(
            conn,
            &anonymous,
            maint_viewer,
            &opts,
            &root.join("anonymous"),
        )
        .await?;
        headline("anonymous", &s);
    }
    println!("report written under {}", root.display());
    Ok(())
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

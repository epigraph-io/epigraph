//! `epigraph-operator` — the one-time operator ownership backfill.
//!
//! See `epigraph_cli::operator` for what each subcommand does and why. This
//! file is argument parsing and exit codes only.
//!
//! Every subcommand is a DRY RUN unless `--apply` is given, and every
//! subcommand connects on `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` alone and refuses
//! a session user that is not a member of `epigraph_maintenance`.
//!
//! Exit codes: 0 success; 1 refused or failed before writing (for
//! `hide-evidence --apply`, also an invariant violation, rolled back); 2 a
//! batch violated an invariant and was rolled back (under `--apply` the run
//! stops there); 3 `link-retired` refused at least one id, `reown-reverse` or
//! `strip-label-reverse` HELD at least one claim or hidden row (it is not fully
//! restored), or `reown-seed` held at least one claim (it is not fully
//! repaired).
//!
//! Usage:
//!     epigraph-operator link-retired --agents-file retired.txt --operator <uuid> [--apply]
//!     epigraph-operator reown-claims --claims-file claims.txt --operator <uuid> \
//!         --derived follow-claim --manifest-out reown-1.jsonl [--apply]
//!     epigraph-operator reown-reverse --manifest reown-2.jsonl --manifest reown-1.jsonl [--apply]
//!     epigraph-operator hide-evidence --claims-file claims.txt --operator <uuid> \
//!         --hide-evidence-type testimony [--hide-evidence-label L] [--hide-evidence-ids f] \
//!         [--apply --confirm-hide N --manifest-out hide-1.jsonl [--reason TEXT]]
//!     epigraph-operator reown-reverse --manifest hide-1.jsonl [--apply]
//!     epigraph-operator reown-seed [--claims-file claims.txt] --manifest-dir dir/ [--apply]
//!     epigraph-operator reown-reverse --manifest dir/reown-seed-<group>.jsonl ... [--apply]
//!     epigraph-operator strip-label [--label 'group:$EPICLAW_GROUP_ID'] \
//!         --manifest-out strip-1.jsonl [--apply]
//!     epigraph-operator strip-label-reverse --manifest strip-1.jsonl [--apply]

use clap::{Parser, Subcommand};
use epigraph_cli::operator::{self, hide, labels, link, reown, reverse, seed};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "epigraph-operator",
    about = "Operator ownership backfill: retired links, claim re-own, and its reversal"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record a RETIRED operator link for each agent id in a file.
    LinkRetired {
        /// One agent UUID per line; `#` comments and blank lines ignored.
        #[arg(long)]
        agents_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// Perform the calls. Without it, every call runs in a transaction that
        /// is rolled back.
        #[arg(long)]
        apply: bool,
    },
    /// Move the listed claims, and the rows they carry, into the operator's
    /// personal group.
    ReownClaims {
        /// One claim UUID per line; only these claims are ever touched.
        #[arg(long)]
        claims_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// What a derived row written by an agent NOT linked to the operator
        /// does. Required: it is a policy decision, so there is no default.
        #[arg(long, value_enum)]
        derived: reown::DerivedMode,
        /// Where to write the undo manifest. Must not exist. Written and
        /// fsynced before the first write under `--apply`.
        #[arg(long)]
        manifest_out: PathBuf,
        /// Perform the writes. Without it, every batch runs in its own
        /// transaction that is rolled back when the batch ends.
        #[arg(long)]
        apply: bool,
        /// Claims per transaction.
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        /// `lock_timeout` for each batch (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
        /// Opt-in evidence hiding. With none of these the run is unchanged.
        #[command(flatten)]
        hide: hide::HideArgs,
    },
    /// Report, and with `--apply` hide and pin, selected evidence on the
    /// operator's claims. Reversed by `reown-reverse --manifest`.
    HideEvidence {
        /// One claim UUID per line: the claims whose evidence is in scope.
        #[arg(long)]
        claims_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        #[command(flatten)]
        hide: hide::HideArgs,
        /// Hide the selected rows. Needs `--confirm-hide <N>` and
        /// `--manifest-out`, and the kernel pin guard (migration 110).
        #[arg(long)]
        apply: bool,
        /// Where to write the undo manifest under `--apply`. Must not exist.
        /// Written and fsynced before the write.
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        /// Recorded on every pin.
        #[arg(
            long,
            default_value = "hidden by the operator (epigraph-operator hide-evidence)"
        )]
        reason: String,
        /// `lock_timeout` for the write (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
    /// Move claims owned by migration 074's memberless seed group to the
    /// owner their author's declaration gives them (backlog 0512ca33). One
    /// manifest per target group; reversed by `reown-reverse`.
    ReownSeed {
        /// One claim UUID per line. Without it, every claim the seed group
        /// owns is considered.
        #[arg(long)]
        claims_file: Option<PathBuf>,
        /// An existing directory for the per-target manifests
        /// (`reown-seed-<group>.jsonl`, each must not exist). Written and
        /// fsynced before the first write under `--apply`.
        #[arg(long)]
        manifest_dir: PathBuf,
        /// Perform the writes. Without it, every batch runs in its own
        /// transaction that is rolled back when the batch ends.
        #[arg(long)]
        apply: bool,
        /// Claims per transaction.
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        /// `lock_timeout` for each batch (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
    /// Remove one label value the write-path validator rejects (backlog
    /// f6310444) from every claim carrying it, keeping every other label in
    /// place. Reversed by `strip-label-reverse`.
    StripLabel {
        /// The exact label value. Must be one the write path refuses.
        #[arg(long, default_value = labels::DEFAULT_LABEL)]
        label: String,
        /// Where to write the undo manifest under `--apply`. Must not exist.
        #[arg(long)]
        manifest_out: PathBuf,
        /// Commit the strip. Without it, it runs in a transaction that is
        /// rolled back.
        #[arg(long)]
        apply: bool,
        /// `lock_timeout` for the transaction (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
    /// Put back every label a `strip-label` manifest removed, where the claim
    /// is still exactly as the strip left it.
    StripLabelReverse {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
    /// Restore every row a manifest's run moved to the owner it recorded.
    ReownReverse {
        /// A manifest to reverse. Repeatable: several are applied newest-first
        /// by their header `created_at`, whatever order they are given in.
        #[arg(long, required = true)]
        manifest: Vec<PathBuf>,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
}

async fn main_inner() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    if let Command::ReownClaims { batch_size, .. }
    | Command::ReownReverse { batch_size, .. }
    | Command::ReownSeed { batch_size, .. } = &cli.command
    {
        if *batch_size == 0 {
            anyhow::bail!("--batch-size must be at least 1");
        }
    }
    let db = operator::connect().await?;
    eprintln!(
        "epigraph-operator: connected as {} (member of epigraph_maintenance)",
        db.session_user
    );
    let mut conn = db.pool().acquire().await?;
    let mut stdout = std::io::stdout();
    match cli.command {
        Command::LinkRetired {
            agents_file,
            operator: op,
            apply,
        } => {
            let agents = operator::read_ids_file(&agents_file)?;
            if agents.is_empty() {
                anyhow::bail!("no agent ids in {}", agents_file.display());
            }
            println!(
                "link-retired: operator={op} agents={} mode={}",
                agents.len(),
                if apply { "APPLY" } else { "DRY-RUN" }
            );
            let results = link::run(&mut conn, &agents, op, apply).await?;
            let mut refused = 0;
            for (a, s) in &results {
                if s.is_refusal() {
                    refused += 1;
                }
                println!("{}", link::describe(*a, s));
            }
            if !apply {
                println!("DRY RUN: every call above ran and was rolled back.");
            }
            Ok(if refused > 0 { 3 } else { 0 })
        }
        Command::ReownClaims {
            claims_file,
            operator: op,
            derived,
            manifest_out,
            apply,
            batch_size,
            lock_timeout,
            hide,
        } => {
            let ids = operator::read_ids_file(&claims_file)?;
            if ids.is_empty() {
                anyhow::bail!("no claim ids in {}", claims_file.display());
            }
            let opts = reown::Options {
                operator: op,
                mode: derived,
                manifest_out,
                apply,
                batch_size,
                lock_timeout,
                hide,
            };
            reown::validate(&opts)?;
            let report = reown::run(&mut conn, &opts, &ids, &mut stdout).await?;
            Ok(if report.batch_failures.is_empty() {
                0
            } else {
                2
            })
        }
        Command::HideEvidence {
            claims_file,
            operator: op,
            hide,
            apply,
            manifest_out,
            reason,
            lock_timeout,
        } => {
            let ids = operator::read_ids_file(&claims_file)?;
            if ids.is_empty() {
                anyhow::bail!("no claim ids in {}", claims_file.display());
            }
            let opts = hide::Standalone {
                operator: op,
                args: hide,
                apply,
                manifest_out,
                reason,
                lock_timeout,
            };
            hide::run_standalone(&mut conn, &opts, &ids, &mut stdout).await?;
            Ok(0)
        }
        Command::ReownSeed {
            claims_file,
            manifest_dir,
            apply,
            batch_size,
            lock_timeout,
        } => {
            let claims = match claims_file {
                Some(f) => {
                    let ids = operator::read_ids_file(&f)?;
                    if ids.is_empty() {
                        anyhow::bail!("no claim ids in {}", f.display());
                    }
                    Some(ids)
                }
                None => None,
            };
            let opts = seed::Options {
                claims,
                manifest_dir,
                apply,
                batch_size,
                lock_timeout,
            };
            let report = seed::run(&mut conn, &opts, &mut stdout).await?;
            let held = report.held.len()
                + report
                    .per_target
                    .values()
                    .map(|r| r.plan_held.len() + r.held_under_lock.len())
                    .sum::<usize>();
            Ok(if report.batch_failures() > 0 {
                2
            } else if held > 0 {
                3
            } else {
                0
            })
        }
        Command::StripLabel {
            label,
            manifest_out,
            apply,
            lock_timeout,
        } => {
            let opts = labels::Options {
                label,
                manifest_out,
                apply,
                lock_timeout,
            };
            labels::run(&mut conn, &opts, &mut stdout).await?;
            Ok(0)
        }
        Command::StripLabelReverse {
            manifest,
            apply,
            lock_timeout,
        } => {
            let opts = labels::ReverseOptions {
                manifest,
                apply,
                lock_timeout,
            };
            let report = labels::reverse(&mut conn, &opts, &mut stdout).await?;
            Ok(if report.held.is_empty() { 0 } else { 3 })
        }
        Command::ReownReverse {
            manifest,
            apply,
            batch_size,
            lock_timeout,
        } => {
            let opts = reverse::Options {
                manifests: manifest,
                apply,
                batch_size,
                lock_timeout,
            };
            let report = reverse::run(&mut conn, &opts, &mut stdout).await?;
            Ok(if !report.batch_failures.is_empty() {
                2
            } else if !report.held.is_empty() {
                3
            } else {
                0
            })
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match main_inner().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("epigraph-operator: {e:#}");
            std::process::exit(1);
        }
    }
}

//! Operator CLI: re-verify external anchors (backlog 94e62824).
//!
//! Read-only except under `--poll`, which advances anchors the ledger has
//! since included.
//!
//! # Exit codes, so this is usable from cron and CI
//!
//! * `0` — every anchor checked came back `verified`
//! * `2` — at least one anchor is drifted, tampered, unconfirmed, or missing
//! * `1` — the run itself failed (no database, unknown backend, bad argument)
//!
//! `2` rather than `1` for findings keeps "I found a problem" distinguishable
//! from "I could not look", which matters when the caller is a timer whose only
//! output is an exit status. Best-effort anchoring means a real backend outage
//! accumulates `status = 'failed'` rows while seals keep succeeding — a nightly
//! `anchor_verify --all` exiting non-zero is what surfaces that.
//!
//! # `trust_basis` is printed on every line for a reason
//!
//! `operator-held` means the anchors were published to the default mock ledger,
//! which lives in the same Postgres as the anchors it attests to. Those results
//! prove the mechanism and NOT third-party existence-at-a-time. Only
//! `third-party` means the operator has actually left the trust base.
//!
//! Usage:
//!     anchor_verify --root-id <uuid> [--root-type manifest]
//!     anchor_verify --all [--limit 500]
//!     anchor_verify --poll [--limit 500]

use anyhow::{bail, Context};
use clap::Parser;
use epigraph_db::anchor::{AnchorService, AnchorVerification};
use epigraph_db::ROOT_TYPE_MANIFEST;
use uuid::Uuid;

/// Findings were reported. Distinct from 1 = the run itself failed.
const EXIT_PROBLEMS_FOUND: i32 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "anchor_verify",
    about = "Re-verify external anchors against the ledger and the live graph"
)]
struct Cli {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Verify one anchored root.
    #[arg(long, conflicts_with = "all")]
    root_id: Option<Uuid>,

    /// Kind of root. Only `manifest` is implemented.
    #[arg(long, default_value = ROOT_TYPE_MANIFEST)]
    root_type: String,

    /// Verify every anchor, newest first.
    #[arg(long)]
    all: bool,

    /// Before verifying, advance anchors the ledger has since included.
    /// The only write this binary performs.
    #[arg(long)]
    poll: bool,

    /// Row cap for `--all` and `--poll`.
    #[arg(long, default_value_t = 500)]
    limit: i64,

    /// Emit the full reports as JSON instead of one line each.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .with_target(false)
        .init();

    match run(Cli::parse()).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    if !cli.all && cli.root_id.is_none() && !cli.poll {
        bail!("pass --root-id <uuid>, --all, or --poll");
    }

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&cli.database_url)
        .await
        .context("connect to database")?;

    let service = AnchorService::from_env(&pool).context("build the anchor service")?;

    if cli.poll {
        let advanced = service
            .poll_pending(&pool, cli.limit)
            .await
            .context("poll pending anchors")?;
        println!("polled: {advanced} anchor(s) advanced to confirmed");
    }

    let reports: Vec<AnchorVerification> = if let Some(root_id) = cli.root_id {
        vec![service
            .verify(&pool, &cli.root_type, root_id)
            .await
            .context("verify one root")?]
    } else if cli.all {
        service
            .verify_all(&pool, cli.limit)
            .await
            .context("verify all anchors")?
    } else {
        // --poll alone: the poll already ran and reported.
        return Ok(0);
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&reports).context("serialize reports")?
        );
    } else {
        for r in &reports {
            println!(
                "{:>20}  {} {}  anchored={}  live={}  tx={}  trust={}{}",
                format!("{:?}", r.verdict).to_lowercase(),
                r.root_type,
                r.root_id,
                r.anchored_root.as_deref().unwrap_or("-"),
                r.live_root.as_deref().unwrap_or("-"),
                r.tx_id.as_deref().unwrap_or("-"),
                r.trust_basis,
                r.detail
                    .as_deref()
                    .map(|d| format!("\n{:>22}{d}", ""))
                    .unwrap_or_default(),
            );
        }
    }

    let problems = reports.iter().filter(|r| r.verdict.is_problem()).count();
    if problems > 0 {
        eprintln!("{problems} of {} anchor(s) did not verify", reports.len());
        return Ok(EXIT_PROBLEMS_FOUND);
    }

    eprintln!("{} anchor(s) verified", reports.len());
    Ok(0)
}

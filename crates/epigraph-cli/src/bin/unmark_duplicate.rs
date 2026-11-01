//! Operator binary: un-mark a duplicate (or every mark of one label-dedup
//! apply) on the maintenance connection (backlog e8113079).
//!
//! # Why a CLI
//!
//! An un-mark is the dedup's act and its reversal together: it makes the
//! duplicate current again AND moves back the edges, mass functions and frame
//! bindings the dedup's repair moved across every writer's rows. Both run in
//! ONE transaction on a privileged maintenance connection
//! (`epigraph_engine::admin_cascade::apply_unmark`), because a committed act
//! whose reversal failed would leave a current claim with its edges still on
//! the canonical, so an un-mark has no deferred form for the replay timer to
//! complete. Operator decision D9 keeps that connection out of every
//! request-serving process, so MCP `unmark_duplicate`, HTTP
//! `POST /api/v1/claims/:id/undedup` and `revert_label_dedup` with marks all
//! refuse there with nothing written. This binary is where an operator runs
//! the un-mark instead, as `sweep_semantic_duplicates` is where the sweep
//! runs.
//!
//! # What it does
//!
//! `--claim-id <dup>` names one marked duplicate; `--canonical` and
//! `--identity-edge` optionally pin WHICH mark is meant (a claim marked since
//! onto another claim, or marked again, is refused). `--applied-marks <file>`
//! instead takes an `apply_label_dedup` response (or its `applied_marks` array)
//! and un-marks each of its marks newest first, with the canonical and the
//! identity edge the apply recorded, as `revert_label_dedup` does. Its label
//! half needs no maintenance connection: run `revert_label_dedup` with
//! `applied_units` only.
//!
//! Every target is checked first, read-only, before anything is written: the
//! claim is a marked duplicate, of the expected canonical, still carrying the
//! expected identity edge, and has a current canonical to be restored against
//! (`ClaimRepository::unmark_chain_conn`; a canonical superseded or
//! consolidated since is followed to its current replacement, operator ruling
//! R-11). A canonical that is itself still a marked duplicate is admissible
//! only when the same run un-marks it first. If any target is refused, the
//! report lists why and nothing is written.
//!
//! DRY RUN BY DEFAULT: without `--apply` it prints that check and writes
//! nothing. With `--apply`, each un-mark is
//! `admin_cascade::apply_unmark` (act, reversal and an applied `undedup` audit
//! row naming `--acting-agent`, atomically, then the belief re-derivation),
//! followed by a best-effort re-embedding of the restored claim (CLAUDE.md's
//! write-path rule; with no `OPENAI_API_KEY` it reports `embedded: false` and
//! `embed_backfill` fills it later). The run holds the cascade replay's lock
//! throughout, so a replay cannot apply a mark's pending cascade while it is
//! being un-marked; while a replay holds it, nothing is written.
//!
//! # Authority
//!
//! `MAINTENANCE_DATABASE_URL` must be SET (the fallback to `DATABASE_URL` is
//! refused) and its login must bypass row security. `--acting-agent` is
//! REQUIRED and must name an existing agent: it is the operator the audit rows
//! attribute each un-mark to (D1).
//!
//! Exit 0: checked (dry run) or every un-mark applied. Exit 1: a refusal, a
//! read failure, or any un-mark that failed (listed in `steps`).

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use epigraph_engine::admin_cascade::{self, CascadeCause, CascadeTrigger};
use epigraph_engine::label_dedup::{revert_marks, AppliedMark};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "unmark_duplicate",
    about = "Un-mark a duplicate (or every mark of a label-dedup apply), audited, on the \
             maintenance connection"
)]
struct Cli {
    /// PostgreSQL connection URL of the application database (names the
    /// database; the work runs on MAINTENANCE_DATABASE_URL, which must be set).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// The operator agent every un-mark is attributed to in its audit row.
    /// Required.
    #[arg(long, value_name = "AGENT_ID")]
    acting_agent: Uuid,

    /// The marked duplicate to un-mark.
    #[arg(
        long,
        value_name = "CLAIM_ID",
        required_unless_present = "applied_marks",
        conflicts_with = "applied_marks"
    )]
    claim_id: Option<Uuid>,

    /// Refuse unless the claim is marked a duplicate of this canonical.
    #[arg(long, value_name = "CLAIM_ID", requires = "claim_id")]
    canonical: Option<Uuid>,

    /// Refuse unless the claim still carries this dedup identity edge (the
    /// mark meant, not a later one).
    #[arg(long, value_name = "EDGE_ID", requires = "claim_id")]
    identity_edge: Option<Uuid>,

    /// An `apply_label_dedup` response (or its `applied_marks` array) whose
    /// marks to un-mark, newest first.
    #[arg(long, value_name = "FILE")]
    applied_marks: Option<PathBuf>,

    /// Un-mark. Without it, nothing is written.
    #[arg(long)]
    apply: bool,
}

/// One un-mark to make, and which mark it must find.
struct Target {
    unit: Option<String>,
    dup: Uuid,
    canonical: Option<Uuid>,
    identity_edge: Option<Uuid>,
}

/// What the read-only check found for one target.
struct Checked {
    canonical: Option<Uuid>,
    content: String,
    report: serde_json::Value,
    admissible: bool,
}

fn targets(cli: &Cli) -> anyhow::Result<Vec<Target>> {
    if let Some(dup) = cli.claim_id {
        return Ok(vec![Target {
            unit: None,
            dup,
            canonical: cli.canonical,
            identity_edge: cli.identity_edge,
        }]);
    }
    let path = cli
        .applied_marks
        .as_ref()
        .ok_or_else(|| anyhow!("name --claim-id or --applied-marks"))?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read --applied-marks {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw).context("--applied-marks is not JSON")?;
    let marks = match v {
        serde_json::Value::Object(mut o) => o
            .remove("applied_marks")
            .ok_or_else(|| anyhow!("--applied-marks has no `applied_marks` field"))?,
        other => other,
    };
    let marks: Vec<AppliedMark> = serde_json::from_value(marks)
        .context("`applied_marks` is not the list an apply_label_dedup response returns")?;
    if marks.is_empty() {
        bail!("--applied-marks lists no marks; nothing to un-mark");
    }
    Ok(revert_marks(&marks)
        .into_iter()
        .map(|m| Target {
            unit: Some(m.unit),
            dup: m.dup,
            canonical: Some(m.canonical),
            identity_edge: m.identity_edge,
        })
        .collect())
}

/// The read-only check of one target, in `unmark_gate`'s order (the MCP
/// tool's): the claim, the expected canonical, the expected identity edge,
/// then a current canonical to restore it against, which a canonical this run
/// un-marks earlier does not need yet.
async fn check(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    t: &Target,
    undone_first: &std::collections::BTreeSet<Uuid>,
) -> anyhow::Result<Checked> {
    let dup = t.dup;
    let mut report = serde_json::json!({ "claim_id": dup });
    if let Some(unit) = &t.unit {
        report["unit"] = serde_json::json!(unit);
    }
    let refuse = |mut report: serde_json::Value,
                  canonical: Option<Uuid>,
                  content: String,
                  why: String|
     -> anyhow::Result<Checked> {
        report["admissible"] = serde_json::json!(false);
        report["reason"] = serde_json::json!(why);
        Ok(Checked {
            canonical,
            content,
            report,
            admissible: false,
        })
    };
    let claim = ClaimRepository::get_by_id(&mut *conn, viewer, ClaimId::from_uuid(dup))
        .await
        .with_context(|| format!("read claim {dup}"))?;
    let Some(claim) = claim else {
        return refuse(
            report,
            None,
            String::new(),
            format!("claim {dup} not found"),
        );
    };
    let content = claim.content.clone();
    let Some(canonical) = claim.supersedes.map(Uuid::from) else {
        return refuse(
            report,
            None,
            content,
            format!("claim {dup} is not a marked duplicate"),
        );
    };
    report["canonical_id"] = serde_json::json!(canonical);
    if let Some(expected) = t.canonical.filter(|e| *e != canonical) {
        return refuse(
            report,
            Some(canonical),
            content,
            format!("claim {dup} is a duplicate of {canonical}, not of {expected}"),
        );
    }
    if let Some(edge) = t.identity_edge {
        let live = ClaimRepository::dedup_identity_edge_of(&mut *conn, viewer, dup)
            .await
            .with_context(|| format!("read claim {dup}'s identity edge"))?;
        if live.map(|(id, _)| id) != Some(edge) {
            return refuse(
                report,
                Some(canonical),
                content,
                format!(
                    "claim {dup} no longer carries the mark with identity edge {edge} (it was \
                     un-marked or marked again since)"
                ),
            );
        }
    }
    if undone_first.contains(&canonical) {
        // Its canonical is un-marked earlier in this run: the chain is read
        // again by the act, once that canonical is current.
        report["chain"] = serde_json::Value::Null;
        report["admissible"] = serde_json::json!(true);
        return Ok(Checked {
            canonical: Some(canonical),
            content,
            report,
            admissible: true,
        });
    }
    match ClaimRepository::unmark_chain_conn(&mut *conn, viewer, dup, canonical)
        .await
        .with_context(|| format!("read claim {dup}'s canonical chain"))?
    {
        Ok(chain) => {
            report["chain"] = serde_json::json!(chain);
            report["admissible"] = serde_json::json!(true);
            Ok(Checked {
                canonical: Some(canonical),
                content,
                report,
                admissible: true,
            })
        }
        Err(why) => refuse(
            report,
            Some(canonical),
            content,
            format!("claim {dup} {why}"),
        ),
    }
}

/// Re-embed a claim made current again, best-effort: `Ok(true)` stored,
/// `Ok(false)` nothing to embed with or the claim is no longer current and
/// unsealed. A failure is logged, never fatal: the un-mark has committed.
async fn embed_restored(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    embedder: Option<&dyn epigraph_embeddings::EmbeddingService>,
    dup: Uuid,
    content: &str,
) -> bool {
    let Some(embedder) = embedder else {
        return false;
    };
    match embedder.generate(content).await {
        Ok(v) => {
            let pgvec = format!(
                "[{}]",
                v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
            );
            match ClaimRepository::store_embedding_if_unsealed(conn, viewer, dup, &pgvec).await {
                Ok(stored) => stored,
                Err(e) => {
                    tracing::warn!(claim = %dup, error = %e, "unmark: embedding not stored");
                    false
                }
            }
        }
        Err(e) => {
            tracing::warn!(claim = %dup, error = %e, "unmark: embedding failed");
            false
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let targets = targets(&cli)?;

    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "unmark_duplicate")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if maint.dsn_source() != epigraph_db::MaintenanceDsnSource::Configured {
        bail!(
            "unmark_duplicate moves rows back across every writer, so it runs only on an \
             explicitly configured MAINTENANCE_DATABASE_URL; it is unset, and the application \
             DSN is never used for this"
        );
    }
    let mut session = maint
        .viewer(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .context("acquire the maintenance session")?;
    session
        .assert_privileged()
        .await
        .context("the maintenance connection cannot bypass row security")?;
    let (conn, viewer) = session.split();

    let agent = epigraph_db::AgentRepository::get_by_id(
        &mut *conn,
        epigraph_core::AgentId::from_uuid(cli.acting_agent),
    )
    .await
    .context("look up --acting-agent")?;
    if agent.is_none() {
        bail!(
            "--acting-agent {} is not an agent; every un-mark is attributed to it in its audit \
             row, so it must exist",
            cli.acting_agent
        );
    }

    // Every target checked, in a READ ONLY transaction, before anything is
    // written.
    let mut checked = Vec::with_capacity(targets.len());
    {
        let mut tx = sqlx::Acquire::begin(&mut *conn)
            .await
            .context("begin the check transaction")?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .context("make the check transaction read-only")?;
        let mut undone_first = std::collections::BTreeSet::new();
        for t in &targets {
            checked.push(check(&mut tx, viewer, t, &undone_first).await?);
            undone_first.insert(t.dup);
        }
        tx.rollback().await.context("end the check transaction")?;
    }
    let admissible = checked.iter().all(|c| c.admissible);
    let plan = serde_json::json!({
        "dry_run": !cli.apply,
        "admissible": admissible,
        "unmarks": checked.iter().map(|c| c.report.clone()).collect::<Vec<_>>(),
    });
    if !admissible || !cli.apply {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).context("serialize the check")?
        );
        if !admissible {
            bail!(
                "{} of {} un-mark(s) would be refused (see `unmarks`); nothing was written",
                checked.iter().filter(|c| !c.admissible).count(),
                checked.len()
            );
        }
        return Ok(());
    }

    // Held for the whole run: a replay cannot apply a mark's pending cascade
    // while that mark is being un-marked (the un-mark retires it instead).
    use epigraph_db::repos::maintenance_lock;
    if !maintenance_lock::try_take(&mut *conn, maintenance_lock::REPLAY_LOCK_KEY)
        .await
        .context("take the cascade replay's lock")?
    {
        bail!(
            "a cascade replay (replay_deferred_cascades) holds its lock; nothing was written. \
             Run again once it has finished"
        );
    }
    let embedder = epigraph_cli::embedding_service();
    let mut steps = Vec::with_capacity(targets.len());
    for (t, c) in targets.iter().zip(&checked) {
        let canonical = c
            .canonical
            .ok_or_else(|| anyhow!("claim {} was admitted without a canonical", t.dup))?;
        let trigger = CascadeTrigger::new(
            CascadeCause::Undedup,
            Some(cli.acting_agent),
            None,
            t.dup,
            Some(canonical),
        );
        // The admin viewer is also the "caller" whose view the report is
        // filtered to: the operator's run reads every row.
        let done =
            admin_cascade::apply_unmark(&mut *conn, viewer, viewer, &trigger, t.dup, canonical)
                .await;
        let mut step = serde_json::json!({
            "step": "unmark",
            "claim_id": t.dup,
            "canonical": canonical,
            "ok": done.is_ok(),
        });
        if let Some(unit) = &t.unit {
            step["unit"] = serde_json::json!(unit);
        }
        match done {
            Ok((outcome, belief_cascade)) => {
                let embedded =
                    embed_restored(&mut *conn, viewer, embedder.as_deref(), t.dup, &c.content)
                        .await;
                step["result"] = serde_json::json!({
                    "canonical_id": outcome.canonical_id,
                    "current_canonical_id": outcome.current_canonical_id,
                    "embedded": embedded,
                    "cascade": outcome.cascade,
                    "belief_cascade": belief_cascade,
                });
            }
            Err(e) => step["error"] = serde_json::json!(e.to_string()),
        }
        steps.push(step);
    }
    if let Err(e) = maintenance_lock::release(&mut *conn, maintenance_lock::REPLAY_LOCK_KEY).await {
        // Session-level: released when the connection closes, at the latest.
        tracing::warn!(error = %e, "unmark: the replay lock was not released");
    }
    let failed = steps.iter().filter(|s| s["ok"] != true).count();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "dry_run": false,
            "status": if failed == 0 { "reverted" } else { "partial" },
            "steps": steps,
        }))
        .context("serialize the report")?
    );
    if failed > 0 {
        bail!("{failed} un-mark(s) failed; see `steps`");
    }
    Ok(())
}

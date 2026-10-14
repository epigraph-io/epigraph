//! `delete-frames`: remove an explicit list of `frames` rows (test or probe
//! frames left in a production graph, backlog 34b3175c / drain U048), refusing
//! every frame whose removal would change anything a real claim depends on.
//!
//! # Why a frame delete needs a tool
//!
//! `frames` is an FK parent. Four tables CASCADE from it (`mass_functions`,
//! `claim_frames`, `ds_combined_beliefs`, `ds_bayesian_divergence`), so a bare
//! `DELETE FROM frames` silently takes every BBA, frame assignment and cached
//! belief on the frame with it, a REAL claim's included. Three references have
//! no action and fail the delete (`factors.frame_id`, `frames.parent_frame_id`,
//! `claims.belief_frame_id`). Edges with a `'frame'` endpoint have no foreign
//! key at all (migration 055's existence trigger fires on INSERT only), so
//! nothing in the schema stops them dangling.
//!
//! # The rule
//!
//! A listed frame is REFUSED, and named with every reason, when it has:
//!
//! * a row in any of the four cascade tables whose `claim_id` is not in the
//!   companion-claims file (the test claims that came with the test frames);
//! * a `factors` row, a child frame, or a claim whose cached belief records it
//!   (`claims.belief_frame_id`);
//! * an edge with the frame as either endpoint.
//!
//! An id in the ids file that is not a frame is reported `MISSING` and
//! skipped. A frame not in the ids file is never touched.
//!
//! # The guards, in the order `--apply` meets them
//!
//! 1. The plan is printed: the frames, and per cascade table the companion
//!    rows that go with them. A dry run (the default) stops there and writes
//!    nothing, audit row included.
//! 2. Any refused frame: exit 3, nothing written, even under `--apply`.
//! 3. `--apply` needs `--confirm-delete <N>` with N the planned frame count.
//! 4. In one transaction, under `lock_timeout`: the listed frames are locked
//!    `FOR UPDATE` (every FK insert that names a frame takes `FOR KEY SHARE` on
//!    it, so no new BBA or assignment can land mid-run), and the plan is
//!    re-derived and must equal the printed one.
//! 5. Only the frames are deleted by this module; the companion rows go by the
//!    foreign keys' `ON DELETE CASCADE`. A referential action runs as the
//!    child table's owner and consults no row-security policy, which is why
//!    `epigraph_maintenance` needs DELETE on `frames` alone (migration 158)
//!    and why the cascade, not a policy, is what has to be accounted for.
//!    The role holds DELETE on `mass_functions` (115) and none on
//!    `claim_frames`, `ds_combined_beliefs` or `ds_bayesian_divergence`
//!    (070); the cascade reaches all four regardless.
//! 6. The transaction's census (`pg_stat_xact_user_tables`, which counts the
//!    cascade's deletes too) must be exactly the planned frames in `frames`,
//!    the planned companion rows in each cascade table, and nothing anywhere
//!    else. A row the plan did not see (a policy-filtered read, a write that
//!    slipped past the locks) makes the counts differ, and the transaction is
//!    rolled back.
//! 7. One `security_events` row (`operator.frames_deleted`) naming the frames,
//!    the cascade counts and the reason, then the commit.
//!
//! # Residual race: edges
//!
//! The `FOR UPDATE` locks stop every FK child insert (those take `FOR KEY
//! SHARE` on the frame), but edges have no FK to `frames`, and 055's existence
//! trigger checks with a plain `EXISTS`. Another session can therefore insert a
//! `'frame'`-endpoint edge after the in-transaction re-plan and commit it; the
//! edge then dangles. The census counts only this transaction's own changes,
//! so it cannot see that write. The window is the milliseconds between the
//! re-plan and the commit, over test frames nothing writes to. Closing it would
//! need the edge trigger to take `FOR KEY SHARE` on the frame, which is out of
//! this tool's scope.

use super::reown::{counter_delta, counter_violations};
use super::tables;
use anyhow::{bail, Context};
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use serde_json::json;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The `security_events.event_type` of an applied run.
pub const EVENT: &str = "operator.frames_deleted";

/// The tables that `ON DELETE CASCADE` from `frames.id`, each keyed on
/// `(frame_id, claim_id)`. This module never deletes from them: the FK
/// cascade empties them when the frames are deleted, the plan counts their
/// rows, and the census checks those counts.
pub const CASCADE_TABLES: &[&str] = &[
    "mass_functions",
    "claim_frames",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
];

/// Everything `delete-frames` was told.
#[derive(Clone, Debug)]
pub struct Options {
    /// The frames to remove, in the ids file's order.
    pub frames: Vec<Uuid>,
    /// Claims whose frame-keyed rows may be removed with the frames.
    pub companions: BTreeSet<Uuid>,
    pub apply: bool,
    pub confirm_delete: Option<usize>,
    pub reason: String,
    pub lock_timeout: String,
}

/// What a run decided and did.
#[derive(Debug, Default)]
pub struct Report {
    /// Frames removed (zero on a dry run).
    pub deleted: usize,
    /// Listed frames refused, with every reason.
    pub refused: Vec<(Uuid, Vec<String>)>,
    /// Listed ids that are not a frame.
    pub missing: Vec<Uuid>,
}

/// One listed frame that exists.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameRow {
    id: Uuid,
    name: String,
    created_at: String,
}

/// Which kinds of reason refused the listed frames, for the operator's hint.
/// The two kinds have different remedies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RefusalKinds {
    /// A cascade-table row of a claim outside the companion set. Listing that
    /// claim as a companion clears it, if it is a test claim.
    cascade: bool,
    /// A factor, a child frame, a `claims.belief_frame_id` or an edge.
    /// The companion set does not affect these.
    reference: bool,
}

/// The plan for a list of frames, derived from the database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Plan {
    /// Frames that will be removed, in the ids file's order.
    deletable: Vec<FrameRow>,
    /// Per cascade table, the companion rows on the deletable frames.
    cascade: BTreeMap<&'static str, i64>,
    refused: Vec<(Uuid, Vec<String>)>,
    /// Over every refused frame, which kinds of reason occurred.
    refusal_kinds: RefusalKinds,
    missing: Vec<Uuid>,
}

impl Plan {
    fn ids(&self) -> Vec<Uuid> {
        self.deletable.iter().map(|f| f.id).collect()
    }
}

/// Count rows per frame for `sql`, which must select `(frame uuid, n bigint)`
/// for the frames bound as `$1`.
async fn per_frame(
    conn: &mut PgConnection,
    sql: &str,
    frames: &[Uuid],
) -> anyhow::Result<BTreeMap<Uuid, i64>> {
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(sql)
        .bind(frames)
        .fetch_all(&mut *conn)
        .await
        .with_context(|| format!("planning: {sql}"))?;
    Ok(rows.into_iter().collect())
}

/// Derive the plan. Read-only; runs inside the write's transaction too.
async fn plan(
    conn: &mut PgConnection,
    frames: &[Uuid],
    companions: &BTreeSet<Uuid>,
) -> anyhow::Result<Plan> {
    let found: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, name::text, created_at::text FROM frames WHERE id = ANY($1)")
            .bind(frames)
            .fetch_all(&mut *conn)
            .await
            .context("reading the listed frames")?;
    let found: BTreeMap<Uuid, FrameRow> = found
        .into_iter()
        .map(|(id, name, created_at)| {
            (
                id,
                FrameRow {
                    id,
                    name,
                    created_at,
                },
            )
        })
        .collect();

    let mut reasons: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    let mut kinds: BTreeMap<Uuid, RefusalKinds> = BTreeMap::new();
    // Per cascade table and frame: the companion rows that may go with it.
    let mut companion_rows: BTreeMap<&'static str, BTreeMap<Uuid, i64>> = BTreeMap::new();
    for &table in CASCADE_TABLES {
        let rows: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(&format!(
            "SELECT frame_id, claim_id, count(*) FROM {table} \
              WHERE frame_id = ANY($1) GROUP BY frame_id, claim_id ORDER BY frame_id, claim_id"
        ))
        .bind(frames)
        .fetch_all(&mut *conn)
        .await
        .with_context(|| format!("planning: reading {table}"))?;
        for (frame, claim, n) in rows {
            if companions.contains(&claim) {
                *companion_rows
                    .entry(table)
                    .or_default()
                    .entry(frame)
                    .or_default() += n;
            } else {
                reasons.entry(frame).or_default().push(format!(
                    "{table}: {n} row(s) of claim {claim}, which is not a companion claim"
                ));
                kinds.entry(frame).or_default().cascade = true;
            }
        }
    }

    let blockers: [(&str, &str); 4] = [
        (
            "factors",
            "SELECT frame_id, count(*) FROM factors WHERE frame_id = ANY($1) GROUP BY frame_id",
        ),
        (
            "frames.parent_frame_id (child frames)",
            "SELECT parent_frame_id, count(*) FROM frames \
              WHERE parent_frame_id = ANY($1) GROUP BY parent_frame_id",
        ),
        (
            "claims.belief_frame_id (claims whose cached belief is this frame's)",
            "SELECT belief_frame_id, count(*) FROM claims \
              WHERE belief_frame_id = ANY($1) GROUP BY belief_frame_id",
        ),
        (
            "edges (this frame is an endpoint; edges have no foreign key to frames)",
            "SELECT f, count(*) FROM ( \
                 SELECT source_id AS f FROM edges \
                  WHERE source_type = 'frame' AND source_id = ANY($1) \
                 UNION ALL \
                 SELECT target_id FROM edges \
                  WHERE target_type = 'frame' AND target_id = ANY($1)) e \
              GROUP BY f",
        ),
    ];
    for (what, sql) in blockers {
        for (frame, n) in per_frame(conn, sql, frames).await? {
            reasons
                .entry(frame)
                .or_default()
                .push(format!("{what}: {n} row(s)"));
            kinds.entry(frame).or_default().reference = true;
        }
    }

    let mut out = Plan::default();
    for &table in CASCADE_TABLES {
        out.cascade.insert(table, 0);
    }
    for id in frames {
        let Some(row) = found.get(id) else {
            out.missing.push(*id);
            continue;
        };
        if let Some(r) = reasons.remove(id) {
            let k = kinds.get(id).copied().unwrap_or_default();
            out.refusal_kinds.cascade |= k.cascade;
            out.refusal_kinds.reference |= k.reference;
            out.refused.push((*id, r));
            continue;
        }
        for &table in CASCADE_TABLES {
            let n = companion_rows
                .get(table)
                .and_then(|m| m.get(id))
                .copied()
                .unwrap_or(0);
            *out.cascade.entry(table).or_default() += n;
        }
        out.deletable.push(row.clone());
    }
    Ok(out)
}

fn print_plan(p: &Plan, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    writeln!(out, "DELETE-PLAN: {} frame(s)", p.deletable.len())?;
    for f in &p.deletable {
        writeln!(out, "FRAME\t{}\t{}\t{}", f.id, f.name, f.created_at)?;
    }
    for (table, n) in &p.cascade {
        writeln!(out, "CASCADE\t{table}\t{n}")?;
    }
    for id in &p.missing {
        writeln!(out, "MISSING\t{id}\tnot a frame; skipped")?;
    }
    for (id, reasons) in &p.refused {
        for r in reasons {
            writeln!(out, "REFUSED\t{id}\t{r}")?;
        }
    }
    Ok(())
}

/// Plan, print, and under `--apply` delete.
///
/// # Errors
/// A statement fails; `--apply` without the exact `--confirm-delete`; or the
/// plan changed under the write's locks, a delete removed a row count other
/// than the plan's, or the census found a change outside the plan (each rolls
/// the transaction back).
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    let p = plan(conn, &opts.frames, &opts.companions).await?;
    print_plan(&p, out)?;
    let mut report = Report {
        deleted: 0,
        refused: p.refused.clone(),
        missing: p.missing.clone(),
    };
    if !p.refused.is_empty() {
        writeln!(
            out,
            "REFUSED: {} listed frame(s) carry rows a real claim or another row depends on; \
             nothing was written.",
            p.refused.len()
        )?;
        if p.refusal_kinds.cascade {
            writeln!(
                out,
                "HINT: a {} row of a claim outside the companion set: if that claim is a test \
                 claim that came with the frame, list that claim in --companion-claims-file; if \
                 it is a real claim, drop the frame from the ids file.",
                CASCADE_TABLES.join(" / ")
            )?;
        }
        if p.refusal_kinds.reference {
            writeln!(
                out,
                "HINT: a factor, a child frame, a claims.belief_frame_id or a frame-endpoint \
                 edge is not affected by --companion-claims-file: drop the frame from the ids \
                 file, or first resolve that row through its own reviewed path."
            )?;
        }
        writeln!(out, "Then re-run the dry run.")?;
        return Ok(report);
    }
    let n = p.deletable.len();
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: nothing written. Re-run with --apply --confirm-delete {n} to remove \
             these frames."
        )?;
        return Ok(report);
    }
    if opts.confirm_delete != Some(n) {
        bail!(
            "--apply needs --confirm-delete {n} (the planned frame count); got {:?}. \
             Nothing was written.",
            opts.confirm_delete
        );
    }
    if n == 0 {
        writeln!(out, "nothing to delete")?;
        return Ok(report);
    }
    report.deleted = apply(conn, opts, &p).await?;
    writeln!(out, "DELETED: {} frame(s)", report.deleted)?;
    Ok(report)
}

async fn apply(conn: &mut PgConnection, opts: &Options, dry: &Plan) -> anyhow::Result<usize> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(&opts.lock_timeout)
        .execute(&mut *tx)
        .await?;
    let ids = dry.ids();
    let locked: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE id = ANY($1) ORDER BY id FOR UPDATE")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await
            .context("locking the frames")?;
    if locked.len() != ids.len() {
        bail!(
            "locked {} of the {} planned frames; a frame was removed since the plan. Nothing \
             was written.",
            locked.len(),
            ids.len()
        );
    }
    let again = plan(&mut tx, &opts.frames, &opts.companions).await?;
    if again != *dry {
        bail!(
            "the plan changed between the read and the write's locks (now {} deletable, {} \
             refused); nothing was written. Re-run the dry run.",
            again.deletable.len(),
            again.refused.len()
        );
    }

    let before = tables::xact_counters(&mut tx).await?;
    // The four cascade tables are emptied by the foreign keys' own ON DELETE
    // CASCADE, which PostgreSQL runs as the child table's owner and without
    // row security. The caller needs no DELETE on them: `epigraph_maintenance`
    // holds it on `mass_functions` (115) but not on `claim_frames`,
    // `ds_combined_beliefs` or `ds_bayesian_divergence`. The census below is
    // what proves the cascade removed exactly the planned companion rows and
    // nothing else.
    let mut expected: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    for &table in CASCADE_TABLES {
        let want = dry.cascade.get(table).copied().unwrap_or(0);
        if want != 0 {
            expected.insert(table.to_string(), (0, 0, want));
        }
    }
    let got = sqlx::query("DELETE FROM frames WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .context("deleting the frames")?
        .rows_affected();
    let n = i64::try_from(ids.len())?;
    if i64::try_from(got).ok() != Some(n) {
        bail!("frames: deleted {got}, the plan has {n}; rolled back, nothing was written");
    }
    expected.insert("frames".to_string(), (0, 0, n));
    let after = tables::xact_counters(&mut tx).await?;
    let violations = counter_violations(&counter_delta(&before, &after), &expected);
    if !violations.is_empty() {
        bail!(
            "the census found changes outside the plan; rolled back, nothing was written:\n{}",
            violations.join("\n")
        );
    }

    let details = json!({
        "tool": "epigraph-operator",
        "command": "delete-frames",
        "operator": super::restrict::operator_details(&mut tx).await?,
        "frames": dry.deletable.iter().map(|f| json!({
            "id": f.id,
            "name": f.name,
            "created_at": f.created_at,
        })).collect::<Vec<_>>(),
        "cascade": dry.cascade,
        "companion_claims": opts.companions,
        "missing": dry.missing,
        "reason": opts.reason,
    });
    let (client_addr, _) = SecurityEventRepository::connection_origin_conn(&mut tx).await?;
    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: Uuid::new_v4(),
            event_type: EVENT.to_string(),
            agent_id: None,
            success: Some(true),
            details,
            ip_address: client_addr,
            user_agent: None,
            correlation_id: None,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .context("writing the audit row")?;
    tx.commit().await.context("committing")?;
    Ok(ids.len())
}

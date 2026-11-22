//! Export and delete the BP factors of `decomposes_to` edges (atom-level
//! belief SPEC §6.2, D3; backlog 444b1f4a).
//!
//! # Why
//!
//! A decomposition is not a BP coupling: a compound is a query over its
//! atoms. Until migration 262 the `edges_auto_factor` trigger minted a
//! `directional_support` factor for every `decomposes_to` edge, and every BP
//! loader filters those out with
//! [`epigraph_db::repos::factor::bp_readable_factor_sql`]. That predicate
//! decides a LEGACY (unkeyed) row by reading `edges` under the caller's row
//! security, so a caller who cannot see the decomposition (another group's,
//! or one co-owned with a group the caller is not in) still reads the row,
//! and BP for that caller couples the compound with its atom. Removing the
//! rows is the structural close; 262 stops new ones.
//!
//! # The set is the predicate's complement, by construction
//!
//! The selection is NOT restated here: it is `NOT (bp_readable_factor_sql())`,
//! run on a session that bypasses row security (refused otherwise, see
//! [`SweepError::NotPrivileged`]), so it sees every edge and selects exactly
//! the rows the predicate hides from a viewer who can see the whole graph:
//!
//! * KEYED: `properties.relationship` is `decomposes_to` (any case);
//! * LEGACY: no `relationship` key, type `directional_support`, two
//!   variables, and those two are the ends of an in-force `decomposes_to`
//!   edge, in either order.
//!
//! A legacy row on a RETRACTED decomposition pair is not selected: the
//! predicate reads it as an ordinary factor again, for every viewer.
//!
//! # Export, then delete, in one transaction
//!
//! [`run`] opens one `REPEATABLE READ` transaction, takes an advisory lock
//! (apply only), selects the set (`FOR UPDATE` on apply), and writes the
//! MANIFEST (JSONL: a [`ManifestHeader`] line, then one [`ManifestRow`] per
//! factor carrying the whole row as `to_jsonb`) and syncs it. A dry run (the
//! default) then rolls back: the manifest is the export. An apply deletes
//! exactly the manifest's ids that still match the predicate, requires the
//! deleted set to equal the manifest, re-measures (no such row may remain),
//! and commits. `bp_messages` rows of a deleted factor go with it
//! (`ON DELETE CASCADE`); the manifest counts them.
//!
//! The sweep for rows minted later (a restore, a hand insert, a writer added
//! after 262) is the same run again: it selects whatever matches at that time,
//! and finds nothing when nothing matches.
//!
//! # Restore
//!
//! [`restore`] re-inserts the manifest's rows (`jsonb_populate_record` over
//! `factors`, so every column comes back as written) with
//! `ON CONFLICT DO NOTHING`: a row whose id, or whose `(type, pair, frame)`
//! slot, is held again is reported as skipped and left alone. A dry run
//! inserts and rolls back. `bp_messages` are not restored (BP re-derives
//! them).
//!
//! # What it does not do
//!
//! A `decomposes_to` row minted before 262 may hold the `(type, pair, frame)`
//! slot a parallel `supports` / `refines` edge on the same pair would have
//! used; that edge has no factor of its own, and deleting the row does not
//! mint one. BP never read a coupling for such an edge before the delete, so
//! nothing BP reads changes; the manifest counts those edges per row
//! (`parallel_unfactored_edges`) so an operator can measure them.

use std::fs::File;
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use epigraph_db::repos::factor::bp_readable_factor_sql;

/// The manifest header's `kind`.
pub const MANIFEST_KIND: &str = "epigraph.decomposes_to_factor_sweep.manifest/1";
/// The advisory lock an apply or a restore holds
/// (`pg_try_advisory_xact_lock(hashtextextended(SWEEP_LOCK_NAME, 0))`).
pub const SWEEP_LOCK_NAME: &str = "epigraph.decomposes_to_factor_sweep";

/// Why a run stopped. Every variant except [`SweepError::CommitUnknown`]
/// means nothing was written to the database.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("manifest: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "the session does not bypass row security (epigraph_bypass() is false): it would see \
         only the decompositions its groups can read and miss the rest; run on the \
         maintenance connection"
    )]
    NotPrivileged,
    #[error("another decomposes_to_factor_sweep run holds the sweep lock; nothing was written")]
    LockHeld,
    #[error(
        "the delete removed {deleted} rows but the manifest lists {listed}; rolled back, \
         nothing was written"
    )]
    DeleteMismatch { deleted: usize, listed: usize },
    #[error("{0} decomposes_to factors remain after the delete; rolled back, nothing was written")]
    Remaining(i64),
    #[error("not a decomposes_to_factor_sweep manifest: {0}")]
    BadManifest(String),
    #[error("the COMMIT failed, so whether the delete landed is unknown (keep the manifest): {0}")]
    CommitUnknown(sqlx::Error),
}

/// The manifest's first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub kind: String,
    /// `dry_run` or `apply`.
    pub mode: String,
    pub rows: usize,
    pub keyed: usize,
    pub legacy: usize,
    pub bp_messages: i64,
    pub parallel_unfactored_edges: i64,
}

/// One selected factor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRow {
    pub id: Uuid,
    /// `keyed` or `legacy` (see the module doc).
    pub arm: String,
    /// `bp_messages` rows that reference the factor (removed with it).
    pub bp_messages: i64,
    /// In-force claim-to-claim edges on the same pair, of a relationship the
    /// mapping sends to the row's factor type, other than `decomposes_to`,
    /// with no factor keyed to them: edges whose slot this row holds, left
    /// factorless after the delete.
    pub parallel_unfactored_edges: i64,
    /// The whole `factors` row, `to_jsonb(f)::text`.
    pub row: String,
}

/// What [`run`] selected (and, on apply, deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub header: ManifestHeader,
    /// The selected factor ids, sorted.
    pub ids: Vec<Uuid>,
    /// Whether the rows were deleted and committed.
    pub applied: bool,
}

/// What [`restore`] did (or, on a dry run, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub dry_run: bool,
    pub restored: Vec<Uuid>,
    /// The id or the `(type, pair, frame)` slot is held: left alone.
    pub skipped: Vec<Uuid>,
}

/// The selection: every factor `bp_readable_factor_sql` hides, with the
/// manifest's columns. `{lock}` is `FOR UPDATE OF f` on apply.
fn select_sql(lock: &str) -> String {
    format!(
        "-- VISIBILITY-EXEMPT: maintenance read; the decomposes_to sweep runs on the privileged connection.
         SELECT f.id,
                CASE WHEN lower(COALESCE(f.properties->>'relationship', '')) = 'decomposes_to'
                     THEN 'keyed' ELSE 'legacy' END,
                (SELECT count(*) FROM bp_messages m WHERE m.factor_id = f.id),
                (SELECT count(*) FROM edges e
                   CROSS JOIN LATERAL edge_to_factor_type(e.relationship) ft
                  WHERE e.source_type = 'claim' AND e.target_type = 'claim'
                    AND lower(e.relationship) <> 'decomposes_to'
                    AND ft.factor_type = f.factor_type
                    AND cardinality(f.variable_ids) = 2
                    AND ( (e.source_id = f.variable_ids[1] AND e.target_id = f.variable_ids[2])
                       OR (e.source_id = f.variable_ids[2] AND e.target_id = f.variable_ids[1]) )
                    AND {in_force}
                    AND NOT EXISTS (SELECT 1 FROM factors g
                                     WHERE g.properties->>'source_edge_id' = e.id::text)),
                to_jsonb(f)::text
           FROM factors f
          WHERE NOT ({pred})
          ORDER BY f.id
          {lock}",
        in_force = epigraph_db::repos::edge::EDGE_IN_FORCE,
        pred = bp_readable_factor_sql(),
    )
}

async fn require_bypass(conn: &mut sqlx::PgConnection) -> Result<(), SweepError> {
    let bypass: Option<bool> = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await?;
    if bypass == Some(true) {
        Ok(())
    } else {
        Err(SweepError::NotPrivileged)
    }
}

async fn set_statement_timeout(
    conn: &mut sqlx::PgConnection,
    statement_timeout_ms: Option<u64>,
) -> Result<(), sqlx::Error> {
    if let Some(ms) = statement_timeout_ms {
        // `SET LOCAL` takes no bind parameter; the value is a parsed integer.
        sqlx::query(&format!("SET LOCAL statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

async fn take_lock(conn: &mut sqlx::PgConnection) -> Result<(), SweepError> {
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(SWEEP_LOCK_NAME)
            .fetch_one(&mut *conn)
            .await?;
    if locked {
        Ok(())
    } else {
        Err(SweepError::LockHeld)
    }
}

/// Export (and, with `apply`, delete) every `decomposes_to` factor: see the
/// module doc. The manifest is written to `out` and synced before any delete.
///
/// # Errors
/// See [`SweepError`]; only [`SweepError::CommitUnknown`] can follow a write.
pub async fn run(
    conn: &mut sqlx::PgConnection,
    out: &mut File,
    apply: bool,
    statement_timeout_ms: Option<u64>,
) -> Result<SweepReport, SweepError> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    sqlx::query(if apply {
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
    } else {
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    })
    .execute(&mut *tx)
    .await?;
    set_statement_timeout(&mut tx, statement_timeout_ms).await?;
    require_bypass(&mut tx).await?;
    if apply {
        take_lock(&mut tx).await?;
    }

    let selected: Vec<(Uuid, String, i64, i64, String)> =
        sqlx::query_as(&select_sql(if apply { "FOR UPDATE OF f" } else { "" }))
            .fetch_all(&mut *tx)
            .await?;
    let rows: Vec<ManifestRow> = selected
        .into_iter()
        .map(
            |(id, arm, bp_messages, parallel_unfactored_edges, row)| ManifestRow {
                id,
                arm,
                bp_messages,
                parallel_unfactored_edges,
                row,
            },
        )
        .collect();
    let header = ManifestHeader {
        kind: MANIFEST_KIND.to_string(),
        mode: if apply { "apply" } else { "dry_run" }.to_string(),
        rows: rows.len(),
        keyed: rows.iter().filter(|r| r.arm == "keyed").count(),
        legacy: rows.iter().filter(|r| r.arm == "legacy").count(),
        bp_messages: rows.iter().map(|r| r.bp_messages).sum(),
        parallel_unfactored_edges: rows.iter().map(|r| r.parallel_unfactored_edges).sum(),
    };
    write_manifest(&mut *out, &header, &rows)?;
    out.sync_all()?;

    let mut ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    if !apply {
        tx.rollback().await?;
        return Ok(SweepReport {
            header,
            ids,
            applied: false,
        });
    }

    let mut deleted: Vec<Uuid> = sqlx::query_scalar(&format!(
        "-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         DELETE FROM factors f WHERE f.id = ANY($1) AND NOT ({})
         RETURNING f.id",
        bp_readable_factor_sql()
    ))
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    deleted.sort_unstable();
    if deleted != ids {
        tx.rollback().await?;
        return Err(SweepError::DeleteMismatch {
            deleted: deleted.len(),
            listed: ids.len(),
        });
    }
    let remaining: i64 = sqlx::query_scalar(&format!(
        "-- VISIBILITY-EXEMPT: maintenance read; the decomposes_to sweep runs on the privileged connection.
         SELECT count(*) FROM factors f WHERE NOT ({})",
        bp_readable_factor_sql()
    ))
    .fetch_one(&mut *tx)
    .await?;
    if remaining != 0 {
        tx.rollback().await?;
        return Err(SweepError::Remaining(remaining));
    }
    tx.commit().await.map_err(SweepError::CommitUnknown)?;
    Ok(SweepReport {
        header,
        ids,
        applied: true,
    })
}

/// Count the factors a run would select, on a session that bypasses row
/// security: the DONE measurement (zero after a successful apply).
///
/// # Errors
/// A database error, or [`SweepError::NotPrivileged`].
pub async fn remaining(conn: &mut sqlx::PgConnection) -> Result<i64, SweepError> {
    require_bypass(&mut *conn).await?;
    Ok(sqlx::query_scalar(&format!(
        "-- VISIBILITY-EXEMPT: maintenance read; the decomposes_to sweep runs on the privileged connection.
         SELECT count(*) FROM factors f WHERE NOT ({})",
        bp_readable_factor_sql()
    ))
    .fetch_one(&mut *conn)
    .await?)
}

/// Write a manifest: the header line, then one line per row.
///
/// # Errors
/// An I/O or serialisation error.
pub fn write_manifest<W: Write>(
    mut w: W,
    header: &ManifestHeader,
    rows: &[ManifestRow],
) -> Result<(), SweepError> {
    serde_json::to_writer(&mut w, header)?;
    w.write_all(b"\n")?;
    for row in rows {
        serde_json::to_writer(&mut w, row)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

/// Read a manifest [`write_manifest`] wrote.
///
/// # Errors
/// [`SweepError::BadManifest`] on a wrong `kind`, a row count that does not
/// match the header, or an unparsable line.
pub fn read_manifest<R: BufRead>(r: R) -> Result<(ManifestHeader, Vec<ManifestRow>), SweepError> {
    let mut lines = r.lines();
    let first = lines
        .next()
        .ok_or_else(|| SweepError::BadManifest("empty file".into()))??;
    let header: ManifestHeader = serde_json::from_str(&first)
        .map_err(|e| SweepError::BadManifest(format!("header: {e}")))?;
    if header.kind != MANIFEST_KIND {
        return Err(SweepError::BadManifest(format!("kind `{}`", header.kind)));
    }
    let mut rows = Vec::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str::<ManifestRow>(&line)
                .map_err(|e| SweepError::BadManifest(format!("row: {e}")))?,
        );
    }
    if rows.len() != header.rows {
        return Err(SweepError::BadManifest(format!(
            "header says {} rows, file holds {}",
            header.rows,
            rows.len()
        )));
    }
    Ok((header, rows))
}

/// Re-insert a manifest's rows: see the module doc. `dry_run` inserts and
/// rolls back.
///
/// # Errors
/// A database error (nothing is written), [`SweepError::NotPrivileged`],
/// [`SweepError::LockHeld`], or [`SweepError::CommitUnknown`].
pub async fn restore(
    conn: &mut sqlx::PgConnection,
    rows: &[ManifestRow],
    dry_run: bool,
) -> Result<RestoreReport, SweepError> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    require_bypass(&mut tx).await?;
    take_lock(&mut tx).await?;
    let texts: Vec<String> = rows.iter().map(|r| r.row.clone()).collect();
    let mut restored: Vec<Uuid> = sqlx::query_scalar(
        "-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         INSERT INTO factors
         SELECT r.* FROM unnest($1::text[]) AS t(row_text)
          CROSS JOIN LATERAL jsonb_populate_record(NULL::public.factors, t.row_text::jsonb) r
         ON CONFLICT DO NOTHING
         RETURNING id",
    )
    .bind(&texts)
    .fetch_all(&mut *tx)
    .await?;
    restored.sort_unstable();
    let mut skipped: Vec<Uuid> = rows
        .iter()
        .map(|r| r.id)
        .filter(|id| restored.binary_search(id).is_err())
        .collect();
    skipped.sort_unstable();
    if dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await.map_err(SweepError::CommitUnknown)?;
    }
    Ok(RestoreReport {
        dry_run,
        restored,
        skipped,
    })
}

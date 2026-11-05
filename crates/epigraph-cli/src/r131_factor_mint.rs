//! The R-131 factor mint: give each factorless claim-to-claim `corroborates` /
//! `refutes` edge's empty BP factor slot its factor, exactly as the read-only
//! dry-run delta measured it (ruling R-131, backlog 5094766c; supersede SPEC
//! §11 K0 (i), the retroactive face of K3).
//!
//! # The set is the measurement's, by construction
//!
//! The selection is NOT restated here. [`plan`] reads
//! [`epigraph_engine::supersede_delta::r131_factorless_edges`] (the
//! predicate `supersede_belief_delta --items r131` reports) and fills exactly
//! the slots [`epigraph_engine::supersede_delta::slots_minted`] names. An edge
//! whose `(type, pair)` slot a factor already holds is never handed to the
//! writer: the measurement calls that slot held whatever the holding factor's
//! frame, while the unique index is per frame, so passing such an edge could
//! mint a second, frame-less factor the measurement never counted.
//!
//! # The write is the cascade's own
//!
//! Each slot is minted by
//! [`epigraph_db::ClaimRepository::regenerate_superseded_edge_factors_conn`]
//! (the K3 mint over `REGENERATE_EDGE_FACTORS_SQL`, the body of the edge
//! INSERT trigger over a set), bound to one endpoint of the slot's pair and
//! to every selected edge on that slot. Its `DISTINCT ON … ORDER BY
//! created_at, id` therefore picks the edge the trigger would have picked,
//! and the plan records that edge ([`trigger_order`] reads the same order).
//! It writes `factors` only: no mass function, no claim cache, no served DS
//! value moves (R-178(2): "BP factors only, no served-DS delta").
//!
//! # Plan, apply, undo
//!
//! * [`dry_run`]: one `REPEATABLE READ READ ONLY` transaction; returns the
//!   [`MintPlan`], the exact set an apply would write.
//! * [`apply`]: one `REPEATABLE READ` transaction on a privileged session,
//!   under an advisory lock. It re-plans and refuses unless the live plan
//!   equals the operator's dry-run plan exactly; mints slot by slot and
//!   requires each mint to return exactly its slot; reads every minted row
//!   back; re-measures and requires no slot left to fill; writes the undo
//!   record (and syncs it); then commits. Any mismatch rolls the whole run
//!   back. A second apply after a successful one finds nothing to mint.
//! * [`undo`]: deletes only the factors the record names, and each only while
//!   every column the mint wrote still holds the recorded value (compared in
//!   SQL as typed values). A factor changed or removed since is reported and
//!   left alone. The record is the authority: the undo trusts the record
//!   file the apply wrote, so keep it where only the operator can change it.
//!   A dry run executes the deletes and rolls back.
//!
//!   The undo restores the `factors` table only as far as the rows it
//!   minted. An edge inserted on a minted pair after the apply got no factor
//!   of its own (its INSERT trigger found the slot held), so once the undo
//!   deletes the minted factor that edge is factorless on an empty slot: it
//!   is back in the R-131 set, and a fresh dry run plans it.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use epigraph_engine::supersede_delta::{
    begin_read_only, r131_factorless_edges, slots_minted, FactorlessEdge,
};

/// The plan file's `kind`.
pub const PLAN_KIND: &str = "epigraph.r131_factor_mint.plan/1";
/// The undo record's header `kind`.
pub const RECORD_KIND: &str = "epigraph.r131_factor_mint.record/1";
/// The advisory lock an apply holds (`pg_try_advisory_lock(hashtextextended(
/// MINT_LOCK_NAME, 0))`), so two applies never run at once.
pub const MINT_LOCK_NAME: &str = "epigraph.r131_factor_mint";

/// Why a run stopped. Every variant except [`MintError::CommitUnknown`]
/// means nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Repo(#[from] epigraph_db::DbError),
    #[error(
        "the session is not a privileged (maintenance) writer: the mint and its undo write \
         factors over every writer's edges; nothing was written"
    )]
    NotPrivileged,
    #[error("another r131_factor_mint run holds the mint lock; nothing was written")]
    Locked,
    #[error(
        "the live selection no longer equals the plan (plan: {planned}; live: {live}); \
         nothing was written. Re-run the dry run and review the new plan"
    )]
    PlanDrift { planned: String, live: String },
    #[error("the mint of slot {slot} wrote {got:?}; nothing was written")]
    MintMismatch { slot: String, got: Vec<String> },
    #[error("read-back of the minted factors: {0}; nothing was written")]
    ReadBack(String),
    #[error("after the mint the measurement still disagrees: {0}; nothing was written")]
    PostCheck(String),
    #[error("{0}")]
    Invalid(String),
    #[error("the undo record could not be written ({0}); nothing was written")]
    Record(std::io::Error),
    #[error(
        "COMMIT failed ({0}): whether the mint landed is unknown. The undo record is kept; \
         `--undo <record>` deletes exactly what landed"
    )]
    CommitUnknown(sqlx::Error),
}

/// One slot an apply fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedSlot {
    /// `factor_type:lo,hi`, as the measurement spells it.
    pub slot: String,
    pub factor_type: String,
    /// The ordered pair, parsed from `slot`.
    pub variable_ids: [Uuid; 2],
    /// The edge whose factor the mint writes (the trigger's pick: earliest
    /// `created_at`, then id).
    pub source_edge_id: Uuid,
    /// Every selected edge on the slot, in that order. All but the first stay
    /// factorless, on a slot that is then held.
    pub edges: Vec<Uuid>,
}

/// The exact set an apply writes, and the measurement it was planned from.
/// Carries no timestamp, so two dry runs on one state are byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintPlan {
    pub kind: String,
    /// The measurement's counts (`R131Report`'s fields of the same names).
    pub edges: usize,
    pub by_relationship: BTreeMap<String, usize>,
    pub likely_migrated: usize,
    pub slots_minted: usize,
    pub edges_on_held_slots: usize,
    /// The slots filled, sorted by `slot`.
    pub slots: Vec<PlannedSlot>,
    /// The factorless edges whose slot a factor already holds (never
    /// touched), sorted.
    pub held_edges: Vec<Uuid>,
}

impl MintPlan {
    fn summary(&self) -> String {
        format!(
            "{} edges, {} slots, {} on held slots",
            self.edges, self.slots_minted, self.edges_on_held_slots
        )
    }

    /// SHA-256 of the plan's JSON, as recorded in the undo record.
    #[must_use]
    pub fn sha256(&self) -> String {
        let body = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(&body))
    }
}

/// Group the measured edges into the plan. `order` maps each edge to its
/// position in the trigger's order (`created_at, id`).
///
/// # Errors
/// A slot string that does not parse, or an edge missing from `order`.
pub fn build_plan(
    edges: &[FactorlessEdge],
    order: &HashMap<Uuid, usize>,
) -> Result<MintPlan, MintError> {
    let fill: std::collections::BTreeSet<String> = slots_minted(edges).into_iter().collect();
    let mut groups: BTreeMap<&str, Vec<&FactorlessEdge>> = BTreeMap::new();
    let mut held_edges = Vec::new();
    let mut by_relationship = BTreeMap::new();
    for e in edges {
        *by_relationship.entry(e.relationship.clone()).or_insert(0) += 1;
        if e.slot_held {
            held_edges.push(e.edge_id);
        } else {
            groups.entry(e.slot.as_str()).or_default().push(e);
        }
    }
    held_edges.sort_unstable();
    let mut slots = Vec::with_capacity(groups.len());
    for (slot, mut group) in groups {
        let rank = |e: &FactorlessEdge| {
            order.get(&e.edge_id).copied().ok_or_else(|| {
                MintError::Invalid(format!("edge {} has no trigger order", e.edge_id))
            })
        };
        for e in &group {
            rank(e)?;
        }
        group.sort_by_key(|e| order[&e.edge_id]);
        let (ft, pair) = slot
            .split_once(':')
            .ok_or_else(|| MintError::Invalid(format!("slot `{slot}` has no factor type")))?;
        let (lo, hi) = pair
            .split_once(',')
            .ok_or_else(|| MintError::Invalid(format!("slot `{slot}` is not a pair")))?;
        let parse = |s: &str| {
            s.parse::<Uuid>()
                .map_err(|e| MintError::Invalid(format!("slot `{slot}`: {e}")))
        };
        slots.push(PlannedSlot {
            slot: slot.to_string(),
            factor_type: ft.to_string(),
            variable_ids: [parse(lo)?, parse(hi)?],
            source_edge_id: group[0].edge_id,
            edges: group.iter().map(|e| e.edge_id).collect(),
        });
    }
    let planned: std::collections::BTreeSet<String> =
        slots.iter().map(|s| s.slot.clone()).collect();
    if planned != fill {
        return Err(MintError::Invalid(format!(
            "the plan's slots ({}) differ from the measurement's ({})",
            planned.len(),
            fill.len()
        )));
    }
    Ok(MintPlan {
        kind: PLAN_KIND.to_string(),
        edges: edges.len(),
        by_relationship,
        likely_migrated: edges.iter().filter(|e| e.likely_migrated).count(),
        slots_minted: fill.len(),
        edges_on_held_slots: edges.iter().filter(|e| e.slot_held).count(),
        slots,
        held_edges,
    })
}

/// Each edge's position in the order the mint's `DISTINCT ON` picks by
/// (`created_at`, then id).
///
/// # Errors
/// The query's error.
pub async fn trigger_order(
    conn: &mut sqlx::PgConnection,
    edges: &[Uuid],
) -> Result<HashMap<Uuid, usize>, sqlx::Error> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "-- VISIBILITY-EXEMPT: maintenance read; the R-131 mint runs on the privileged connection.
         SELECT id FROM edges WHERE id = ANY($1) ORDER BY created_at, id",
    )
    .bind(edges)
    .fetch_all(&mut *conn)
    .await?;
    Ok(ids.into_iter().enumerate().map(|(i, id)| (id, i)).collect())
}

/// The plan, read in the caller's transaction.
///
/// # Errors
/// A read error, or [`build_plan`]'s.
pub async fn plan(conn: &mut sqlx::PgConnection) -> Result<MintPlan, MintError> {
    let edges = r131_factorless_edges(&mut *conn).await?;
    let ids: Vec<Uuid> = edges.iter().map(|e| e.edge_id).collect();
    let order = trigger_order(&mut *conn, &ids).await?;
    build_plan(&edges, &order)
}

async fn set_statement_timeout(
    conn: &mut sqlx::PgConnection,
    ms: Option<u64>,
) -> Result<(), sqlx::Error> {
    if let Some(ms) = ms {
        sqlx::query(&format!("SET LOCAL statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

async fn require_privileged(conn: &mut sqlx::PgConnection) -> Result<(), MintError> {
    let privileged: bool =
        sqlx::query_scalar("SELECT public.epigraph_session_is_privileged_writer()")
            .fetch_one(&mut *conn)
            .await?;
    if privileged {
        Ok(())
    } else {
        Err(MintError::NotPrivileged)
    }
}

/// The dry run: the plan, read in one `REPEATABLE READ READ ONLY`
/// transaction (a write inside it would fail 25006). Writes nothing.
///
/// # Errors
/// A read error, or [`build_plan`]'s.
pub async fn dry_run(
    conn: &mut sqlx::PgConnection,
    statement_timeout_ms: Option<u64>,
) -> Result<MintPlan, MintError> {
    let mut tx = begin_read_only(&mut *conn).await?;
    set_statement_timeout(&mut tx, statement_timeout_ms).await?;
    let p = plan(&mut tx).await?;
    tx.rollback().await?;
    Ok(p)
}

/// The undo record's first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordHeader {
    pub kind: String,
    /// [`MintPlan::sha256`] of the plan applied.
    pub plan_sha256: String,
    pub minted: usize,
}

/// One minted factor, as it was when the mint wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedFactor {
    pub factor_id: Uuid,
    pub slot: String,
    pub source_edge_id: Uuid,
    /// `to_jsonb(factors row)::text` read in the mint's transaction: the
    /// undo's compare-and-set operand, decoded and compared in SQL (never
    /// re-encoded in Rust).
    pub row: String,
}

/// A parsed undo record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRecord {
    pub header: RecordHeader,
    pub factors: Vec<MintedFactor>,
}

/// Write `header` and `factors` as JSON lines.
///
/// # Errors
/// The writer's error.
pub fn write_record(
    out: &mut impl Write,
    header: &RecordHeader,
    factors: &[MintedFactor],
) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, header)?;
    out.write_all(b"\n")?;
    for f in factors {
        serde_json::to_writer(&mut *out, f)?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// Read an undo record written by [`apply`].
///
/// # Errors
/// An unreadable file, a wrong `kind`, or a count that disagrees with the
/// header.
pub fn read_record(input: impl BufRead) -> Result<MintRecord, MintError> {
    let mut lines = input.lines();
    let first = lines
        .next()
        .ok_or_else(|| MintError::Invalid("the record is empty".into()))?
        .map_err(|e| MintError::Invalid(format!("read the record: {e}")))?;
    let header: RecordHeader = serde_json::from_str(&first)
        .map_err(|e| MintError::Invalid(format!("the record's header: {e}")))?;
    if header.kind != RECORD_KIND {
        return Err(MintError::Invalid(format!(
            "not an r131_factor_mint record (kind `{}`)",
            header.kind
        )));
    }
    let mut factors = Vec::new();
    for (i, line) in lines.enumerate() {
        let line = line.map_err(|e| MintError::Invalid(format!("read the record: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        factors.push(
            serde_json::from_str(&line)
                .map_err(|e| MintError::Invalid(format!("record line {}: {e}", i + 2)))?,
        );
    }
    if factors.len() != header.minted {
        return Err(MintError::Invalid(format!(
            "the record lists {} factors, its header {}",
            factors.len(),
            header.minted
        )));
    }
    Ok(MintRecord { header, factors })
}

/// The measurement's three counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub edges: usize,
    pub slots_minted: usize,
    pub edges_on_held_slots: usize,
}

/// What [`apply`] wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReport {
    pub minted: usize,
    /// The measurement re-read inside the mint's transaction, after it.
    pub after: Counts,
}

/// Apply `expected` (a dry run's plan): see the module doc. `record` is the
/// undo record's file, written and synced before the COMMIT.
///
/// # Errors
/// See [`MintError`]; only [`MintError::CommitUnknown`] can follow a write.
pub async fn apply(
    conn: &mut sqlx::PgConnection,
    expected: &MintPlan,
    record: &mut std::fs::File,
    statement_timeout_ms: Option<u64>,
) -> Result<ApplyReport, MintError> {
    if expected.kind != PLAN_KIND {
        return Err(MintError::Invalid(format!(
            "not an r131_factor_mint plan (kind `{}`)",
            expected.kind
        )));
    }
    require_privileged(&mut *conn).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(MINT_LOCK_NAME)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        return Err(MintError::Locked);
    }
    let result = apply_locked(&mut *conn, expected, record, statement_timeout_ms).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(MINT_LOCK_NAME)
        .execute(&mut *conn)
        .await;
    result
}

async fn apply_locked(
    conn: &mut sqlx::PgConnection,
    expected: &MintPlan,
    record: &mut std::fs::File,
    statement_timeout_ms: Option<u64>,
) -> Result<ApplyReport, MintError> {
    let mut tx = sqlx::Connection::begin_with(
        &mut *conn,
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    )
    .await?;
    set_statement_timeout(&mut tx, statement_timeout_ms).await?;

    // Compare-and-set on the whole plan: the operator reviewed THIS set.
    let live = plan(&mut tx).await?;
    if live != *expected {
        return Err(MintError::PlanDrift {
            planned: expected.summary(),
            live: live.summary(),
        });
    }

    for s in &expected.slots {
        let got = epigraph_db::ClaimRepository::regenerate_superseded_edge_factors_conn(
            &mut tx,
            s.variable_ids[0],
            &s.edges,
        )
        .await?;
        if got != [s.slot.clone()] {
            return Err(MintError::MintMismatch {
                slot: s.slot.clone(),
                got,
            });
        }
    }

    // Read every minted row back: no factor named any planned edge before
    // (the selection's NOT EXISTS), so the rows naming the winners are the
    // mint's, one per slot, frame-less.
    let winners: Vec<String> = expected
        .slots
        .iter()
        .map(|s| s.source_edge_id.to_string())
        .collect();
    let rows: Vec<(String, Uuid, String, bool, String)> = sqlx::query_as(
        "-- VISIBILITY-EXEMPT: maintenance read; the R-131 mint runs on the privileged connection.
         SELECT f.properties->>'source_edge_id', f.id,
                f.factor_type || ':' || array_to_string(f.variable_ids, ','),
                f.frame_id IS NULL, to_jsonb(f)::text
           FROM factors f
          WHERE f.properties->>'source_edge_id' = ANY($1)
          ORDER BY f.id",
    )
    .bind(&winners)
    .fetch_all(&mut *tx)
    .await?;
    let by_edge: HashMap<&str, &PlannedSlot> = expected
        .slots
        .iter()
        .zip(winners.iter())
        .map(|(s, w)| (w.as_str(), s))
        .collect();
    if rows.len() != expected.slots.len() {
        return Err(MintError::ReadBack(format!(
            "{} rows name the planned edges, {} slots were planned",
            rows.len(),
            expected.slots.len()
        )));
    }
    let mut minted = Vec::with_capacity(rows.len());
    for (edge, factor_id, slot, frameless, row) in rows {
        let planned = by_edge
            .get(edge.as_str())
            .ok_or_else(|| MintError::ReadBack(format!("factor {factor_id} names edge {edge}")))?;
        if planned.slot != slot || !frameless {
            return Err(MintError::ReadBack(format!(
                "factor {factor_id} of edge {edge} sits on {slot} (frame-less: {frameless}), \
                 planned {}",
                planned.slot
            )));
        }
        minted.push(MintedFactor {
            factor_id,
            slot,
            source_edge_id: planned.source_edge_id,
            row,
        });
    }
    minted.sort_by(|a, b| a.slot.cmp(&b.slot));

    // Re-measure in the same transaction: nothing left to fill, and exactly
    // the minted edges left the set.
    let after = r131_factorless_edges(&mut tx).await?;
    let counts = Counts {
        edges: after.len(),
        slots_minted: slots_minted(&after).len(),
        edges_on_held_slots: after.iter().filter(|e| e.slot_held).count(),
    };
    if counts.slots_minted != 0
        || counts.edges + minted.len() != expected.edges
        || counts.edges_on_held_slots != counts.edges
    {
        return Err(MintError::PostCheck(format!(
            "{} edges, {} slots, {} on held slots after minting {} from {} edges",
            counts.edges,
            counts.slots_minted,
            counts.edges_on_held_slots,
            minted.len(),
            expected.edges
        )));
    }

    let header = RecordHeader {
        kind: RECORD_KIND.to_string(),
        plan_sha256: expected.sha256(),
        minted: minted.len(),
    };
    write_record(record, &header, &minted).map_err(MintError::Record)?;
    record.sync_all().map_err(MintError::Record)?;

    tx.commit().await.map_err(MintError::CommitUnknown)?;
    Ok(ApplyReport {
        minted: minted.len(),
        after: counts,
    })
}

/// What [`undo`] did (or, on a dry run, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UndoReport {
    pub dry_run: bool,
    /// Deleted: the row still equalled the recorded one.
    pub deleted: Vec<Uuid>,
    /// No row with the recorded id exists.
    pub absent: Vec<Uuid>,
    /// A row with the recorded id exists but differs: kept.
    pub changed_since: Vec<Uuid>,
    /// `bp_messages` rows the deletes remove through their foreign key.
    pub bp_messages_removed: i64,
}

/// The recorded factors of an undo, as a relation of typed columns: each
/// recorded `to_jsonb` text read back through `jsonb_populate_record`, so the
/// comparison ([`UNDO_MATCH`]) is on values, not on text. A column added to
/// `factors` since the mint is simply not compared, and `created_at` compares
/// as a timestamp whatever time zone either session rendered it in.
const UNDO_WANT: &str = "WITH want AS (
         SELECT w.id AS want_id, r.factor_type, r.variable_ids, r.potential, r.properties,
                r.description, r.frame_id, r.created_at
           FROM unnest($1::uuid[], $2::text[]) AS w(id, row_text)
          CROSS JOIN LATERAL jsonb_populate_record(NULL::public.factors, w.row_text::jsonb) r)";

/// The factor `f` is still exactly what the mint wrote as `w`: every column
/// the mint set.
const UNDO_MATCH: &str = "f.id = w.want_id
            AND f.factor_type = w.factor_type
            AND f.variable_ids = w.variable_ids
            AND f.potential = w.potential
            AND f.properties = w.properties
            AND f.description IS NOT DISTINCT FROM w.description
            AND f.frame_id IS NOT DISTINCT FROM w.frame_id
            AND f.created_at = w.created_at";

/// Undo `record` by compare-and-set: see the module doc.
///
/// # Errors
/// A database error (nothing is written), or [`MintError::NotPrivileged`].
pub async fn undo(
    conn: &mut sqlx::PgConnection,
    record: &MintRecord,
    dry_run: bool,
) -> Result<UndoReport, MintError> {
    require_privileged(&mut *conn).await?;
    let ids: Vec<Uuid> = record.factors.iter().map(|f| f.factor_id).collect();
    let rows: Vec<String> = record.factors.iter().map(|f| f.row.clone()).collect();
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let bp: i64 = sqlx::query_scalar(&format!(
        "-- VISIBILITY-EXEMPT: maintenance read; the R-131 undo runs on the privileged connection.
         {UNDO_WANT}
         SELECT count(*) FROM bp_messages m
           JOIN factors f ON f.id = m.factor_id
           JOIN want w ON {UNDO_MATCH}"
    ))
    .bind(&ids)
    .bind(&rows)
    .fetch_one(&mut *tx)
    .await?;
    let mut deleted: Vec<Uuid> = sqlx::query_scalar(&format!(
        "-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         {UNDO_WANT}
         DELETE FROM factors f USING want w
          WHERE {UNDO_MATCH}
         RETURNING f.id"
    ))
    .bind(&ids)
    .bind(&rows)
    .fetch_all(&mut *tx)
    .await?;
    let mut present: Vec<Uuid> = sqlx::query_scalar(
        "-- VISIBILITY-EXEMPT: maintenance read; the R-131 undo runs on the privileged connection.
         SELECT id FROM factors WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    if dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    deleted.sort_unstable();
    present.sort_unstable();
    let mut absent: Vec<Uuid> = ids
        .iter()
        .copied()
        .filter(|id| deleted.binary_search(id).is_err() && present.binary_search(id).is_err())
        .collect();
    absent.sort_unstable();
    Ok(UndoReport {
        dry_run,
        deleted,
        absent,
        changed_since: present,
        bp_messages_removed: bp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(id: u128, slot: &str, held: bool) -> FactorlessEdge {
        FactorlessEdge {
            edge_id: Uuid::from_u128(id),
            source_id: Uuid::from_u128(1),
            target_id: Uuid::from_u128(2),
            relationship: "corroborates".into(),
            factor_type: "evidential_support".into(),
            slot: slot.into(),
            slot_held: held,
            likely_migrated: false,
        }
    }

    #[test]
    fn a_shared_slot_goes_to_the_earliest_edge_and_held_slots_are_never_planned() {
        let s = format!(
            "evidential_support:{},{}",
            Uuid::from_u128(1),
            Uuid::from_u128(2)
        );
        let edges = vec![
            edge(10, &s, false),
            edge(11, &s, false),
            edge(12, "x:y,z", true),
        ];
        // Edge 11 is earlier in the trigger's order than edge 10.
        let order: HashMap<Uuid, usize> = [
            (Uuid::from_u128(11), 0),
            (Uuid::from_u128(10), 1),
            (Uuid::from_u128(12), 2),
        ]
        .into_iter()
        .collect();
        let p = build_plan(&edges, &order).expect("plan");
        assert_eq!(p.slots.len(), 1);
        assert_eq!(p.slots[0].source_edge_id, Uuid::from_u128(11));
        assert_eq!(
            p.slots[0].edges,
            vec![Uuid::from_u128(11), Uuid::from_u128(10)]
        );
        assert_eq!(
            p.slots[0].variable_ids,
            [Uuid::from_u128(1), Uuid::from_u128(2)]
        );
        assert_eq!(p.held_edges, vec![Uuid::from_u128(12)]);
        assert_eq!((p.edges, p.slots_minted, p.edges_on_held_slots), (3, 1, 1));
    }

    #[test]
    fn a_record_with_a_count_its_header_does_not_state_is_refused() {
        let mut buf = Vec::new();
        let header = RecordHeader {
            kind: RECORD_KIND.into(),
            plan_sha256: "x".into(),
            minted: 2,
        };
        let f = MintedFactor {
            factor_id: Uuid::from_u128(1),
            slot: "s".into(),
            source_edge_id: Uuid::from_u128(2),
            row: "{}".into(),
        };
        write_record(&mut buf, &header, std::slice::from_ref(&f)).expect("write");
        let err = read_record(buf.as_slice()).expect_err("1 line, header says 2");
        assert!(err.to_string().contains("lists 1 factors"), "{err}");
        let mut ok = Vec::new();
        write_record(
            &mut ok,
            &RecordHeader {
                minted: 1,
                ..header
            },
            std::slice::from_ref(&f),
        )
        .expect("w");
        assert_eq!(read_record(ok.as_slice()).expect("read").factors, vec![f]);
    }
}

//! The edge and BBA selections of the supersede belief fixes (supersede SPEC
//! §11 K3, K10(2), K12(b)), shared by the fixes and by the read-only dry-run
//! delta that measures them (K0, X-3), so the measurement and the fix cannot
//! select different rows.
//!
//! * [`RETIRED_SOURCE_EDGE_BBAS_SQL`]: the live edge-keyed BBAs that a
//!   retired claim's outgoing edges froze onto current claims. The supersede
//!   cascade invalidates them for the claim it just retired
//!   (`retraction_cascade::cascade_after_supersede`); the delta reads them for
//!   every retired claim (the retroactive sweep K10(3), operator decision
//!   OD-10, ruled by R-178(2) and R-179; its apply is the operator binary
//!   `sweep_retired_source_bbas`, which plans from [`measure_k10_retro`]).
//! * [`SUPERSEDES_EDGE_BBAS_SQL`]: the live BBAs keyed on a `supersedes` edge
//!   (either spelling). K12(b) stops new ones being wired
//!   (`sheaf::restriction_kind_with_profile` maps `supersedes` to Neutral);
//!   the ones already stored are measured, never removed here.
//! * [`R131_FACTORLESS_EDGES_SQL`]: the in-force claim-to-claim
//!   `corroborates` / `refutes` edges between current claims that carry no BP
//!   factor (ruling R-131), the retroactive face of K3.
//!
//! Every statement here is a READ. The write halves live in the repo layer
//! and in the cascade that sequences them, and this module calls none of
//! them.
//!
//! # The dry-run delta (K0)
//!
//! [`run_read_only`] opens ONE `REPEATABLE READ READ ONLY` transaction
//! ([`begin_read_only`]), reads the selections above, and computes in memory,
//! with the engine's own fold
//! ([`crate::edge_factor::preview_claim_belief_on_frame_adjusted`]), what
//! each would change on the claims it touches. It mirrors what the cascade's
//! repair does to a claim whose edge BBAs were invalidated
//! (`retraction_cascade::repair_targets`): the binary frame's fold of what
//! survives; else, when nothing survives on that frame, the cache kept if the
//! claim still holds a BBA on another frame, or cleared if it held a cache
//! and holds no BBA at all. The served value it compares is the DS cache
//! (`claims.pignistic_prob`): BP marginals are not served (BP apply is
//! retired), so the R-131 block reports factors and slots, not a served
//! delta. The sheaf half of K12(b) changes no served value either: the
//! sheaf readers (`SheafRepository`) select an explicit relationship list
//! that never included `supersedes`.
//!
//! # The calibration delta (`r173`)
//!
//! [`r173`] measures, in the same kind of transaction (or one per chunk), what
//! re-folding each claim's owner frame under the shipped calibration would
//! change on caches written under the empty calibration vocabulary (ruling
//! R-173). See that module.

pub mod r173;

use uuid::Uuid;

/// Live BBAs keyed on an edge whose SOURCE is a retired claim, held by a
/// current claim. `$1` (`uuid[]`): the retired sources to read, or NULL for
/// every retired claim.
///
/// * A BBA is edge-keyed when its `perspective_id` is the edge's id, whatever
///   the perspective row's `perspective_type`: the same keying the cascade's
///   delete (`delete_for_perspective`, by edge id) and the backfill's
///   `REWIRE_EDGE_QUERY` use. `ensure_edge_perspective` types a new row
///   `'edge'` but keeps an existing one (`ON CONFLICT DO NOTHING`), and nothing
///   backfills the type, so a type predicate could miss legacy rows.
/// * Retracted rows are never selected (SPEC §4, "retracted BBAs"; ruling
///   R-79): an invalidation skips them, so they are kept.
/// * The edge's own in-force state is NOT a predicate: a BBA keyed on a
///   withdrawn edge from a retired claim is as stale as one on an edge in
///   force. It is returned so a report can tell the two apart.
pub const RETIRED_SOURCE_EDGE_BBAS_SQL: &str = r#"-- VISIBILITY-EXEMPT: maintenance read; the supersede cascade and the dry-run delta run on the privileged connection.
SELECT mf.id, mf.claim_id, e.id, e.source_id, lower(e.relationship),
       (e.valid_to IS NULL OR e.valid_to > now())
  FROM mass_functions mf
  JOIN edges e ON e.id = mf.perspective_id
  JOIN claims s ON s.id = e.source_id
  JOIN claims h ON h.id = mf.claim_id
 WHERE e.source_type = 'claim'
   AND NOT COALESCE(s.is_current, true)
   AND COALESCE(h.is_current, true)
   AND mf.retracted_at IS NULL
   AND ($1::uuid[] IS NULL OR e.source_id = ANY($1::uuid[]))
 ORDER BY e.id, mf.claim_id, mf.id"#;

/// Live BBAs keyed on a `supersedes` edge of either spelling, held by a
/// current claim. Same keying rule as [`RETIRED_SOURCE_EDGE_BBAS_SQL`].
pub const SUPERSEDES_EDGE_BBAS_SQL: &str = r#"-- VISIBILITY-EXEMPT: maintenance read; the dry-run delta runs on the privileged connection.
SELECT mf.id, mf.claim_id, e.id, e.source_id, lower(e.relationship),
       (e.valid_to IS NULL OR e.valid_to > now())
  FROM mass_functions mf
  JOIN edges e ON e.id = mf.perspective_id
  JOIN claims h ON h.id = mf.claim_id
 WHERE lower(e.relationship) = 'supersedes'
   AND COALESCE(h.is_current, true)
   AND mf.retracted_at IS NULL
 ORDER BY e.id, mf.claim_id, mf.id"#;

/// In-force claim-to-claim `corroborates` / `refutes` edges (either spelling)
/// between two current claims, with no BP factor keyed on them, and the
/// factor slot each would mint: the mapping of `edge_to_factor_type`, the
/// function the INSERT trigger and `REGENERATE_EDGE_FACTORS_SQL` both use, and
/// whether a factor already holds that `(type, pair)` slot (in which case the
/// mint keeps the existing one, as the trigger's `ON CONFLICT DO NOTHING`
/// does). Ruling R-131's set (SPEC §11 K0 (i)). The last column is a
/// "likely migrated" heuristic: the edge is older than one of its endpoints,
/// the fingerprint of an edge a past cascade re-pointed.
pub const R131_FACTORLESS_EDGES_SQL: &str = r#"-- VISIBILITY-EXEMPT: maintenance read; the dry-run delta runs on the privileged connection.
SELECT e.id, e.source_id, e.target_id, lower(e.relationship), ft.factor_type::text,
       ft.factor_type || ':' || array_to_string(
           CASE WHEN e.source_id < e.target_id THEN ARRAY[e.source_id, e.target_id]
                ELSE ARRAY[e.target_id, e.source_id] END, ','),
       EXISTS (SELECT 1 FROM factors f
                WHERE f.factor_type = ft.factor_type
                  AND f.variable_ids = CASE WHEN e.source_id < e.target_id
                                            THEN ARRAY[e.source_id, e.target_id]
                                            ELSE ARRAY[e.target_id, e.source_id] END),
       e.created_at < GREATEST(s.created_at, t.created_at)
  FROM edges e
  JOIN claims s ON s.id = e.source_id
  JOIN claims t ON t.id = e.target_id
  CROSS JOIN LATERAL edge_to_factor_type(e.relationship) ft
 WHERE e.source_type = 'claim' AND e.target_type = 'claim'
   AND (e.valid_to IS NULL OR e.valid_to > now())
   AND COALESCE(s.is_current, true) AND COALESCE(t.is_current, true)
   AND lower(e.relationship) IN ('corroborates', 'refutes')
   AND NOT EXISTS (SELECT 1 FROM factors f WHERE f.properties->>'source_edge_id' = e.id::text)
 ORDER BY e.id"#;

/// One row of [`RETIRED_SOURCE_EDGE_BBAS_SQL`] or [`SUPERSEDES_EDGE_BBAS_SQL`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EdgeKeyedBba {
    pub mass_function_id: Uuid,
    /// The current claim holding the row.
    pub holder_id: Uuid,
    pub edge_id: Uuid,
    pub source_id: Uuid,
    /// Lower-cased.
    pub relationship: String,
    pub edge_in_force: bool,
}

type EdgeKeyedRow = (Uuid, Uuid, Uuid, Uuid, String, bool);

fn edge_keyed(rows: Vec<EdgeKeyedRow>) -> Vec<EdgeKeyedBba> {
    rows.into_iter()
        .map(
            |(mass_function_id, holder_id, edge_id, source_id, relationship, edge_in_force)| {
                EdgeKeyedBba {
                    mass_function_id,
                    holder_id,
                    edge_id,
                    source_id,
                    relationship,
                    edge_in_force,
                }
            },
        )
        .collect()
}

/// [`RETIRED_SOURCE_EDGE_BBAS_SQL`] for `sources`, or for every retired claim
/// when `None`.
///
/// # Errors
/// The query's error.
pub async fn retired_source_edge_bbas(
    conn: &mut sqlx::PgConnection,
    sources: Option<&[Uuid]>,
) -> Result<Vec<EdgeKeyedBba>, sqlx::Error> {
    let rows: Vec<EdgeKeyedRow> = sqlx::query_as(RETIRED_SOURCE_EDGE_BBAS_SQL)
        .bind(sources.map(<[Uuid]>::to_vec))
        .fetch_all(&mut *conn)
        .await?;
    Ok(edge_keyed(rows))
}

/// [`SUPERSEDES_EDGE_BBAS_SQL`].
///
/// # Errors
/// The query's error.
pub async fn supersedes_edge_bbas(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<EdgeKeyedBba>, sqlx::Error> {
    let rows: Vec<EdgeKeyedRow> = sqlx::query_as(SUPERSEDES_EDGE_BBAS_SQL)
        .fetch_all(&mut *conn)
        .await?;
    Ok(edge_keyed(rows))
}

/// One row of [`R131_FACTORLESS_EDGES_SQL`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FactorlessEdge {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// Lower-cased.
    pub relationship: String,
    pub factor_type: String,
    /// `factor_type:lo,hi`, the slot a mint would fill.
    pub slot: String,
    /// A factor already holds the slot, so a mint would keep it and add none.
    pub slot_held: bool,
    /// Older than one of its endpoints (a heuristic for "migrated").
    pub likely_migrated: bool,
}

/// [`R131_FACTORLESS_EDGES_SQL`].
///
/// # Errors
/// The query's error.
pub async fn r131_factorless_edges(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<FactorlessEdge>, sqlx::Error> {
    type Row = (Uuid, Uuid, Uuid, String, String, String, bool, bool);
    let rows: Vec<Row> = sqlx::query_as(R131_FACTORLESS_EDGES_SQL)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                edge_id,
                source_id,
                target_id,
                relationship,
                factor_type,
                slot,
                slot_held,
                likely_migrated,
            )| FactorlessEdge {
                edge_id,
                source_id,
                target_id,
                relationship,
                factor_type,
                slot,
                slot_held,
                likely_migrated,
            },
        )
        .collect())
}

/// The factor slots a mint over `edges` would fill: one per distinct slot no
/// factor holds yet (the mint's `DISTINCT ON (type, pair)` and its
/// `ON CONFLICT DO NOTHING`), sorted.
#[must_use]
pub fn slots_minted(edges: &[FactorlessEdge]) -> Vec<String> {
    let mut slots: Vec<String> = edges
        .iter()
        .filter(|e| !e.slot_held)
        .map(|e| e.slot.clone())
        .collect();
    slots.sort_unstable();
    slots.dedup();
    slots
}

/// Retracted BBAs keyed on an edge whose source is a retired claim, held by
/// a current claim: the rows the K10 invalidation keeps (SPEC §4,
/// "retracted BBAs"; the cascade audit's `retracted_key_kept`). Read for its
/// count only; nothing folds it.
const RETIRED_SOURCE_RETRACTED_BBAS_SQL: &str = r#"-- VISIBILITY-EXEMPT: maintenance read; the dry-run delta runs on the privileged connection.
SELECT count(*)
  FROM mass_functions mf
  JOIN edges e ON e.id = mf.perspective_id
  JOIN claims s ON s.id = e.source_id
  JOIN claims h ON h.id = mf.claim_id
 WHERE e.source_type = 'claim'
   AND NOT COALESCE(s.is_current, true)
   AND COALESCE(h.is_current, true)
   AND mf.retracted_at IS NOT NULL"#;

/// Which measurements a run makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct DeltaItems {
    /// R-131: factorless claim-to-claim `corroborates` / `refutes` edges.
    pub r131: bool,
    /// K10(3): BBAs from already-retired sources (OD-10; applied only by the
    /// operator binary `sweep_retired_source_bbas`).
    pub k10_retro: bool,
    /// K12(b): BBAs keyed on `supersedes` edges (DS), and the sheaf half.
    pub k12b: bool,
    /// R-173: the calibration delta of the owner-frame caches ([`r173`]).
    pub r173: bool,
}

impl DeltaItems {
    /// Parse a comma-separated list of `r131`, `k10-retro`, `k12b`, `r173`.
    ///
    /// # Errors
    /// An unknown item, or an empty list.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut items = Self::default();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item {
                "r131" => items.r131 = true,
                "k10-retro" => items.k10_retro = true,
                "k12b" => items.k12b = true,
                "r173" => items.r173 = true,
                other => {
                    return Err(format!(
                        "unknown item `{other}` (expected r131, k10-retro, k12b, r173)"
                    ))
                }
            }
        }
        if items == Self::default() {
            return Err("no item selected (expected r131, k10-retro, k12b, r173)".to_string());
        }
        Ok(items)
    }
}

/// Options for [`run_read_only`].
#[derive(Debug, Clone)]
pub struct DeltaOptions {
    pub items: DeltaItems,
    /// How many top movers each block lists.
    pub top: usize,
    /// `SET LOCAL statement_timeout` (milliseconds) in every transaction the
    /// run opens; `None` keeps the session's.
    pub statement_timeout_ms: Option<u64>,
    /// The `r173` item's options.
    pub r173: r173::R173Options,
}

/// A claim's cached DS scalars.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Served {
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub betp: Option<f64>,
}

/// What the cascade's repair would leave in a claim's cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaOutcome {
    /// The binary frame's fold of the BBAs that survive.
    Recomputed,
    /// No BBA survives anywhere and the claim held a cache: cleared (NULL).
    Unbacked,
    /// No BBA survives on the binary frame, but one does on another frame:
    /// the cache is kept as it is.
    KeptOtherFrame,
    /// Nothing survives and there was no cache to clear.
    NoCache,
    /// BBAs survive on the binary frame but the derivation scope rule admits
    /// none of them: a real run may VACATE the cache (ruling R-80), which the
    /// in-memory fold does not model. Reported, not predicted.
    VacatePossible,
}

/// One affected claim.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ClaimDelta {
    pub id: Uuid,
    pub old: Served,
    /// `None` for [`DeltaOutcome::VacatePossible`] (not predicted).
    pub new: Option<Served>,
    /// `new.betp - old.betp`, when both are present.
    pub delta: Option<f64>,
    pub outcome: DeltaOutcome,
    /// The items whose rows this claim loses: `k10_retro`, `k12b_ds`.
    pub causes: Vec<&'static str>,
    /// How many of its stored rows the items remove.
    pub rows_removed: usize,
    /// The served value crosses 0.5 (either direction, or to/from NULL).
    pub crosses_half: bool,
}

/// Aggregates over one block's [`ClaimDelta`]s.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct DeltaTotals {
    pub claims: usize,
    pub recomputed: usize,
    pub unbacked: usize,
    pub kept_other_frame: usize,
    pub no_cache: usize,
    pub vacate_possible: usize,
    pub moved_over_0_10: usize,
    pub moved_over_0_20: usize,
    pub crossing_half: usize,
    pub max_abs_delta: f64,
    /// Counts of `|delta|` in `[0, .01)`, `[.01, .05)`, `[.05, .1)`,
    /// `[.1, .2)`, `[.2, .5)`, `[.5, 1]`.
    pub abs_delta_histogram: [usize; 6],
    /// Up to `top` claim ids, largest `|delta|` first (ties by id).
    pub top_movers: Vec<Uuid>,
}

/// One block of claim deltas: the rows a set of items removes, and what that
/// does to each claim holding one.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct DeltaBlock {
    pub rows: usize,
    pub claims: Vec<ClaimDelta>,
    pub totals: DeltaTotals,
}

/// The K10(3) measurement.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct K10RetroReport {
    /// Live rows the invalidation would delete (SPEC §11 K0 (ii)).
    pub live_rows: usize,
    pub edges: usize,
    pub edges_not_in_force: usize,
    pub retired_sources: usize,
    /// Retracted rows keyed on ANY edge whose source is a retired claim,
    /// held by a current claim: rows an invalidation keeps. Wider than the
    /// cascade audit's field of the same name, which counts only the
    /// retracted rows on edges the cascade actually invalidated (an edge
    /// holding only retracted rows is never visited, but is counted here).
    pub retracted_key_kept: i64,
    pub by_relationship: std::collections::BTreeMap<String, usize>,
    pub delta: DeltaBlock,
}

/// The K12(b) measurement.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct K12bReport {
    /// Live BBAs keyed on `supersedes` edges held by current claims (SPEC
    /// §11 K0 (iii)); by spelling in `ds_rows_by_spelling`.
    pub ds_rows: usize,
    pub ds_rows_by_spelling: std::collections::BTreeMap<String, usize>,
    /// No deployed code path removes these rows: the delta is what a
    /// separate cleanup decision would change.
    pub ds_counterfactual: bool,
    pub ds_delta: DeltaBlock,
}

/// The R-131 measurement.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct R131Report {
    /// Factorless edges (SPEC §11 K0 (i)).
    pub edges: usize,
    pub by_relationship: std::collections::BTreeMap<String, usize>,
    pub likely_migrated: usize,
    /// Distinct `(type, pair)` slots a mint over them would fill.
    pub slots_minted: usize,
    /// Edges whose slot a factor already holds (no factor added for them).
    pub edges_on_held_slots: usize,
    /// Current claims that are an endpoint of such an edge.
    pub endpoints: usize,
    /// BP marginals are not served (BP apply is retired), so this item moves
    /// no served value.
    pub served_delta: bool,
}

/// What [`run_read_only`] measured.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct DeltaReport {
    pub items: DeltaItems,
    /// `current_setting('transaction_read_only')` inside the run: `on`.
    pub transaction_read_only: String,
    /// `current_setting('transaction_isolation')` inside the run:
    /// `repeatable read`.
    pub transaction_isolation: String,
    pub served_value: &'static str,
    pub r131: Option<R131Report>,
    pub k10_retro: Option<K10RetroReport>,
    pub k12b: Option<K12bReport>,
    /// The union of the K10(3) and K12(b) DS removals, when both are selected.
    pub combined: Option<DeltaBlock>,
    /// The R-173 calibration delta.
    pub r173: Option<r173::R173Report>,
}

/// Begin the delta's transaction: `REPEATABLE READ READ ONLY`, through
/// sqlx, so the engine's nested `begin()` calls become savepoints inside it
/// and cannot end the snapshot. Any write inside it fails with SQLSTATE
/// 25006.
///
/// # Errors
/// The BEGIN's error.
pub async fn begin_read_only(
    conn: &mut sqlx::PgConnection,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    sqlx::Connection::begin_with(
        conn,
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
    )
    .await
}

/// `SET LOCAL statement_timeout` inside the current transaction (allowed in
/// a READ ONLY one), when `ms` is given.
async fn set_statement_timeout(
    conn: &mut sqlx::PgConnection,
    ms: Option<u64>,
) -> Result<(), String> {
    if let Some(ms) = ms {
        sqlx::query(&format!("SET LOCAL statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("set the statement timeout: {e}"))?;
    }
    Ok(())
}

/// Run the delta in one read-only transaction on `conn`, which must be a
/// privileged (maintenance) connection with its bypass `viewer`: the
/// selections read every group's rows. The transaction is rolled back.
///
/// With `r173` and `opts.r173.chunk`, the r173 item instead runs after it in
/// one read-only transaction for the candidate list and one per chunk of
/// claims, each rolled back and each snapshot recorded
/// ([`r173::R173Report::snapshots`]); chunks see different snapshots.
///
/// # Errors
/// Any read's error, a write attempted inside the transaction (which is a
/// bug: SQLSTATE 25006), or, with `r173`, a served calibration that has a
/// startup problem ([`r173::calibration_guard`]).
pub async fn run_read_only(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    opts: &DeltaOptions,
) -> Result<DeltaReport, String> {
    let identity = if opts.items.r173 {
        Some(r173::calibration_identity()?)
    } else {
        None
    };
    let mut tx = begin_read_only(conn)
        .await
        .map_err(|e| format!("begin the read-only transaction: {e}"))?;
    let report = async {
        set_statement_timeout(&mut tx, opts.statement_timeout_ms).await?;
        let mut report = measure(&mut tx, viewer, opts).await?;
        if let (Some(identity), None) = (&identity, opts.r173.chunk) {
            report.r173 = Some(r173_in_one(&mut tx, viewer, opts, identity.clone()).await?);
        }
        Ok::<_, String>(report)
    }
    .await;
    tx.rollback()
        .await
        .map_err(|e| format!("end the read-only transaction: {e}"))?;
    let mut report = report?;
    if let (Some(identity), Some(chunk)) = (identity, opts.r173.chunk) {
        report.r173 = Some(r173_chunked(conn, viewer, opts, identity, chunk).await?);
    }
    Ok(report)
}

/// The r173 item inside the current (read-only) transaction.
async fn r173_in_one(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    opts: &DeltaOptions,
    identity: r173::CalibrationIdentity,
) -> Result<r173::R173Report, String> {
    let o = &opts.r173;
    let ids = r173::candidates(&mut *conn, o.only.as_deref())
        .await
        .map_err(|e| format!("r173 candidates: {e}"))?;
    let snap = r173::snapshot(&mut *conn, None, &ids).await?;
    let mut run = r173::Run::new();
    let measured = r173::measure_ids(&mut *conn, viewer, &mut run, &ids).await?;
    let canary = match o.canary {
        Some(id) => Some(r173_canary(&mut *conn, viewer, &mut run, &measured, id).await?),
        None => None,
    };
    Ok(r173::report(
        identity,
        o,
        opts.top,
        vec![snap],
        ids.len(),
        measured,
        canary,
    ))
}

/// The r173 item in one read-only transaction per chunk of claims.
async fn r173_chunked(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    opts: &DeltaOptions,
    identity: r173::CalibrationIdentity,
    chunk: usize,
) -> Result<r173::R173Report, String> {
    let o = &opts.r173;
    let timeout = opts.statement_timeout_ms;
    let mut snapshots = Vec::new();

    let mut tx = begin_read_only(&mut *conn)
        .await
        .map_err(|e| format!("begin a read-only transaction: {e}"))?;
    let listed = async {
        set_statement_timeout(&mut tx, timeout).await?;
        let ids = r173::candidates(&mut tx, o.only.as_deref())
            .await
            .map_err(|e| format!("r173 candidates: {e}"))?;
        let snap = r173::snapshot(&mut tx, None, &ids).await?;
        Ok::<_, String>((ids, snap))
    }
    .await;
    tx.rollback()
        .await
        .map_err(|e| format!("end a read-only transaction: {e}"))?;
    let (ids, snap) = listed?;
    snapshots.push(snap);

    let mut run = r173::Run::new();
    let mut measured = Vec::with_capacity(ids.len());
    for (n, part) in ids.chunks(chunk.max(1)).enumerate() {
        let mut tx = begin_read_only(&mut *conn)
            .await
            .map_err(|e| format!("begin a read-only transaction: {e}"))?;
        let got = async {
            set_statement_timeout(&mut tx, timeout).await?;
            let snap = r173::snapshot(&mut tx, Some(n), part).await?;
            let got = r173::measure_ids(&mut tx, viewer, &mut run, part).await?;
            Ok::<_, String>((got, snap))
        }
        .await;
        tx.rollback()
            .await
            .map_err(|e| format!("end a read-only transaction: {e}"))?;
        let (got, snap) = got?;
        snapshots.push(snap);
        measured.extend(got);
    }

    let canary = match o.canary {
        Some(id) => {
            let mut tx = begin_read_only(&mut *conn)
                .await
                .map_err(|e| format!("begin a read-only transaction: {e}"))?;
            let got = async {
                set_statement_timeout(&mut tx, timeout).await?;
                r173_canary(&mut tx, viewer, &mut run, &measured, id).await
            }
            .await;
            tx.rollback()
                .await
                .map_err(|e| format!("end a read-only transaction: {e}"))?;
            Some(got?)
        }
        None => None,
    };
    Ok(r173::report(
        identity,
        o,
        opts.top,
        snapshots,
        ids.len(),
        measured,
        canary,
    ))
}

/// The canary's record: the measured one, or measured now when it was not a
/// candidate.
async fn r173_canary(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    run: &mut r173::Run,
    measured: &[r173::R173Claim],
    id: Uuid,
) -> Result<r173::Canary, String> {
    let claim = match measured.iter().find(|c| c.id == id) {
        Some(c) => Some(c.clone()),
        None => r173::measure_ids(&mut *conn, viewer, run, &[id])
            .await?
            .into_iter()
            .next()
            .filter(|c| c.outcome != r173::R173Outcome::Vanished),
    };
    Ok(r173::canary_of(id, claim))
}

async fn measure(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    opts: &DeltaOptions,
) -> Result<DeltaReport, String> {
    // Read back from the server, so a report proves the transaction it was
    // measured in (SPEC §11 K0: one REPEATABLE READ READ ONLY transaction).
    let (read_only, isolation): (String, String) = sqlx::query_as(
        "SELECT current_setting('transaction_read_only'), current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("read the transaction's mode: {e}"))?;
    let mut report = DeltaReport {
        items: opts.items,
        transaction_read_only: read_only,
        transaction_isolation: isolation,
        served_value: "the DS cache on claims (BetP, Bel, Pl); BP marginals are not served",
        ..DeltaReport::default()
    };
    if opts.items.r131 {
        report.r131 = Some(r131_report(&mut *conn).await?);
    }
    if !(opts.items.k10_retro || opts.items.k12b) {
        return Ok(report);
    }
    let frame_id = binary_frame_id(&mut *conn, viewer).await?;

    let mut k10_rows = Vec::new();
    if opts.items.k10_retro {
        let (rows, k10) = measure_k10_retro(&mut *conn, viewer, frame_id, opts.top).await?;
        k10_rows = rows;
        report.k10_retro = Some(k10);
    }
    let mut k12b_rows = Vec::new();
    if opts.items.k12b {
        k12b_rows = supersedes_edge_bbas(&mut *conn)
            .await
            .map_err(|e| format!("K12(b) selection: {e}"))?;
        let spelling: Vec<(Uuid, String)> = sqlx::query_as(
            "-- VISIBILITY-EXEMPT: maintenance read; the dry-run delta runs on the privileged connection.
             SELECT id, relationship FROM edges WHERE id = ANY($1)",
        )
        .bind(k12b_rows.iter().map(|r| r.edge_id).collect::<Vec<_>>())
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("K12(b) spellings: {e}"))?;
        let spelling: std::collections::HashMap<Uuid, String> = spelling.into_iter().collect();
        let mut by_spelling = std::collections::BTreeMap::new();
        for r in &k12b_rows {
            let s = spelling
                .get(&r.edge_id)
                .cloned()
                .unwrap_or_else(|| r.relationship.clone());
            *by_spelling.entry(s).or_insert(0) += 1;
        }
        let ds_delta = delta_block(
            &mut *conn,
            viewer,
            frame_id,
            &[("k12b_ds", &k12b_rows)],
            opts.top,
        )
        .await?;
        report.k12b = Some(K12bReport {
            ds_rows: k12b_rows.len(),
            ds_rows_by_spelling: by_spelling,
            ds_counterfactual: true,
            ds_delta,
        });
    }
    if opts.items.k10_retro && opts.items.k12b {
        report.combined = Some(
            delta_block(
                &mut *conn,
                viewer,
                frame_id,
                &[("k10_retro", &k10_rows), ("k12b_ds", &k12b_rows)],
                opts.top,
            )
            .await?,
        );
    }
    Ok(report)
}

/// The binary frame's id, READ (never created): the frame the cascade's
/// repair folds on, by the name its lookup uses (`edge_factor`). `None` when
/// no such frame exists yet.
///
/// # Errors
/// The read's error.
pub async fn binary_frame_id(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<Option<Uuid>, String> {
    Ok(epigraph_db::FrameRepository::get_by_name(
        &mut *conn,
        viewer,
        crate::edge_factor::BINARY_FRAME_NAME,
    )
    .await
    .map_err(|e| format!("read the binary frame: {e}"))?
    .map(|f| f.id))
}

/// The K10(3) measurement on `conn`, in whatever transaction it is in: the
/// rows [`retired_source_edge_bbas`] selects for EVERY retired claim, and
/// what removing all of them does to each claim holding one (as the
/// cascade's repair would leave it; `frame_id` from [`binary_frame_id`]).
///
/// The dry-run delta's `k10_retro` block is this function's report, and the
/// retroactive sweep's apply (`sweep_retired_source_bbas`) plans from the
/// same call, so the rows it deletes are the rows this measured.
///
/// # Errors
/// Any read's error.
pub async fn measure_k10_retro(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    frame_id: Option<Uuid>,
    top: usize,
) -> Result<(Vec<EdgeKeyedBba>, K10RetroReport), String> {
    let rows = retired_source_edge_bbas(&mut *conn, None)
        .await
        .map_err(|e| format!("K10(3) selection: {e}"))?;
    let retracted: i64 = sqlx::query_scalar(RETIRED_SOURCE_RETRACTED_BBAS_SQL)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("K10(3) retracted count: {e}"))?;
    let delta = delta_block(&mut *conn, viewer, frame_id, &[("k10_retro", &rows)], top).await?;
    let edges: std::collections::BTreeSet<Uuid> = rows.iter().map(|r| r.edge_id).collect();
    let not_in_force: std::collections::BTreeSet<Uuid> = rows
        .iter()
        .filter(|r| !r.edge_in_force)
        .map(|r| r.edge_id)
        .collect();
    let sources: std::collections::BTreeSet<Uuid> = rows.iter().map(|r| r.source_id).collect();
    let mut by_relationship = std::collections::BTreeMap::new();
    for r in &rows {
        *by_relationship.entry(r.relationship.clone()).or_insert(0) += 1;
    }
    let report = K10RetroReport {
        live_rows: rows.len(),
        edges: edges.len(),
        edges_not_in_force: not_in_force.len(),
        retired_sources: sources.len(),
        retracted_key_kept: retracted,
        by_relationship,
        delta,
    };
    Ok((rows, report))
}

async fn r131_report(conn: &mut sqlx::PgConnection) -> Result<R131Report, String> {
    let edges = r131_factorless_edges(&mut *conn)
        .await
        .map_err(|e| format!("R-131 selection: {e}"))?;
    let mut by_relationship = std::collections::BTreeMap::new();
    let mut endpoints = std::collections::BTreeSet::new();
    for e in &edges {
        *by_relationship.entry(e.relationship.clone()).or_insert(0) += 1;
        endpoints.insert(e.source_id);
        endpoints.insert(e.target_id);
    }
    Ok(R131Report {
        edges: edges.len(),
        by_relationship,
        likely_migrated: edges.iter().filter(|e| e.likely_migrated).count(),
        slots_minted: slots_minted(&edges).len(),
        edges_on_held_slots: edges.iter().filter(|e| e.slot_held).count(),
        endpoints: endpoints.len(),
        served_delta: false,
    })
}

/// The claims holding any of `sets`' rows, and what removing every one of
/// those rows does to each, as the cascade's repair would leave it.
async fn delta_block(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    frame_id: Option<Uuid>,
    sets: &[(&'static str, &[EdgeKeyedBba])],
    top: usize,
) -> Result<DeltaBlock, String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut removed: BTreeMap<Uuid, (BTreeSet<Uuid>, Vec<&'static str>)> = BTreeMap::new();
    let mut rows: BTreeSet<Uuid> = BTreeSet::new();
    for (cause, set) in sets {
        for r in *set {
            rows.insert(r.mass_function_id);
            let entry = removed.entry(r.holder_id).or_default();
            entry.0.insert(r.mass_function_id);
            if !entry.1.contains(cause) {
                entry.1.push(cause);
            }
        }
    }
    let ids: Vec<Uuid> = removed.keys().copied().collect();
    type OldRow = (Uuid, Option<f64>, Option<f64>, Option<f64>, Option<String>);
    let olds: Vec<OldRow> = sqlx::query_as(
        "-- VISIBILITY-EXEMPT: maintenance read; the dry-run delta runs on the privileged connection.
         SELECT id, belief, plausibility, pignistic_prob, classification FROM claims WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("read the affected claims' caches: {e}"))?;
    let olds: std::collections::HashMap<Uuid, OldRow> =
        olds.into_iter().map(|r| (r.0, r)).collect();

    let mut claims = Vec::with_capacity(removed.len());
    for (id, (gone, causes)) in removed {
        let (_, bel, pl, betp, class) = olds
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("claim {id} holds a selected row but cannot be read"))?;
        let old = Served {
            belief: bel,
            plausibility: pl,
            betp,
        };
        let had_cache = bel.is_some() || pl.is_some() || betp.is_some() || class.is_some();
        let on_frame = match frame_id {
            Some(f) => {
                epigraph_db::MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, id, f)
                    .await
                    .map_err(|e| format!("read {id}'s binary-frame BBAs: {e}"))?
                    .into_iter()
                    .filter(|r| !gone.contains(&r.id))
                    .count()
            }
            None => 0,
        };
        let (outcome, new) = if let (Some(f), true) = (frame_id, on_frame > 0) {
            let preview = crate::edge_factor::preview_claim_belief_on_frame_adjusted(
                &mut *conn,
                viewer,
                id,
                f,
                |stored| {
                    stored
                        .into_iter()
                        .filter(|r| !gone.contains(&r.id))
                        .collect()
                },
            )
            .await
            .map_err(|e| format!("fold {id} without the removed rows: {e}"))?;
            match preview {
                Some(p) => {
                    // The write clamps exactly so (`update_claim_belief`).
                    let (b, pl, bp, _, _) = epigraph_ds::measures::clamp_claim_belief_measures(
                        p.belief,
                        p.plausibility,
                        Some(p.pignistic_prob),
                        p.conflict_k,
                        p.missing_mass,
                    );
                    (
                        DeltaOutcome::Recomputed,
                        Some(Served {
                            belief: Some(b),
                            plausibility: Some(pl),
                            betp: bp,
                        }),
                    )
                }
                None => (DeltaOutcome::VacatePossible, None),
            }
        } else {
            let elsewhere =
                epigraph_db::MassFunctionRepository::get_for_claim(&mut *conn, viewer, id)
                    .await
                    .map_err(|e| format!("read {id}'s BBAs: {e}"))?
                    .into_iter()
                    .any(|r| !gone.contains(&r.id));
            if elsewhere {
                (DeltaOutcome::KeptOtherFrame, Some(old))
            } else if had_cache {
                (
                    DeltaOutcome::Unbacked,
                    Some(Served {
                        belief: None,
                        plausibility: None,
                        betp: None,
                    }),
                )
            } else {
                (DeltaOutcome::NoCache, Some(old))
            }
        };
        let delta = match (old.betp, new.and_then(|n| n.betp)) {
            (Some(a), Some(b)) => Some(b - a),
            _ => None,
        };
        let side = |v: Option<f64>| v.map(|x| x > 0.5);
        let crosses_half = match new {
            Some(n) => side(old.betp) != side(n.betp),
            None => false,
        };
        claims.push(ClaimDelta {
            id,
            old,
            new,
            delta,
            outcome,
            causes,
            rows_removed: gone.len(),
            crosses_half,
        });
    }
    let totals = totals(&claims, top);
    Ok(DeltaBlock {
        rows: rows.len(),
        claims,
        totals,
    })
}

fn totals(claims: &[ClaimDelta], top: usize) -> DeltaTotals {
    let mut t = DeltaTotals {
        claims: claims.len(),
        ..DeltaTotals::default()
    };
    for c in claims {
        match c.outcome {
            DeltaOutcome::Recomputed => t.recomputed += 1,
            DeltaOutcome::Unbacked => t.unbacked += 1,
            DeltaOutcome::KeptOtherFrame => t.kept_other_frame += 1,
            DeltaOutcome::NoCache => t.no_cache += 1,
            DeltaOutcome::VacatePossible => t.vacate_possible += 1,
        }
        if c.crosses_half {
            t.crossing_half += 1;
        }
        if let Some(d) = c.delta {
            let a = d.abs();
            if a > 0.10 {
                t.moved_over_0_10 += 1;
            }
            if a > 0.20 {
                t.moved_over_0_20 += 1;
            }
            if a > t.max_abs_delta {
                t.max_abs_delta = a;
            }
            let bin = match a {
                x if x < 0.01 => 0,
                x if x < 0.05 => 1,
                x if x < 0.10 => 2,
                x if x < 0.20 => 3,
                x if x < 0.50 => 4,
                _ => 5,
            };
            t.abs_delta_histogram[bin] += 1;
        }
    }
    let mut movers: Vec<(f64, Uuid)> = claims
        .iter()
        .filter_map(|c| c.delta.map(|d| (d.abs(), c.id)))
        .collect();
    movers.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    t.top_movers = movers.into_iter().take(top).map(|(_, id)| id).collect();
    t
}

//! The read-only cache-owner audit behind the `cache_owner_audit` binary
//! (backlog d33a5c9f, the measurement for the repair after the per-write
//! cache-owner gate).
//!
//! Before that gate, MCP `submit_ds_evidence`, `POST /frames/:id/evidence`
//! and the edge wire folded the frame they were handed into the claim's ONE
//! cached belief, whichever frame owned it, and wrote a compound's cache from
//! its own BBAs. The gate stops new damage; this audit measures what is left:
//!
//! 1. **`repointed_cache`**: current claims holding a cached belief
//!    (`claims.belief` non-NULL) whose recorded `belief_frame_id` is not the
//!    frame the owner rule elects
//!    ([`MassFunctionRepository::cache_owner_frame_for_claim`], called as is,
//!    never copied). Feed these ids to `recompute_claim_belief`, which folds
//!    exactly that owner frame. NOT every row here is a pre-gate re-point: a
//!    widening act (publicize, share) keeps the recorded frame on purpose
//!    (`cache_owner_frame_keeping_recorded`), and a cache recorded before
//!    `belief_frame_id` existed records none. Recomputing those is what their
//!    next ordinary recompute does anyway.
//! 2. **`compound_cached`**: compounds (no owner, and the definer-rights
//!    compound test [`IS_COMPOUND_DEFINER_CALL`] holds) that still hold a
//!    cached belief. `recompute_claim_belief` SKIPS these (a compound has no
//!    owner), so this list is report-only: clearing a compound's cache is the
//!    compound-cache cleanup, an operator decision this tool does not make.
//! 3. **`edge_without_bba`**: in-force claim-to-claim edges whose relationship
//!    the edge wire treats as epistemic (`restriction_kind_with_profile` is
//!    not `Neutral`, decided by the engine function per stored relationship)
//!    with NO mass function keyed on the edge id (any row, retracted
//!    included: the wire's own "ever wired" test,
//!    `MassFunctionRepository::exists_for_perspective`). Each carries
//!    `http_created`: the edge has a `provenance_log` row
//!    (`record_type = 'edge'`, `action = 'create'`), which only `POST /edges`
//!    and `POST /claims/:id/relate` write. MCP writes none, so the HTTP count
//!    is the subset with that row. It is a LOWER BOUND on edges created over
//!    HTTP: the provenance write is best-effort (after the commit, failure only
//!    logged). And `source_state` replays the wire's own gate
//!    (`restrict_edge_source` on the source's CURRENT cache): `factorless`
//!    (no belief interval, the wire skips) and `vacuous` (the wire stores
//!    nothing) are not wiring failures; only `would_wire` is.
//!
//! # Read only
//!
//! Every read runs in ONE `REPEATABLE READ READ ONLY` transaction
//! (`epigraph_engine::supersede_delta::begin_read_only`), so any write inside
//! it fails with SQLSTATE 25006, and the transaction is rolled back at the
//! end. The report records `transaction_read_only` as read from inside it.
//! Nothing here writes: no recompute, no cache write, no repair.
//!
//! # Scope and paging
//!
//! Claims: current claims holding at least one `mass_functions` row,
//! RETRACTED rows included (a compound whose only BBA was retracted is
//! exactly the shape whose cache the old retract path left behind), keyset
//! paged by id. Edges: the in-force epistemic claim-to-claim edges, keyset
//! paged by id. `limit` bounds each pass separately; the report says whether
//! each pass finished (`claims_complete`, `edges_complete`), so a trial run is
//! never read as totals.

use std::collections::BTreeMap;
use std::io::Write;

use serde::Serialize;
use uuid::Uuid;

use epigraph_db::repos::edge::EDGE_IN_FORCE;
use epigraph_db::repos::mass_function::IS_COMPOUND_DEFINER_CALL;
use epigraph_db::visibility::Viewer;
use epigraph_db::MassFunctionRepository;
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::edge_factor::{restrict_edge_source, EdgeRestriction};
use epigraph_engine::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};

/// Default rows per keyset page.
pub const DEFAULT_PAGE: i64 = 1000;

/// Largest accepted page.
pub const MAX_PAGE: i64 = 10_000;

/// How the audit runs.
#[derive(Debug, Clone)]
pub struct Options {
    /// Rows per keyset page (1..=[`MAX_PAGE`]).
    pub page_size: i64,
    /// Stop each pass after this many rows (claims, then edges).
    pub limit: Option<u64>,
    /// How many ids each category lists in the report (all of them go to
    /// the JSONL sink).
    pub sample: usize,
    /// `SET LOCAL statement_timeout` inside the transaction, in milliseconds.
    pub statement_timeout_ms: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_PAGE,
            limit: None,
            sample: 10,
            statement_timeout_ms: None,
        }
    }
}

/// The wire's gate replayed on an edge's source as it is NOW.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    /// The source holds no belief interval: the wire stores nothing.
    Factorless,
    /// The restricted interval is vacuous: the wire stores nothing.
    Vacuous,
    /// The wire would store a BBA today.
    WouldWire,
}

impl SourceState {
    fn label(self) -> &'static str {
        match self {
            Self::Factorless => "factorless",
            Self::Vacuous => "vacuous",
            Self::WouldWire => "would_wire",
        }
    }
}

/// One JSONL line of the `--out` file.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum Finding {
    /// Category (1): the cache records another frame than its owner.
    RepointedCache {
        claim_id: Uuid,
        stored_frame_id: Option<Uuid>,
        owner_frame_id: Uuid,
    },
    /// Category (2): a compound that holds a cached belief.
    CompoundCached {
        claim_id: Uuid,
        stored_frame_id: Option<Uuid>,
    },
    /// Category (3): an epistemic edge with no BBA keyed on it.
    EdgeWithoutBba {
        edge_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        relationship: String,
        http_created: bool,
        source_state: SourceState,
    },
}

/// A category's count and its first `sample` ids.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Category {
    pub count: u64,
    pub sample: Vec<Uuid>,
}

impl Category {
    fn add(&mut self, id: Uuid, sample: usize) {
        self.count += 1;
        if self.sample.len() < sample {
            self.sample.push(id);
        }
    }
}

/// The audit's summary.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Report {
    /// `current_setting('transaction_read_only')`, read inside the audit's
    /// transaction: `true` is the proof that nothing could be written.
    pub transaction_read_only: bool,
    pub transaction_isolation: String,
    pub claims_scanned: u64,
    pub claims_complete: bool,
    /// Category (1).
    pub repointed_cache: Category,
    /// Of category (1), the caches that record no frame at all.
    pub repointed_cache_unrecorded_frame: u64,
    /// Category (2).
    pub compound_cached: Category,
    /// Claims with a cache and no owner that are NOT compounds (only ingest
    /// templates or only retracted rows left). Informational: a claim whose
    /// last BBA was retracted keeps a vacuous cache by design.
    pub ownerless_cached_not_compound: u64,
    /// The stored relationships the wire treats as epistemic.
    pub epistemic_relationships: Vec<String>,
    pub edges_scanned: u64,
    pub edges_complete: bool,
    /// Category (3), every origin.
    pub edges_without_bba: Category,
    /// Of category (3), the edges with an HTTP create provenance row (a lower
    /// bound on HTTP-created edges, see the module docs).
    pub edges_without_bba_http: Category,
    /// Category (3) by [`SourceState`].
    pub edges_without_bba_by_source_state: BTreeMap<String, u64>,
    /// Of the HTTP subset, the edges the wire would wire today.
    pub edges_without_bba_http_would_wire: u64,
}

/// Run the audit in one read-only transaction on `conn` (a connection whose
/// row security `viewer` may bypass: the maintenance connection the
/// binary's session hands out), writing every finding to `sink` as a JSON
/// line.
///
/// # Errors
/// A database error, a sink write error, or a refused option.
pub async fn run_read_only(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    opts: &Options,
    sink: &mut dyn Write,
) -> Result<Report, String> {
    if !(1..=MAX_PAGE).contains(&opts.page_size) {
        return Err(format!("page size must be between 1 and {MAX_PAGE}"));
    }
    let mut tx = epigraph_engine::supersede_delta::begin_read_only(conn)
        .await
        .map_err(|e| format!("begin the read-only transaction: {e}"))?;
    let report = audit(&mut tx, viewer, opts, sink).await;
    tx.rollback()
        .await
        .map_err(|e| format!("end the read-only transaction: {e}"))?;
    report
}

/// The audit inside the already-open transaction.
async fn audit(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    opts: &Options,
    sink: &mut dyn Write,
) -> Result<Report, String> {
    if let Some(ms) = opts.statement_timeout_ms {
        sqlx::query(&format!("SET LOCAL statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("set the statement timeout: {e}"))?;
    }
    let (read_only, isolation): (String, String) = sqlx::query_as(
        "SELECT current_setting('transaction_read_only'), \
                current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("read the transaction mode: {e}"))?;
    let mut report = Report {
        transaction_read_only: read_only == "on",
        transaction_isolation: isolation,
        ..Report::default()
    };
    audit_claims(conn, viewer, opts, sink, &mut report).await?;
    audit_edges(conn, opts, sink, &mut report).await?;
    sink.flush()
        .map_err(|e| format!("flush the findings: {e}"))?;
    Ok(report)
}

fn emit(sink: &mut dyn Write, finding: &Finding) -> Result<(), String> {
    serde_json::to_writer(&mut *sink, finding).map_err(|e| format!("write a finding: {e}"))?;
    sink.write_all(b"\n")
        .map_err(|e| format!("write a finding: {e}"))
}

/// The next page of current claims holding at least one `mass_functions`
/// row, retracted rows included, after `after` (the nil id, below every
/// generated id, starts the scan).
async fn claim_page(
    conn: &mut sqlx::PgConnection,
    after: Option<Uuid>,
    page: i64,
) -> Result<Vec<Uuid>, String> {
    sqlx::query_scalar(
        "SELECT c.id FROM claims c \
          WHERE c.is_current \
            AND c.id > $1 \
            AND EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = c.id) \
          ORDER BY c.id \
          LIMIT $2",
    )
    .bind(after.unwrap_or(Uuid::nil()))
    .bind(page)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("claim page: {e}"))
}

/// Remaining room under `limit` after `done` rows, capped at `page`.
fn room(limit: Option<u64>, done: u64, page: i64) -> i64 {
    match limit {
        Some(l) => i64::try_from(l.saturating_sub(done))
            .unwrap_or(i64::MAX)
            .min(page),
        None => page,
    }
}

async fn audit_claims(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    opts: &Options,
    sink: &mut dyn Write,
    report: &mut Report,
) -> Result<(), String> {
    let mut after = None;
    loop {
        let want = room(opts.limit, report.claims_scanned, opts.page_size);
        if want == 0 {
            // Stopped at the limit: complete only if nothing is left.
            report.claims_complete = claim_page(conn, after, 1).await?.is_empty();
            return Ok(());
        }
        let ids = claim_page(conn, after, want).await?;
        if ids.is_empty() {
            report.claims_complete = true;
            return Ok(());
        }
        let caches = crate::belief_cache::read_cache_columns(&mut *conn, &ids)
            .await
            .map_err(|e| format!("read the cache columns: {e}"))?;
        for &id in &ids {
            report.claims_scanned += 1;
            let Some(cache) = caches.get(&id) else {
                continue;
            };
            if cache.belief.is_none() {
                continue;
            }
            // The REAL owner rule, with the bypass viewer, on this snapshot.
            let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, id)
                .await
                .map_err(|e| format!("cache_owner_frame_for_claim({id}): {e}"))?;
            match owner {
                Some(owner_frame) => {
                    if cache.belief_frame_id != Some(owner_frame) {
                        if cache.belief_frame_id.is_none() {
                            report.repointed_cache_unrecorded_frame += 1;
                        }
                        report.repointed_cache.add(id, opts.sample);
                        emit(
                            sink,
                            &Finding::RepointedCache {
                                claim_id: id,
                                stored_frame_id: cache.belief_frame_id,
                                owner_frame_id: owner_frame,
                            },
                        )?;
                    }
                }
                None => {
                    // The owner rule's own compound test (migration 193's
                    // definer), bound to this claim.
                    let compound: bool =
                        sqlx::query_scalar(&format!("SELECT {IS_COMPOUND_DEFINER_CALL}"))
                            .bind(id)
                            .fetch_one(&mut *conn)
                            .await
                            .map_err(|e| format!("compound test ({id}): {e}"))?;
                    if compound {
                        report.compound_cached.add(id, opts.sample);
                        emit(
                            sink,
                            &Finding::CompoundCached {
                                claim_id: id,
                                stored_frame_id: cache.belief_frame_id,
                            },
                        )?;
                    } else {
                        report.ownerless_cached_not_compound += 1;
                    }
                }
            }
        }
        after = ids.last().copied();
    }
}

/// The stored relationships of in-force claim-to-claim edges that the edge
/// wire treats as epistemic, decided by the engine's own
/// `restriction_kind_with_profile` (the wire's first gate), not by a list.
async fn epistemic_relationships(conn: &mut sqlx::PgConnection) -> Result<Vec<String>, String> {
    let all: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT DISTINCT e.relationship FROM edges e \
          WHERE e.source_type = 'claim' AND e.target_type = 'claim' AND {EDGE_IN_FORCE} \
          ORDER BY 1"
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("edge relationships: {e}"))?;
    let profile = RestrictionProfile::scientific();
    Ok(all
        .into_iter()
        .filter(|r| {
            !matches!(
                restriction_kind_with_profile(r, &profile),
                RestrictionKind::Neutral
            )
        })
        .collect())
}

/// `(id, source, target, relationship, has an edge-keyed BBA, has an HTTP
/// create provenance row, the source's open_world_mass)`.
type EdgeTuple = (Uuid, Uuid, Uuid, String, bool, bool, Option<f64>);

/// The next page of in-force epistemic claim-to-claim edges after `after`.
///
/// The edge-keyed BBA test is the wire's "ever wired" test
/// (`MassFunctionRepository::exists_for_perspective`: any row with
/// `perspective_id` = the edge, retracted included), narrowed to the edge's
/// two endpoints so it rides the `claim_id` index: the wire stores the BBA on
/// the edge's target (`edge_factor::auto_wire_ds_for_edge`).
async fn edge_page(
    conn: &mut sqlx::PgConnection,
    relationships: &[String],
    after: Option<Uuid>,
    page: i64,
) -> Result<Vec<EdgeTuple>, String> {
    sqlx::query_as(&format!(
        "SELECT e.id, e.source_id, e.target_id, e.relationship::text, \
                EXISTS (SELECT 1 FROM mass_functions mf \
                         WHERE mf.claim_id IN (e.source_id, e.target_id) \
                           AND mf.perspective_id = e.id), \
                EXISTS (SELECT 1 FROM provenance_log p \
                         WHERE p.record_type = 'edge' AND p.record_id = e.id \
                           AND p.action = 'create'), \
                (SELECT s.open_world_mass FROM claims s WHERE s.id = e.source_id) \
           FROM edges e \
          WHERE e.source_type = 'claim' AND e.target_type = 'claim' AND {EDGE_IN_FORCE} \
            AND e.relationship = ANY($1) \
            AND e.id > $2 \
          ORDER BY e.id \
          LIMIT $3"
    ))
    .bind(relationships)
    .bind(after.unwrap_or(Uuid::nil()))
    .bind(page)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("edge page: {e}"))
}

async fn audit_edges(
    conn: &mut sqlx::PgConnection,
    opts: &Options,
    sink: &mut dyn Write,
    report: &mut Report,
) -> Result<(), String> {
    let relationships = epistemic_relationships(conn).await?;
    report.epistemic_relationships.clone_from(&relationships);
    if relationships.is_empty() {
        report.edges_complete = true;
        return Ok(());
    }
    let profile = BeliefProfile::served();
    let mut after = None;
    loop {
        let want = room(opts.limit, report.edges_scanned, opts.page_size);
        if want == 0 {
            report.edges_complete = edge_page(conn, &relationships, after, 1).await?.is_empty();
            return Ok(());
        }
        let rows = edge_page(conn, &relationships, after, want).await?;
        if rows.is_empty() {
            report.edges_complete = true;
            return Ok(());
        }
        let sources: Vec<Uuid> = rows
            .iter()
            .filter(|r| !r.4)
            .map(|r| r.1)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let caches = crate::belief_cache::read_cache_columns(&mut *conn, &sources)
            .await
            .map_err(|e| format!("read the source caches: {e}"))?;
        for (edge_id, source_id, target_id, relationship, has_bba, http, open_world) in &rows {
            report.edges_scanned += 1;
            if *has_bba {
                continue;
            }
            // The wire's gate (`auto_wire_ds_for_edge`) on the source's
            // cache as it is now.
            let source_state = match caches
                .get(source_id)
                .and_then(|c| c.belief.zip(c.plausibility))
            {
                None => SourceState::Factorless,
                Some((bel, pl)) => {
                    match restrict_edge_source((bel, pl, *open_world), relationship, profile) {
                        EdgeRestriction::Restricted(_) => SourceState::WouldWire,
                        // NonEpistemic cannot occur (the relationship passed
                        // the same gate); counted with the no-op outcome.
                        EdgeRestriction::Vacuous | EdgeRestriction::NonEpistemic => {
                            SourceState::Vacuous
                        }
                    }
                }
            };
            report.edges_without_bba.add(*edge_id, opts.sample);
            *report
                .edges_without_bba_by_source_state
                .entry(source_state.label().to_string())
                .or_default() += 1;
            if *http {
                report.edges_without_bba_http.add(*edge_id, opts.sample);
                if source_state == SourceState::WouldWire {
                    report.edges_without_bba_http_would_wire += 1;
                }
            }
            emit(
                sink,
                &Finding::EdgeWithoutBba {
                    edge_id: *edge_id,
                    source_id: *source_id,
                    target_id: *target_id,
                    relationship: relationship.clone(),
                    http_created: *http,
                    source_state,
                },
            )?;
        }
        after = rows.last().map(|r| r.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_caps_at_the_limit_and_the_page() {
        assert_eq!(room(None, 5, 100), 100);
        assert_eq!(room(Some(250), 200, 100), 50);
        assert_eq!(room(Some(250), 250, 100), 0);
        assert_eq!(room(Some(10), 0, 100), 10);
    }

    #[test]
    fn findings_serialize_with_their_category() {
        let id = Uuid::nil();
        let line = serde_json::to_value(Finding::RepointedCache {
            claim_id: id,
            stored_frame_id: None,
            owner_frame_id: id,
        })
        .unwrap();
        assert_eq!(line["category"], "repointed_cache");
        let line = serde_json::to_value(Finding::EdgeWithoutBba {
            edge_id: id,
            source_id: id,
            target_id: id,
            relationship: "supports".into(),
            http_created: true,
            source_state: SourceState::WouldWire,
        })
        .unwrap();
        assert_eq!(line["category"], "edge_without_bba");
        assert_eq!(line["source_state"], "would_wire");
    }
}

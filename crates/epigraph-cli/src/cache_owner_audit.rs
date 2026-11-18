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
//!    **`ownerless_cached`** sits beside it: NON-compound claims that hold a
//!    cache but have no owner (every input retracted, or only ingest-template
//!    or inadmissible rows left). Each line says whether every input is
//!    retracted (`all_retracted`) and whether the cache is vacuous
//!    (`vacuous`: Bel 0, Pl 1). Since the retract path learned to vacate
//!    (2026-10-27), a claim whose last BBA is retracted gets a vacuous cache;
//!    one retracted before then, with no backfill, may still serve the
//!    retracted fold, which is the d33a5c9f (2) shape on a non-compound:
//!    `all_retracted && !vacuous` (counted as
//!    `ownerless_cached_retracted_not_vacuous`). Report-only too:
//!    `recompute_claim_belief` skips a claim with no owner.
//! 3. **`edge_without_bba`**: in-force claim-to-claim edges whose relationship
//!    the edge wire treats as epistemic (`restriction_kind_with_profile` is
//!    not `Neutral`, decided by the engine function per stored relationship)
//!    with NO mass function keyed on the edge id ON ANY CLAIM (any row,
//!    retracted included: the wire's own "ever wired" test,
//!    `MassFunctionRepository::exists_for_perspective`, which has no claim
//!    restriction). Each carries two
//!    HTTP-origin markers, neither complete alone, so `http_created` is
//!    either one:
//!    * `http_signed`: `edges.signer_id` is the API's OWN edge signer
//!      (`epigraph-api` attests its edges with a separate key held by a
//!      separate agent, named [`API_SIGNER_DISPLAY_NAME`], so an API signature
//!      is never an MCP one), or an agent passed in [`Options::api_signers`].
//!      Absent for an edge written before the API had its key, or by an API
//!      with no key configured (it writes unsigned), or one signing as a
//!      borrowed agent (its boot warns).
//!    * `http_provenance`: a `provenance_log` row (`record_type = 'edge'`,
//!      `action = 'create'`), which only `POST /edges` and
//!      `POST /claims/:id/relate` write, and MCP never does. Best-effort:
//!      written after the commit, a failure only logged.
//!
//!    So the HTTP count is a LOWER BOUND on edges created over HTTP; the
//!    all-origins count is the upper one. And `source_state` replays the
//!    wire's own gate
//!    (`restrict_edge_source` on the source's CURRENT cache): `factorless`
//!    (no belief interval, the wire skips) and `vacuous` (the wire stores
//!    nothing) are not wiring failures; only `would_wire` is.
//! 4. **`edge_bba_off_endpoint`**: an in-force epistemic edge whose
//!    edge-keyed BBA exists but sits on neither of the edge's CURRENT
//!    endpoints. Superseding the target re-targets the edge
//!    (`migrate_superseded_edges`) and moves no `mass_functions` row, so the
//!    BBA stays on the retired target. The wire counts the edge as wired, so
//!    it is NOT in (3); listed so the leftover BBAs can be found.
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
//! paged by id, tested against the set of edge ids that key ANY mass
//! function, read once (`perspective_id` has no index, so a per-edge test
//! would scan the table per edge). `limit` bounds each pass separately; the report says whether
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

/// The display name `epigraph-api` registers its own edge-signer agent
/// under (`epigraph_api::edge_signer::SIGNER_DISPLAY_NAME`; this crate does
/// not link the API, and a test pins the two equal).
pub const API_SIGNER_DISPLAY_NAME: &str = "epigraph-api-signer";

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
    /// Agents whose edge signatures mark an edge as created over HTTP, besides
    /// every agent named [`API_SIGNER_DISPLAY_NAME`] (e.g. an agent the API
    /// signed as with a borrowed key).
    pub api_signers: Vec<Uuid>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_PAGE,
            limit: None,
            sample: 10,
            statement_timeout_ms: None,
            api_signers: Vec::new(),
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
    /// Beside (2): a NON-compound with a cache and no owner.
    OwnerlessCached {
        claim_id: Uuid,
        stored_frame_id: Option<Uuid>,
        /// Every mass function on the claim is retracted.
        all_retracted: bool,
        /// The cache is the explicit vacuous value (Bel 0, Pl 1).
        vacuous: bool,
    },
    /// Category (4): the edge's BBA exists, on neither current endpoint.
    EdgeBbaOffEndpoint {
        edge_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        relationship: String,
    },
    /// Category (3): an epistemic edge with no BBA keyed on it.
    EdgeWithoutBba {
        edge_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        relationship: String,
        /// `http_signed || http_provenance`.
        http_created: bool,
        http_signed: bool,
        http_provenance: bool,
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
    /// Claims with a cache and no owner that are NOT compounds (every input
    /// retracted, or only ingest-template or inadmissible rows left). A claim
    /// whose last BBA was retracted gets a vacuous cache only since the
    /// retract path learned to vacate (2026-10-27); older ones may still
    /// serve the retracted fold. Report-only (`recompute_claim_belief` skips a
    /// claim with no owner).
    pub ownerless_cached: Category,
    /// Of `ownerless_cached`, the claims whose every input is retracted and
    /// whose cache is NOT vacuous: the d33a5c9f (2) shape on a non-compound.
    pub ownerless_cached_retracted_not_vacuous: u64,
    /// The stored relationships the wire treats as epistemic.
    pub epistemic_relationships: Vec<String>,
    /// The agents whose edge signatures count as HTTP origin.
    pub api_signer_agents: Vec<Uuid>,
    pub edges_scanned: u64,
    pub edges_complete: bool,
    /// Category (3), every origin.
    pub edges_without_bba: Category,
    /// Of category (3), the edges with either HTTP-origin marker (a lower
    /// bound on HTTP-created edges, see the module docs).
    pub edges_without_bba_http: Category,
    /// Of category (3), the edges signed by an API signer agent.
    pub edges_without_bba_http_signed: u64,
    /// Of category (3), the edges with an HTTP create provenance row.
    pub edges_without_bba_http_provenance: u64,
    /// Category (3) by [`SourceState`].
    pub edges_without_bba_by_source_state: BTreeMap<String, u64>,
    /// Of the HTTP subset, the edges the wire would wire today.
    pub edges_without_bba_http_would_wire: u64,
    /// Category (4): edges whose edge-keyed BBA sits on neither current
    /// endpoint (wired, so not in (3)).
    pub edges_bba_off_endpoint: Category,
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

/// Tolerance of the vacuous test (Bel 0, Pl 1).
const VACUOUS_EPS: f64 = 1e-9;

/// Whether a cache is the explicit vacuous value (Bel 0, Pl 1).
fn is_vacuous(belief: Option<f64>, plausibility: Option<f64>) -> bool {
    matches!((belief, plausibility),
        (Some(b), Some(p)) if b.abs() <= VACUOUS_EPS && (1.0 - p).abs() <= VACUOUS_EPS)
}

/// Whether every mass function on `claim_id` is retracted (none live).
async fn all_retracted(conn: &mut sqlx::PgConnection, claim_id: Uuid) -> Result<bool, String> {
    sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM mass_functions mf \
                             WHERE mf.claim_id = $1 AND mf.retracted_at IS NULL)",
    )
    .bind(claim_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("live inputs ({claim_id}): {e}"))
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
                        let retracted_only = all_retracted(conn, id).await?;
                        let vacuous = is_vacuous(cache.belief, cache.plausibility);
                        report.ownerless_cached.add(id, opts.sample);
                        if retracted_only && !vacuous {
                            report.ownerless_cached_retracted_not_vacuous += 1;
                        }
                        emit(
                            sink,
                            &Finding::OwnerlessCached {
                                claim_id: id,
                                stored_frame_id: cache.belief_frame_id,
                                all_retracted: retracted_only,
                                vacuous,
                            },
                        )?;
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

/// `(id, source, target, relationship, signer, has an edge-keyed BBA on one
/// of its endpoints, has an HTTP create provenance row, the source's
/// open_world_mass)`.
type EdgeTuple = (
    Uuid,
    Uuid,
    Uuid,
    String,
    Option<Uuid>,
    bool,
    bool,
    Option<f64>,
);

/// Every claim-to-claim edge id that keys at least one mass function, on any
/// claim, retracted rows included: the wire's "ever wired" test
/// (`MassFunctionRepository::exists_for_perspective`, which has no claim
/// restriction) for every edge at once. One read: `perspective_id` has no
/// index, so testing each edge would scan the table per edge.
async fn edge_keyed_perspectives(
    conn: &mut sqlx::PgConnection,
) -> Result<std::collections::HashSet<Uuid>, String> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT mf.perspective_id FROM mass_functions mf \
           JOIN edges e ON e.id = mf.perspective_id \
          WHERE e.source_type = 'claim' AND e.target_type = 'claim'",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("edge-keyed mass functions: {e}"))?;
    Ok(ids.into_iter().collect())
}

/// The next page of in-force epistemic claim-to-claim edges after `after`.
///
/// The per-edge flag is whether the edge-keyed BBA sits on one of the edge's
/// CURRENT endpoints (the wire stores it on the target,
/// `edge_factor::auto_wire_ds_for_edge`), which rides the `claim_id` index.
/// It is NOT the wire's "ever wired" test: an edge re-targeted by a supersede
/// keeps its BBA on the retired target. [`edge_keyed_perspectives`] is that
/// test; this flag only tells (3) from (4).
async fn edge_page(
    conn: &mut sqlx::PgConnection,
    relationships: &[String],
    after: Option<Uuid>,
    page: i64,
) -> Result<Vec<EdgeTuple>, String> {
    sqlx::query_as(&format!(
        "SELECT e.id, e.source_id, e.target_id, e.relationship::text, e.signer_id, \
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
    let mut signers: Vec<Uuid> =
        sqlx::query_scalar("SELECT a.id FROM agents a WHERE a.display_name = $1 ORDER BY a.id")
            .bind(API_SIGNER_DISPLAY_NAME)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| format!("the API signer agents: {e}"))?;
    signers.extend(opts.api_signers.iter().copied());
    signers.sort_unstable();
    signers.dedup();
    report.api_signer_agents.clone_from(&signers);
    if relationships.is_empty() {
        report.edges_complete = true;
        return Ok(());
    }
    // Read in the same snapshot as the edge pages.
    let keyed = edge_keyed_perspectives(conn).await?;
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
            .filter(|r| !r.5 && !keyed.contains(&r.0))
            .map(|r| r.1)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let caches = crate::belief_cache::read_cache_columns(&mut *conn, &sources)
            .await
            .map_err(|e| format!("read the source caches: {e}"))?;
        for (
            edge_id,
            source_id,
            target_id,
            relationship,
            signer,
            has_bba,
            provenance,
            open_world,
        ) in &rows
        {
            report.edges_scanned += 1;
            if *has_bba {
                continue;
            }
            if keyed.contains(edge_id) {
                // Wired (the wire's own test), but the BBA sits on neither
                // current endpoint: (4), not (3).
                report.edges_bba_off_endpoint.add(*edge_id, opts.sample);
                emit(
                    sink,
                    &Finding::EdgeBbaOffEndpoint {
                        edge_id: *edge_id,
                        source_id: *source_id,
                        target_id: *target_id,
                        relationship: relationship.clone(),
                    },
                )?;
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
            let signed = signer.is_some_and(|s| signers.binary_search(&s).is_ok());
            if signed {
                report.edges_without_bba_http_signed += 1;
            }
            if *provenance {
                report.edges_without_bba_http_provenance += 1;
            }
            let http = signed || *provenance;
            if http {
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
                    http_created: http,
                    http_signed: signed,
                    http_provenance: *provenance,
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
    fn vacuous_is_bel_zero_and_pl_one() {
        assert!(is_vacuous(Some(0.0), Some(1.0)));
        assert!(!is_vacuous(Some(0.6), Some(1.0)));
        assert!(!is_vacuous(Some(0.0), Some(0.9)));
        assert!(!is_vacuous(None, Some(1.0)));
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
            http_signed: true,
            http_provenance: false,
            source_state: SourceState::WouldWire,
        })
        .unwrap();
        assert_eq!(line["category"], "edge_without_bba");
        assert_eq!(line["source_state"], "would_wire");
    }
}

//! `sweep_semantic_duplicates` MCP tool (backlog e3732d16 / design F4).
//!
//! Retroactive counterpart to the write-side novelty gate (PR #324). The gate
//! stops NEW near-duplicates; this sweeps the corpus that accumulated before
//! it, measured at a 68.4% duplicate rate across 20+ agents.
//!
//! Why that matters for retrieval: when `recall()` returns 10 claims and ~7
//! are restatements of each other, the apparent evidence mass for a handful of
//! underlying facts is inflated — the memory-induced sycophancy failure mode
//! MemSyco-Bench traces 61-62% of post-retrieval errors to.
//!
//! # Dry run is the default
//!
//! The sweep mutates lineage across agents, so `dry_run` defaults to `true`
//! and must be turned off explicitly. Sweeping ~450k claims is many bounded
//! calls by design, driven by cron with an advancing `offset`, which keeps
//! each call's blast radius reviewable.
//!
//! # Where it runs (operator decision D9, batch W12a)
//!
//! The collapse is an administrative act across every writer's rows, so it
//! runs on a maintenance connection, which no request-serving process holds.
//! The MCP tool answers MOVED on a real server; the operator runs the
//! `sweep_semantic_duplicates` CLI (epigraph-cli), which calls [`sweep`].
//!
//! # Every collapse is audited as D1 requires
//!
//! Each pair goes through the same two halves as the single-shot
//! `mark_duplicate`: the act (`ClaimRepository::mark_duplicate_act_conn`), then
//! the administrative cascade (`admin_cascade::apply_after_dedup`), which
//! commits its repair together with ONE `cascade.admin_applied` row naming the
//! acting agent (`--acting-agent`) and cause `dedup`. Before W12a the sweep
//! called `retraction_cascade::mark_duplicate_with_cascade` inline and wrote no
//! audit row at all.

use std::collections::HashMap;

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::types::SweepSemanticDuplicatesParams;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_engine::admin_cascade::{
    apply_after_dedup, CascadeCause, CascadeState, CascadeTrigger,
};

/// Disjoint-set over claim ids, so A~B and B~C land in one cluster even when
/// A and C were never directly compared.
struct UnionFind {
    parent: HashMap<Uuid, Uuid>,
}

impl UnionFind {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }
    fn find(&mut self, x: Uuid) -> Uuid {
        let p = *self.parent.entry(x).or_insert(x);
        if p == x {
            return x;
        }
        let root = self.find(p);
        self.parent.insert(x, root);
        root
    }
    fn union(&mut self, a: Uuid, b: Uuid) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

/// One exact-restatement cluster or merge candidate the sweep found.
#[derive(Debug, Serialize)]
pub struct ClusterOut {
    /// The claim every duplicate is forwarded at.
    pub survivor: String,
    /// The claims collapsed onto the survivor (or proposed for consolidation).
    pub duplicates: Vec<String>,
    /// The largest embedding distance between the survivor and a duplicate.
    pub max_distance: f64,
    /// `true` when every member shares the survivor's content hash — an exact
    /// restatement set, safe to collapse with `mark_duplicate`. `false` means
    /// the members differ in wording, so collapsing would DISCARD text: those
    /// are surfaced as merge candidates for `consolidate_claims` instead.
    pub exact: bool,
}

/// What one sweep page found and did.
#[derive(Debug, Serialize)]
pub struct SweepResponse {
    /// Whether this was a dry run (nothing written).
    pub dry_run: bool,
    /// Claims enumerated on this page.
    pub scanned: usize,
    /// Exact-restatement clusters — acted on when `dry_run=false`.
    pub clusters: Vec<ClusterOut>,
    /// Near-but-not-identical clusters. Never auto-collapsed: an agent should
    /// synthesize these through `consolidate_claims` so no wording is lost.
    pub merge_candidates: Vec<ClusterOut>,
    /// Pairs whose collapse (the act) committed.
    pub pairs_marked: u64,
    /// The `cascade.admin_applied` rows written, one per pair whose
    /// administrative cascade committed.
    pub audit_event_ids: Vec<Uuid>,
    /// Per-pair problems, in three classes that are **not** complementary with
    /// `pairs_marked`:
    ///
    /// * `"<dup> -> <survivor>: <err>"` — the act itself failed. The pair is not
    ///   counted in `pairs_marked`.
    /// * `"<dup> -> <survivor> (cascade): <reason>"` — the act committed and
    ///   **is** counted, but the administrative repair failed and rolled back
    ///   (its `cascade.admin_failed` row makes it replayable).
    /// * `"<dup> -> <survivor> (belief cascade): <err>"` — the repair
    ///   committed, but the downstream belief re-derivation hit a non-fatal
    ///   error for one claim.
    pub failures: Vec<String>,
    /// Offset to pass on the next call to continue the sweep.
    pub next_offset: i64,
}

/// One page of the sweep, on `session`'s connection: find clusters, and unless
/// `params.dry_run` is not `Some(false)`, collapse the exact-restatement pairs,
/// each through the act and the audited administrative cascade, attributed to
/// `acting_agent` with cause `dedup`.
///
/// Every statement, reads and the collapse alike, runs on `session`'s
/// connection, which must bypass RLS: the sweep's value is the pair that spans
/// two tenants, and only a connection that sees every tenant can find it. No
/// server pool is named here (`tests/maintenance_tools_spend_only_the_session.rs`).
///
/// # Errors
/// A read failure (enumeration, neighbours, hashes). Per-pair write failures
/// are reported in [`SweepResponse::failures`], never as an `Err`.
pub async fn sweep(
    session: &mut epigraph_db::MaintenanceSession<'_>,
    params: &SweepSemanticDuplicatesParams,
    acting_agent: Uuid,
) -> Result<SweepResponse, epigraph_db::DbError> {
    let (conn, viewer) = session.split();
    let threshold = params.similarity_threshold.unwrap_or(0.10).clamp(0.0, 2.0);
    let limit = params.limit.unwrap_or(500).clamp(1, 2000);
    let offset = params.offset.unwrap_or(0).max(0);
    let dry_run = params.dry_run.unwrap_or(true);

    let agent_scope: Option<Vec<Uuid>> = match params.agent_scope.as_ref() {
        Some(v) => Some(
            v.iter()
                .map(|s| {
                    s.parse::<Uuid>()
                        .map_err(|e| epigraph_db::DbError::InvalidData {
                            reason: format!("agent_scope entry {s:?} is not a UUID: {e}"),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        None => None,
    };

    let candidates = ClaimRepository::enumerate_current_embedded(
        &mut *conn,
        viewer,
        agent_scope.as_deref(),
        params.labels_scope.as_deref(),
        offset,
        limit,
    )
    .await?;

    // Pair discovery: per-claim ANN top-5, keeping pairs under the threshold.
    let mut uf = UnionFind::new();
    let mut meta: HashMap<Uuid, (f64, chrono::DateTime<chrono::Utc>)> = HashMap::new();
    let mut pair_distance: HashMap<(Uuid, Uuid), f64> = HashMap::new();

    for c in &candidates {
        meta.insert(c.id, (c.truth_value, c.created_at));
        let neighbors =
            ClaimRepository::nearest_neighbors_of_claim(&mut *conn, viewer, c.id, 5).await?;
        for n in neighbors {
            if n.distance >= threshold {
                continue;
            }
            meta.entry(n.claim_id)
                .or_insert((n.truth_value, n.created_at));
            let key = if c.id < n.claim_id {
                (c.id, n.claim_id)
            } else {
                (n.claim_id, c.id)
            };
            pair_distance.insert(key, n.distance);
            uf.union(c.id, n.claim_id);
        }
    }

    // Group by root.
    let members: Vec<Uuid> = meta.keys().copied().collect();
    let mut clusters: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for m in members {
        let root = uf.find(m);
        clusters.entry(root).or_default().push(m);
    }

    let all_ids: Vec<Uuid> = meta.keys().copied().collect();
    let hashes = ClaimRepository::content_hashes_for(&mut *conn, viewer, &all_ids).await?;

    let mut exact_clusters: Vec<(Uuid, Vec<Uuid>, f64)> = Vec::new();
    let mut near_clusters: Vec<(Uuid, Vec<Uuid>, f64)> = Vec::new();

    for (_root, mut group) in clusters {
        if group.len() < 2 {
            continue;
        }
        // Survivor: highest truth_value, ties broken by earliest created_at
        // (the original statement outlives its restatements).
        group.sort_by(|a, b| {
            let (ta, ca) = meta[a];
            let (tb, cb) = meta[b];
            tb.total_cmp(&ta).then(ca.cmp(&cb)).then(a.cmp(b))
        });
        let survivor = group[0];
        let duplicates: Vec<Uuid> = group[1..].to_vec();

        let max_distance = duplicates
            .iter()
            .filter_map(|d| {
                let key = if survivor < *d {
                    (survivor, *d)
                } else {
                    (*d, survivor)
                };
                pair_distance.get(&key).copied()
            })
            .fold(0.0_f64, f64::max);

        let survivor_hash = hashes.get(&survivor);
        let all_exact = duplicates
            .iter()
            .all(|d| hashes.contains_key(d) && hashes.get(d) == survivor_hash);

        if all_exact {
            exact_clusters.push((survivor, duplicates, max_distance));
        } else {
            near_clusters.push((survivor, duplicates, max_distance));
        }
    }

    // Execute: only exact-restatement clusters are collapsed automatically.
    // Each pair is its own act and its own administrative transaction, so one
    // edge collision cannot roll back the whole sweep; failures are collected
    // and returned, never fatal.
    let mut pairs_marked = 0_u64;
    let mut audit_event_ids: Vec<Uuid> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    if !dry_run {
        for (survivor, duplicates, _) in &exact_clusters {
            for dup in duplicates {
                // The act: retire the duplicate and forward it at the survivor
                // (its own transaction on this connection).
                if let Err(e) = ClaimRepository::mark_duplicate_act_conn(
                    &mut *conn,
                    ClaimId::from_uuid(*dup),
                    ClaimId::from_uuid(*survivor),
                )
                .await
                {
                    failures.push(format!("{dup} -> {survivor}: {e}"));
                    continue;
                }
                pairs_marked += 1;
                // The administrative cascade (D1): repair the edge and derived
                // layers with its audit row, atomically, then re-derive belief.
                // The acting operator is the trigger; the "caller" whose view
                // the report is filtered to is the sweep's own bypass viewer.
                let trigger = CascadeTrigger::new(
                    CascadeCause::Dedup,
                    Some(acting_agent),
                    None,
                    *dup,
                    Some(*survivor),
                );
                let (status, report) =
                    apply_after_dedup(&mut *conn, viewer, viewer, &trigger, *dup, *survivor).await;
                match status.status {
                    CascadeState::Applied => {
                        if let Some(id) = status.audit_event_id {
                            audit_event_ids.push(id);
                        }
                    }
                    CascadeState::Failed | CascadeState::Deferred => failures.push(format!(
                        "{dup} -> {survivor} (cascade): {}",
                        status.reason.unwrap_or_default()
                    )),
                }
                for err in report.errors {
                    failures.push(format!("{dup} -> {survivor} (belief cascade): {err}"));
                }
            }
        }
    }

    let to_out = |v: Vec<(Uuid, Vec<Uuid>, f64)>, exact: bool| -> Vec<ClusterOut> {
        v.into_iter()
            .map(|(s, d, dist)| ClusterOut {
                survivor: s.to_string(),
                duplicates: d.iter().map(ToString::to_string).collect(),
                max_distance: dist,
                exact,
            })
            .collect()
    };

    Ok(SweepResponse {
        dry_run,
        scanned: candidates.len(),
        clusters: to_out(exact_clusters, true),
        merge_candidates: to_out(near_clusters, false),
        pairs_marked,
        audit_event_ids,
        failures,
        next_offset: offset + candidates.len() as i64,
    })
}

/// The MCP tool body: [`sweep`], attributed to `acting_agent` (the server's
/// own agent), as a tool result. Reached only on a server with a maintenance
/// pool attached, which under D9 is a test harness; a real server answers
/// MOVED before this (`maintenance::maintenance_tool_session`).
///
/// # Errors
/// An MCP internal error on a read failure.
pub async fn sweep_semantic_duplicates(
    session: &mut epigraph_db::MaintenanceSession<'_>,
    params: SweepSemanticDuplicatesParams,
    acting_agent: Uuid,
) -> Result<CallToolResult, McpError> {
    // A malformed scope is the caller's error, answered as such (not as an
    // internal error) before anything runs.
    for s in params.agent_scope.iter().flatten() {
        crate::errors::parse_uuid(s)?;
    }
    let response = sweep(session, &params, acting_agent)
        .await
        .map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}

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

use std::collections::HashMap;

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::SweepSemanticDuplicatesParams;

use epigraph_db::ClaimRepository;

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

#[derive(Debug, Serialize)]
struct ClusterOut {
    survivor: String,
    duplicates: Vec<String>,
    max_distance: f64,
    /// `true` when every member shares the survivor's content hash — an exact
    /// restatement set, safe to collapse with `mark_duplicate`. `false` means
    /// the members differ in wording, so collapsing would DISCARD text: those
    /// are surfaced as merge candidates for `consolidate_claims` instead.
    exact: bool,
}

#[derive(Debug, Serialize)]
struct SweepResponse {
    dry_run: bool,
    scanned: usize,
    /// Exact-restatement clusters — acted on when `dry_run=false`.
    clusters: Vec<ClusterOut>,
    /// Near-but-not-identical clusters. Never auto-collapsed: an agent should
    /// synthesize these through `consolidate_claims` so no wording is lost.
    merge_candidates: Vec<ClusterOut>,
    pairs_marked: u64,
    failures: Vec<String>,
    /// Offset to pass on the next call to continue the sweep.
    next_offset: i64,
}

pub async fn sweep_semantic_duplicates(
    server: &EpiGraphMcpFull,
    params: SweepSemanticDuplicatesParams,
) -> Result<CallToolResult, McpError> {
    let threshold = params.similarity_threshold.unwrap_or(0.10).clamp(0.0, 2.0);
    let limit = params.limit.unwrap_or(500).clamp(1, 2000);
    let offset = params.offset.unwrap_or(0).max(0);
    let dry_run = params.dry_run.unwrap_or(true);

    let agent_scope: Option<Vec<Uuid>> = match params.agent_scope.as_ref() {
        Some(v) => Some(
            v.iter()
                .map(|s| crate::errors::parse_uuid(s))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        None => None,
    };

    let candidates = ClaimRepository::enumerate_current_embedded(
        &server.pool,
        agent_scope.as_deref(),
        params.labels_scope.as_deref(),
        offset,
        limit,
    )
    .await
    .map_err(internal_error)?;

    // Pair discovery: per-claim ANN top-5, keeping pairs under the threshold.
    let mut uf = UnionFind::new();
    let mut meta: HashMap<Uuid, (f64, chrono::DateTime<chrono::Utc>)> = HashMap::new();
    let mut pair_distance: HashMap<(Uuid, Uuid), f64> = HashMap::new();

    for c in &candidates {
        meta.insert(c.id, (c.truth_value, c.created_at));
        let neighbors = ClaimRepository::nearest_neighbors_of_claim(&server.pool, c.id, 5)
            .await
            .map_err(internal_error)?;
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
    let hashes = ClaimRepository::content_hashes_for(&server.pool, &all_ids)
        .await
        .map_err(internal_error)?;

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
    // Each pair is its own transaction, so one edge collision cannot roll back
    // the whole sweep; failures are collected and returned, never fatal.
    let mut pairs_marked = 0_u64;
    let mut failures: Vec<String> = Vec::new();
    if !dry_run {
        for (survivor, duplicates, _) in &exact_clusters {
            for dup in duplicates {
                // Same retraction cascade as the single-shot `mark_duplicate`
                // tool (backlog 20e9ed83): collapsing a cluster orphans and
                // strands the duplicates' edge-factor BBAs exactly the same
                // way, so the sweep must repair belief too — a bulk path that
                // skipped it would reintroduce the defect at scale. Cascade
                // errors land in `failures` alongside the mark failures; they
                // do not undo an already-committed collapse, so `pairs_marked`
                // still counts the pair.
                match epigraph_engine::retraction_cascade::mark_duplicate_with_cascade(
                    &server.pool,
                    *dup,
                    *survivor,
                )
                .await
                {
                    Ok(cascade) => {
                        pairs_marked += 1;
                        for err in cascade.errors {
                            failures.push(format!("{dup} -> {survivor} (belief cascade): {err}"));
                        }
                    }
                    Err(e) => failures.push(format!("{dup} -> {survivor}: {e}")),
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

    let response = SweepResponse {
        dry_run,
        scanned: candidates.len(),
        clusters: to_out(exact_clusters, true),
        merge_candidates: to_out(near_clusters, false),
        pairs_marked,
        failures,
        next_offset: offset + candidates.len() as i64,
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}

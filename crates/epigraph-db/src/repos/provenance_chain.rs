//! Provenance-chain traversal (backlog 3216b086).
//!
//! Answers "what derivation supports this conclusion" in ONE call, replacing
//! the `recall` → `get_neighborhood` per node → `get_claim` per neighbour
//! round-trip loop agents use today.
//!
//! # Why the frontier is mixed-direction
//!
//! Ancestry does not live in a single edge direction in this schema, so a
//! uniformly-incoming walk is wrong:
//!
//! - `supports` / `corroborates` / `elaborates` are written evidence→claim,
//!   so an ancestor sits behind an **incoming** edge.
//! - `decomposes_to` is written parent→child (paragraph→atom), so a node's
//!   parent also sits behind an **incoming** edge.
//! - `supersedes` is written new→old by
//!   [`crate::repos::claim::ClaimRepository::supersede`], so a claim's
//!   predecessor sits behind an **outgoing** edge.
//!
//! Direction is therefore a property OF THE RELATIONSHIP, not a caller
//! parameter — exposing it as a knob would only let callers ask for
//! incoherent walks.

use std::collections::{HashMap, HashSet, VecDeque};

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// Relationships whose ancestor sits behind an INCOMING edge
/// (`ancestor -> node`).
pub const PROVENANCE_INCOMING: &[&str] =
    &["supports", "corroborates", "elaborates", "decomposes_to"];

/// Relationships whose ancestor sits behind an OUTGOING edge
/// (`node -> ancestor`). Currently only `supersedes`, which
/// `ClaimRepository::supersede` writes as new→old.
pub const PROVENANCE_OUTGOING: &[&str] = &["supersedes"];

/// Hard cap on returned nodes; beyond this the chain reports `truncated`.
pub const MAX_CHAIN_NODES: usize = 500;

/// A claim in a provenance chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenanceNode {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub labels: Vec<String>,
    pub is_current: bool,
    /// Fewest hops from the root at which this claim was reached.
    pub depth: i32,
}

/// A derivation edge, reported exactly as stored (NOT normalised), so callers
/// can distinguish `supersedes` from the evidence relationships.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProvenanceEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

/// Result of a provenance-chain traversal.
#[derive(Debug, Clone)]
pub struct ProvenanceChain {
    pub root: Uuid,
    /// Topologically ordered, evidence first and the conclusion last.
    pub nodes: Vec<ProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
    /// `true` when the node cap or depth bound cut the walk short.
    pub truncated: bool,
    /// Cycles found during traversal, each as the node path that closed the
    /// loop. Reported, never fatal — a cyclic graph is a data-quality signal
    /// the caller should see, not an error that hides the rest of the chain.
    pub cycles: Vec<Vec<Uuid>>,
}

pub struct ProvenanceChainRepository;

impl ProvenanceChainRepository {
    /// Walk the derivation graph backwards from `claim_id`.
    ///
    /// `max_depth` is clamped to `1..=8`. `relationships`, when supplied,
    /// filters the default traversal set (unknown names are ignored); `None`
    /// uses every relationship in [`PROVENANCE_INCOMING`] +
    /// [`PROVENANCE_OUTGOING`].
    ///
    /// Non-current ancestors are deliberately INCLUDED (flagged via
    /// [`ProvenanceNode::is_current`]) — derivation history legitimately runs
    /// through superseded claims, which is the entire point of the
    /// `supersedes` hop.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the traversal or hydration query
    /// fails.
    #[instrument(skip(pool, viewer))]
    pub async fn chain(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: u8,
        relationships: Option<&[String]>,
    ) -> Result<ProvenanceChain, DbError> {
        let depth = i32::from(max_depth.clamp(1, 8));

        let (incoming, outgoing) = match relationships {
            Some(filter) => {
                let want: HashSet<&str> = filter.iter().map(String::as_str).collect();
                (
                    PROVENANCE_INCOMING
                        .iter()
                        .filter(|r| want.contains(*r))
                        .map(|r| (*r).to_string())
                        .collect::<Vec<_>>(),
                    PROVENANCE_OUTGOING
                        .iter()
                        .filter(|r| want.contains(*r))
                        .map(|r| (*r).to_string())
                        .collect::<Vec<_>>(),
                )
            }
            None => (
                PROVENANCE_INCOMING
                    .iter()
                    .map(|r| (*r).to_string())
                    .collect(),
                PROVENANCE_OUTGOING
                    .iter()
                    .map(|r| (*r).to_string())
                    .collect(),
            ),
        };

        // The recursive term walks BOTH directions in one frontier (see module
        // docs). `is_cycle` rows are emitted so the caller can see the loop,
        // but are not expanded further — that is what makes this terminate.
        //
        // MACRO SITE — static three-bind spelling. The predicate lives on the
        // RECURSIVE term, which is the only place `edges` is read: an edge the
        // viewer cannot see must not extend the frontier, or the walk leaks the
        // shape of another tenant's graph one hop at a time. The hydration
        // query below filters `claims` the same way, so a node id that survived
        // the walk still yields no content unless the claim itself is visible.
        let rows = sqlx::query!(
            r#"
            WITH RECURSIVE chain AS (
                SELECT $1::uuid AS node,
                       0 AS depth,
                       ARRAY[$1::uuid] AS path,
                       false AS is_cycle,
                       NULL::uuid AS e_source,
                       NULL::uuid AS e_target,
                       NULL::varchar AS e_rel
                UNION ALL
                SELECT nxt.id,
                       c.depth + 1,
                       c.path || nxt.id,
                       nxt.id = ANY(c.path),
                       e.source_id,
                       e.target_id,
                       e.relationship
                FROM chain c
                JOIN edges e
                  ON e.source_type = 'claim'
                 AND e.target_type = 'claim'
                 AND ( (e.target_id = c.node AND e.relationship = ANY($2::text[]))
                    OR (e.source_id = c.node AND e.relationship = ANY($3::text[])) )
                CROSS JOIN LATERAL (
                    SELECT CASE WHEN e.target_id = c.node
                                THEN e.source_id ELSE e.target_id END AS id
                ) nxt
                WHERE c.depth < $4 AND NOT c.is_cycle
                  AND ($5::bool OR e.visibility = 'public'
                       OR (e.owner_group_id = ANY($6::uuid[])
                           AND (e.co_owner_group_id IS NULL
                                OR e.co_owner_group_id = ANY($6::uuid[]))))
            )
            SELECT node AS "node!", depth AS "depth!", is_cycle AS "is_cycle!",
                   path AS "path!", e_source, e_target, e_rel
            FROM chain
            LIMIT 20000
            "#,
            claim_id,
            &incoming[..],
            &outgoing[..],
            depth,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(pool)
        .await?;

        // Fewest-hops depth per node, the stored edge set, and any cycles.
        let mut min_depth: HashMap<Uuid, i32> = HashMap::new();
        let mut edges: HashSet<ProvenanceEdge> = HashSet::new();
        let mut cycles: Vec<Vec<Uuid>> = Vec::new();

        for r in &rows {
            if r.is_cycle {
                cycles.push(r.path.clone());
                continue;
            }
            min_depth
                .entry(r.node)
                .and_modify(|d| *d = (*d).min(r.depth))
                .or_insert(r.depth);
            if let (Some(s), Some(t), Some(rel)) = (r.e_source, r.e_target, r.e_rel.as_ref()) {
                edges.insert(ProvenanceEdge {
                    source: s,
                    target: t,
                    relationship: rel.clone(),
                });
            }
        }

        // Node cap. Keep the shallowest nodes: they are the ones closest to the
        // conclusion the caller actually asked about.
        let mut truncated = min_depth.len() > MAX_CHAIN_NODES;
        let mut kept: Vec<(Uuid, i32)> = min_depth.into_iter().collect();
        kept.sort_by_key(|(id, d)| (*d, *id));
        kept.truncate(MAX_CHAIN_NODES);
        let kept_ids: HashSet<Uuid> = kept.iter().map(|(id, _)| *id).collect();
        edges.retain(|e| kept_ids.contains(&e.source) && kept_ids.contains(&e.target));

        // A walk stopped by the depth bound is also a partial answer.
        if rows.iter().any(|r| r.depth >= depth && !r.is_cycle) {
            truncated = true;
        }

        let ids: Vec<Uuid> = kept.iter().map(|(id, _)| *id).collect();
        let hydrated = sqlx::query!(
            r#"
            SELECT id, content, truth_value, labels, is_current
            FROM claims
            WHERE id = ANY($1)
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            "#,
            &ids[..],
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(pool)
        .await?;

        let depth_of: HashMap<Uuid, i32> = kept.iter().copied().collect();
        let nodes: Vec<ProvenanceNode> = hydrated
            .into_iter()
            .map(|r| ProvenanceNode {
                id: r.id,
                content: r.content,
                truth_value: r.truth_value,
                labels: r.labels,
                is_current: r.is_current,
                depth: depth_of.get(&r.id).copied().unwrap_or(0),
            })
            .collect();

        let nodes = topo_sort(nodes, &edges);

        Ok(ProvenanceChain {
            root: claim_id,
            nodes,
            edges: edges.into_iter().collect(),
            truncated,
            cycles,
        })
    }
}

/// Kahn topological sort, evidence first.
///
/// Depth is NOT a valid ordering key on its own: a node reachable at several
/// depths would sort by whichever path found it first. Ordering runs over the
/// edge set instead.
///
/// Edges are normalised to ancestor→descendant before sorting. `supersedes`
/// is stored new→old, i.e. descendant→ancestor, so it is FLIPPED here; the
/// evidence relationships already point ancestor→descendant.
///
/// Any nodes left over (a cycle the emit-but-don't-expand guard let through)
/// are appended in depth order rather than dropped — a partial order beats
/// losing rows.
fn topo_sort(nodes: Vec<ProvenanceNode>, edges: &HashSet<ProvenanceEdge>) -> Vec<ProvenanceNode> {
    let by_id: HashMap<Uuid, ProvenanceNode> = nodes.iter().cloned().map(|n| (n.id, n)).collect();

    let mut adjacency: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    let mut in_degree: HashMap<Uuid, usize> = by_id.keys().map(|id| (*id, 0)).collect();

    for e in edges {
        let (ancestor, descendant) = if PROVENANCE_OUTGOING.contains(&e.relationship.as_str()) {
            (e.target, e.source)
        } else {
            (e.source, e.target)
        };
        if !by_id.contains_key(&ancestor) || !by_id.contains_key(&descendant) {
            continue;
        }
        adjacency.entry(ancestor).or_default().push(descendant);
        *in_degree.entry(descendant).or_insert(0) += 1;
    }

    // Deterministic tie-breaking: deepest-first, then by id, so equal-rank
    // evidence comes out in a stable order across runs.
    let mut ready: Vec<Uuid> = in_degree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| *id)
        .collect();
    ready.sort_by_key(|id| (by_id.get(id).map(|n| -n.depth).unwrap_or(0), *id));
    let mut queue: VecDeque<Uuid> = ready.into();

    let mut ordered: Vec<ProvenanceNode> = Vec::with_capacity(by_id.len());
    let mut emitted: HashSet<Uuid> = HashSet::new();

    while let Some(id) = queue.pop_front() {
        if !emitted.insert(id) {
            continue;
        }
        if let Some(n) = by_id.get(&id) {
            ordered.push(n.clone());
        }
        let mut next: Vec<Uuid> = Vec::new();
        for child in adjacency.get(&id).cloned().unwrap_or_default() {
            let d = in_degree.entry(child).or_insert(0);
            *d = d.saturating_sub(1);
            if *d == 0 {
                next.push(child);
            }
        }
        next.sort_by_key(|cid| (by_id.get(cid).map(|n| -n.depth).unwrap_or(0), *cid));
        for c in next {
            queue.push_back(c);
        }
    }

    // Cycle remnants: keep them, deepest first.
    let mut leftovers: Vec<ProvenanceNode> = by_id
        .values()
        .filter(|n| !emitted.contains(&n.id))
        .cloned()
        .collect();
    leftovers.sort_by_key(|n| (-n.depth, n.id));
    ordered.extend(leftovers);

    ordered
}

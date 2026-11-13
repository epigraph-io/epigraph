//! The node set of one Atlas leaf group (Atlas W3, backlog bd6f0a02): the
//! group's claims, the agents that asserted or authored them, the evidence
//! attached to them, and the edges among those nodes, capped at
//! [`ATLAS_LEAF_NODE_CAP`] nodes. It is the input to the leaf layout (W6) and
//! the flow weights (W7); the level document W10 serves is assembled from it.
//!
//! # Two halves
//!
//! * **The read**, [`AtlasLeafRepository::read_leaf_rows`]: every row the MAP
//!   may draw around a candidate leaf's claims, as [`LeafRows`]. Five
//!   set-based statements, whatever the leaf's size.
//! * **The assembly**, pure and testable without a database:
//!   [`assemble_leaf`] turns [`LeafRows`] into a [`LeafOutcome`]: the node set
//!   when it fits the cap, a typed [`NeedsSplit`] when it does not.
//!   [`fallback_split`] is a deterministic split the hierarchy builders (W4 "by
//!   meaning", W5 "by links") may call; they replace it with their own
//!   clustering. [`resolve_with_fallback`] assembles a leaf and, when it is over
//!   the cap, each fallback part.
//!
//! # Scope: only what the map may draw
//!
//! A map's readable set (migration 210, section 1) is, for team T's map, the
//! rows `('group', T)` plus every public row; for the public map, the public
//! rows. The nightly reads on the maintenance connection with a bypass viewer,
//! where the viewer splice renders nothing and row security filters nothing, so
//! every statement carries an explicit MAP predicate:
//!
//! * claims and evidence: `visibility = 'public' OR (visibility = 'group' AND
//!   owner_group_id = T)`;
//! * edges: `visibility = 'public' OR (visibility = 'group' AND
//!   owner_group_id = T AND co_owner_group_id IS NULL)`. A map draws an edge
//!   only when its whole audience may read the edge row. Row security (077's
//!   `edges_tenancy`, after 072) lets a session read an edge co-owned by two
//!   teams only when it is in BOTH, so a member of T alone cannot read it and
//!   a co-owned edge is never baked into a single-team map, neither the
//!   owner's nor the co-owner's. A view for a viewer in both teams is future
//!   work. Migration 210 already treats "the edge gained a co-owner" as the
//!   edge leaving the owner's map;
//! * the public map binds T as NULL, so only public rows pass.
//!
//! The edge predicate is the MAP rule, not
//! [`crate::visibility::Viewer::edge_predicate_fragment`]: that admits a
//! co-owned edge for a session in both teams, the map rule never does. Every
//! later Atlas read that draws edges on a team map (the outgoing links, the
//! "by links" hierarchy) must use the same map rule, or an edge hidden from a
//! leaf would reappear between leaves.
//!
//! Every statement is ALSO spliced on the viewer, so a scoped caller is
//! filtered by its own session as well. The map predicate still decides then:
//! a viewer in teams A and B passes B's rows through the splice, and the map
//! predicate removes them from A's map.
//!
//! A node reached only through a row the map cannot read never appears: an
//! agent whose only authorship edge is another team's, an evidence row of
//! another team, an edge owned by another team or co-owned at all, a claim of
//! another team named in the input (counted in
//! [`LeafCounts::unreadable_claims`]).
//! `agents` has no tenancy (077's `agents_identity` is `USING (true)`); the
//! read only drops agent ids that name no agent row, since `edges` has no
//! foreign key.
//!
//! Call [`AtlasLeafRepository::read_leaf_rows`] on the build's transaction,
//! after [`crate::AtlasMapRepository::begin_build_snapshot`], so the rows come
//! from the snapshot whose epochs the run records.
//!
//! # Who joins a leaf
//!
//! * a claim: the candidate ids the builder passes, if the map may draw them
//!   (the builder decides which claims are current);
//! * an agent: the claim's filer (`claims.agent_id`), or the credited end of a
//!   drawable authorship edge to or from the claim
//!   ([`crate::repos::claim_ingest::credited_agent_end`]);
//! * evidence: a drawable evidence row that a drawable STORED edge links to the
//!   claim, in either direction, under the relationship name stored on it
//!   (`supports` and `SUPPORTS` both occur). An evidence row whose only link to
//!   the leaf is its `claim_id` is NOT a node, since the W10a contract requires
//!   every evidence node to have an edge to a claim and no edge is derived for
//!   evidence. It is counted in [`LeafCounts::unlinked_evidence`] until the
//!   evidence-edge backfill (backlog 2d60f619) gives it a stored edge.
//!
//! Every drawable stored edge whose two endpoints (kind and id) are both nodes
//! of the leaf is an edge of the leaf. Edges to claims outside the leaf belong
//! to the outgoing-links stage, not here.
//!
//! # The cap
//!
//! The node count is claims + distinct agents + distinct evidence: an agent or
//! evidence row shared by many claims is ONE node. Before counting, a claim
//! whose own agents and evidence do not fit beside it keeps a deterministic
//! prefix of them ([`CappedClaim`]: its filer, its other agents by id, then
//! its evidence by id). That cut is what makes every split terminate: every
//! claim alone fits, so a part of one claim always fits.
//!
//! # Edges, and the W10a contract
//!
//! Node kinds and relationship names follow the Atlas level contract (W10a,
//! schema v1): kinds `claim`, `agent`, `evidence`; the stored relationship name,
//! unnormalised. Stored edges repeating one (source, target, relationship)
//! collapse into one [`LeafEdge`] carrying every stored edge id, so W7 can take
//! the largest weight among them. The contract wants every agent and evidence
//! node to have an edge to a claim of the leaf. Evidence has one by
//! construction (it joins only through a stored edge). A filer with no stored
//! authorship edge to its claim gets the one DERIVED edge ([`LeafEdgeOrigin`]):
//! `agent -asserts-> claim` ([`DERIVED_FILER_RELATIONSHIP`]) from
//! `claims.agent_id`.
//!
//! Three contract rules this node set does NOT yet enforce; W7/W10, which
//! assemble the served level document, must:
//!
//! * **direction**: a [`LeafEdge`] points the way its stored row points; the
//!   contract's edge points the way belief flows, so a stored `claim ->
//!   evidence` row must be re-oriented before its `exact` basis applies;
//! * **relationship spelling**: the contract requires `^[A-Za-z][A-Za-z0-9_]*$`
//!   and at most 32 characters, while `edges.relationship` is `varchar(100)`
//!   with only a non-empty check; the name is passed through unchecked, so a
//!   name outside the pattern must be dropped or mapped before validation;
//! * **edge limit**: the contract allows at most 1,024 edges per leaf.
//!   [`LeafCounts::edges`] reports the count; nothing here splits on it.
//!
//! # Determinism
//!
//! Every output is built from ordered collections, so it depends on the SET of
//! input ids and the rows, never on input order or SQL row order.
//!
//! No belief column is read here: belief and flow weights are W7's and W10's,
//! behind the role-aware belief reads.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::atlas_map::AtlasMap;
use crate::repos::claim_ingest::{credited_agent_end, CreditedEnd};
use crate::visibility::Viewer;

/// The design's cap: at most 100 nodes (claims, agents and evidence counted
/// together) in one leaf.
pub const ATLAS_LEAF_NODE_CAP: usize = 100;

/// The relationship of a derived filer edge (`agent -> claim` from
/// `claims.agent_id`): the stored spelling of the same fact.
pub const DERIVED_FILER_RELATIONSHIP: &str = "asserts";

/// A node kind, spelled as the W10a contract and `edges.source_type` spell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafNodeKind {
    Claim,
    Agent,
    Evidence,
}

impl LeafNodeKind {
    /// The stored and served spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Agent => "agent",
            Self::Evidence => "evidence",
        }
    }

    /// The kind an `edges.source_type` / `target_type` names, if a leaf can
    /// hold it.
    #[must_use]
    pub fn from_stored(s: &str) -> Option<Self> {
        match s {
            "claim" => Some(Self::Claim),
            "agent" => Some(Self::Agent),
            "evidence" => Some(Self::Evidence),
            _ => None,
        }
    }
}

/// One node of a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafNode {
    pub kind: LeafNodeKind,
    pub id: Uuid,
}

impl LeafNode {
    #[must_use]
    pub const fn claim(id: Uuid) -> Self {
        Self {
            kind: LeafNodeKind::Claim,
            id,
        }
    }

    #[must_use]
    pub const fn agent(id: Uuid) -> Self {
        Self {
            kind: LeafNodeKind::Agent,
            id,
        }
    }

    #[must_use]
    pub const fn evidence(id: Uuid) -> Self {
        Self {
            kind: LeafNodeKind::Evidence,
            id,
        }
    }
}

/// One drawable stored edge between two nodes a leaf could hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLeafEdge {
    pub id: Uuid,
    pub source: LeafNode,
    pub target: LeafNode,
    /// As stored.
    pub relationship: String,
}

/// Everything the map may draw around a candidate leaf, read once. The input
/// of [`assemble_leaf`] and [`fallback_split`]; built by
/// [`AtlasLeafRepository::read_leaf_rows`], or by hand in a test.
///
/// Rows outside the map's readable set are never in it. Edges whose endpoint
/// is not in `claims`, `agents` or `evidence` are ignored by the assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafRows {
    /// The candidate ids as requested, deduplicated.
    pub requested: BTreeSet<Uuid>,
    /// The candidate claims the map may draw, each with its filer
    /// (`claims.agent_id`), `None` when that id names no agent row.
    pub claims: BTreeMap<Uuid, Option<Uuid>>,
    /// Drawable evidence rows reached from the claims, by `claim_id` or
    /// through an edge, each with its `claim_id` when that claim is one of
    /// `claims`, `None` otherwise (an evidence row reached only through an
    /// edge, whose own claim the map cannot draw or the leaf does not hold).
    /// Only a row a stored edge links to a claim of the leaf becomes a node;
    /// the others are counted ([`LeafCounts::unlinked_evidence`]). The id of
    /// a claim outside `claims` is never carried here, so a builder that logs
    /// or stores these rows cannot leak another team's claim id.
    pub evidence: BTreeMap<Uuid, Option<Uuid>>,
    /// Agent rows reached from the claims (filers and edge endpoints).
    pub agents: BTreeSet<Uuid>,
    /// Drawable stored edges among those claims, agents and evidence rows.
    pub edges: Vec<StoredLeafEdge>,
}

/// How a [`LeafEdge`] came to be.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafEdgeOrigin {
    /// One or more stored edges with this (source, target, relationship),
    /// their ids sorted.
    Stored { edge_ids: Vec<Uuid> },
    /// Derived from `claims.agent_id`: the filer, with no stored authorship
    /// edge between it and the claim.
    Filer,
}

impl LeafEdgeOrigin {
    /// `true` for an edge no stored row backs.
    #[must_use]
    pub const fn is_derived(&self) -> bool {
        !matches!(self, Self::Stored { .. })
    }
}

/// One edge of a leaf, pointing the way the stored row points.
///
/// NOT yet the W10a contract's direction: the contract's `edge` points "the
/// way belief flows" (evidence to claim for its `exact` basis), and a stored
/// `claim -> evidence` row is emitted here as claim to evidence. W7 (flow
/// weights) or W10 (the level document) re-orients; see the module
/// documentation's contract gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafEdge {
    pub source: LeafNode,
    pub target: LeafNode,
    pub relationship: String,
    pub origin: LeafEdgeOrigin,
}

/// A claim whose own agents and evidence did not fit beside it: the prefix it
/// kept, and what it had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CappedClaim {
    pub claim: Uuid,
    pub kept_agents: usize,
    pub kept_evidence: usize,
    pub total_agents: usize,
    /// The evidence a stored edge links to the claim; a row attached by
    /// `claim_id` alone is not counted here ([`LeafCounts::unlinked_evidence`]).
    pub total_evidence: usize,
}

/// The counts of one assembled leaf (or of one over the cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeafCounts {
    pub claims: usize,
    pub agents: usize,
    pub evidence: usize,
    /// `claims + agents + evidence`.
    pub nodes: usize,
    /// Collapsed edges among the nodes, derived filer edges included.
    pub edges: usize,
    pub cap: usize,
    /// Requested ids the map may not draw.
    ///
    /// BUILDER-INTERNAL: never serve it, log it or store it in a run row. On a
    /// team map it counts the other teams' claims a candidate leaf named,
    /// which is itself a fact about rows this map's readers cannot see.
    pub unreadable_claims: usize,
    /// Claims whose attachments were cut ([`CappedClaim`]).
    pub capped_claims: usize,
    /// Drawable evidence rows attached by `claim_id` to a claim of the leaf
    /// that no stored edge links to any claim of the leaf, so they are not
    /// nodes. A row the per-claim cap cut is in [`Self::capped_claims`], not
    /// here.
    ///
    /// BUILDER-INTERNAL: not part of the served level document (the W10a
    /// contract has no field for it). It counts only rows this map may draw,
    /// so a build log or run metric may carry it; it measures what the
    /// evidence-edge backfill (backlog 2d60f619) still has to link.
    pub unlinked_evidence: usize,
}

/// A leaf that fits: its nodes and edges, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNodeSet {
    /// Sorted by kind (claims, agents, evidence), then id.
    pub nodes: Vec<LeafNode>,
    /// Sorted by (source, target, relationship).
    pub edges: Vec<LeafEdge>,
    /// Sorted by claim id.
    pub capped: Vec<CappedClaim>,
    pub counts: LeafCounts,
}

impl LeafNodeSet {
    /// The leaf's claim ids, sorted.
    #[must_use]
    pub fn claim_ids(&self) -> Vec<Uuid> {
        self.nodes
            .iter()
            .filter(|n| n.kind == LeafNodeKind::Claim)
            .map(|n| n.id)
            .collect()
    }
}

/// Why a leaf must split one level further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitReason {
    /// Claims + agents + evidence exceed the cap.
    NodeCap,
}

/// The split request: the leaf is over the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedsSplit {
    pub reason: SplitReason,
    pub counts: LeafCounts,
}

/// What [`assemble_leaf`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafOutcome {
    /// The node set, at most `cap` nodes.
    Fits(LeafNodeSet),
    /// Over the cap: split one level further (W4/W5's clustering, or
    /// [`fallback_split`]).
    NeedsSplit(NeedsSplit),
    /// No requested claim is drawable on this map: no leaf (the W10a contract
    /// requires at least one node). `unreadable_claims` requested ids were
    /// dropped; builder-internal, as [`LeafCounts::unreadable_claims`].
    Empty { unreadable_claims: usize },
}

// ── the pure assembly ───────────────────────────────────────────────────────

/// Each drawable claim's attachments, before any cap.
struct LeafIndex<'r> {
    rows: &'r LeafRows,
    /// claim -> its agents: the filer first, then the others by id.
    agents_of: BTreeMap<Uuid, Vec<Uuid>>,
    /// claim -> the evidence a stored edge links to it, by id.
    evidence_of: BTreeMap<Uuid, Vec<Uuid>>,
    /// claim -> the evidence whose `claim_id` it is, by id (not nodes by
    /// themselves; [`LeafCounts::unlinked_evidence`]).
    by_claim_id: BTreeMap<Uuid, Vec<Uuid>>,
    /// Unordered (agent, claim) pairs a stored authorship edge already links.
    authorship_pairs: BTreeSet<(Uuid, Uuid)>,
}

impl<'r> LeafIndex<'r> {
    fn new(rows: &'r LeafRows) -> Self {
        let mut agents: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
        let mut evidence: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
        let mut authorship_pairs = BTreeSet::new();

        let mut by_claim_id: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for (&ev, &claim) in &rows.evidence {
            let Some(claim) = claim else { continue };
            if rows.claims.contains_key(&claim) {
                by_claim_id.entry(claim).or_default().push(ev);
            }
        }
        for e in &rows.edges {
            if !Self::endpoint_known(rows, e.source) || !Self::endpoint_known(rows, e.target) {
                continue;
            }
            match (e.source.kind, e.target.kind) {
                (LeafNodeKind::Agent, LeafNodeKind::Claim)
                | (LeafNodeKind::Claim, LeafNodeKind::Agent) => {
                    let credited = credited_agent_end(
                        e.source.kind.as_str(),
                        e.target.kind.as_str(),
                        &e.relationship,
                    );
                    let pair = match (credited, e.source.kind) {
                        (Some(CreditedEnd::Source), LeafNodeKind::Agent) => {
                            Some((e.source.id, e.target.id))
                        }
                        (Some(CreditedEnd::Target), LeafNodeKind::Claim) => {
                            Some((e.target.id, e.source.id))
                        }
                        _ => None,
                    };
                    if let Some((agent, claim)) = pair {
                        agents.entry(claim).or_default().insert(agent);
                        authorship_pairs.insert((agent, claim));
                    }
                }
                (LeafNodeKind::Evidence, LeafNodeKind::Claim) => {
                    evidence.entry(e.target.id).or_default().insert(e.source.id);
                }
                (LeafNodeKind::Claim, LeafNodeKind::Evidence) => {
                    evidence.entry(e.source.id).or_default().insert(e.target.id);
                }
                _ => {}
            }
        }

        let mut agents_of = BTreeMap::new();
        for (&claim, &filer) in &rows.claims {
            let mut list: Vec<Uuid> = Vec::new();
            if let Some(f) = filer {
                list.push(f);
            }
            if let Some(others) = agents.get(&claim) {
                list.extend(others.iter().copied().filter(|a| Some(*a) != filer));
            }
            agents_of.insert(claim, list);
        }
        let evidence_of = evidence
            .into_iter()
            .map(|(c, s)| (c, s.into_iter().collect()))
            .collect();

        Self {
            rows,
            agents_of,
            evidence_of,
            by_claim_id,
            authorship_pairs,
        }
    }

    /// Whether `n` is a row the leaf may hold at all.
    fn endpoint_known(rows: &LeafRows, n: LeafNode) -> bool {
        match n.kind {
            LeafNodeKind::Claim => rows.claims.contains_key(&n.id),
            LeafNodeKind::Agent => rows.agents.contains(&n.id),
            LeafNodeKind::Evidence => rows.evidence.contains_key(&n.id),
        }
    }

    /// `claim` and its attachments after the per-claim cap, and the cut when
    /// there was one. At most `cap` nodes.
    fn claim_nodes(&self, claim: Uuid, cap: usize) -> (Vec<LeafNode>, Option<CappedClaim>) {
        let agents = self.agents_of.get(&claim).map_or(&[][..], Vec::as_slice);
        let evidence = self.evidence_of.get(&claim).map_or(&[][..], Vec::as_slice);
        let room = cap - 1;
        let (kept_agents, kept_evidence) = if agents.len() + evidence.len() > room {
            let ka = agents.len().min(room);
            (ka, room - ka)
        } else {
            (agents.len(), evidence.len())
        };
        let mut nodes = Vec::with_capacity(1 + kept_agents + kept_evidence);
        nodes.push(LeafNode::claim(claim));
        nodes.extend(agents[..kept_agents].iter().map(|&a| LeafNode::agent(a)));
        nodes.extend(
            evidence[..kept_evidence]
                .iter()
                .map(|&e| LeafNode::evidence(e)),
        );
        let cut =
            (kept_agents < agents.len() || kept_evidence < evidence.len()).then_some(CappedClaim {
                claim,
                kept_agents,
                kept_evidence,
                total_agents: agents.len(),
                total_evidence: evidence.len(),
            });
        (nodes, cut)
    }

    /// The edges among `nodes`: stored edges collapsed by (source, target,
    /// relationship), then the derived filer edges no stored authorship edge
    /// already shows.
    fn edges_among(&self, nodes: &BTreeSet<LeafNode>) -> Vec<LeafEdge> {
        let mut out: BTreeMap<(LeafNode, LeafNode, String), LeafEdgeOrigin> = BTreeMap::new();
        for e in &self.rows.edges {
            if !nodes.contains(&e.source) || !nodes.contains(&e.target) {
                continue;
            }
            let origin = out
                .entry((e.source, e.target, e.relationship.clone()))
                .or_insert_with(|| LeafEdgeOrigin::Stored {
                    edge_ids: Vec::new(),
                });
            if let LeafEdgeOrigin::Stored { edge_ids } = origin {
                edge_ids.push(e.id);
            }
        }
        for origin in out.values_mut() {
            if let LeafEdgeOrigin::Stored { edge_ids } = origin {
                edge_ids.sort_unstable();
                edge_ids.dedup();
            }
        }
        for n in nodes.iter().filter(|n| n.kind == LeafNodeKind::Claim) {
            if let Some(Some(filer)) = self.rows.claims.get(&n.id) {
                let agent = LeafNode::agent(*filer);
                if nodes.contains(&agent) && !self.authorship_pairs.contains(&(*filer, n.id)) {
                    out.entry((agent, *n, DERIVED_FILER_RELATIONSHIP.to_string()))
                        .or_insert(LeafEdgeOrigin::Filer);
                }
            }
        }
        out.into_iter()
            .map(|((source, target, relationship), origin)| LeafEdge {
                source,
                target,
                relationship,
                origin,
            })
            .collect()
    }

    /// The drawable claims of `part`, sorted and deduplicated, and how many
    /// distinct requested ids were not drawable.
    fn drawable(&self, part: &[Uuid]) -> (BTreeSet<Uuid>, usize) {
        let asked: BTreeSet<Uuid> = part.iter().copied().collect();
        let drawable: BTreeSet<Uuid> = asked
            .iter()
            .copied()
            .filter(|c| self.rows.claims.contains_key(c))
            .collect();
        let unreadable = asked.len() - drawable.len();
        (drawable, unreadable)
    }

    /// The evidence attached by `claim_id` to one of `claims` that no stored
    /// edge links to any of them.
    fn unlinked_evidence(&self, claims: &BTreeSet<Uuid>) -> usize {
        let linked: BTreeSet<Uuid> = claims
            .iter()
            .filter_map(|c| self.evidence_of.get(c))
            .flatten()
            .copied()
            .collect();
        claims
            .iter()
            .filter_map(|c| self.by_claim_id.get(c))
            .flatten()
            .filter(|ev| !linked.contains(ev))
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn assemble(&self, part: &[Uuid], cap: usize) -> LeafOutcome {
        let (claims, unreadable_claims) = self.drawable(part);
        if claims.is_empty() {
            return LeafOutcome::Empty { unreadable_claims };
        }
        let mut nodes: BTreeSet<LeafNode> = BTreeSet::new();
        let mut capped = Vec::new();
        for &c in &claims {
            let (claim_nodes, cut) = self.claim_nodes(c, cap);
            nodes.extend(claim_nodes);
            capped.extend(cut);
        }
        let count = |k: LeafNodeKind| nodes.iter().filter(|n| n.kind == k).count();
        let edges = self.edges_among(&nodes);
        let counts = LeafCounts {
            claims: count(LeafNodeKind::Claim),
            agents: count(LeafNodeKind::Agent),
            evidence: count(LeafNodeKind::Evidence),
            nodes: nodes.len(),
            edges: edges.len(),
            cap,
            unreadable_claims,
            capped_claims: capped.len(),
            unlinked_evidence: self.unlinked_evidence(&claims),
        };
        if nodes.len() > cap {
            return LeafOutcome::NeedsSplit(NeedsSplit {
                reason: SplitReason::NodeCap,
                counts,
            });
        }
        LeafOutcome::Fits(LeafNodeSet {
            nodes: nodes.into_iter().collect(),
            edges,
            capped,
            counts,
        })
    }

    fn split(&self, part: &[Uuid], cap: usize) -> Vec<Vec<Uuid>> {
        let (claims, _) = self.drawable(part);
        let mut parts = Vec::new();
        let mut current: Vec<Uuid> = Vec::new();
        let mut current_nodes: BTreeSet<LeafNode> = BTreeSet::new();
        for c in claims {
            let (claim_nodes, _) = self.claim_nodes(c, cap);
            let added = claim_nodes
                .iter()
                .filter(|n| !current_nodes.contains(n))
                .count();
            if !current.is_empty() && current_nodes.len() + added > cap {
                parts.push(std::mem::take(&mut current));
                current_nodes.clear();
            }
            current.push(c);
            current_nodes.extend(claim_nodes);
        }
        if !current.is_empty() {
            parts.push(current);
        }
        parts
    }
}

fn check_cap(cap: usize) -> Result<(), DbError> {
    if cap == 0 {
        return Err(DbError::InvalidData {
            reason: "an Atlas leaf cap must be at least 1 node".to_string(),
        });
    }
    Ok(())
}

/// Assemble the leaf made of the claims `part` names (any order, duplicates
/// allowed; ids `rows` does not hold as drawable are counted unreadable and
/// dropped).
///
/// # Errors
/// `DbError::InvalidData` for a cap of 0.
pub fn assemble_leaf(rows: &LeafRows, part: &[Uuid], cap: usize) -> Result<LeafOutcome, DbError> {
    check_cap(cap)?;
    Ok(LeafIndex::new(rows).assemble(part, cap))
}

/// The fallback split: the drawable claims of `part` in id order, cut into
/// consecutive parts, each claim with its (capped) agents and evidence, a new
/// part started when the next claim would take the current one over `cap`.
/// Every part assembles to [`LeafOutcome::Fits`]; a node shared by claims in
/// two parts is in both. A leaf that already fits comes back as one part.
///
/// A stable partition by id, not a clustering: W4 and W5 replace it with their
/// own and keep it only as the last resort.
///
/// # Errors
/// `DbError::InvalidData` for a cap of 0.
pub fn fallback_split(
    rows: &LeafRows,
    part: &[Uuid],
    cap: usize,
) -> Result<Vec<Vec<Uuid>>, DbError> {
    check_cap(cap)?;
    Ok(LeafIndex::new(rows).split(part, cap))
}

/// [`assemble_leaf`], and when the leaf is over the cap, every
/// [`fallback_split`] part assembled: the leaves of `part`, each within `cap`.
/// Empty when no claim of `part` is drawable.
///
/// # Errors
/// `DbError::InvalidData` for a cap of 0, or if a fallback part does not fit
/// (which the per-claim cap rules out).
pub fn resolve_with_fallback(
    rows: &LeafRows,
    part: &[Uuid],
    cap: usize,
) -> Result<Vec<LeafNodeSet>, DbError> {
    check_cap(cap)?;
    let index = LeafIndex::new(rows);
    match index.assemble(part, cap) {
        LeafOutcome::Fits(set) => Ok(vec![set]),
        LeafOutcome::Empty { .. } => Ok(Vec::new()),
        LeafOutcome::NeedsSplit(_) => index
            .split(part, cap)
            .iter()
            .map(|p| match index.assemble(p, cap) {
                LeafOutcome::Fits(set) => Ok(set),
                other => Err(DbError::InvalidData {
                    reason: format!("an Atlas fallback part did not fit its cap: {other:?}"),
                }),
            })
            .collect(),
    }
}

// ── the read ────────────────────────────────────────────────────────────────

/// The read half of the leaf node sets. See the module documentation.
pub struct AtlasLeafRepository;

/// One `edges` row as the read selects it.
type EdgeRow = (Uuid, String, Uuid, String, Uuid, String);

impl AtlasLeafRepository {
    /// Every row `map` may draw around the candidate claims `claim_ids`, as
    /// [`LeafRows`], read on `conn` (the build's snapshot transaction) and
    /// spliced on `viewer`. Five set-based statements:
    /// 1. the drawable candidate claims and their filers;
    /// 2. the drawable edges touching them whose other end is a claim, an
    ///    agent or an evidence row;
    /// 3. the drawable evidence rows at the end of those edges, or attached
    ///    to those claims by `claim_id` (counted, not drawn, unless an edge
    ///    links them);
    /// 4. the agent rows at the end of those edges (no tenancy; drops ids that
    ///    name no agent);
    /// 5. the drawable edges among those agents and the evidence rows of 3
    ///    an edge reached.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a statement fails.
    pub async fn read_leaf_rows(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        claim_ids: &[Uuid],
    ) -> Result<LeafRows, DbError> {
        let team = map_team(map);
        let requested: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
        let asked: Vec<Uuid> = requested.iter().copied().collect();

        // 1. Claims. The filer through a LEFT JOIN, so an id that names no
        //    agent row is no node. `agents` carries no tenancy.
        let sql = viewer.splice(
            "SELECT c.id, a.id \
               FROM claims c \
               LEFT JOIN agents a ON a.id = c.agent_id \
              WHERE c.id = ANY($1) \
                AND (c.visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND c.visibility = 'group' \
                         AND c.owner_group_id = $2)) \
                /* {VISIBILITY:c} */",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(&sql)
            .bind(&asked)
            .bind(team);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let claims: BTreeMap<Uuid, Option<Uuid>> =
            q.fetch_all(&mut *conn).await?.into_iter().collect();
        let mut agents: BTreeSet<Uuid> = claims.values().flatten().copied().collect();
        let claim_list: Vec<Uuid> = claims.keys().copied().collect();
        if claim_list.is_empty() {
            return Ok(LeafRows {
                requested,
                ..LeafRows::default()
            });
        }

        // 2. Edges touching the claims. A co-owned edge is never drawn on a
        //    team map (module documentation).
        let sql = viewer.splice(
            "SELECT e.id, e.source_type::text, e.source_id, e.target_type::text, e.target_id, \
                    e.relationship::text \
               FROM edges e \
              WHERE ((e.source_type = 'claim' AND e.source_id = ANY($1)) \
                     OR (e.target_type = 'claim' AND e.target_id = ANY($1))) \
                AND e.source_type IN ('claim', 'agent', 'evidence') \
                AND e.target_type IN ('claim', 'agent', 'evidence') \
                AND (e.valid_to IS NULL OR e.valid_to > now()) \
                AND (e.visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND e.visibility = 'group' \
                         AND e.owner_group_id = $2 AND e.co_owner_group_id IS NULL)) \
                /* {EDGE_VISIBILITY:e} */",
            3,
        );
        let mut q = sqlx::query_as::<_, EdgeRow>(&sql)
            .bind(&claim_list)
            .bind(team);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let touching = q.fetch_all(&mut *conn).await?;

        let mut edge_agents: BTreeSet<Uuid> = BTreeSet::new();
        let mut edge_evidence: BTreeSet<Uuid> = BTreeSet::new();
        for (_, st, sid, tt, tid, _) in &touching {
            for (t, id) in [(st.as_str(), *sid), (tt.as_str(), *tid)] {
                match t {
                    "agent" if !agents.contains(&id) => {
                        edge_agents.insert(id);
                    }
                    "evidence" => {
                        edge_evidence.insert(id);
                    }
                    _ => {}
                }
            }
        }

        // 3. Evidence: at the end of an edge (a node), or attached by
        //    claim_id (counted when no stored edge links it).
        let sql = viewer.splice(
            "SELECT ev.id, ev.claim_id \
               FROM evidence ev \
              WHERE (ev.claim_id = ANY($1) OR ev.id = ANY($2)) \
                AND (ev.visibility = 'public' \
                     OR ($3::uuid IS NOT NULL AND ev.visibility = 'group' \
                         AND ev.owner_group_id = $3)) \
                /* {VISIBILITY:ev} */",
            4,
        );
        let edge_evidence_ids: Vec<Uuid> = edge_evidence.iter().copied().collect();
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql)
            .bind(&claim_list)
            .bind(&edge_evidence_ids)
            .bind(team);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        // A claim_id outside the drawable candidate claims is dropped here
        // (`LeafRows::evidence`): it may name another team's claim.
        let evidence: BTreeMap<Uuid, Option<Uuid>> = q
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|(ev, claim): (Uuid, Uuid)| (ev, claims.contains_key(&claim).then_some(claim)))
            .collect();

        // 4. Agents at the end of an edge: `agents` is readable by every
        //    session (077's agents_identity), so this only drops dangling ids.
        if !edge_agents.is_empty() {
            let ids: Vec<Uuid> = edge_agents.into_iter().collect();
            let found: Vec<Uuid> =
                sqlx::query_scalar("SELECT a.id FROM agents a WHERE a.id = ANY($1)")
                    .bind(&ids)
                    .fetch_all(&mut *conn)
                    .await?;
            agents.extend(found);
        }

        // 5. Edges among the agents and the evidence rows an edge reached
        //    (the only evidence that can be a node).
        let others: Vec<Uuid> = agents
            .iter()
            .chain(evidence.keys().filter(|ev| edge_evidence.contains(ev)))
            .copied()
            .collect();
        let sql = viewer.splice(
            "SELECT e.id, e.source_type::text, e.source_id, e.target_type::text, e.target_id, \
                    e.relationship::text \
               FROM edges e \
              WHERE e.source_id = ANY($1) AND e.target_id = ANY($1) \
                AND e.source_type IN ('agent', 'evidence') \
                AND e.target_type IN ('agent', 'evidence') \
                AND (e.valid_to IS NULL OR e.valid_to > now()) \
                AND (e.visibility = 'public' \
                     OR ($2::uuid IS NOT NULL AND e.visibility = 'group' \
                         AND e.owner_group_id = $2 AND e.co_owner_group_id IS NULL)) \
                /* {EDGE_VISIBILITY:e} */",
            3,
        );
        let mut q = sqlx::query_as::<_, EdgeRow>(&sql).bind(&others).bind(team);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let among = q.fetch_all(&mut *conn).await?;

        let mut rows = LeafRows {
            requested,
            claims,
            evidence,
            agents,
            edges: Vec::new(),
        };
        let mut seen: BTreeSet<Uuid> = BTreeSet::new();
        let mut edges: Vec<StoredLeafEdge> = touching
            .into_iter()
            .chain(among)
            .filter_map(|(id, st, sid, tt, tid, relationship)| {
                Some(StoredLeafEdge {
                    id,
                    source: LeafNode {
                        kind: LeafNodeKind::from_stored(&st)?,
                        id: sid,
                    },
                    target: LeafNode {
                        kind: LeafNodeKind::from_stored(&tt)?,
                        id: tid,
                    },
                    relationship,
                })
            })
            .filter(|e| {
                LeafIndex::endpoint_known(&rows, e.source)
                    && LeafIndex::endpoint_known(&rows, e.target)
            })
            .filter(|e| seen.insert(e.id))
            .collect();
        edges.sort_unstable_by_key(|e| e.id);
        rows.edges = edges;
        Ok(rows)
    }

    /// [`Self::read_leaf_rows`] then [`assemble_leaf`] over every requested
    /// claim.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a statement fails; `DbError::InvalidData` for
    /// a cap of 0.
    pub async fn build_leaf(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        claim_ids: &[Uuid],
        cap: usize,
    ) -> Result<LeafOutcome, DbError> {
        check_cap(cap)?;
        let rows = Self::read_leaf_rows(conn, viewer, map, claim_ids).await?;
        assemble_leaf(&rows, claim_ids, cap)
    }
}

/// The team a map's predicate binds: `None` for the public map, so only
/// public rows pass.
const fn map_team(map: AtlasMap) -> Option<Uuid> {
    match map {
        AtlasMap::Public => None,
        AtlasMap::Team(t) => Some(t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64: a seeded generator, so a failing case reproduces.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn uuid(&mut self) -> Uuid {
            Uuid::from_u64_pair(self.next(), self.next())
        }
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn edge(eid: u128, source: LeafNode, target: LeafNode, rel: &str) -> StoredLeafEdge {
        StoredLeafEdge {
            id: id(eid),
            source,
            target,
            relationship: rel.to_string(),
        }
    }

    /// Evidence `ev` on `claim`: its `claim_id` and a stored `evidence ->
    /// claim` edge, spelled `supports` and `SUPPORTS` in turn (both spellings
    /// are stored today).
    fn attach(rows: &mut LeafRows, ev: Uuid, claim: Uuid) {
        rows.evidence.insert(ev, Some(claim));
        let n = rows.edges.len() as u64;
        rows.edges.push(StoredLeafEdge {
            id: Uuid::from_u64_pair(u64::MAX, n),
            source: LeafNode::evidence(ev),
            target: LeafNode::claim(claim),
            relationship: if n.is_multiple_of(2) {
                "supports"
            } else {
                "SUPPORTS"
            }
            .to_string(),
        });
    }

    /// `n` claims with ids 1..=n, all filed by agent 1000, each with
    /// `per_claim` evidence rows of its own, each linked by a stored edge.
    fn rows_with(n: u128, per_claim: u128) -> LeafRows {
        let mut rows = LeafRows::default();
        rows.agents.insert(id(1000));
        for c in 1..=n {
            rows.requested.insert(id(c));
            rows.claims.insert(id(c), Some(id(1000)));
            for k in 0..per_claim {
                attach(&mut rows, id(10_000 + c * 1_000 + k), id(c));
            }
        }
        rows
    }

    fn all(rows: &LeafRows) -> Vec<Uuid> {
        rows.requested.iter().copied().collect()
    }

    fn fits(outcome: LeafOutcome) -> LeafNodeSet {
        match outcome {
            LeafOutcome::Fits(set) => set,
            other => panic!("expected Fits, got {other:?}"),
        }
    }

    /// Every agent and evidence node has an edge to a claim of the leaf (the
    /// W10a invariant), and every edge joins two nodes of the leaf.
    fn assert_attached(set: &LeafNodeSet) {
        let nodes: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
        for e in &set.edges {
            assert!(
                nodes.contains(&e.source) && nodes.contains(&e.target),
                "{e:?}"
            );
        }
        for n in nodes.iter().filter(|n| n.kind != LeafNodeKind::Claim) {
            assert!(
                set.edges
                    .iter()
                    .any(|e| (e.source == *n && e.target.kind == LeafNodeKind::Claim)
                        || (e.target == *n && e.source.kind == LeafNodeKind::Claim)),
                "{n:?} has no edge to a claim of the leaf"
            );
        }
    }

    #[test]
    fn count_is_claims_plus_distinct_agents_plus_distinct_evidence() {
        // 3 claims, one shared filer, one evidence row on claim 1 that an edge
        // also links to claims 2 and 3, and a second agent authoring two.
        let mut rows = rows_with(3, 0);
        rows.evidence.insert(id(500), Some(id(1)));
        rows.agents.insert(id(2000));
        rows.edges = vec![
            edge(
                1,
                LeafNode::evidence(id(500)),
                LeafNode::claim(id(2)),
                "supports",
            ),
            edge(
                2,
                LeafNode::claim(id(3)),
                LeafNode::evidence(id(500)),
                "cites",
            ),
            edge(
                3,
                LeafNode::agent(id(2000)),
                LeafNode::claim(id(1)),
                "AUTHORED",
            ),
            edge(
                4,
                LeafNode::agent(id(2000)),
                LeafNode::claim(id(2)),
                "authored",
            ),
        ];
        let set = fits(assemble_leaf(&rows, &all(&rows), 100).unwrap());
        assert_eq!(
            (
                set.counts.claims,
                set.counts.agents,
                set.counts.evidence,
                set.counts.nodes
            ),
            (3, 2, 1, 6)
        );
        assert_attached(&set);
    }

    #[test]
    fn exactly_at_the_cap_fits_and_one_over_needs_a_split() {
        // 33 claims + 1 filer + 66 evidence = 100.
        let rows = rows_with(33, 2);
        let set = fits(assemble_leaf(&rows, &all(&rows), 100).unwrap());
        assert_eq!(set.counts.nodes, 100);
        assert!(set.counts.nodes <= ATLAS_LEAF_NODE_CAP);

        // One more evidence row: 101.
        let mut over = rows.clone();
        attach(&mut over, id(9_999), id(1));
        match assemble_leaf(&over, &all(&over), 100).unwrap() {
            LeafOutcome::NeedsSplit(n) => {
                assert_eq!(n.reason, SplitReason::NodeCap);
                assert_eq!(
                    (n.counts.nodes, n.counts.evidence, n.counts.agents),
                    (101, 67, 1)
                );
            }
            other => panic!("expected NeedsSplit, got {other:?}"),
        }

        // One more AGENT instead: 101 too.
        let mut over = rows;
        over.agents.insert(id(2000));
        over.edges.push(edge(
            1,
            LeafNode::agent(id(2000)),
            LeafNode::claim(id(5)),
            "asserts",
        ));
        assert!(matches!(
            assemble_leaf(&over, &all(&over), 100).unwrap(),
            LeafOutcome::NeedsSplit(n) if n.counts.nodes == 101 && n.counts.agents == 2
        ));
    }

    #[test]
    fn a_claim_with_more_evidence_than_fits_is_capped_and_recorded() {
        let rows = rows_with(1, 150);
        let set = fits(assemble_leaf(&rows, &all(&rows), 100).unwrap());
        assert_eq!(set.counts.nodes, 100);
        assert_eq!(
            set.capped,
            vec![CappedClaim {
                claim: id(1),
                kept_agents: 1,
                kept_evidence: 98,
                total_agents: 1,
                total_evidence: 150,
            }]
        );
        // The prefix is the lowest evidence ids, whatever the row order.
        let kept: Vec<Uuid> = set
            .nodes
            .iter()
            .filter(|n| n.kind == LeafNodeKind::Evidence)
            .map(|n| n.id)
            .collect();
        let expect: Vec<Uuid> = (0..98).map(|k| id(10_000 + 1_000 + k)).collect();
        assert_eq!(kept, expect);
        assert_attached(&set);
    }

    #[test]
    fn fallback_split_partitions_the_claims_and_every_part_fits() {
        for seed in 0..64_u64 {
            let mut r = Rng(seed);
            let mut rows = LeafRows::default();
            let agents: Vec<Uuid> = (0..1 + r.below(12)).map(|_| r.uuid()).collect();
            rows.agents.extend(agents.iter().copied());
            let n_claims = 1 + r.below(220);
            let claims: Vec<Uuid> = (0..n_claims).map(|_| r.uuid()).collect();
            for (i, &c) in claims.iter().enumerate() {
                let filer = agents[r.below(agents.len() as u64) as usize];
                rows.claims.insert(c, Some(filer));
                rows.requested.insert(c);
                // Mostly a few evidence rows, sometimes a flood.
                let k = if r.below(20) == 0 {
                    90 + r.below(80)
                } else {
                    r.below(4)
                };
                for _ in 0..k {
                    let ev = r.uuid();
                    attach(&mut rows, ev, c);
                }
                // Sometimes a row attached by claim_id alone: no node.
                if r.below(5) == 0 {
                    rows.evidence.insert(r.uuid(), Some(c));
                }
                if i > 0 && r.below(3) == 0 {
                    let other = claims[r.below(i as u64) as usize];
                    rows.edges.push(StoredLeafEdge {
                        id: r.uuid(),
                        source: LeafNode::claim(c),
                        target: LeafNode::claim(other),
                        relationship: "supports".into(),
                    });
                }
                if r.below(4) == 0 {
                    let a = agents[r.below(agents.len() as u64) as usize];
                    rows.edges.push(StoredLeafEdge {
                        id: r.uuid(),
                        source: LeafNode::agent(a),
                        target: LeafNode::claim(c),
                        relationship: "AUTHORED".into(),
                    });
                }
            }
            // The input in a scrambled order, with a duplicate and an id the
            // map cannot draw.
            let mut input: Vec<Uuid> = claims.iter().rev().copied().collect();
            input.push(claims[0]);
            input.push(r.uuid());

            let cap = 100;
            let parts = fallback_split(&rows, &input, cap).unwrap();
            let flat: Vec<Uuid> = parts.iter().flatten().copied().collect();
            let mut sorted: Vec<Uuid> = rows.claims.keys().copied().collect();
            sorted.sort_unstable();
            assert_eq!(flat, sorted, "seed {seed}: every claim once, in id order");
            for p in &parts {
                assert!(!p.is_empty());
                let set = fits(assemble_leaf(&rows, p, cap).unwrap());
                assert!(set.counts.nodes <= cap, "seed {seed}");
                assert_attached(&set);
                // Each claim keeps its (capped) evidence in its part.
                let nodes: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
                let index = LeafIndex::new(&rows);
                for &c in p {
                    for n in index.claim_nodes(c, cap).0 {
                        assert!(nodes.contains(&n), "seed {seed}: {n:?} left its claim");
                    }
                }
            }
            let resolved = resolve_with_fallback(&rows, &input, cap).unwrap();
            assert_eq!(resolved.len(), parts.len(), "seed {seed}");
            assert!(resolved.iter().all(|s| s.counts.nodes <= cap));
        }
    }

    #[test]
    fn duplicate_stored_edges_collapse_and_keep_every_id() {
        let mut rows = rows_with(2, 0);
        rows.edges = vec![
            edge(
                30,
                LeafNode::claim(id(1)),
                LeafNode::claim(id(2)),
                "supports",
            ),
            edge(
                10,
                LeafNode::claim(id(1)),
                LeafNode::claim(id(2)),
                "supports",
            ),
            edge(
                20,
                LeafNode::claim(id(1)),
                LeafNode::claim(id(2)),
                "SUPPORTS",
            ),
            // An edge to a claim outside the leaf is not the leaf's.
            edge(
                40,
                LeafNode::claim(id(1)),
                LeafNode::claim(id(77)),
                "supports",
            ),
        ];
        let set = fits(assemble_leaf(&rows, &all(&rows), 100).unwrap());
        let stored: Vec<&LeafEdge> = set
            .edges
            .iter()
            .filter(|e| !e.origin.is_derived())
            .collect();
        assert_eq!(stored.len(), 2, "{stored:?}");
        assert_eq!(
            stored
                .iter()
                .find(|e| e.relationship == "supports")
                .unwrap()
                .origin,
            LeafEdgeOrigin::Stored {
                edge_ids: vec![id(10), id(30)]
            }
        );
    }

    fn evidence_nodes(set: &LeafNodeSet) -> BTreeSet<Uuid> {
        set.nodes
            .iter()
            .filter(|n| n.kind == LeafNodeKind::Evidence)
            .map(|n| n.id)
            .collect()
    }

    /// Evidence is a node only through a stored edge to a claim of the leaf,
    /// in either direction and under its stored spelling; a row attached by
    /// `claim_id` alone is no node and no edge, and is counted in
    /// `unlinked_evidence`. The filer is the only derived edge, and only
    /// where no stored authorship edge stands.
    #[test]
    fn evidence_joins_only_through_a_stored_edge_and_only_the_filer_edge_is_derived() {
        let mut rows = rows_with(3, 0);
        let (bare, linked, reversed) = (id(501), id(502), id(503));
        // Claim 1: a row attached by claim_id alone.
        rows.evidence.insert(bare, Some(id(1)));
        // Claim 2: a row with a stored `evidence -> claim` edge.
        rows.evidence.insert(linked, Some(id(2)));
        // Claim 3: a row whose claim is not the leaf's, linked by a stored
        // `claim -> evidence` edge.
        rows.evidence.insert(reversed, None);
        rows.edges = vec![
            edge(
                1,
                LeafNode::agent(id(1000)),
                LeafNode::claim(id(2)),
                "ASSERTS",
            ),
            edge(
                2,
                LeafNode::evidence(linked),
                LeafNode::claim(id(2)),
                "refutes",
            ),
            edge(
                3,
                LeafNode::claim(id(3)),
                LeafNode::evidence(reversed),
                "cites",
            ),
        ];
        let set = fits(assemble_leaf(&rows, &all(&rows), 100).unwrap());
        assert_eq!(
            evidence_nodes(&set),
            BTreeSet::from([linked, reversed]),
            "the bare row is no node"
        );
        assert_eq!(set.counts.unlinked_evidence, 1);
        assert!(
            set.edges
                .iter()
                .all(|e| e.source != LeafNode::evidence(bare)
                    && e.target != LeafNode::evidence(bare)),
            "no edge is made for the bare row"
        );
        let derived: Vec<(LeafNode, LeafNode, &str)> = set
            .edges
            .iter()
            .filter(|e| e.origin.is_derived())
            .map(|e| (e.source, e.target, e.relationship.as_str()))
            .collect();
        assert_eq!(
            derived,
            vec![
                (
                    LeafNode::agent(id(1000)),
                    LeafNode::claim(id(1)),
                    DERIVED_FILER_RELATIONSHIP
                ),
                (
                    LeafNode::agent(id(1000)),
                    LeafNode::claim(id(3)),
                    DERIVED_FILER_RELATIONSHIP
                ),
            ]
        );
        assert_attached(&set);

        // Claim 1 alone: no evidence node at all.
        let one = fits(assemble_leaf(&rows, &[id(1)], 100).unwrap());
        assert_eq!((one.counts.evidence, one.counts.unlinked_evidence), (0, 1));
    }

    /// `unlinked_evidence` counts the rows attached by `claim_id` to a claim
    /// of THIS leaf that no stored edge links to any claim of this leaf. A row
    /// the per-claim cap cut is capped, not unlinked; a row linked only to a
    /// claim in another part is unlinked in the part that lacks that claim.
    #[test]
    fn unlinked_evidence_counts_rows_no_stored_edge_links_to_the_leaf() {
        // Claim 1: 12 linked rows, 4 of them cut at a cap of 10, and two
        // bare rows.
        let mut rows = rows_with(1, 12);
        rows.evidence.insert(id(601), Some(id(1)));
        rows.evidence.insert(id(602), Some(id(1)));
        let set = fits(assemble_leaf(&rows, &all(&rows), 10).unwrap());
        assert_eq!(set.capped.len(), 1);
        assert_eq!(
            (set.capped[0].kept_evidence, set.capped[0].total_evidence),
            (8, 12)
        );
        assert_eq!(set.counts.unlinked_evidence, 2, "the cut rows are capped");

        // Claim 2 joins; a row on claim 1 by claim_id is linked to claim 2.
        let mut rows = rows_with(2, 0);
        let elsewhere = id(600);
        rows.evidence.insert(elsewhere, Some(id(1)));
        rows.edges.push(edge(
            7,
            LeafNode::evidence(elsewhere),
            LeafNode::claim(id(2)),
            "supports",
        ));
        let both = fits(assemble_leaf(&rows, &[id(1), id(2)], 100).unwrap());
        assert_eq!(evidence_nodes(&both), BTreeSet::from([elsewhere]));
        assert_eq!(both.counts.unlinked_evidence, 0);
        let first = fits(assemble_leaf(&rows, &[id(1)], 100).unwrap());
        assert_eq!(
            (first.counts.evidence, first.counts.unlinked_evidence),
            (0, 1)
        );
        let second = fits(assemble_leaf(&rows, &[id(2)], 100).unwrap());
        assert_eq!(
            (second.counts.evidence, second.counts.unlinked_evidence),
            (1, 0)
        );
    }

    #[test]
    fn a_zero_cap_is_refused_and_no_drawable_claim_is_empty() {
        let rows = rows_with(2, 1);
        assert!(assemble_leaf(&rows, &all(&rows), 0).is_err());
        assert!(fallback_split(&rows, &all(&rows), 0).is_err());
        assert_eq!(
            assemble_leaf(&rows, &[id(88), id(89), id(88)], 100).unwrap(),
            LeafOutcome::Empty {
                unreadable_claims: 2
            }
        );
        assert!(resolve_with_fallback(&rows, &[id(88)], 100)
            .unwrap()
            .is_empty());
    }
}

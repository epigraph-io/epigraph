//! The frozen plan of one workflow generation: its `executes` targets in
//! `plan_index` order, the integrity counts that say when that order cannot be
//! used, and the `wfd1` digest echo.
//!
//! This module is the PURE half of `GET /api/v1/workflows/:id/plan` and MCP
//! `get_workflow_plan`: it decides nothing about visibility (the caller's
//! viewer already did, in the repository read) and touches no database. It is
//! here, next to the builder whose ids and stored hashes it re-derives, so the
//! two cannot drift apart.
//!
//! # `plan_index` is a mutable edge property
//!
//! The ingest executor records `{"level", "plan_index"}` on each `executes`
//! edge. Any writer of the plan's group can rewrite those properties with
//! `patch_edge`, or retract the edge, and nothing in the edge mutation paths
//! looks at `relationship` (measured; see the read-contract tests). So this
//! module never REPAIRS an order:
//!
//! * an index or level that is not a JSON integer `>= 0` fitting `u32` makes
//!   the edge UNINDEXED: counted, not an item, never given a synthetic index;
//! * duplicates, gaps, retracted edges and hidden targets are counted;
//! * the digest echo is withheld unless the stored indices are exactly
//!   `0..n-1` and nothing is hidden or retracted;
//! * an exchanged pair of indices is reported in the order the edges now
//!   carry, with the digest of THAT order.
//!
//! The integrity anchor is a digest the publisher holds outside the server.
//! The echo is informational: equal to that digest when the plan is what was
//! published, different when it is not, and a resolver decides on its own
//! recomputation, never on the echo.
//!
//! # `chain_order` is not digested
//!
//! [`FrozenPlan::chain_order`] carries the plan's steps in the `step_follows`
//! order the other plan-order readers use (ruling R-81). It is passed through
//! as read, never an input of [`wfd1`], never used to order `items`, and never
//! attested: a resolver that pins a plan reads `items` alone.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common::ids::content_hash;
use crate::document::stored_content_hash_is_canonical_name_scoped;
use crate::workflow::builder::canonical_name_scoped_hash_matches;

/// The domain-separation prefix of [`wfd1`].
pub const WFD1_DOMAIN: &[u8] = b"epigraph-wf-v1\n";

/// One row of the digest, in plan order.
#[derive(Debug, Clone, Copy)]
pub struct DigestItem<'a> {
    pub level: u32,
    pub claim_id: Uuid,
    pub content: &'a str,
}

/// The `wfd1` digest of a plan, over `items` IN THE ORDER GIVEN (the caller
/// passes them in `plan_index` order):
///
/// ```text
/// "wfd1:" + hex(BLAKE3( "epigraph-wf-v1\n" ‖ canonical_name ‖ "\n" ‖ decimal(generation) ‖ "\n"
///     ‖ for each item: decimal(level) ‖ "\t" ‖ claim_id ‖ "\t" ‖ decimal(byte_len(content)) ‖ "\n"
///                      ‖ content ‖ "\n" ))
/// ```
///
/// `claim_id` is the lowercase hyphenated UUID; `byte_len` counts UTF-8 bytes.
/// Pinned by `tests/fixtures/wfd1-vectors.json`, computed outside this crate.
#[must_use]
pub fn wfd1<'a>(
    canonical_name: &str,
    generation: u32,
    items: impl IntoIterator<Item = DigestItem<'a>>,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(WFD1_DOMAIN);
    h.update(canonical_name.as_bytes());
    h.update(b"\n");
    h.update(generation.to_string().as_bytes());
    h.update(b"\n");
    for item in items {
        let head = format!(
            "{}\t{}\t{}\n",
            item.level,
            item.claim_id.as_hyphenated(),
            item.content.len()
        );
        h.update(head.as_bytes());
        h.update(item.content.as_bytes());
        h.update(b"\n");
    }
    format!("wfd1:{}", h.finalize().to_hex())
}

/// Whether a plan item's stored `content_hash` matches its body, seed-aware.
///
/// * A row carrying the workflow scope marker
///   ([`stored_content_hash_is_canonical_name_scoped`]) must store
///   `compound_content_hash(blake3(content), canonical_name)`, where
///   `canonical_name` is the name of the workflow BEING READ: the seed is known
///   here, not recovered.
/// * Any other row (level-3 atoms, and workflow rows written before the scope
///   marker existed) must store the plain `blake3(content)`.
///
/// A plain digest on a MARKED row is therefore `false`: the plain digest is
/// accepted only on unmarked rows (SPEC V5). The marker lives in
/// `claims.properties`, which `patch_claim` can rewrite; moving it either way
/// turns a matching row into a non-matching one, never the reverse, because a
/// match needs a blake3 preimage of what is stored.
#[must_use]
pub fn content_hash_ok(
    canonical_name: &str,
    content: &str,
    stored: &[u8],
    properties: &serde_json::Value,
) -> bool {
    if stored_content_hash_is_canonical_name_scoped(properties) {
        // The same seed formula `verify_claim` checks, with the one seed known
        // here. A stored hash that is not 32 bytes cannot match.
        <[u8; 32]>::try_from(stored).is_ok_and(|stored| {
            canonical_name_scoped_hash_matches(content, &stored, [canonical_name]) == Some(true)
        })
    } else {
        stored == content_hash(content).as_slice()
    }
}

/// A plan target the caller may read, as the repository read returns it.
#[derive(Debug, Clone)]
pub struct PlanClaim {
    pub content: String,
    /// `claims.content_hash`, raw.
    pub content_hash: Vec<u8>,
    pub properties: serde_json::Value,
    pub visibility: String,
    pub owner_group_id: Uuid,
    pub truth_value: f64,
    pub is_current: bool,
    /// The claim's step lineage has a head, visible to the caller, other than
    /// this claim (an `evolve_step` happened). Informational.
    pub heads_diverged: bool,
}

/// One `executes` edge of the workflow that the caller may see.
#[derive(Debug, Clone)]
pub struct ExecutesEdge {
    /// The edge's `properties`, raw: `plan_index` and `level` are read here.
    pub properties: serde_json::Value,
    /// `valid_to` is set.
    pub retracted: bool,
    pub target_id: Uuid,
    /// `None`: the caller may see the edge but not read its target.
    pub target: Option<PlanClaim>,
}

/// Everything [`assemble`] needs: the `workflows` row and its visible edges.
#[derive(Debug, Clone)]
pub struct FrozenPlanInput {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: u32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    pub truth_value: f64,
    pub submitter: Option<Uuid>,
    pub edges: Vec<ExecutesEdge>,
    /// The level-2 steps in `step_follows` chain order, as read. Copied to
    /// [`FrozenPlan::chain_order`]; nothing here reads it.
    pub chain_order: Vec<Uuid>,
}

/// One item of a [`FrozenPlan`] (SPEC §2.13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenPlanItem {
    pub plan_index: u32,
    pub level: u32,
    pub claim_id: Uuid,
    pub content: String,
    /// `properties.phase` of the claim, when it has one.
    pub phase: Option<serde_json::Value>,
    /// Lowercase hex of the stored `claims.content_hash`.
    pub content_hash: String,
    pub content_hash_ok: bool,
    pub visibility: String,
    pub owner_group_id: Uuid,
    pub truth_value: f64,
    pub is_current: bool,
    pub heads_diverged: bool,
}

/// The frozen plan of one workflow generation, as the caller reads it
/// (SPEC §2.13, plus `duplicate_plan_indices` and `retracted_edges`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenPlan {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: u32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    /// The `workflows` row's truth; deprecation writes 0.05.
    pub truth_value: f64,
    pub submitter: Option<Uuid>,
    /// Live, indexed, readable targets in `plan_index` order.
    pub items: Vec<FrozenPlanItem>,
    /// Live edges the caller can see whose target it cannot read. A count,
    /// never ids. NOT a count of every unreadable target: an `executes` edge
    /// takes its target's tenancy, so a target in a group the caller is not in
    /// usually hides its edge as well, and such an item is not countable on the
    /// caller's connection. Its absence shows as a gap, or, when it is at the
    /// end of the plan, only as a mismatch with the pinned digest.
    pub hidden_count: u64,
    /// Live, readable edges whose `plan_index` or `level` is not a JSON integer
    /// `>= 0` fitting `u32` (a step `add_step` did not index, or a rewritten
    /// edge).
    pub unindexed_edges: u64,
    /// Indices missing from `0..=max(plan_index)` over the items.
    pub plan_index_gaps: u64,
    /// Items sharing a `plan_index` with an earlier item.
    pub duplicate_plan_indices: u64,
    /// Visible `executes` edges with `valid_to` set. A retraction is a plan
    /// change; such an edge is never an item.
    pub retracted_edges: u64,
    /// The server's [`wfd1`] of `items`, only when every count above is zero
    /// and there is at least one item. Informational, and NOT a statement that
    /// the plan is complete: if the highest-index items sit in a group the
    /// caller is not in, their edges are invisible, no count moves, and this is
    /// the digest of the shortened plan. Only a comparison with the digest the
    /// publisher pinned detects a missing tail.
    pub digest_echo: Option<String>,
    /// The ids of the plan's level-2 steps in `step_follows` chain order: the
    /// order `find_workflow` and `find_workflow_hierarchical` list them in and
    /// the outcome reports' `step_index` counts, so `chain_order[i]` is the
    /// step those readers call step `i` (ruling R-81). Informational, like the
    /// echo, and OUTSIDE it: not digested, not attested, and `items` stay in
    /// `plan_index` order whatever it says.
    ///
    /// Where it is not the order of `items`' steps:
    ///
    /// * a step `add_step` inserted is unindexed, so it is listed here at its
    ///   chain slot and is no item;
    /// * a writer can rewrite a `plan_index` or a `step_follows` edge, and the
    ///   two orders then differ with every count still zero;
    /// * a retracted `executes` edge's step is listed here (the plan-order
    ///   readers do not drop it) and is no item.
    ///
    /// Where it is not a single chain: when the `step_follows` pairs fork or
    /// cycle (two generations of one `canonical_name` sharing reordered
    /// steps), it falls back to stored `plan_index` order, an unindexed step
    /// last; a step the caller cannot read splits the chain, and the pieces
    /// follow each other in plan order. It is not cut where a hidden item
    /// leaves a position unproven, as the outcome reports' `step_index`
    /// resolution is, so with a nonzero `hidden_count` or `plan_index_gaps`
    /// a slot here can name a step those reports leave unresolved.
    #[serde(default)]
    pub chain_order: Vec<Uuid>,
}

/// A JSON integer `>= 0` that fits `u32`. A string, a float (`1.0`), a
/// negative or larger number, `null` or an absent key is `None`.
fn json_u32(v: Option<&serde_json::Value>) -> Option<u32> {
    match v? {
        serde_json::Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Build the [`FrozenPlan`] from the row and the caller's visible edges.
#[must_use]
pub fn assemble(input: FrozenPlanInput) -> FrozenPlan {
    let mut hidden_count = 0_u64;
    let mut unindexed_edges = 0_u64;
    let mut retracted_edges = 0_u64;
    let mut items = Vec::with_capacity(input.edges.len());

    for edge in input.edges {
        if edge.retracted {
            retracted_edges += 1;
            continue;
        }
        let Some(claim) = edge.target else {
            hidden_count += 1;
            continue;
        };
        let (Some(plan_index), Some(level)) = (
            json_u32(edge.properties.get("plan_index")),
            json_u32(edge.properties.get("level")),
        ) else {
            unindexed_edges += 1;
            continue;
        };
        items.push(FrozenPlanItem {
            plan_index,
            level,
            claim_id: edge.target_id,
            content_hash_ok: content_hash_ok(
                &input.canonical_name,
                &claim.content,
                &claim.content_hash,
                &claim.properties,
            ),
            content_hash: hex(&claim.content_hash),
            phase: claim.properties.get("phase").cloned(),
            content: claim.content,
            visibility: claim.visibility,
            owner_group_id: claim.owner_group_id,
            truth_value: claim.truth_value,
            is_current: claim.is_current,
            heads_diverged: claim.heads_diverged,
        });
    }

    // The stored order; the claim id only makes ties deterministic.
    items.sort_by_key(|i| (i.plan_index, i.claim_id));
    let distinct: BTreeSet<u32> = items.iter().map(|i| i.plan_index).collect();
    let distinct_len = distinct.len() as u64;
    let duplicate_plan_indices = items.len() as u64 - distinct_len;
    let plan_index_gaps = distinct
        .last()
        .map_or(0, |max| u64::from(*max) + 1 - distinct_len);

    let well_formed = !items.is_empty()
        && hidden_count == 0
        && unindexed_edges == 0
        && retracted_edges == 0
        && duplicate_plan_indices == 0
        && plan_index_gaps == 0;
    let digest_echo = well_formed.then(|| {
        wfd1(
            &input.canonical_name,
            input.generation,
            items.iter().map(|i| DigestItem {
                level: i.level,
                claim_id: i.claim_id,
                content: &i.content,
            }),
        )
    });

    FrozenPlan {
        workflow_id: input.workflow_id,
        canonical_name: input.canonical_name,
        generation: input.generation,
        goal: input.goal,
        parent_id: input.parent_id,
        truth_value: input.truth_value,
        submitter: input.submitter,
        items,
        hidden_count,
        unindexed_edges,
        plan_index_gaps,
        duplicate_plan_indices,
        retracted_edges,
        digest_echo,
        chain_order: input.chain_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_u32_accepts_only_non_negative_integers_that_fit() {
        use serde_json::json;
        assert_eq!(json_u32(Some(&json!(0))), Some(0));
        assert_eq!(json_u32(Some(&json!(u32::MAX))), Some(u32::MAX));
        for bad in [
            json!(u64::from(u32::MAX) + 1),
            json!(-1),
            json!(1.0),
            json!(1.5),
            json!("1"),
            json!(null),
            json!([1]),
        ] {
            assert_eq!(json_u32(Some(&bad)), None, "{bad}");
        }
        assert_eq!(json_u32(None), None);
    }
}

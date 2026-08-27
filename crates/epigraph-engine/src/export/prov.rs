//! PROV-O export mapping: internal edge relationship names to
//! `http://www.w3.org/ns/prov#` predicates, applied **only** at
//! serialization time — no `edges.relationship` value is ever rewritten.
//!
//! # This module DOES write to the database
//!
//! It did not, until manifests landed (backlog 6e2364b8). Every export now
//! anchors a signed Merkle manifest over exactly the claim ids and edge ids it
//! emitted, which inserts one `manifests` row and one `manifest_entries` row
//! per committed row. There is no `--manifest` flag and no
//! `enable_manifests` setting: a subgraph export whose recipient must simply
//! trust that nothing was dropped is precisely the failure this exists to
//! remove, and a feature that ships behind an off-by-default switch is off
//! everywhere that matters. An anchored export is a RECORDED export.
//!
//! The consequence is real and deliberate: `export_provenance_prov_o` is no
//! longer callable against a read-only connection, and an operator scripting it
//! in a loop grows the manifest tables.
//!
//! # Why PROV-O over RO-Crate
//!
//! This graph's provenance shape is claims (PROV Entities), the edges
//! between them (PROV relations), the agents that authored them (PROV
//! Agents), and reasoning traces (PROV Activities) — there are no packaged
//! research-object *files* to describe, which is RO-Crate's core use case
//! (an `ro-crate-metadata.json` manifest for a directory of research
//! artifacts). PROV-O also already has a foothold here:
//! `crates/epigraph-mcp/src/tools/provenance.rs::get_provenance` already
//! emits a partial `prov:` JSON-LD bundle, and `edges.relationship` already
//! carries PROV-flavored names (`attributed_to`, `associated_with`) with
//! comments citing `prov:wasAttributedTo` / `prov:wasAssociatedWith`
//! directly. Extending that vocabulary end-to-end is the smaller, more
//! natural change.
//!
//! # Export-time-only
//!
//! `edges.relationship` stores internal names (`derived_from`,
//! `supersedes`, ...) and an edges-API allow-list
//! (`crates/epigraph-api/src/routes/edges.rs::VALID_RELATIONSHIPS`) rejects
//! unknown relationship types — renaming the column to PROV-O predicates
//! live is not possible without breaking every write path, and this repo's
//! `CLAUDE.md` reserves `supersedes` specifically for epistemic-replacement
//! semantics. So the mapping in this module is applied only when building
//! the exported JSON-LD document; the underlying row is never touched.
//!
//! # Scope: no `prov:Activity` nodes (yet)
//!
//! `get_provenance` (the existing MCP tool) maps `reasoning_traces` rows to
//! `prov:Activity`. This module deliberately does not: it emits the
//! activity-less shorthand form of derivation (`entity1 prov:wasDerivedFrom
//! entity2`, which PROV-O explicitly permits as short for "some activity
//! generated entity1 by using entity2") rather than reconstructing full
//! Entity-Activity-Agent triples. Adding `reasoning_traces` as `prov:Activity`
//! nodes (as `get_provenance` already does) is a natural follow-up once
//! there's a concrete consumer that needs the activity-level detail.

use crate::export::manifest::{anchor_manifest, ManifestError};

/// The result of a PROV-O export: the JSON-LD document (with its `manifest`
/// block already spliced in) plus the exact id sets the manifest commits to.
///
/// The id sets are returned rather than left implicit so a caller can assert
/// what was committed without re-parsing the document, and so a second anchor
/// over the same set is reproducible.
#[derive(Debug, Clone)]
pub struct ProvExport {
    pub document: serde_json::Value,
    /// Claims actually emitted as `prov:Entity` nodes.
    pub claim_ids: Vec<uuid::Uuid>,
    /// Edges that actually produced a `prov:Relation` — NOT every edge visited.
    pub edge_ids: Vec<uuid::Uuid>,
}

/// Map an internal `edges.relationship` value to its PROV-O predicate,
/// for use in exported JSON-LD only. Returns `None` for relationship types
/// that have no natural PROV-O analogue (the caller should fall back to a
/// generic `prov:wasInfluencedBy` or skip the edge).
///
/// Both historical/current spellings are accepted where the schema has
/// carried more than one (`derived_from` is the canonical value in
/// `VALID_RELATIONSHIPS`; `derives_from` shows up in older docs/specs).
#[must_use]
pub fn relationship_to_prov_predicate(relationship: &str) -> Option<&'static str> {
    match relationship {
        "derived_from" | "derives_from" => Some("prov:wasDerivedFrom"),
        "supersedes" => Some("prov:wasRevisionOf"),
        "asserts" | "authored_by" | "attributed_to" | "ATTRIBUTED_TO" => {
            Some("prov:wasAttributedTo")
        }
        "associated_with" => Some("prov:wasAssociatedWith"),
        "generated" => Some("prov:wasGeneratedBy"),
        "uses_evidence" => Some("prov:used"),
        _ => None,
    }
}

/// `edges.relationship` values are not all written in the same direction.
/// `derived_from`-family edges (and everything else this module maps) point
/// **ancestor -> descendant** (`source_id` = the older/ancestor claim,
/// `target_id` = the newer/descendant claim) — this is the convention
/// `LineageRepository`'s recursive CTEs assume. `supersedes` is the
/// opposite: both production write paths
/// (`ClaimRepository::supersede` and `ClaimRepository::evolve_step`) insert
/// it as `source_id` = the *new* claim, `target_id` = the claim being
/// superseded. This helper returns, for a mapped relationship, which edge
/// endpoint is the PROV-O "generated" (newer) entity and which is the
/// "used" (older/source) entity — so callers don't have to hardcode the
/// direction per relationship type at each call site.
fn prov_relation_endpoints(
    relationship: &str,
    source_id: uuid::Uuid,
    target_id: uuid::Uuid,
) -> (uuid::Uuid, uuid::Uuid) {
    if relationship == "supersedes" {
        // source = new claim (generated), target = old claim (used).
        (source_id, target_id)
    } else {
        // derived_from / derives_from / generated / uses_evidence:
        // source = ancestor (used), target = descendant (generated).
        (target_id, source_id)
    }
}

/// Build a PROV-O JSON-LD document describing the provenance of
/// `root_claim_id`: the claim itself, every ancestor claim reachable via
/// `derived_from`-family claim-to-claim edges (up to `max_depth`, default
/// 100 — mirrors [`epigraph_db::LineageRepository::get_lineage`]'s
/// default), one hop of `supersedes` predecessors for each of those claims,
/// the edges between them mapped to PROV-O predicates, and the authoring
/// agent of each claim as a `prov:Agent`.
///
/// `supersedes` is only expanded one hop per claim (not recursively) in
/// this first pass — deeper supersession *chains* (claims that themselves
/// supersede a claim already reached via a supersedes edge) are a follow-up;
/// see the module's PR description.
///
/// Internal relationship strings in the DB are left exactly as they are; the
/// PROV-O predicate only ever appears in the returned JSON value, and nothing
/// in `claims` or `edges` is modified.
///
/// It is NOT read-only, however: before returning, the emitted set is anchored
/// as a signed Merkle manifest (see [`crate::export::manifest`]), which inserts
/// a `manifests` row and its `manifest_entries`. The resulting bundle is
/// spliced into the returned document under `manifest`, and the committed id
/// sets come back on [`ProvExport`] so callers do not have to re-derive them.
///
/// The committed sets are the EMITTED ones, not the enumerated ones: a claim
/// whose `get_by_id` returned `None` (deleted mid-export) is skipped and is not
/// committed to, and only edges that actually produced a relation are
/// committed. Anchoring a row the document does not contain would be a false
/// commitment.
///
/// Works for any claim's provenance — there is no filter on evidence type
/// or claim label. Computational-model claims (marked by
/// `evidence.evidence_type = 'computation'`) are simply one shape of input;
/// the exporter does not special-case them.
///
/// # Errors
/// Returns [`ManifestError`] if any underlying repository call fails or if the
/// manifest cannot be anchored — including [`ManifestError::UnknownRow`] when a
/// committed row was deleted between assembly and anchoring. That last case
/// converts what used to be a silently partial document into a hard failure,
/// which is the intended trade.
pub async fn export_provenance_prov_o(
    pool: &epigraph_db::PgPool,
    root_claim_id: uuid::Uuid,
    max_depth: Option<i32>,
    signer: &epigraph_crypto::AgentSigner,
    signer_agent_id: uuid::Uuid,
) -> Result<ProvExport, ManifestError> {
    use epigraph_core::domain::ids::{AgentId, ClaimId};
    use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, LineageRepository};

    // --- Pass 1: assemble the full claim set ---------------------------
    //
    // `get_ancestor_ids` walks the ancestor-first convention
    // (`derived_from`-family edges); it includes the root itself. It does
    // NOT reach a claim's supersedes-predecessor, because that edge's
    // *target* (the old claim) is never itself an edge *source* pointing
    // at something already in the lineage — the direction is inverted
    // relative to what the CTE looks for. So we add supersedes targets
    // explicitly, one hop per claim already in the set.
    let ancestor_ids = LineageRepository::get_ancestor_ids(pool, root_claim_id, max_depth).await?;
    let mut claim_ids = ancestor_ids;
    if !claim_ids.contains(&root_claim_id) {
        claim_ids.push(root_claim_id);
    }

    let mut supersedes_targets = Vec::new();
    for &claim_id in &claim_ids {
        let outgoing = EdgeRepository::get_by_source(pool, claim_id, "claim").await?;
        for edge in outgoing {
            if edge.target_type == "claim"
                && edge.relationship == "supersedes"
                && !claim_ids.contains(&edge.target_id)
            {
                supersedes_targets.push(edge.target_id);
            }
        }
    }
    for id in supersedes_targets {
        if !claim_ids.contains(&id) {
            claim_ids.push(id);
        }
    }

    // --- Pass 2: emit entities, agents, and relations -------------------

    let mut entities = Vec::new();
    let mut agents_seen = std::collections::HashSet::new();
    let mut agent_entities = Vec::new();
    let mut relations = Vec::new();
    let mut edges_seen = std::collections::HashSet::new();
    // The manifest commits to what was EMITTED, not to what was enumerated.
    // `claim_ids` is the candidate set; a claim whose `get_by_id` returns None
    // hits the `continue` below and never becomes an entity, so committing to
    // it would be a false claim about the document's contents.
    let mut emitted_claim_ids = Vec::new();
    let mut emitted_edge_ids = Vec::new();

    for &claim_id in &claim_ids {
        let Some(claim) = ClaimRepository::get_by_id(pool, ClaimId::from_uuid(claim_id)).await?
        else {
            continue;
        };
        emitted_claim_ids.push(claim_id);

        entities.push(serde_json::json!({
            "@id": format!("claim:{claim_id}"),
            "@type": "prov:Entity",
            "content": claim.content,
            "truth_value": claim.truth_value.value(),
        }));

        let agent_uuid: uuid::Uuid = claim.agent_id.into();
        if agents_seen.insert(agent_uuid) {
            if let Some(agent) =
                AgentRepository::get_by_id(pool, AgentId::from_uuid(agent_uuid)).await?
            {
                agent_entities.push(serde_json::json!({
                    "@id": format!("agent:{agent_uuid}"),
                    "@type": "prov:Agent",
                    "display_name": agent.display_name,
                }));
            }
        }
        relations.push(serde_json::json!({
            "@id": format!("relation:attribution:{claim_id}"),
            "@type": "prov:Attribution",
            "prov:entity": format!("claim:{claim_id}"),
            "prov:agent": format!("agent:{agent_uuid}"),
            "predicate": "prov:wasAttributedTo",
        }));

        // Collect claim-to-claim edges touching this claim from both
        // directions — `derived_from` edges have this claim as the
        // `target_id` (see doc comment on `prov_relation_endpoints`),
        // `supersedes` edges have this claim as the `source_id`. Dedup by
        // edge id since a claim can appear on both sides across the loop
        // (e.g. the root is both a target of its ancestor's edge and a
        // source of its own supersedes edge).
        let mut claim_edges = EdgeRepository::get_by_target(pool, claim_id, "claim").await?;
        claim_edges.extend(EdgeRepository::get_by_source(pool, claim_id, "claim").await?);

        for edge in claim_edges {
            if !edges_seen.insert(edge.id) {
                continue;
            }
            if edge.source_type != "claim"
                || edge.target_type != "claim"
                || !claim_ids.contains(&edge.source_id)
                || !claim_ids.contains(&edge.target_id)
            {
                continue;
            }
            let Some(predicate) = relationship_to_prov_predicate(&edge.relationship) else {
                continue;
            };
            let (generated, used) =
                prov_relation_endpoints(&edge.relationship, edge.source_id, edge.target_id);
            relations.push(serde_json::json!({
                "@id": format!("edge:{}", edge.id),
                "@type": "prov:Relation",
                "prov:generatedEntity": format!("claim:{generated}"),
                "prov:usedEntity": format!("claim:{used}"),
                "predicate": predicate,
                "source_relationship": edge.relationship,
            }));
            // Only here — `edges_seen` also holds every edge that hit one of
            // the three `continue`s above and produced no relation at all.
            emitted_edge_ids.push(edge.id);
        }
    }

    // --- Pass 3: anchor a signed commitment over exactly what was emitted ---

    let anchored = anchor_manifest(
        pool,
        signer,
        signer_agent_id,
        serde_json::json!({
            "kind": "provenance_export",
            "root_claim_id": root_claim_id,
            "max_depth": max_depth,
        }),
        &emitted_claim_ids,
        &emitted_edge_ids,
    )
    .await?;

    let document = serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{root_claim_id}"),
        "entities": entities,
        "agents": agent_entities,
        "relations": relations,
        "manifest": anchored.to_json(),
    });

    Ok(ProvExport {
        document,
        claim_ids: emitted_claim_ids,
        edge_ids: emitted_edge_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_derived_from_to_prov_was_derived_from() {
        assert_eq!(
            relationship_to_prov_predicate("derived_from"),
            Some("prov:wasDerivedFrom")
        );
    }

    #[test]
    fn maps_legacy_derives_from_spelling_to_prov_was_derived_from() {
        assert_eq!(
            relationship_to_prov_predicate("derives_from"),
            Some("prov:wasDerivedFrom")
        );
    }

    #[test]
    fn maps_supersedes_to_prov_was_revision_of() {
        assert_eq!(
            relationship_to_prov_predicate("supersedes"),
            Some("prov:wasRevisionOf")
        );
    }

    #[test]
    fn maps_attributed_to_to_prov_was_attributed_to() {
        assert_eq!(
            relationship_to_prov_predicate("attributed_to"),
            Some("prov:wasAttributedTo")
        );
    }

    #[test]
    fn unknown_relationship_maps_to_none() {
        assert_eq!(relationship_to_prov_predicate("relates_to"), None);
    }
}

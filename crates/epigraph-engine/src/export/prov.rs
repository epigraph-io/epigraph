//! PROV-O export mapping: internal edge relationship names to
//! `http://www.w3.org/ns/prov#` predicates, applied **only** at
//! serialization time. Nothing here writes to the database.
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
/// This is **read-only**: it issues only `SELECT`s (via
/// `LineageRepository`, `EdgeRepository`, `ClaimRepository`,
/// `AgentRepository`) and never writes to `edges` or `claims`. Internal
/// relationship strings in the DB are left exactly as they are; the PROV-O
/// predicate only ever appears in the returned JSON value.
///
/// Works for any claim's provenance — there is no filter on evidence type
/// or claim label. Computational-model claims (marked by
/// `evidence.evidence_type = 'computation'`) are simply one shape of input;
/// the exporter does not special-case them.
///
/// # Errors
/// Returns [`epigraph_db::DbError`] if any underlying repository call fails.
pub async fn export_provenance_prov_o(
    pool: &epigraph_db::PgPool,
    root_claim_id: uuid::Uuid,
    max_depth: Option<i32>,
) -> Result<serde_json::Value, epigraph_db::DbError> {
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

    for &claim_id in &claim_ids {
        let Some(claim) = ClaimRepository::get_by_id(pool, ClaimId::from_uuid(claim_id)).await?
        else {
            continue;
        };

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
        }
    }

    Ok(serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{root_claim_id}"),
        "entities": entities,
        "agents": agent_entities,
        "relations": relations,
    }))
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

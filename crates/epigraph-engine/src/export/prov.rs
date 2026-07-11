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

/// Build a PROV-O JSON-LD document describing the provenance of
/// `root_claim_id`: the claim itself, every ancestor claim reachable via
/// claim-to-claim edges (up to `max_depth`, default 100 — mirrors
/// [`epigraph_db::LineageRepository::get_lineage`]'s default), the edges
/// between them mapped to PROV-O predicates, and the authoring agent of
/// each claim as a `prov:Agent`.
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

    let ancestor_ids = LineageRepository::get_ancestor_ids(pool, root_claim_id, max_depth).await?;

    // `get_ancestor_ids` includes the root itself at depth 0; dedupe just in
    // case callers pass a claim with no ancestors.
    let mut claim_ids = ancestor_ids;
    if !claim_ids.contains(&root_claim_id) {
        claim_ids.push(root_claim_id);
    }

    let mut entities = Vec::new();
    let mut agents_seen = std::collections::HashSet::new();
    let mut agent_entities = Vec::new();
    let mut relations = Vec::new();

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

        // Inbound edges (ancestor -> this claim) carry the derivation and
        // supersession relationships in this schema: `LineageRepository`'s
        // recursive CTEs treat `edges.source_id` as the ancestor and
        // `edges.target_id` as the descendant already in the lineage
        // (`JOIN edges e ON e.source_id = c.id ... e.target_id = l.id`), so
        // we mirror that direction here rather than inventing a new one.
        let edges = EdgeRepository::get_by_target(pool, claim_id, "claim").await?;
        for edge in edges {
            if edge.source_type != "claim" || !claim_ids.contains(&edge.source_id) {
                continue;
            }
            let Some(predicate) = relationship_to_prov_predicate(&edge.relationship) else {
                continue;
            };
            relations.push(serde_json::json!({
                "@id": format!("edge:{}", edge.id),
                "@type": "prov:Relation",
                // PROV-O reads "target wasDerivedFrom source": the claim
                // this edge points at is the derived/newer entity, and the
                // edge's source is the ancestor entity it was derived from.
                "prov:generatedEntity": format!("claim:{}", edge.target_id),
                "prov:usedEntity": format!("claim:{}", edge.source_id),
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

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

/// Bounds on one export. [`Self::default`] is unbounded, which is what the
/// operator CLI passes, so its output is the whole lineage as before. A
/// request path (the MCP tool) passes finite limits, because the walk has no
/// row cap of its own and every kept claim costs about two statements plus
/// its full content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProvExportLimits {
    /// Most claims kept as entities, nearest-first: the root, then its
    /// ancestors by ascending depth, then one-hop `supersedes` predecessors.
    /// Applied before any per-claim statement, and counted over claims the
    /// viewer can READ only, so a hidden candidate never takes a slot and
    /// never sets `truncated`.
    pub max_nodes: Option<usize>,
    /// Most characters of each entity's `content`. A clipped entity carries
    /// `content_truncated: true` and the original `content_chars`.
    pub max_content_chars: Option<usize>,
}

/// `content` cut to `max` characters (not bytes), and whether it was cut.
fn clip_content(content: String, max: Option<usize>) -> (String, Option<usize>) {
    match max {
        Some(max) => {
            let chars = content.chars().count();
            if chars > max {
                (content.chars().take(max).collect(), Some(chars))
            } else {
                (content, None)
            }
        }
        None => (content, None),
    }
}

/// Build a PROV-O JSON-LD document describing the provenance of
/// `root_claim_id`: the claim itself, every ancestor claim reachable over
/// claim-to-claim edges INTO it (recursively, up to `max_depth`, default 100
/// as in [`epigraph_db::LineageRepository::get_lineage`]), one hop of
/// `supersedes` predecessors for each of those claims, the edges between
/// them mapped to PROV-O predicates, and the authoring agent of each claim as
/// a `prov:Agent`.
///
/// # What the walk follows
///
/// [`epigraph_db::LineageRepository::get_ancestor_ids`] walks EVERY incoming
/// claim-to-claim edge, of any relationship, not only the `derived_from`
/// family. A claim that `refutes` or `contradicts` an ancestor is therefore
/// in the export as a `prov:Entity` (with its attribution), but its edge has
/// no PROV-O predicate ([`relationship_to_prov_predicate`]) and is omitted, so
/// such an entity carries no `prov:Relation` to the rest of the document.
///
/// # One relation per fact
///
/// One `(source, target, relationship)` fact can be stored as several edge
/// rows (the edges table has no triple uniqueness since migrations
/// 017/018/053). Each fact is emitted as ONE `prov:Relation`, named after the
/// first of its rows the export meets (backlog 11402482).
///
/// `supersedes` is only expanded one hop per claim (not recursively) in
/// this first pass — deeper supersession *chains* (claims that themselves
/// supersede a claim already reached via a supersedes edge) are a follow-up;
/// see the module's PR description.
///
/// # `truncated`
///
/// The document's `truncated` is true iff `limits.max_nodes` cut the claim
/// set. It does NOT report a `max_depth` cutoff: the ancestor walk returns no
/// signal for one, so a depth-limited export can be incomplete with
/// `truncated: false`.
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
/// # The caller's connection
///
/// Every statement runs on `conn`, which the caller stamps for `viewer`
/// (`ScopedPool::read_as` in a request handler, the maintenance connection in
/// the CLI). It took a raw pool until it was exposed over MCP: under FORCEd
/// row security a raw application-login pool admits public rows only, so a
/// member's own group-private ancestors would have silently dropped out of
/// the export while the in-query viewer predicate admitted them.
///
/// # A claim the viewer cannot read is absent everywhere
///
/// A claim id is emitted only once [`ClaimRepository::get_by_ids_with_labels`]
/// has returned it for `viewer`: as an entity, an attribution, or an endpoint
/// of a relation. A `supersedes` edge the viewer can see may still point at a
/// claim it cannot (an edge is visible on its own row, not its endpoints'),
/// so relation endpoints are checked against the KEPT readable set, never
/// against the candidate set, which would print a hidden claim's id in a
/// relation.
///
/// # Statements
///
/// One ancestor walk, one `get_by_source` per kept ancestor (reused for that
/// claim's relations), one batched readability read, then per kept claim one
/// `get_by_target` (plus a `get_by_source` for a supersedes predecessor) and
/// one agent read per distinct author: about `2 * max_nodes + 2`.
///
/// # Errors
/// Returns [`epigraph_db::DbError`] if any underlying repository call fails.
pub async fn export_provenance_prov_o(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    root_claim_id: uuid::Uuid,
    max_depth: Option<i32>,
    limits: ProvExportLimits,
) -> Result<serde_json::Value, epigraph_db::DbError> {
    use epigraph_core::domain::ids::AgentId;
    use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, LineageRepository};
    use std::collections::{HashMap, HashSet};

    // --- Pass 1: assemble the candidate claim set -----------------------
    //
    // `get_ancestor_ids` walks every incoming claim-to-claim edge (see the
    // doc comment); it includes the root itself and returns ancestors-first
    // (descending depth), so reversed it is nearest-first. It does NOT reach
    // a claim's supersedes-predecessor, because that edge's *target* (the old
    // claim) is never itself an edge *source* pointing at something already
    // in the lineage — the direction is inverted relative to what the CTE
    // looks for. So we add supersedes targets explicitly, one hop per claim
    // already in the set.
    let mut claim_ids =
        LineageRepository::get_ancestor_ids(&mut *conn, viewer, root_claim_id, max_depth).await?;
    claim_ids.reverse();
    claim_ids.retain(|id| *id != root_claim_id);
    claim_ids.insert(0, root_claim_id);

    // The node cap, BEFORE any per-claim statement, nearest-first. Every id
    // the walk returned is readable (it filters claims and edges for the
    // viewer), so this cut counts readable claims only.
    let mut truncated = false;
    if let Some(n) = limits.max_nodes {
        if claim_ids.len() > n {
            claim_ids.truncate(n);
            truncated = true;
        }
    }

    let mut outgoing_by_claim: HashMap<uuid::Uuid, Vec<epigraph_db::EdgeRow>> = HashMap::new();
    let mut supersedes_targets = Vec::new();
    for &claim_id in &claim_ids {
        let outgoing = EdgeRepository::get_by_source(&mut *conn, viewer, claim_id, "claim").await?;
        for edge in &outgoing {
            if edge.target_type == "claim"
                && edge.relationship == "supersedes"
                && !claim_ids.contains(&edge.target_id)
                && !supersedes_targets.contains(&edge.target_id)
            {
                supersedes_targets.push(edge.target_id);
            }
        }
        outgoing_by_claim.insert(claim_id, outgoing);
    }
    claim_ids.extend(supersedes_targets);

    // --- Pass 2: emit entities, agents, and relations -------------------

    // Pass 2a: keep only the candidates this viewer can READ (one batched
    // statement), in candidate order. A candidate reached through a visible
    // edge to a hidden claim (a supersedes target) is dropped here, before
    // any of its ids can be printed, and before the cap counts it.
    let mut fetched: HashMap<uuid::Uuid, epigraph_core::Claim> =
        ClaimRepository::get_by_ids_with_labels(&mut *conn, viewer, &claim_ids)
            .await?
            .into_iter()
            .map(|(claim, _labels)| (claim.id.into(), claim))
            .collect();
    let mut readable: Vec<(uuid::Uuid, epigraph_core::Claim)> = claim_ids
        .iter()
        .filter_map(|id| fetched.remove(id).map(|claim| (*id, claim)))
        .collect();
    if let Some(n) = limits.max_nodes {
        if readable.len() > n {
            readable.truncate(n);
            truncated = true;
        }
    }
    let readable_ids: HashSet<uuid::Uuid> = readable.iter().map(|(id, _)| *id).collect();

    let mut entities = Vec::new();
    let mut agents_seen = HashSet::new();
    let mut agent_entities = Vec::new();
    let mut relations = Vec::new();
    // Keyed on the FACT, not the row: parallel rows of one
    // `(source, target, relationship)` are one relation.
    let mut facts_seen: HashSet<(uuid::Uuid, uuid::Uuid, String)> = HashSet::new();

    for (claim_id, claim) in readable {
        let (content, content_chars) = clip_content(claim.content, limits.max_content_chars);
        let mut entity = serde_json::json!({
            "@id": format!("claim:{claim_id}"),
            "@type": "prov:Entity",
            "content": content,
            "truth_value": claim.truth_value.value(),
        });
        if let Some(chars) = content_chars {
            entity["content_truncated"] = serde_json::Value::Bool(true);
            entity["content_chars"] = serde_json::json!(chars);
        }
        entities.push(entity);

        let agent_uuid: uuid::Uuid = claim.agent_id.into();
        if agents_seen.insert(agent_uuid) {
            if let Some(agent) =
                AgentRepository::get_by_id(&mut *conn, AgentId::from_uuid(agent_uuid)).await?
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
        // `supersedes` edges have this claim as the `source_id`. The outgoing
        // half was fetched in pass 1 for every ancestor; only a supersedes
        // predecessor needs it fetched here. Dedup by fact (source, target,
        // relationship): a claim can appear on both sides across the loop
        // (e.g. the root is both a target of its ancestor's edge and a source
        // of its own supersedes edge), and one fact can have several rows.
        let outgoing = match outgoing_by_claim.remove(&claim_id) {
            Some(edges) => edges,
            None => EdgeRepository::get_by_source(&mut *conn, viewer, claim_id, "claim").await?,
        };
        let mut claim_edges =
            EdgeRepository::get_by_target(&mut *conn, viewer, claim_id, "claim").await?;
        claim_edges.extend(outgoing);

        for edge in claim_edges {
            if edge.source_type != "claim"
                || edge.target_type != "claim"
                || !readable_ids.contains(&edge.source_id)
                || !readable_ids.contains(&edge.target_id)
            {
                continue;
            }
            let Some(predicate) = relationship_to_prov_predicate(&edge.relationship) else {
                continue;
            };
            if !facts_seen.insert((edge.source_id, edge.target_id, edge.relationship.clone())) {
                continue;
            }
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
        "truncated": truncated,
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
    fn content_is_clipped_by_characters_not_bytes() {
        // 'é' is two bytes; a byte-indexed cut at 2 would split it.
        let (clipped, chars) = clip_content("aébéc".to_string(), Some(2));
        assert_eq!(clipped, "aé");
        assert_eq!(chars, Some(5));
        let (kept, none) = clip_content("abc".to_string(), Some(3));
        assert_eq!((kept.as_str(), none), ("abc", None));
        let (kept, none) = clip_content("abcdef".to_string(), None);
        assert_eq!((kept.as_str(), none), ("abcdef", None));
    }

    #[test]
    fn unknown_relationship_maps_to_none() {
        assert_eq!(relationship_to_prov_predicate("relates_to"), None);
    }
}

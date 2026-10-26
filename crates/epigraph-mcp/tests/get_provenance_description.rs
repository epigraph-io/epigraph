//! `get_provenance`'s description states which edges count as ancestry.
//!
//! I104 / U042: the tool said only "all ancestor claims", while the walk
//! followed every incoming claim->claim edge -- so an agent planning from the
//! description could not know that a contradicting claim, a matcher
//! corroboration or a NEWER superseding claim came back as an "ancestor".
//! The walk is now restricted to derivation edges; the description is the
//! contract an agent reads, so it must name the set and the direction.

/// Pins the new sentence positively, including the two facts an agent cannot
/// infer from "ancestor": that supersedes is walked to the predecessor, and
/// that disputes and corroborations are excluded (and where to find them).
#[test]
fn get_provenance_description_names_the_derivation_edges_it_walks() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    let description = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "get_provenance")
        .and_then(|t| t["description"].as_str())
        .expect("get_provenance is registered with a description")
        .to_string();
    for needle in [
        "Walks derivation edges only: supports/elaborates/decomposes_to (incoming)",
        "supersedes (to the predecessor the claim replaced)",
        "Contradicts, refutes and cross-source corroborations are not ancestry",
        "use get_neighborhood for those",
    ] {
        assert!(
            description.contains(needle),
            "get_provenance's description must say {needle:?}; got: {description}"
        );
    }
}

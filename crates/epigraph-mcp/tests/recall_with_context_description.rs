//! The `recall_with_context` tool description is the contract an agent reads
//! before it decides which recall tool to call, so it must describe the
//! candidate population the tool actually searches (drain U082, backlog
//! a1d89aab; operator ruling 2026-10-14: whole-corpus seeding, `paper`
//! optional).
//!
//! Before the ruling it opened "Paragraph-primary semantic search", which was
//! accurate then; now every embedded claim is a candidate and a parentless
//! hit omits `paper`, so an agent reading the old text would conclude a
//! `submit_claim` claim cannot be found here, and would read `paper.title`
//! unconditionally.

fn recall_with_context_description() -> String {
    epigraph_mcp::server::EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == "recall_with_context")
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .expect("recall_with_context is in the manifest and has a description")
}

#[test]
fn recall_with_context_description_no_longer_claims_paragraph_primary_search() {
    let d = recall_with_context_description();
    assert!(
        !d.contains("Paragraph-primary"),
        "the seed is the whole corpus; the paragraph-primary claim must be gone: {d}"
    );
}

#[test]
fn recall_with_context_description_states_the_whole_corpus_seed_and_optional_paper() {
    let d = recall_with_context_description();
    for needle in [
        "Semantic search over every embedded claim in the graph",
        "submit_claim / memorize claims",
        "a hit with no paper attribution omits `paper`, has `section: null`",
        "`paragraph_id` is the hit's claim id whatever its level",
        "from all embedded claims",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
}

//! The Atlas "by links" hierarchy (Atlas W5, backlog 4e02c23f, with W5b
//! febb2a77): under each theme of one map, its claims grouped by the
//! communities of the claim graph until every leaf fits the 100-node cap
//! (claims + agents + evidence, a shared agent or evidence row counted once,
//! exactly as the "by meaning" hierarchy weighs a leaf). Run by the operator
//! binary `atlas_links`.
//!
//! **Which edges count** ([`graph::counted_links`]): claim-to-claim edges
//! between two members of the theme on the map whose relationship is
//! supports, refutes, contradicts, cites, elaborates, corroborates or
//! decomposes_to (either spelling), read through W3's leaf read, so only
//! edges the map may draw: public, or the team's own with no co-owner
//! (ATLAS-R3b). A co-owned or other-team edge never shapes a team map.
//!
//! **Unlinked claims (W5b):** a member with no counted link goes into a links
//! leaf that MIRRORS its "by meaning" leaf: exactly the unlinked claims of
//! that leaf, minted in the links namespace ([`graph::check_mirrors`]).
//!
//! Three steps, W4's shape (the maths leaves the box on ids, integers and
//! the linked claims' embeddings only):
//!
//! 1. **export** (box, [`build::export_links`]): per theme, the meaning
//!    result resolved now, the members, attachment integers, links as index
//!    pairs, meaning-leaf integers, the linked members' embeddings
//!    ([`files`]);
//! 2. **compute** (anywhere, `scripts/atlas_links_core.py compute`): Louvain
//!    communities (networkx), packed into a tree, with W4's embedding split
//!    for a dense community that will not split;
//! 3. **apply** (box, [`build::apply_hierarchies`]): the meaning result and
//!    the links result checked in one snapshot and written as ONE run holding
//!    both hierarchies, so every level's switch resolves
//!    ([`graph::switch_targets`]).
//!
//! **Ids** are W4's ([`crate::atlas_meaning::tree::root_id`],
//! [`crate::atlas_meaning::tree::group_id`]) with `hierarchy = links`: the
//! links root is known from the theme alone, which is what the meaning
//! root's switch points at.

pub mod build;
pub mod files;
pub mod graph;

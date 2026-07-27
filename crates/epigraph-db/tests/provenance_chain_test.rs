//! `ProvenanceChainRepository::chain` — topological derivation traversal
//! (backlog 3216b086 / design F2).
//!
//! The behaviours pinned here are the ones a plausible-but-wrong
//! implementation gets backwards:
//!
//! 1. **Mixed-direction frontier.** `supports`/`corroborates`/`elaborates`/
//!    `decomposes_to` ancestors sit behind INCOMING edges, but `supersedes`
//!    ancestors sit behind OUTGOING ones (`supersede()` writes new→old).
//!    A uniformly-incoming walk silently returns an empty chain for the
//!    supersedes case — the single easiest way to get this wrong.
//! 2. **Topological order is evidence-first**, and `supersedes` must be
//!    flipped when ordering (its stored source is the *descendant*).
//! 3. **Cycles are reported, not fatal**, and must terminate.
//! 4. **Depth bounds** actually bound.

use epigraph_db::ProvenanceChainRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-provchain', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.7, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

fn pos(chain: &epigraph_db::ProvenanceChain, id: Uuid) -> usize {
    chain
        .nodes
        .iter()
        .position(|n| n.id == id)
        .unwrap_or_else(|| panic!("node {id} missing from chain"))
}

/// Evidence reached through INCOMING `supports` edges, returned
/// evidence-first. `base` supports `mid`, `mid` supports `root`.
#[sqlx::test(migrations = "../../migrations")]
async fn supports_chain_is_returned_evidence_first(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let root = seed_claim(&pool, agent, "conclusion").await;
    let mid = seed_claim(&pool, agent, "intermediate").await;
    let base = seed_claim(&pool, agent, "base evidence").await;

    seed_edge(&pool, mid, root, "supports").await;
    seed_edge(&pool, base, mid, "supports").await;

    let chain = ProvenanceChainRepository::chain(&pool, root, 4, None)
        .await
        .expect("chain");

    assert_eq!(chain.nodes.len(), 3, "root + 2 ancestors");
    assert!(
        pos(&chain, base) < pos(&chain, mid) && pos(&chain, mid) < pos(&chain, root),
        "topological order must be evidence-first: base < mid < root"
    );
    assert!(!chain.truncated);
    assert!(chain.cycles.is_empty());
}

/// The direction-sensitive case. `supersede()` writes new→old, so the
/// predecessor sits behind the root's OUTGOING edge. A uniformly-incoming
/// traversal returns just the root here.
#[sqlx::test(migrations = "../../migrations")]
async fn supersedes_predecessor_reached_via_outgoing_edge(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let new = seed_claim(&pool, agent, "revised claim").await;
    let old = seed_claim(&pool, agent, "superseded claim").await;

    // supersede() convention: source = new, target = old.
    seed_edge(&pool, new, old, "supersedes").await;

    let chain = ProvenanceChainRepository::chain(&pool, new, 4, None)
        .await
        .expect("chain");

    assert_eq!(
        chain.nodes.len(),
        2,
        "predecessor must be reached through the OUTGOING supersedes edge"
    );
    assert!(
        pos(&chain, old) < pos(&chain, new),
        "the superseded predecessor is ancestry: it must sort BEFORE its replacement, \
         which requires flipping the stored new->old edge when ordering"
    );
}

/// `decomposes_to` is written parent→child (paragraph→atom), so an atom's
/// parent is behind its INCOMING edge.
#[sqlx::test(migrations = "../../migrations")]
async fn decomposes_to_parent_reached_via_incoming_edge(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let paragraph = seed_claim(&pool, agent, "parent paragraph").await;
    let atom = seed_claim(&pool, agent, "child atom").await;

    seed_edge(&pool, paragraph, atom, "decomposes_to").await;

    let chain = ProvenanceChainRepository::chain(&pool, atom, 4, None)
        .await
        .expect("chain");

    assert_eq!(chain.nodes.len(), 2);
    assert!(
        pos(&chain, paragraph) < pos(&chain, atom),
        "parent paragraph precedes its atom"
    );
}

/// A cycle must be REPORTED and must terminate — not error, not hang.
#[sqlx::test(migrations = "../../migrations")]
async fn cycle_is_reported_not_fatal(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "claim a").await;
    let b = seed_claim(&pool, agent, "claim b").await;

    seed_edge(&pool, a, b, "supports").await;
    seed_edge(&pool, b, a, "supports").await;

    let chain = ProvenanceChainRepository::chain(&pool, a, 6, None)
        .await
        .expect("a cycle must not be an error");

    assert!(
        !chain.cycles.is_empty(),
        "the cycle must be surfaced to the caller"
    );
    assert!(
        chain.nodes.len() <= 2,
        "traversal terminates instead of revisiting the cycle forever"
    );
}

/// `max_depth` bounds the walk.
#[sqlx::test(migrations = "../../migrations")]
async fn max_depth_bounds_the_walk(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let ids: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..5 {
            v.push(seed_claim(&pool, agent, &format!("link-{i}")).await);
        }
        v
    };
    // ids[4] supports ids[3] supports ... supports ids[0] (root).
    for i in 0..4 {
        seed_edge(&pool, ids[i + 1], ids[i], "supports").await;
    }

    let shallow = ProvenanceChainRepository::chain(&pool, ids[0], 2, None)
        .await
        .expect("chain");
    assert_eq!(
        shallow.nodes.len(),
        3,
        "max_depth=2 yields root + 2 hops, not the whole 5-node chain"
    );

    let deep = ProvenanceChainRepository::chain(&pool, ids[0], 8, None)
        .await
        .expect("chain");
    assert_eq!(deep.nodes.len(), 5, "max_depth=8 reaches the full chain");
}

/// Derivation history legitimately crosses superseded claims — a non-current
/// ancestor must be INCLUDED and flagged, not filtered out (that is the whole
/// point of following the supersedes hop).
#[sqlx::test(migrations = "../../migrations")]
async fn non_current_ancestors_are_included_and_flagged(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let root = seed_claim(&pool, agent, "current conclusion").await;
    let retired = seed_claim(&pool, agent, "retired evidence").await;
    seed_edge(&pool, retired, root, "supports").await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .expect("retire");

    let chain = ProvenanceChainRepository::chain(&pool, root, 4, None)
        .await
        .expect("chain");

    let node = chain
        .nodes
        .iter()
        .find(|n| n.id == retired)
        .expect("superseded ancestor must still appear in the derivation");
    assert!(!node.is_current, "and must be flagged as non-current");
}

/// Relationships outside the traversal set are not followed — a `contradicts`
/// edge is not derivation.
#[sqlx::test(migrations = "../../migrations")]
async fn unrelated_relationships_are_not_traversed(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let root = seed_claim(&pool, agent, "target claim").await;
    let contester = seed_claim(&pool, agent, "contesting claim").await;
    seed_edge(&pool, contester, root, "contradicts").await;

    let chain = ProvenanceChainRepository::chain(&pool, root, 4, None)
        .await
        .expect("chain");

    assert_eq!(
        chain.nodes.len(),
        1,
        "only the root; a contradicts edge is dispute, not derivation"
    );
}

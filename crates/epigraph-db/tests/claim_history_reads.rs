//! `ClaimRepository::predecessors_of` and `::search_retired_lexical`: the
//! viewer-scoped reads over retired claims (backlog c3e208a4, split 1/3 of
//! 28a2f938).
//!
//! The property every test here pins: a retired row is returned only when the
//! viewer can read THAT row. A predecessor never inherits its successor's
//! visibility. The fixtures force every `supersedes` edge public (migration
//! 070's trigger would otherwise stamp a private endpoint's group on it), so an
//! outsider's empty result cannot be the edge predicate's work alone: it has
//! to be the claim predicate on the predecessor row.

use epigraph_db::repos::{PredecessorHit, RetiredLexicalHit};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

/// A token `websearch_to_tsquery('english', …)` keeps as one lexeme: letters
/// only, unique per call, so no other row in the database matches it.
fn token() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .map(|c| match c.to_digit(16) {
            Some(d) if d < 10 => char::from(b'g' + d as u8),
            _ => c,
        })
        .collect()
}

/// A current claim with explicit tenancy, optionally naming `supersedes`.
async fn claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    visibility: &str,
    group: Uuid,
    supersedes: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, supersedes) \
         VALUES ($1, sha256($1::bytea), 0.7, $2, true, $3, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .bind(supersedes)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn retire(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE claims SET is_current = false, updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("retire claim");
}

/// Narrow a claim to `group` after the fact: privatization acts on one
/// version, so its successor stays public.
async fn privatize(pool: &PgPool, id: Uuid, group: Uuid) {
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(id)
        .bind(group)
        .execute(pool)
        .await
        .expect("privatize claim");
}

/// A `supersedes` edge `successor -> predecessor` spelled `relationship`,
/// forced public so it is never what hides a row.
async fn supersedes_edge(pool: &PgPool, successor: Uuid, predecessor: Uuid, relationship: &str) {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(successor)
    .bind(predecessor)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed supersedes edge");
    let world = fixture::world_group(pool).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(world)
    .execute(pool)
    .await
    .expect("force edge public");
}

async fn walk(pool: &PgPool, viewer: &Viewer, ids: &[Uuid], depth: i32) -> Vec<PredecessorHit> {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::predecessors_of(&mut conn, viewer, ids, depth, 50)
        .await
        .expect("predecessors_of")
}

async fn lexical(pool: &PgPool, viewer: &Viewer, query: &str) -> Vec<RetiredLexicalHit> {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::search_retired_lexical(&mut conn, viewer, query, 50)
        .await
        .expect("search_retired_lexical")
}

fn ids_of(hits: &[PredecessorHit]) -> Vec<(Uuid, Uuid, i32)> {
    hits.iter()
        .map(|h| (h.id, h.successor_id, h.depth))
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_predecessor_of_a_public_successor_reaches_its_owner_only(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "history-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "history-outsider").await;
    let world = fixture::world_group(&pool).await;
    let word = token();

    let pred = claim(
        &pool,
        owner,
        &format!("earlier {word} statement"),
        "public",
        world,
        None,
    )
    .await;
    let succ = claim(&pool, owner, "later statement", "public", world, Some(pred)).await;
    supersedes_edge(&pool, succ, pred, "supersedes").await;
    retire(&pool, pred).await;
    privatize(&pool, pred, group).await;

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let outsider_v = Viewer::resolve(&pool, outsider)
        .await
        .expect("resolve outsider");
    let anon = fixture::public_viewer(&pool).await;

    for (who, v) in [("outsider", &outsider_v), ("public", &anon)] {
        assert_eq!(
            walk(&pool, v, &[succ], 5).await,
            vec![],
            "the {who} viewer reads the public successor but must not get its private predecessor"
        );
        assert_eq!(
            lexical(&pool, v, &word).await,
            vec![],
            "the {who} viewer must not find the private retired row lexically"
        );
    }

    let hits = walk(&pool, &owner_v, &[succ], 5).await;
    assert_eq!(
        ids_of(&hits),
        vec![(pred, succ, 1)],
        "CALIBRATION: the owner gets its own private predecessor, or the outsider's empty \
         result proves nothing"
    );
    assert!(!hits[0].is_current);
    assert!(hits[0].content.contains(&word));

    let found = lexical(&pool, &owner_v, &word).await;
    assert_eq!(found.len(), 1, "the owner finds its retired row: {found:?}");
    assert_eq!(found[0].id, pred);
    assert_eq!(found[0].successor_id, Some(succ));
    assert!(!found[0].is_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_withdrawn_claim_with_no_successor_is_found_by_the_lexical_leg(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "history-withdrawn").await;
    let world = fixture::world_group(&pool).await;
    let word = token();

    let withdrawn = claim(
        &pool,
        author,
        &format!("withdrawn {word} claim"),
        "public",
        world,
        None,
    )
    .await;
    retire(&pool, withdrawn).await;
    let live = claim(
        &pool,
        author,
        &format!("live {word} claim"),
        "public",
        world,
        None,
    )
    .await;

    let anon = fixture::public_viewer(&pool).await;
    let found = lexical(&pool, &anon, &word).await;
    assert_eq!(
        found.iter().map(|h| h.id).collect::<Vec<_>>(),
        vec![withdrawn],
        "the retired row is found and the current one is not"
    );
    assert_eq!(
        found[0].successor_id, None,
        "nothing succeeds a withdrawn claim"
    );
    assert!(found[0].rank > 0.0);

    assert_eq!(
        walk(&pool, &anon, &[live], 5).await,
        vec![],
        "a lineage walk cannot reach a claim nothing supersedes"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_follows_legacy_edges_and_stops_at_an_invisible_link(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "history-chain").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "history-chain-out").await;
    let world = fixture::world_group(&pool).await;

    // head -(edge only, legacy spelling)-> p1 -(column)-> p2 -(column)-> p3
    let p3 = claim(&pool, owner, "third version", "public", world, None).await;
    let p2 = claim(&pool, owner, "second version", "public", world, Some(p3)).await;
    let p1 = claim(&pool, owner, "first version", "public", world, Some(p2)).await;
    let head = claim(&pool, owner, "current version", "public", world, None).await;
    supersedes_edge(&pool, head, p1, "SUPERSEDES").await;
    for id in [p3, p2, p1] {
        retire(&pool, id).await;
    }
    privatize(&pool, p2, group).await;

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let outsider_v = Viewer::resolve(&pool, outsider)
        .await
        .expect("resolve outsider");

    assert_eq!(
        ids_of(&walk(&pool, &owner_v, &[head], 5).await),
        vec![(p1, head, 1), (p2, p1, 2), (p3, p2, 3)],
        "the owner walks the whole chain: the legacy upper-case edge, then the columns"
    );
    assert_eq!(
        ids_of(&walk(&pool, &outsider_v, &[head], 5).await),
        vec![(p1, head, 1)],
        "the walk stops at the private version: the public one beyond it is not returned, \
         or its depth would disclose the hidden revision"
    );
    assert_eq!(
        ids_of(&walk(&pool, &owner_v, &[head], 2).await),
        vec![(p1, head, 1), (p2, p1, 2)],
        "the depth bound holds"
    );
    assert_eq!(
        ids_of(&walk(&pool, &owner_v, &[head, p1], 5).await),
        vec![(p2, p1, 2), (p3, p2, 3)],
        "a seed is never returned even when another seed's walk reaches it, and a RETIRED \
         seed's own column is not followed (it may name the claim it was retired into), so \
         p2 is reached through head at depth 2"
    );
    let mut conn = pool.acquire().await.unwrap();
    let capped = ClaimRepository::predecessors_of(&mut conn, &owner_v, &[head], 5, 1)
        .await
        .unwrap();
    assert_eq!(ids_of(&capped), vec![(p1, head, 1)], "the cap holds");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_the_viewer_cannot_read_starts_no_walk(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "history-seed").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "history-seed-out").await;
    let world = fixture::world_group(&pool).await;

    let pred = claim(&pool, owner, "public predecessor", "public", world, None).await;
    let succ = claim(
        &pool,
        owner,
        "private successor",
        "group",
        group,
        Some(pred),
    )
    .await;
    // A public edge too, so only the seed's own predicate can stop the walk.
    supersedes_edge(&pool, succ, pred, "supersedes").await;
    retire(&pool, pred).await;

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let outsider_v = Viewer::resolve(&pool, outsider)
        .await
        .expect("resolve outsider");
    assert_eq!(
        ids_of(&walk(&pool, &owner_v, &[succ], 5).await),
        vec![(pred, succ, 1)],
        "CALIBRATION: the owner walks from its private successor"
    );
    assert_eq!(
        walk(&pool, &outsider_v, &[succ], 5).await,
        vec![],
        "a guessed private id must not confirm itself by returning its public predecessor"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_rows_column_is_not_walked_into_the_claim_it_was_retired_into(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "history-dedup").await;
    let world = fixture::world_group(&pool).await;

    // `canonical` is later superseded by `next`, so it is retired too.
    let canonical = claim(&pool, author, "canonical", "public", world, None).await;
    let next = claim(
        &pool,
        author,
        "canonical restated",
        "public",
        world,
        Some(canonical),
    )
    .await;
    retire(&pool, canonical).await;
    // A dedup mark: the RETIRED duplicate names the claim it was retired into.
    let dup = claim(&pool, author, "duplicate", "public", world, Some(canonical)).await;
    retire(&pool, dup).await;
    // A duplicate of the live head: the canonical is current.
    let dup_of_live = claim(
        &pool,
        author,
        "duplicate of head",
        "public",
        world,
        Some(next),
    )
    .await;
    retire(&pool, dup_of_live).await;
    // A `supersedes` edge whose target is current again (an un-mark re-opens
    // a row and leaves history edges where they are).
    let reopened = claim(&pool, author, "reopened", "public", world, None).await;
    supersedes_edge(&pool, next, reopened, "supersedes").await;

    let anon = fixture::public_viewer(&pool).await;
    assert_eq!(
        walk(&pool, &anon, &[dup], 5).await,
        vec![],
        "a retired duplicate's column names its successor, not a predecessor"
    );
    assert_eq!(
        walk(&pool, &anon, &[dup_of_live], 5).await,
        vec![],
        "a live canonical is never returned as a predecessor"
    );
    assert_eq!(
        ids_of(&walk(&pool, &anon, &[next], 5).await),
        vec![(canonical, next, 1)],
        "the supersession itself is walked; the duplicates pointing at the canonical are not \
         its predecessors, and a current claim behind an edge is not returned"
    );
}

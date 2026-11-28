//! Integration test for SharedTripleBlocker.

use epigraph_engine::matching::blocker::{shared_triple::SharedTripleBlocker, Blocker};
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn insert_entity(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, canonical_name, type_top)
         VALUES ($1, $2, 'Concept')",
    )
    .bind(id)
    .bind(format!("entity-{}", id))
    .execute(pool)
    .await
    .expect("entity");
    id
}

async fn insert_triple(pool: &PgPool, claim_id: Uuid, subject_id: Uuid, predicate: &str) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO triples (id, claim_id, subject_id, predicate, object_literal, confidence, extractor)
         VALUES ($1, $2, $3, $4, 'lit', 0.9, 'test')",
    )
    .bind(id)
    .bind(claim_id)
    .bind(subject_id)
    .bind(predicate)
    .execute(pool)
    .await
    .expect("triple");
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_shared_triple_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let seed = insert_claim(&pool, agent).await;
    let other = insert_claim(&pool, agent).await;

    let subject = insert_entity(&pool).await;
    let predicate = "has_property";
    insert_triple(&pool, seed, subject, predicate).await;
    insert_triple(&pool, other, subject, predicate).await;

    let b = SharedTripleBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.expect("candidates");

    let expected = if seed < other {
        (seed, other)
    } else {
        (other, seed)
    };
    assert!(
        pairs.contains(&expected),
        "expected pair {:?} in {:?}",
        expected,
        pairs
    );
    for (a, b) in &pairs {
        assert!(a < b, "pair not canonical: ({a}, {b})");
        assert_ne!(a, b, "self-pair found");
    }
}

/// The per-seed statement `SharedTripleBlocker` ran once per seed before
/// backlog d69a4d24, kept here as the reference the batched statement must
/// agree with.
async fn per_seed_reference(pool: &PgPool, seeds: &[Uuid], cap: usize) -> Vec<(Uuid, Uuid)> {
    let mut out = Vec::new();
    for &seed in seeds {
        let nbrs: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT t2.claim_id
             FROM triples t1
             JOIN triples t2
                  ON t2.subject_id = t1.subject_id
                 AND t2.predicate  = t1.predicate
                 AND t2.claim_id  <> t1.claim_id
             WHERE t1.claim_id = $1
             LIMIT $2",
        )
        .bind(seed)
        .bind(cap as i64)
        .fetch_all(pool)
        .await
        .expect("reference");
        for (n,) in nbrs {
            if let Some(p) = epigraph_engine::matching::blocker::canonical(seed, n) {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Pairs of `pairs` that touch `claim`.
fn touching(pairs: &[(Uuid, Uuid)], claim: Uuid) -> Vec<(Uuid, Uuid)> {
    pairs
        .iter()
        .copied()
        .filter(|&(a, b)| a == claim || b == claim)
        .collect()
}

/// Backlog d69a4d24: the blocker answers every seed in ONE statement, and the
/// answer is the one the per-seed loop gave.
///
/// The seed set covers the shapes a batched rewrite can get wrong:
/// * three seeds under the cap, two of which are each other's neighbours
///   (one shared `(subject, predicate)`), and one with a neighbour of its own;
/// * a seed with no triples at all;
/// * a duplicated seed;
/// * a seed with MORE neighbours than the cap, on a triple no other seed
///   shares, which must yield exactly `cap` pairs. A per-seed `LIMIT` turned
///   into one global `LIMIT` over the whole seed set fails this arm or the
///   equivalence arm.
///
/// Every seed but the over-cap one stays under the cap, because
/// `DISTINCT ... LIMIT` without an `ORDER BY` picks an arbitrary subset above
/// it, so only the over-cap seed's COUNT is comparable.
#[sqlx::test(migrations = "../../migrations")]
async fn one_statement_for_every_seed_matches_the_per_seed_path(pool: PgPool) {
    let cap = 3usize;
    let agent = insert_agent(&pool).await;
    let s1 = insert_claim(&pool, agent).await;
    let s2 = insert_claim(&pool, agent).await;
    let s3 = insert_claim(&pool, agent).await;
    let empty = insert_claim(&pool, agent).await;
    let hub = insert_claim(&pool, agent).await;
    let n3 = insert_claim(&pool, agent).await;
    let n1 = insert_claim(&pool, agent).await;

    let shared = insert_entity(&pool).await;
    let other = insert_entity(&pool).await;
    let hub_subject = insert_entity(&pool).await;

    // s1 <-> s2 <-> n1 on (shared, has_property).
    insert_triple(&pool, s1, shared, "has_property").await;
    insert_triple(&pool, s2, shared, "has_property").await;
    insert_triple(&pool, n1, shared, "has_property").await;
    // Same subject, different predicate: NOT a neighbour of s1/s2.
    insert_triple(&pool, s3, shared, "made_of").await;
    // s3 <-> n3 on (other, made_of).
    insert_triple(&pool, s3, other, "made_of").await;
    insert_triple(&pool, n3, other, "made_of").await;
    // hub shares (hub_subject, part_of) with cap + 2 claims nobody else touches.
    insert_triple(&pool, hub, hub_subject, "part_of").await;
    for _ in 0..cap + 2 {
        let c = insert_claim(&pool, agent).await;
        insert_triple(&pool, c, hub_subject, "part_of").await;
    }

    let b = SharedTripleBlocker::new(cap);
    let under_cap = [s1, s2, s3, empty, s1];
    let batched = b.candidates(&pool, &under_cap).await.expect("batched");
    let reference = per_seed_reference(&pool, &under_cap, cap).await;
    assert_eq!(batched, reference, "batched answer differs from per-seed");
    let mut expected = vec![
        epigraph_engine::matching::blocker::canonical(s1, s2).unwrap(),
        epigraph_engine::matching::blocker::canonical(s1, n1).unwrap(),
        epigraph_engine::matching::blocker::canonical(s2, n1).unwrap(),
        epigraph_engine::matching::blocker::canonical(s3, n3).unwrap(),
    ];
    expected.sort_unstable();
    assert_eq!(batched, expected, "CALIBRATION: the seeded neighbourhoods");

    // The over-cap seed alongside the others: its own pairs are capped at
    // `cap`, and every other seed's pairs are unchanged.
    let with_hub = [s1, hub, s2, s3, empty, s1];
    let batched = b.candidates(&pool, &with_hub).await.expect("batched");
    assert_eq!(
        touching(&batched, hub).len(),
        cap,
        "the over-cap seed must yield exactly `cap` pairs: {batched:?}"
    );
    let without_hub: Vec<_> = batched
        .iter()
        .copied()
        .filter(|&(a, b)| a != hub && b != hub)
        .collect();
    assert_eq!(
        without_hub, expected,
        "a capped seed must not eat another seed's share"
    );
    let reference = per_seed_reference(&pool, &with_hub, cap).await;
    assert_eq!(
        touching(&reference, hub).len(),
        cap,
        "CALIBRATION: the per-seed path caps the hub too"
    );

    assert!(
        b.candidates(&pool, &[]).await.expect("no seeds").is_empty(),
        "no seeds, no pairs"
    );
}

async fn insert_claim_with_id(pool: &PgPool, agent: Uuid, id: Uuid) {
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
}

/// A seed's own claim must not take one of its `per_triple_cap` slots.
///
/// Every seed here has exactly `cap` (= 1) neighbour, so the correct answer
/// is one pair per seed with no arbitrary choice inside the `LIMIT`. Without
/// the `t2.claim_id <> t1.claim_id` self-exclusion each seed's subquery has
/// two candidates (itself and its neighbour) for one slot; the seed's id is
/// minted below its neighbour's so a sort-based `DISTINCT` picks the seed
/// itself, and over 16 seeds a hash-based one does too with overwhelming
/// probability. The self pair is then dropped by `canonical`, and the seed
/// comes back with no pair at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_never_spends_its_cap_on_its_own_claim(pool: PgPool) {
    let cap = 1usize;
    let agent = insert_agent(&pool).await;
    let mut seeds = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..16 {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (seed, neighbour) = if a < b { (a, b) } else { (b, a) };
        insert_claim_with_id(&pool, agent, seed).await;
        insert_claim_with_id(&pool, agent, neighbour).await;
        let subject = insert_entity(&pool).await;
        insert_triple(&pool, seed, subject, "part_of").await;
        insert_triple(&pool, neighbour, subject, "part_of").await;
        seeds.push(seed);
        expected.push((seed, neighbour));
    }
    expected.sort_unstable();

    let b = SharedTripleBlocker::new(cap);
    let batched = b.candidates(&pool, &seeds).await.expect("batched");
    assert_eq!(
        batched, expected,
        "every seed must yield its one neighbour, not spend the cap on itself"
    );
    assert_eq!(
        per_seed_reference(&pool, &seeds, cap).await,
        expected,
        "CALIBRATION: the per-seed path agrees"
    );
}

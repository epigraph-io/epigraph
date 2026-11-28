//! `TripleRepository::get_by_claims` reads the triples of several claims in
//! ONE statement, with the answer the per-claim path gave (backlog d69a4d24).
//!
//! `search_triples` (MCP) used to call `get_by_claim` once per embedding hit
//! and truncate the concatenation to `limit` afterwards. `get_by_claims` keeps
//! that order (the claims in the order given, then each claim's triples by
//! confidence, highest first) and stops at `limit` in the database.
//!
//! The harness connection is the test superuser, which BYPASSES row security,
//! so every visibility answer here comes from the statement's own spliced
//! predicate and none from the policies.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::TripleRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn entity(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, 'Concept', true) RETURNING id",
    )
    .bind(format!("{name}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed entity")
}

/// One triple on `claim` with the given confidence; the literal names it so a
/// failure message is readable.
async fn triple(pool: &PgPool, claim: Uuid, subject: Uuid, confidence: f64, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO triples (claim_id, subject_id, predicate, object_literal, confidence, extractor) \
         VALUES ($1, $2, 'has_property', $3, $4, 'd69a4d24-test') RETURNING id",
    )
    .bind(claim)
    .bind(subject)
    .bind(label)
    .bind(confidence)
    .fetch_one(pool)
    .await
    .expect("seed triple")
}

/// The pre-d69a4d24 path: `get_by_claim` per claim, concatenated, truncated.
async fn per_claim(pool: &PgPool, viewer: &Viewer, claims: &[Uuid], limit: usize) -> Vec<Uuid> {
    let mut out = Vec::new();
    for &c in claims {
        out.extend(
            TripleRepository::get_by_claim(pool, viewer, c)
                .await
                .expect("get_by_claim")
                .into_iter()
                .map(|t| t.id),
        );
    }
    out.truncate(limit);
    out
}

async fn batched(pool: &PgPool, viewer: &Viewer, claims: &[Uuid], limit: i64) -> Vec<Uuid> {
    TripleRepository::get_by_claims(pool, viewer, claims, limit)
        .await
        .expect("get_by_claims")
        .into_iter()
        .map(|t| t.id)
        .collect()
}

/// Three claims in a deliberately non-sorted order, each with triples at
/// distinct confidences (ties have no defined order on either path). The
/// limit cuts in the MIDDLE of the second claim, so a statement that ignores
/// the claim order, sorts by confidence across claims, or applies the limit
/// per claim gives a different list.
///
/// The second claim is private to another group: a stranger skips its rows
/// (and the limit then reaches into the third claim), a member sees them.
#[sqlx::test(migrations = "../../migrations")]
async fn one_statement_matches_the_per_claim_path_in_order_and_visibility(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "d69a-author").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "d69a-member").await;
    let a = fixture::seed_public_claim(&pool, author, "d69a claim a").await;
    let b = fixture::seed_group_claim(&pool, member, group, "d69a claim b").await;
    let c = fixture::seed_public_claim(&pool, author, "d69a claim c").await;
    let s = entity(&pool, "d69a-subject").await;

    let a_lo = triple(&pool, a, s, 0.2, "a-lo").await;
    let a_hi = triple(&pool, a, s, 0.9, "a-hi").await;
    let b_hi = triple(&pool, b, s, 0.8, "b-hi").await;
    let b_mid = triple(&pool, b, s, 0.5, "b-mid").await;
    let _b_lo = triple(&pool, b, s, 0.1, "b-lo").await;
    let c_hi = triple(&pool, c, s, 0.95, "c-hi").await;
    let c_lo = triple(&pool, c, s, 0.3, "c-lo").await;

    let stranger = fixture::public_viewer(&pool).await;
    let insider = Viewer::resolve(&pool, member)
        .await
        .expect("resolve member");
    // Search order c, b, a: the reverse of the insertion order, so a
    // statement that returns claims in table order is caught.
    let order = [c, b, a];

    // The member sees all of b; the limit (4) stops inside b.
    let want = vec![c_hi, c_lo, b_hi, b_mid];
    assert_eq!(
        per_claim(&pool, &insider, &order, 4).await,
        want,
        "CALIBRATION"
    );
    assert_eq!(batched(&pool, &insider, &order, 4).await, want, "member");

    // The stranger sees none of b; the limit reaches into a.
    let want = vec![c_hi, c_lo, a_hi, a_lo];
    assert_eq!(
        per_claim(&pool, &stranger, &order, 4).await,
        want,
        "CALIBRATION"
    );
    assert_eq!(batched(&pool, &stranger, &order, 4).await, want, "stranger");

    // Another order, a limit past the end: everything visible, claim by claim.
    let order = [a, b, c];
    for (viewer, name) in [(&insider, "member"), (&stranger, "stranger")] {
        assert_eq!(
            batched(&pool, viewer, &order, 100).await,
            per_claim(&pool, viewer, &order, 100).await,
            "{name}, order a b c"
        );
    }

    assert!(
        batched(&pool, &insider, &[], 10).await.is_empty(),
        "no claims"
    );
}

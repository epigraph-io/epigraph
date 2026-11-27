//! `ClaimRepository::claim_has_embedding` answers "does this claim carry a
//! vector" only for a claim the viewer may read: for a group-private claim
//! that has a vector, a non-member and the public viewer get `false`, the same
//! answer as for a claim with no vector or no such claim. Otherwise the read
//! would tell an outsider that a hidden claim id exists and is embedded.
//!
//! Its production callers (the `embedding_generation` job) read as the
//! maintenance viewer, so this pins the read for the viewers a future caller
//! may pass.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// A 1536-d pgvector literal, all zero except index 0.
fn vector_literal() -> String {
    let mut v = vec![0.0_f32; 1536];
    v[0] = 1.0;
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn has(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> bool {
    ClaimRepository::claim_has_embedding(pool, viewer, claim)
        .await
        .expect("claim_has_embedding")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_claims_vector_is_not_reported_to_a_non_member(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "outsider").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "a private claim").await;
    fixture::set_claim_embedding(&pool, private, &vector_literal()).await;

    for (who, viewer) in [
        ("public viewer", fixture::public_viewer(&pool).await),
        (
            "outsider",
            Viewer::resolve(&pool, outsider).await.expect("viewer"),
        ),
    ] {
        assert!(
            !has(&pool, &viewer, private).await,
            "{who} learned that a group-private claim has a vector"
        );
    }

    // Calibration: the owner reads it as embedded, so the arms above test the
    // visibility filter and not a missing vector.
    let owner_v = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    assert!(
        has(&pool, &owner_v, private).await,
        "the owner reads the vector"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_claim_answers_by_its_vector(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let embedded = fixture::seed_public_claim(&pool, agent, "an embedded claim").await;
    let bare = fixture::seed_public_claim(&pool, agent, "a claim with no vector").await;
    fixture::set_claim_embedding(&pool, embedded, &vector_literal()).await;

    assert!(
        has(&pool, &viewer, embedded).await,
        "the vector is reported"
    );
    assert!(!has(&pool, &viewer, bare).await, "a NULL vector is not");
    assert!(
        !has(&pool, &viewer, Uuid::new_v4()).await,
        "no such claim is not"
    );
}

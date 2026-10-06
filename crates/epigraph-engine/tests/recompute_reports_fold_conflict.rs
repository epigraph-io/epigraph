//! The claim-belief recompute must report the conflict its fold SAW
//! (drain unit U025, backlog 9d4821c1).
//!
//! `edge_factor::compute_combined_belief` fed the CDST classifier, and wrote
//! `claims.mass_on_empty` from, `combined.mass_of_conflict()`: the residual
//! empty-set mass left in the combined BBA. That residual is path-dependent:
//! 0 after a Dempster or Inagaki step, non-zero only after a CdstConjunctive
//! step. Two BBAs in head-on conflict (K = 0.64) therefore cached
//! `mass_on_empty = 0` and the classifier's Rule 1 (`conflict_k >= ct &&
//! has_opposing` -> contradicted) never saw the conflict. Since U025 every
//! `combine_multiple` step is Dempster, so the residual is ALWAYS 0; the
//! recompute must take the fold's aggregate conflict instead.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::edge_factor::{
    preview_claim_belief_on_frame, recompute_claim_belief_on_frame,
};
use uuid::Uuid;

async fn new_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, masses: serde_json::Value) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        None,
        None,
        Some("empirical"), // calibrated weight 1.0: no discount muddies K
        "unknown",         // locality factor 1.0
        None,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn head_on_conflict_is_cached_and_classified(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .unwrap();

    let owner = new_agent(&pool).await;
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("u025 head-on conflict {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    FrameRepository::assign_claim(&pool, claim, frame.id, Some(0))
        .await
        .unwrap();

    // m(TRUE) = 0.8 vs m(FALSE) = 0.8 from two different writers:
    // K = 0.8 * 0.8 = 0.64.
    store(
        &pool,
        claim,
        frame.id,
        new_agent(&pool).await,
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;
    store(
        &pool,
        claim,
        frame.id,
        new_agent(&pool).await,
        serde_json::json!({"1": 0.8, "0,1": 0.2}),
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let preview = preview_claim_belief_on_frame(&mut conn, &viewer, claim, frame.id)
        .await
        .unwrap()
        .expect("two BBAs on the frame");
    assert!(
        (preview.conflict_k - 0.64).abs() < 1e-9,
        "the recompute must report the fold's conflict K = 0.64, got {}",
        preview.conflict_k
    );
    assert_eq!(
        preview.classification.as_deref(),
        Some("contradicted"),
        "K = 0.64 with an opposing source is classifier Rule 1 (contradicted)"
    );

    assert!(
        recompute_claim_belief_on_frame(&mut conn, &viewer, claim, frame.id)
            .await
            .unwrap(),
        "the recompute wrote the cache"
    );
    drop(conn);
    let (mass_on_empty, classification): (f64, Option<String>) =
        sqlx::query_as("SELECT mass_on_empty, classification FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        (mass_on_empty - 0.64).abs() < 1e-9,
        "claims.mass_on_empty must keep meaning 'conflict seen': got {mass_on_empty}"
    );
    assert_eq!(classification.as_deref(), Some("contradicted"));

    // The framed compute-on-read path must report the same conflict the cache
    // holds; otherwise `get_belief` with and without a frame disagree.
    let framed = epigraph_engine::belief_query::get_belief(&pool, &viewer, claim, Some(frame.id))
        .await
        .unwrap();
    assert!(
        (framed.mass_on_conflict - 0.64).abs() < 1e-9,
        "framed get_belief reported mass_on_conflict {}, cache holds 0.64",
        framed.mass_on_conflict
    );
}

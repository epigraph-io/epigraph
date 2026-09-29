//! Every reader of one (claim, frame) BBA set answers about the SAME hypothesis
//! (backlog 45cbaef4, G6).
//!
//! The cache writer (`edge_factor::compute_combined_belief`, behind
//! `recompute_claim_belief_on_frame`) resolved `claim_frames.hypothesis_index`
//! by clamping: a negative or past-the-end index meant hypothesis 0. The three
//! framed readers in `belief_query` did `unwrap_or(0) as usize`, so the same
//! row read as a hypothesis that does not exist (a negative index wraps to
//! `usize::MAX`) and reported Bel = Pl = BetP = 0 beside a cached belief about
//! hypothesis 0. Both now go through `edge_factor::resolve_hypothesis_index`.
//!
//! In-range indices are covered too, so the helper cannot "agree" by always
//! answering 0.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_engine::belief_query;
use epigraph_engine::edge_factor::{recompute_claim_belief_on_frame, resolve_hypothesis_index};
use uuid::Uuid;

#[test]
fn resolve_hypothesis_index_clamps_to_the_frame() {
    assert_eq!(resolve_hypothesis_index(None, 3), 0);
    assert_eq!(resolve_hypothesis_index(Some(0), 3), 0);
    assert_eq!(resolve_hypothesis_index(Some(2), 3), 2);
    assert_eq!(resolve_hypothesis_index(Some(3), 3), 0, "one past the end");
    assert_eq!(resolve_hypothesis_index(Some(-1), 3), 0, "negative");
    assert_eq!(resolve_hypothesis_index(Some(i32::MAX), 3), 0);
}

async fn claim_on_frame(pool: &PgPool, frame_id: Uuid, stored_index: i32) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!(
        "g6 claim at index {stored_index} {}",
        Uuid::new_v4()
    ))
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap();
    FrameRepository::assign_claim(pool, claim, frame_id, Some(stored_index))
        .await
        .unwrap();
    // Mass on hypothesis 0 and on hypothesis 2, so Bel differs by index:
    // Bel({0}) = 0.5, Bel({1}) = 0, Bel({2}) = 0.2.
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame_id,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.5, "2": 0.2, "0,1,2": 0.3}),
        None,
        None,
        None,
        Some("empirical"), // calibrated weight 1.0: no discount muddies the numbers
        "unknown",
        None,
    )
    .await
    .unwrap();
    claim
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_cache_and_every_framed_reader_agree_on_the_hypothesis(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let frame = FrameRepository::create(
        &pool,
        "g6_three_way",
        None,
        &["low".to_string(), "mid".to_string(), "high".to_string()],
    )
    .await
    .unwrap();
    let lens = PerspectiveRepository::create(
        &pool,
        "g6 no-opinion lens",
        None,
        None,
        None,
        &[],
        None,
        None,
    )
    .await
    .unwrap();

    for stored in [0, 2, 3, -1, 99] {
        let claim = claim_on_frame(&pool, frame.id, stored).await;

        let mut conn = pool.acquire().await.unwrap();
        assert!(
            recompute_claim_belief_on_frame(&mut conn, &viewer, claim, frame.id)
                .await
                .unwrap(),
            "the recompute wrote the cache"
        );
        drop(conn);
        let (c_bel, c_pl, c_betp): (f64, f64, f64) =
            sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
                .bind(claim)
                .fetch_one(&pool)
                .await
                .unwrap();

        let framed = belief_query::get_belief(&pool, &viewer, claim, Some(frame.id))
            .await
            .unwrap();
        let lensed = belief_query::get_perspective_belief(&pool, &viewer, claim, frame.id, lens.id)
            .await
            .unwrap();
        let batch =
            belief_query::get_perspective_belief_batch(&pool, &viewer, &[claim], frame.id, lens.id)
                .await
                .unwrap()
                .pop()
                .unwrap()
                .1
                .unwrap();

        for (who, b) in [
            ("get_belief", &framed),
            ("perspective", &lensed),
            ("batch", &batch),
        ] {
            for (what, cache, read) in [
                ("belief", c_bel, b.belief),
                ("plausibility", c_pl, b.plausibility),
                ("pignistic_prob", c_betp, b.pignistic_prob),
            ] {
                assert!(
                    (cache - read).abs() < 1e-9,
                    "stored index {stored}: {who} {what} = {read}, but the cache says {cache}"
                );
            }
        }

        // And the answer is about the RIGHT hypothesis, not a constant.
        let want_bel = match resolve_hypothesis_index(Some(stored), 3) {
            0 => 0.5,
            2 => 0.2,
            other => panic!("unexpected resolved index {other}"),
        };
        assert!(
            (framed.belief - want_bel).abs() < 1e-9,
            "stored index {stored}: Bel = {}, expected {want_bel}",
            framed.belief
        );
    }
}

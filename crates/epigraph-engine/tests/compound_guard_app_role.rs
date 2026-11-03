//! `edge_factor::recompute_claim_cached_belief`, the per-request refresh
//! behind `POST /api/v1/claims/:id/assess` and the BBA retract / un-retract
//! paths, never refolds a COMPOUND's cache on the caller's application
//! session, even when the caller's row security hides the compound's whole
//! decomposition (backlog 0dc20fad, migration 193).
//!
//! Every read and write runs on an `epigraph_app` transaction stamped from
//! the caller's viewer (`ScopedPool::begin_as`), as the request path stamps
//! it; fixtures are seeded and the cache read back on the harness superuser
//! pool. Expected values are sentinels the fold cannot produce.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("0dc20fad engine {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// `parent -decomposes_to-> child`, in force, its tenancy forced to
/// `(visibility, group)`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

async fn bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid) {
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("0dc20fad-engine-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed perspective");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, source_strength) \
         VALUES ($1, $2, $3, $4, $5, 1.0)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(perspective)
    .bind(serde_json::json!({"0": 0.7, "0,1": 0.3}))
    .execute(pool)
    .await
    .expect("seed BBA");
}

/// `(belief, plausibility, pignistic_prob, belief_frame_id)` of the cache.
async fn cache(
    pool: &PgPool,
    claim: Uuid,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// A cache no fold of the seeded BBA produces, recorded on `frame`.
async fn sentinel(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                belief_frame_id = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
}

const SENTINEL: (Option<f64>, Option<f64>, Option<f64>) = (Some(0.613), Some(0.887), Some(0.741));

/// The caller writes its own group's public compound `hidden`, whose only
/// child (and the edge to it) is private to another group. On the caller's
/// stamped application transaction the refresh writes nothing and the
/// compound keeps its sentinel cache. CALIBRATION in the same transaction: a
/// standalone twin holding the same BBA, with the same sentinel, IS refolded,
/// so the session can read the BBA rows and write the cache.
#[sqlx::test(migrations = "../../migrations")]
async fn the_refresh_leaves_a_compound_whose_decomposition_the_caller_cannot_see(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "0dc20fad-engine-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "0dc20fad-engine-other").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("0dc20fad-engine-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");

    let hidden = claim(&pool, caller, mine, "public", "compound").await;
    let child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, child, "group", theirs).await;
    let twin = claim(&pool, caller, mine, "public", "standalone twin").await;
    for c in [hidden, twin] {
        bba(&pool, caller, c, frame).await;
        sentinel(&pool, c, frame).await;
    }

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("session_user");
    assert_eq!(who, "epigraph_app");
    let hidden_written =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut tx, &viewer, hidden)
            .await
            .expect("refresh the compound");
    let twin_written =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut tx, &viewer, twin)
            .await
            .expect("refresh the twin");
    tx.commit().await.expect("commit");

    let twin_after = cache(&pool, twin).await;
    assert!(
        twin_written && (twin_after.0, twin_after.1, twin_after.2) != SENTINEL,
        "calibration: the app session refolds a standalone claim's cache (written \
         {twin_written}, cache {twin_after:?})"
    );
    let hidden_after = cache(&pool, hidden).await;
    assert!(
        !hidden_written,
        "0dc20fad: the refresh must not write a compound's cache on the caller's session"
    );
    assert_eq!(
        (hidden_after.0, hidden_after.1, hidden_after.2),
        SENTINEL,
        "0dc20fad: the compound's cache was refolded from its own BBA: {hidden_after:?}"
    );
    assert_eq!(
        hidden_after.3,
        Some(frame),
        "the recorded owner is untouched"
    );
}

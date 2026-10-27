//! MCP `retract_bba` (operator ruling R-79, migration 184), the twin of
//! `POST /api/v1/mass-functions/:id/retract`, driven on the APPLICATION ROLE.
//!
//! Both of the server's pools are downgraded to `epigraph_app` (the shape of
//! `writer_owned_attach_app_role.rs`), so the database's refusals happen here
//! as in production. Fixtures are seeded, and state read back, on the harness
//! superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::bba_retract::{retract_bba, RetractBbaParams};
use sqlx::PgPool;
use uuid::Uuid;

const EPS: f64 = 1e-9;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

async fn owned_public_claim(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("r79 mcp claim {tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// One BBA of `agent` on (claim, frame) under a fresh perspective, seeded on
/// the harness pool (tenancy follows the claim, migration 074).
async fn seed_bba(
    pool: &PgPool,
    agent: Uuid,
    claim: Uuid,
    frame: Uuid,
    masses: serde_json::Value,
) -> Uuid {
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("r79-mcp-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed perspective");
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, source_strength) \
         VALUES ($1, $2, $3, $4, $5, 1.0) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(perspective)
    .bind(masses)
    .fetch_one(pool)
    .await
    .expect("seed BBA")
}

/// Recompute `claim`'s cache on the harness connection with `viewer`, and read
/// it back.
async fn recomputed(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> (f64, f64, f64) {
    let mut conn = pool.acquire().await.expect("acquire");
    assert!(
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, viewer, claim)
            .await
            .expect("recompute"),
        "the control's cache is written"
    );
    drop(conn);
    cached(pool, claim).await
}

async fn cached(pool: &PgPool, claim: Uuid) -> (f64, f64, f64) {
    let (b, p, t): (Option<f64>, Option<f64>, Option<f64>) =
        sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("read the cache");
    (
        b.expect("belief"),
        p.expect("plausibility"),
        t.expect("pignistic"),
    )
}

fn close(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    (a.0 - b.0).abs() < EPS && (a.1 - b.1).abs() < EPS && (a.2 - b.2).abs() < EPS
}

async fn audit_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'mass_functions.retract' AND details->>'mass_function_id' = $1::text",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

async fn is_retracted(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read the row")
}

fn params(id: Uuid, reason: &str) -> RetractBbaParams {
    RetractBbaParams {
        mass_function_id: id.to_string(),
        reason: reason.to_string(),
    }
}

/// The owner retracts one of its claim's two BBAs over MCP: the claim's cache
/// becomes exactly the fold of the remaining BBA (a control claim holding only
/// that BBA), not the two-BBA fold (a control holding both); a repeat answers
/// `already_retracted` with one audit row in total.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_retracts_over_mcp_and_the_belief_is_the_remaining_bbas(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (owner, owner_auth, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let group = personal_group_of(&pool, owner).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r79-mcp-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let support = serde_json::json!({"0": 0.9, "0,1": 0.1});
    let refute = serde_json::json!({"1": 0.6, "0,1": 0.4});
    let claim = owned_public_claim(&pool, owner, group, "target").await;
    let only_refute = owned_public_claim(&pool, owner, group, "control one").await;
    let both = owned_public_claim(&pool, owner, group, "control two").await;
    let target = seed_bba(&pool, owner, claim, frame, support.clone()).await;
    seed_bba(&pool, owner, claim, frame, refute.clone()).await;
    seed_bba(&pool, owner, only_refute, frame, refute.clone()).await;
    seed_bba(&pool, owner, both, frame, support).await;
    seed_bba(&pool, owner, both, frame, refute).await;
    let expected = recomputed(&pool, &owner_viewer, only_refute).await;
    let unretracted = recomputed(&pool, &owner_viewer, both).await;
    assert!(
        !close(expected, unretracted),
        "calibration: the one-BBA and two-BBA folds must differ"
    );

    let res = retract_bba(
        &server,
        &owner_viewer,
        params(target, "duplicate re-observation"),
        Some(&owner_auth),
    )
    .await
    .expect("the owner retracts its BBA over MCP");
    let body = first_text(&res);
    assert_eq!(body["status"], "retracted", "{body}");
    assert_eq!(body["arm"], "owner", "{body}");
    assert_eq!(body["retracted_by"], owner.to_string(), "{body}");
    assert_eq!(body["belief_recomputed"], true, "{body}");
    let after = cached(&pool, claim).await;
    assert!(
        close(after, expected),
        "after the retraction the claim's belief {after:?} must be the remaining BBA's \
         {expected:?}, not the two-BBA fold {unretracted:?}"
    );
    assert!(
        is_retracted(&pool, target).await,
        "the row is kept, retracted"
    );

    let again = retract_bba(
        &server,
        &owner_viewer,
        params(target, "again"),
        Some(&owner_auth),
    )
    .await
    .expect("a repeat is not an error");
    let again = first_text(&again);
    assert_eq!(again["status"], "already_retracted", "{again}");
    assert_eq!(
        audit_count(&pool, target).await,
        1,
        "one audit row in total"
    );
}

/// Refusals over MCP: a stranger that can read the owner's public BBA is
/// refused; a BBA on a group-private claim it cannot read is "not found", in
/// the SAME words as a random id; nothing is written. A `claims:admin` token
/// whose client record holds the grant retracts it, recorded as the admin.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_is_refused_an_unreadable_bba_is_not_found_and_an_admin_retracts(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (owner, _, _) = seed_caller(&pool, &["claims:write"]).await;
    let group = personal_group_of(&pool, owner).await;
    let (_, stranger_auth, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (admin, mut admin_auth, admin_viewer) =
        seed_caller(&pool, &["claims:write", "claims:admin"]).await;
    admin_auth.client_type = epigraph_auth::ClientType::Human;
    seed_admin_grant(&pool, &admin_auth).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r79-mcp-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let claim = owned_public_claim(&pool, owner, group, "public").await;
    let target = seed_bba(
        &pool,
        owner,
        claim,
        frame,
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    let private_claim = fixture::seed_group_claim(&pool, owner, group, "r79 mcp private").await;
    let hidden = seed_bba(
        &pool,
        owner,
        private_claim,
        frame,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;

    let refused = retract_bba(
        &server,
        &stranger_viewer,
        params(target, "not mine"),
        Some(&stranger_auth),
    )
    .await
    .expect_err("a stranger may not retract the owner's BBA");
    assert!(
        refused
            .message
            .contains("only a writer of the mass function's owning group"),
        "{refused:?}"
    );
    let hidden_err = retract_bba(
        &server,
        &stranger_viewer,
        params(hidden, "hidden"),
        Some(&stranger_auth),
    )
    .await
    .expect_err("an unreadable BBA is not found");
    let random = Uuid::new_v4();
    let random_err = retract_bba(
        &server,
        &stranger_viewer,
        params(random, "random"),
        Some(&stranger_auth),
    )
    .await
    .expect_err("a random id is not found");
    assert_eq!(
        hidden_err.message.replace(&hidden.to_string(), "<id>"),
        random_err.message.replace(&random.to_string(), "<id>"),
        "an unreadable BBA and a random id get the same answer"
    );
    for id in [target, hidden] {
        assert!(!is_retracted(&pool, id).await);
        assert_eq!(audit_count(&pool, id).await, 0);
    }

    let res = retract_bba(
        &server,
        &admin_viewer,
        params(target, "promotion duplicate"),
        Some(&admin_auth),
    )
    .await
    .expect("a live claims:admin grant retracts another owner's BBA");
    let body = first_text(&res);
    assert_eq!(body["arm"], "admin", "{body}");
    assert_eq!(body["retracted_by"], admin.to_string(), "{body}");
    assert_eq!(audit_count(&pool, target).await, 1);
}

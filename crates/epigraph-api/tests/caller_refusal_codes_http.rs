#![cfg(feature = "db")]
//! Backlog e2c22c7c (ruling R-25), HTTP half: a designed database refusal an
//! API caller can reach answers with its refusal CODE and a 4xx, not the
//! generic 500 "A database error occurred".
//!
//! Three representative refusals, each raised for real by the database on the
//! write the API makes:
//!
//! * AGK01 (55000), migration 148's guard on `agents`: `POST /api/v1/agents`
//!   with a public key registered for a system agent that has since rotated
//!   off it. Driven through the real router.
//! * GRM05 (42501), migration 164's roster guard: an application-role write
//!   to a team group's roster (`GroupMembershipRepository::add_member`, the
//!   HTTP add-member write), mapped by `From<DbError> for ApiError`.
//! * PRV01 (42501), migration 081's sealing guard: an application-role
//!   `claim_encryption` row for a public claim
//!   (`ClaimEncryptionRepository::insert_conn`, the HTTP claim create's
//!   sealing write), mapped the same way.
//!
//! And the fail-closed edge: an UNCODED database refusal with the same
//! SQLSTATE still answers the redacted 500.

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    response::IntoResponse,
};
use epigraph_api::{create_router, ApiConfig, ApiError, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn token(scopes: &[&str], agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn body_of(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The status and JSON body `ApiError::from(e)` answers.
async fn http_answer(e: epigraph_db::DbError) -> (StatusCode, Value) {
    body_of(ApiError::from(e).into_response()).await
}

/// A team group (migration 164's shape: keyless, `did:epigraph:group:<id>`),
/// written on the harness superuser, which the guards treat as a maintenance
/// session.
async fn seed_team_group(pool: &PgPool, admin: Uuid) -> Uuid {
    let group = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'refusal-code team', 'did:epigraph:group:' || $1::text, ''::bytea, 'team', $2)",
    )
    .bind(group)
    .bind(admin)
    .execute(pool)
    .await
    .expect("seed a team group");
    group
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_system_key_answers_409_with_agk01_over_http(pool: PgPool) {
    // A system agent registered under key K, then rotated off it: K stays
    // registered, so migration 148 refuses any other agent holding it.
    let key: [u8; 32] = *blake3::hash(b"refusal-code registered key").as_bytes();
    let system: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'refusal-code system') \
         RETURNING id",
    )
    .bind(key.as_slice())
    .fetch_one(&pool)
    .await
    .expect("seed the system agent");
    assert!(fixture::register_system_agent(&pool, system).await);
    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(system)
    .execute(&pool)
    .await
    .expect("rotate the system agent off K");

    let caller: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'refusal-code caller') \
         RETURNING id",
    )
    .bind(blake3::hash(b"refusal-code caller").as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("seed the caller");

    let app = create_router(AppState::with_db(pool.clone(), ApiConfig::default()));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agents")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", token(&["agents:write"], caller)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "public_key": hex::encode(key), "display_name": "squatter" }).to_string(),
        ))
        .unwrap();
    let (status, body) = body_of(app.oneshot(request).await.unwrap()).await;
    let text = body.to_string();

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a key registered for a system agent is a 409 the caller can read, not a 500: {text}"
    );
    assert!(
        text.contains("AGK01:") && text.contains("registered for a system agent"),
        "the body carries the refusal code and its reason: {text}"
    );
    assert!(
        !text.contains("workflow-ingest"),
        "the reply names no system identity (the role is in DETAIL only): {text}"
    );
    let holders: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(holders, 0, "nothing was written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_team_group_roster_write_answers_403_with_grm05(pool: PgPool) {
    let (admin, _) = fixture::seed_agent_with_group(&pool, "refusal-code admin").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "refusal-code member").await;
    let team = seed_team_group(&pool, admin).await;

    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let refused = epigraph_db::GroupMembershipRepository::add_member(
        &app_pool,
        team,
        member,
        &[],
        0,
        "writer",
    )
    .await
    .expect_err("an application write to a team group's roster is refused");
    let (status, body) = http_answer(refused).await;
    let text = body.to_string();

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the roster refusal is a denial (42501 -> 403), not a 500: {text}"
    );
    assert!(
        text.contains("GRM05:") && text.contains("team-group verbs"),
        "the body carries the refusal code and the remedy: {text}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn sealing_a_public_claim_answers_403_with_prv01(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "refusal-code author").await;
    let claim = fixture::seed_public_claim(&pool, author, "refusal-code public claim").await;

    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = app_pool.acquire().await.expect("app conn");
    let refused = epigraph_db::ClaimEncryptionRepository::insert_conn(
        &mut conn,
        claim,
        group,
        0,
        "fully_private",
        b"ciphertext",
        None,
    )
    .await
    .expect_err("sealing a public claim is refused");
    let (status, body) = http_answer(refused).await;
    let text = body.to_string();

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the sealing refusal is a denial (42501 -> 403), not a 500: {text}"
    );
    assert!(
        text.contains("PRV01:") && text.contains("Restrict first, then seal"),
        "the body carries the refusal code and the remedy: {text}"
    );
}

/// Fail closed: a database refusal WITHOUT a refusal code keeps the redacted
/// 500 even when its SQLSTATE (42501) is one the coded arm maps to 403.
#[sqlx::test(migrations = "../../migrations")]
async fn an_uncoded_refusal_keeps_the_redacted_500(pool: PgPool) {
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let e = sqlx::query("SELECT public.epigraph_register_system_agent('x', $1, 'y')")
        .bind(Uuid::new_v4())
        .execute(&app_pool)
        .await
        .expect_err("the application role may not EXECUTE the registry verb");
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42501")
    );
    let (status, body) = http_answer(epigraph_db::DbError::from(e)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(
        !body.to_string().contains("permission denied"),
        "the uncoded database text stays server-side: {body}"
    );
}

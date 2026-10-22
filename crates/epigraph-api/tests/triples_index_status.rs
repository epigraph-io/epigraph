//! `POST /api/v1/triples/query` and `GET /api/v1/entities/:id/neighborhood`
//! report whether the triple index is populated, and `query_triples` returns
//! nothing for a name it cannot resolve.
//!
//! The MCP tools over the same index are pinned in
//! `crates/epigraph-mcp/tests/rdf_index_status.rs`; these arms pin the HTTP
//! side. Responses are read as JSON so the assertions are about the wire shape
//! a client sees.
//!
//! Every handler here reads through `AppState::read_as`, so `index_populated`
//! is evaluated on the caller's viewer-stamped connection: it says whether any
//! triple is visible to THIS caller.

mod viewer_fixture;

use axum::extract::{Path, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::entities::{entity_neighborhood, query_triples, QueryTriplesRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_api::ApiError;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{public_viewer, scoped_pool, seed_agent_with_group, seed_public_claim};

/// An `AppState` whose `read_as` hands out viewer-stamped connections.
async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

fn request(
    subject: Option<(&str, Option<&str>)>,
    object: Option<(&str, Option<&str>)>,
) -> QueryTriplesRequest {
    QueryTriplesRequest {
        subject_name: subject.map(|(n, _)| n.to_string()),
        subject_type: subject.and_then(|(_, t)| t.map(str::to_string)),
        predicate: None,
        object_name: object.map(|(n, _)| n.to_string()),
        object_type: object.and_then(|(_, t)| t.map(str::to_string)),
        min_confidence: None,
        limit: Some(50),
    }
}

async fn seed_entity(pool: &PgPool, name: &str, type_top: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, $2, true) RETURNING id",
    )
    .bind(name)
    .bind(type_top)
    .fetch_one(pool)
    .await
    .expect("seed entity")
}

/// One public triple `silicon(Material) --is_a--> semiconductor(Concept)`;
/// returns `(triple_id, subject_entity_id)`.
async fn seed_public_triple(pool: &PgPool) -> (Uuid, Uuid) {
    let (agent, _group) = seed_agent_with_group(pool, "http-rdf-index").await;
    let claim = seed_public_claim(pool, agent, "silicon is a semiconductor").await;
    let subject = seed_entity(pool, "silicon", "Material").await;
    let object = seed_entity(pool, "semiconductor", "Concept").await;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO triples (claim_id, subject_id, predicate, object_id, confidence, extractor) \
         VALUES ($1, $2, 'is_a', $3, 0.9, 'test') RETURNING id",
    )
    .bind(claim)
    .bind(subject)
    .bind(object)
    .fetch_one(pool)
    .await
    .expect("seed triple");
    let visibility: String =
        sqlx::query_scalar("SELECT visibility::text FROM triples WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read back triple tenancy");
    assert_eq!(
        visibility, "public",
        "CALIBRATION: the seeded triple must be public, or the arms assert nothing"
    );
    (id, subject)
}

async fn query(pool: &PgPool, req: QueryTriplesRequest) -> Result<serde_json::Value, ApiError> {
    let viewer = public_viewer(pool).await;
    query_triples(
        ViewerExtractor(viewer),
        State(state(pool).await),
        axum::Json(req),
    )
    .await
    .map(|r| serde_json::to_value(r.0).expect("serialize response"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_reports_whether_the_index_is_populated(pool: PgPool) {
    let empty = query(&pool, request(None, None))
        .await
        .expect("query on an empty index");
    assert_eq!(
        empty["index_populated"],
        serde_json::json!(false),
        "got {empty}"
    );

    seed_public_triple(&pool).await;

    let populated = query(&pool, request(None, None))
        .await
        .expect("query on a populated index");
    assert_eq!(
        populated["index_populated"],
        serde_json::json!(true),
        "got {populated}"
    );
    assert_eq!(populated["count"], serde_json::json!(1), "got {populated}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn entity_neighborhood_reports_whether_the_index_is_populated(pool: PgPool) {
    let (triple, subject) = seed_public_triple(&pool).await;

    let viewer = public_viewer(&pool).await;
    let v = entity_neighborhood(
        ViewerExtractor(viewer),
        State(state(&pool).await),
        Path(subject),
    )
    .await
    .map(|r| serde_json::to_value(r.0).expect("serialize response"))
    .expect("neighborhood of a seeded entity");

    assert_eq!(v["index_populated"], serde_json::json!(true), "got {v}");
    assert_eq!(v["count"], serde_json::json!(1), "got {v}");
    assert_eq!(
        v["triples"][0]["id"],
        serde_json::json!(triple.to_string()),
        "got {v}"
    );
}

/// The handler's own rustdoc promised "an empty list when a named entity does
/// not exist"; it returned the top-confidence triples of the whole index.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_unresolved_subject_returns_nothing(pool: PgPool) {
    seed_public_triple(&pool).await;

    let v = query(
        &pool,
        request(Some(("no-such-entity", Some("Material"))), None),
    )
    .await
    .expect("query with an unresolved subject");
    assert_eq!(
        v["count"],
        serde_json::json!(0),
        "the subject names no entity; returning the seeded triple means the name \
         became a wildcard. Got {v}"
    );
    assert_eq!(v["unresolved"], serde_json::json!(["subject"]), "got {v}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_resolved_names_still_match(pool: PgPool) {
    let (triple, _) = seed_public_triple(&pool).await;

    let v = query(
        &pool,
        request(
            Some(("silicon", Some("Material"))),
            Some(("semiconductor", Some("Concept"))),
        ),
    )
    .await
    .expect("query with resolved names");
    assert_eq!(v["count"], serde_json::json!(1), "got {v}");
    assert_eq!(
        v["triples"][0]["id"],
        serde_json::json!(triple.to_string()),
        "got {v}"
    );
    assert_eq!(v["unresolved"], serde_json::json!([]), "got {v}");
}

/// A name with no type used to be dropped from the filter without a word, so
/// the call wildcarded. It is now a 400.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_refuses_a_name_without_a_type(pool: PgPool) {
    seed_public_triple(&pool).await;

    let res = query(&pool, request(Some(("silicon", None)), None)).await;
    match res {
        Err(ApiError::BadRequest { message }) => assert!(
            message.contains("subject_type"),
            "the refusal must name the missing field. Got: {message}"
        ),
        other => panic!("expected a 400 naming subject_type, got {other:?}"),
    }
}

//! The three RDF read tools must not let an empty index pass for a negative
//! answer, and `query_triples` must not turn a name it could not resolve into
//! a wildcard.
//!
//! No pipeline populates the `entities` / `triples` index today, so every call
//! to `query_triples`, `search_triples` or `entity_neighborhood` comes back
//! empty. Before this file, that empty answer was indistinguishable from "the
//! index is populated and nothing matched", and agents filed index-outage
//! tickets on the strength of it. Each response now carries `index_populated`.
//!
//! **`index_populated` is viewer-relative.** It answers "is any triple visible
//! to this caller", through the same tenancy predicate the reads themselves
//! use, so it cannot disclose that a private row exists.
//! [`index_populated_does_not_disclose_another_groups_triple`] pins that.
//!
//! Every arm seeds rows straight into the tables and then calibrates their
//! tenancy, because the triples insert trigger rewrites `visibility` /
//! `owner_group_id` from the parent claim: an arm whose seeded triple the caller
//! cannot see would assert nothing.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_mcp::tools::rdf::{entity_neighborhood, query_triples, search_triples};
use epigraph_mcp::types::{EntityNeighborhoodParams, QueryTriplesParams, SearchTriplesParams};
use rmcp::model::CallToolResult;
use sqlx::PgPool;
use uuid::Uuid;

// ── helpers ──

fn body(result: CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("tool returned text content");
    serde_json::from_str(&text).expect("tool returned JSON")
}

fn params(
    subject: Option<(&str, Option<&str>)>,
    object: Option<(&str, Option<&str>)>,
) -> QueryTriplesParams {
    QueryTriplesParams {
        subject: subject.map(|(n, _)| n.to_string()),
        subject_type: subject.and_then(|(_, t)| t.map(str::to_string)),
        predicate: None,
        object: object.map(|(n, _)| n.to_string()),
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

/// Insert `(subject) --predicate--> (object)` attributed to `claim`, and check
/// that the row landed with the tenancy `expect_visibility` names (inherited
/// from the claim by the insert trigger).
async fn seed_triple(
    pool: &PgPool,
    claim: Uuid,
    subject: Uuid,
    predicate: &str,
    object: Uuid,
    expect_visibility: &str,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO triples (claim_id, subject_id, predicate, object_id, confidence, extractor) \
         VALUES ($1, $2, $3, $4, 0.9, 'test') RETURNING id",
    )
    .bind(claim)
    .bind(subject)
    .bind(predicate)
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
        visibility, expect_visibility,
        "CALIBRATION: the seeded triple did not inherit the tenancy the arm relies on"
    );
    id
}

/// One public triple `silicon(Material) --is_a--> semiconductor(Concept)`.
async fn seed_public_triple(pool: &PgPool) -> Uuid {
    let (agent, _group) = fixture::seed_agent_with_group(pool, "rdf-index-author").await;
    let claim = fixture::seed_public_claim(pool, agent, "silicon is a semiconductor").await;
    let subject = seed_entity(pool, "silicon", "Material").await;
    let object = seed_entity(pool, "semiconductor", "Concept").await;
    seed_triple(pool, claim, subject, "is_a", object, "public").await
}

// ── index_populated ──

/// The ruling's first failing test. The SAME call must report `false` on an
/// empty index and `true` once a visible triple exists, so a hard-coded value
/// fails one half or the other.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_discloses_whether_the_index_is_populated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let empty = body(
        query_triples(&server, &viewer, params(None, None))
            .await
            .expect("query_triples on an empty index"),
    );
    assert_eq!(
        empty["index_populated"],
        serde_json::json!(false),
        "an empty index must say so, or count 0 reads as a negative answer. Got {empty}"
    );

    seed_public_triple(&pool).await;

    let populated = body(
        query_triples(&server, &viewer, params(None, None))
            .await
            .expect("query_triples on a populated index"),
    );
    assert_eq!(
        populated["index_populated"],
        serde_json::json!(true),
        "a visible triple exists, so the index is populated. Got {populated}"
    );
}

/// `index_populated` goes through the tenancy predicate: a triple private to
/// another group leaves it `false` for the public viewer and `true` for a member
/// of the owning group. A corpus-wide count would be `true` for both, which
/// would tell the public viewer that a private row exists.
#[sqlx::test(migrations = "../../migrations")]
async fn index_populated_does_not_disclose_another_groups_triple(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "rdf-index-private").await;
    let claim = fixture::seed_group_claim(&pool, owner, group, "private triple claim").await;
    let subject = seed_entity(&pool, "private-subject", "Concept").await;
    let object = seed_entity(&pool, "private-object", "Concept").await;
    seed_triple(&pool, claim, subject, "relates_to", object, "group").await;

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let public = fixture::public_viewer(&pool).await;
    let as_public = body(
        query_triples(&server, &public, params(None, None))
            .await
            .expect("query_triples as the public viewer"),
    );
    assert_eq!(
        as_public["index_populated"],
        serde_json::json!(false),
        "the only triple is private to a group the public viewer is not in. Got {as_public}"
    );

    let member = epigraph_db::visibility::Viewer::resolve(&pool, owner)
        .await
        .expect("resolve the owning agent");
    let as_member = body(
        query_triples(&server, &member, params(None, None))
            .await
            .expect("query_triples as a member"),
    );
    assert_eq!(
        as_member["index_populated"],
        serde_json::json!(true),
        "a member of the owning group can see the triple. Got {as_member}"
    );
}

/// `search_triples` reports the empty index too, and on an empty index it
/// answers without the embedding call. The test server has no embedding key, so
/// a handler that still embeds first fails here instead of answering.
#[sqlx::test(migrations = "../../migrations")]
async fn search_triples_on_an_empty_index_says_so(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let v = body(
        search_triples(
            &server,
            &viewer,
            SearchTriplesParams {
                query: "what is silicon".to_string(),
                limit: Some(10),
            },
        )
        .await
        .expect("search_triples on an empty index must answer, not fail on the embedder"),
    );
    assert_eq!(v["index_populated"], serde_json::json!(false), "got {v}");
    assert_eq!(v["count"], serde_json::json!(0), "got {v}");
}

/// A miss on an empty index says the index is empty. A miss on a populated
/// index does not, and a hit carries `index_populated: true`.
#[sqlx::test(migrations = "../../migrations")]
async fn entity_neighborhood_reports_the_empty_index(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let miss = |name: &str| EntityNeighborhoodParams {
        entity: name.to_string(),
        entity_type: Some("Material".to_string()),
    };

    let err = entity_neighborhood(&server, &viewer, miss("silicon"))
        .await
        .expect_err("no entity exists yet");
    assert!(
        err.message.contains("index is empty"),
        "a miss on an empty index must say the index is empty. Got: {}",
        err.message
    );

    seed_public_triple(&pool).await;

    let err = entity_neighborhood(&server, &viewer, miss("germanium"))
        .await
        .expect_err("germanium was never seeded");
    assert!(
        !err.message.contains("index is empty"),
        "the index now holds a visible triple, so a miss is a real miss. Got: {}",
        err.message
    );

    let hit = body(
        entity_neighborhood(&server, &viewer, miss("silicon"))
            .await
            .expect("silicon was seeded"),
    );
    assert_eq!(hit["index_populated"], serde_json::json!(true), "got {hit}");
    assert_eq!(hit["triple_count"], serde_json::json!(1), "got {hit}");
}

// ── unresolved names ──

/// A subject name that resolves to no entity returns NOTHING, flagged
/// `unresolved`, rather than wildcarding the subject filter and returning the
/// top-confidence triples of the whole index.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_unresolved_subject_returns_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    seed_public_triple(&pool).await;

    let v = body(
        query_triples(
            &server,
            &viewer,
            params(Some(("no-such-entity", Some("Material"))), None),
        )
        .await
        .expect("query_triples with an unresolved subject"),
    );
    assert_eq!(
        v["count"],
        serde_json::json!(0),
        "the subject names no entity, so no triple can match; returning the seeded \
         triple means the unresolved name became a wildcard. Got {v}"
    );
    assert_eq!(v["unresolved"], serde_json::json!(["subject"]), "got {v}");
}

/// The same for the object side, with the subject resolved: the object filter
/// must not silently drop out.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_unresolved_object_returns_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    seed_public_triple(&pool).await;

    let v = body(
        query_triples(
            &server,
            &viewer,
            params(
                Some(("silicon", Some("Material"))),
                Some(("no-such-object", Some("Concept"))),
            ),
        )
        .await
        .expect("query_triples with an unresolved object"),
    );
    assert_eq!(v["count"], serde_json::json!(0), "got {v}");
    assert_eq!(v["unresolved"], serde_json::json!(["object"]), "got {v}");
}

/// Both names resolve: the seeded triple comes back and nothing is flagged.
/// Guards against a fix that returns nothing whenever a name is given.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_resolved_names_still_match(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let triple = seed_public_triple(&pool).await;

    let v = body(
        query_triples(
            &server,
            &viewer,
            params(
                Some(("silicon", Some("Material"))),
                Some(("semiconductor", Some("Concept"))),
            ),
        )
        .await
        .expect("query_triples with resolved names"),
    );
    assert_eq!(v["count"], serde_json::json!(1), "got {v}");
    assert_eq!(
        v["triples"][0]["id"],
        serde_json::json!(triple.to_string()),
        "got {v}"
    );
    assert_eq!(v["unresolved"], serde_json::json!([]), "got {v}");
}

/// A name without a type is refused. Entities are keyed by `(name, type_top)`,
/// and the old hidden `"Material"` default made a correctly named `Concept`
/// entity miss, after which the miss wildcarded.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_refuses_a_name_without_a_type(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    seed_public_triple(&pool).await;

    let err = query_triples(
        &server,
        &viewer,
        params(None, Some(("semiconductor", None))),
    )
    .await
    .expect_err("an object name with no object_type must be refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("object_type"),
        "the refusal must name the missing parameter. Got: {}",
        err.message
    );
}

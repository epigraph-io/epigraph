//! The entity, mention and triple writes on the APPLICATION ROLE (backlog
//! 850dcc61).
//!
//! `entity_triple_write_authz.rs` drives these routes over HTTP on the test
//! superuser, which bypasses row security, so it proves the handler's own
//! target-claim check and nothing about the database. This file proves the
//! other half: the writes now run on a transaction stamped with the caller's
//! viewer, and on `epigraph_app` (no BYPASSRLS, the `*_tenancy` policies FORCEd)
//! the owner's writes COMMIT. A write that passed under the superuser and was
//! refused in production would fail here and nowhere else.
//!
//! Both pools of the `AppState` are the application role, as in
//! `own_claim_authority_http.rs`; handlers are invoked directly with the
//! caller's `ViewerExtractor`.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, RequireScopeWrite, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::entities::{
    batch_create_mentions, batch_create_triples, create_entity, BatchMentionItem,
    BatchMentionsRequest, BatchTripleItem, BatchTriplesRequest, CreateEntityRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve"))
}

fn write_scope(agent: Uuid) -> RequireScopeWrite {
    RequireScopeWrite(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    })
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(format!("850dcc61 app-role claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `(owner_group_id, visibility)` of every `table` row on `claim`, read on the
/// superuser harness connection so nothing is filtered.
async fn tenancy_of_rows(pool: &PgPool, table: &str, claim: Uuid) -> Vec<(Uuid, String)> {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE claim_id = $1"
    ))
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("rows")
}

fn triple(claim: Uuid, subject: Uuid) -> BatchTripleItem {
    BatchTripleItem {
        claim_id: claim,
        subject_id: subject,
        predicate: "is_a".to_string(),
        object_id: None,
        object_literal: Some("probe".to_string()),
        confidence: 0.9,
        extractor: "850dcc61-app-role".to_string(),
        properties: None,
    }
}

fn mention(claim: Uuid, entity: Uuid) -> BatchMentionItem {
    BatchMentionItem {
        entity_id: entity,
        claim_id: claim,
        surface_form: "probe".to_string(),
        mention_role: "subject".to_string(),
        confidence: 0.9,
        extractor: "850dcc61-app-role".to_string(),
        span_start: None,
        span_end: None,
    }
}

/// The owner creates an entity, then attaches mentions and triples to its own
/// private and public claims, all on the application role; every row commits
/// and carries its claim's tenancy.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owners_entity_mentions_and_triples_commit_on_the_application_role(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (owner, og) = seed_agent_with_group(&pool, "850-app-owner").await;
    let private = claim_of(&pool, owner, og, "group").await;
    let public = claim_of(&pool, owner, og, "public").await;

    let Json(e) = create_entity(
        State(state.clone()),
        write_scope(owner),
        viewer(&pool, owner).await,
        Json(CreateEntityRequest {
            canonical_name: format!("850dcc61 app-role entity {}", Uuid::new_v4()),
            type_top: "Material".to_string(),
            type_sub: None,
            properties: None,
        }),
    )
    .await
    .unwrap_or_else(|err| panic!("create_entity on the app role: {err:?}"));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM entities WHERE id = $1")
        .bind(e.id)
        .fetch_one(&pool)
        .await
        .expect("entity row");
    assert_eq!(stored, 1, "the entity committed");

    let Json(m) = batch_create_mentions(
        State(state.clone()),
        write_scope(owner),
        viewer(&pool, owner).await,
        Json(BatchMentionsRequest {
            mentions: vec![mention(private, e.id), mention(public, e.id)],
        }),
    )
    .await
    .unwrap_or_else(|err| panic!("mentions on the app role: {err:?}"));
    assert_eq!(m.count, 2);

    let Json(t) = batch_create_triples(
        State(state.clone()),
        write_scope(owner),
        viewer(&pool, owner).await,
        Json(BatchTriplesRequest {
            triples: vec![triple(private, e.id), triple(public, e.id)],
        }),
    )
    .await
    .unwrap_or_else(|err| panic!("triples on the app role: {err:?}"));
    assert_eq!(t.count, 2);

    for table in ["entity_mentions", "triples"] {
        assert_eq!(
            tenancy_of_rows(&pool, table, private).await,
            vec![(og, "group".to_string())],
            "{table} on the private claim"
        );
        assert_eq!(
            tenancy_of_rows(&pool, table, public).await,
            vec![(og, "public".to_string())],
            "{table} on the public claim"
        );
    }
}

/// On the application role a stranger's batch naming another group's private
/// claim is `404` and writes nothing, the same answer as over HTTP on the
/// superuser: the handler resolves the claim through the stamped viewer, and
/// row security agrees with the in-query predicate.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_batch_is_refused_on_the_application_role(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (owner, og) = seed_agent_with_group(&pool, "850-app-owner").await;
    let (stranger, sg) = seed_agent_with_group(&pool, "850-app-stranger").await;
    let theirs = claim_of(&pool, owner, og, "group").await;
    let mine = claim_of(&pool, stranger, sg, "group").await;
    let e: Uuid = sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, 'Material', true) RETURNING id",
    )
    .bind(format!("850dcc61 app-role entity {}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed entity");

    let err = batch_create_triples(
        State(state.clone()),
        write_scope(stranger),
        viewer(&pool, stranger).await,
        Json(BatchTriplesRequest {
            triples: vec![triple(mine, e), triple(theirs, e)],
        }),
    )
    .await
    .err()
    .expect("refused");
    assert_eq!(err.into_response().status().as_u16(), 404);
    assert!(tenancy_of_rows(&pool, "triples", mine).await.is_empty());
    assert!(tenancy_of_rows(&pool, "triples", theirs).await.is_empty());
}

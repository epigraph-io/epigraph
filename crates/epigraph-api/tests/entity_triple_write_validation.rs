//! The entity-mention and triple batch writes refuse an oversize batch and an
//! out-of-range confidence with `400`, before anything is written (backlog
//! 591b2f6f).
//!
//! `POST /api/v1/entity-mentions/batch` and `POST /api/v1/triples/batch`
//! accepted any number of items and any `f64` confidence; neither table has a
//! CHECK on `confidence`, so `1.5`, `-0.1` and NaN were stored as given. The
//! rule these tests pin, for both endpoints:
//!
//! * more than `MAX_BATCH_ITEMS` (1000) items is `400`; exactly 1000 is not;
//! * a confidence that is not finite, or is outside `[0.0, 1.0]`, is `400`,
//!   whichever item carries it;
//! * a refused batch writes nothing.
//!
//! JSON cannot carry NaN or infinity, so those two arms call the handlers
//! directly, on the application role as `entity_triple_write_app_role.rs`
//! does, where the old handler would have committed the row.
#![cfg(feature = "db")]

mod common;
mod viewer_fixture;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, RequireScopeWrite, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::entities::{
    batch_create_mentions, batch_create_triples, BatchMentionItem, BatchMentionsRequest,
    BatchTripleItem, BatchTriplesRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
    )
    .bind(id)
    .bind(format!("591b2f6f claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn entity(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, 'Material', true) RETURNING id",
    )
    .bind(format!("591b2f6f entity {}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed entity")
}

/// Rows of `table` (`triples` or `entity_mentions`) attached to `claim`, read
/// on the superuser harness connection so nothing is filtered.
async fn rows_on(pool: &PgPool, table: &str, claim: Uuid) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE claim_id = $1"))
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count rows")
}

fn triple_json(claim: Uuid, subject: Uuid, confidence: f64, tag: &str) -> serde_json::Value {
    serde_json::json!({
        "claim_id": claim,
        "subject_id": subject,
        "predicate": "is_a",
        "object_literal": tag,
        "confidence": confidence,
        "extractor": "591b2f6f-test",
    })
}

fn mention_json(claim: Uuid, entity: Uuid, confidence: f64, tag: &str) -> serde_json::Value {
    serde_json::json!({
        "entity_id": entity,
        "claim_id": claim,
        "surface_form": tag,
        "mention_role": "subject",
        "confidence": confidence,
        "extractor": "591b2f6f-test",
    })
}

struct App {
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn app(pool: &PgPool) -> App {
    let (addr, _shutdown) = common::spawn_app(&database_url_for(pool).await).await;
    App { addr, _shutdown }
}

async fn post(
    app: &App,
    agent: Uuid,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{}{path}", app.addr))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

async fn post_triples(
    app: &App,
    agent: Uuid,
    items: Vec<serde_json::Value>,
) -> (u16, serde_json::Value) {
    post(
        app,
        agent,
        "/api/v1/triples/batch",
        serde_json::json!({ "triples": items }),
    )
    .await
}

async fn post_mentions(
    app: &App,
    agent: Uuid,
    items: Vec<serde_json::Value>,
) -> (u16, serde_json::Value) {
    post(
        app,
        agent,
        "/api/v1/entity-mentions/batch",
        serde_json::json!({ "mentions": items }),
    )
    .await
}

/// 1001 items is refused and writes nothing; 1000 items on the same claim is
/// accepted, so the cap is exactly 1000 (a `>=` in place of `>` fails here).
#[sqlx::test(migrations = "../../migrations")]
async fn a_batch_over_1000_items_is_refused_and_1000_is_not(pool: PgPool) {
    let (caller, cg) = seed_agent_with_group(&pool, "591-caller").await;
    let over = claim_of(&pool, caller, cg).await;
    let at = claim_of(&pool, caller, cg).await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let items = |claim: Uuid, n: usize| -> Vec<serde_json::Value> {
        (0..n)
            .map(|i| triple_json(claim, e, 0.5, &format!("t{i}")))
            .collect()
    };
    let (status, body) = post_triples(&app, caller, items(over, 1001)).await;
    assert_eq!(status, 400, "1001 triples: {body}");
    assert_eq!(
        rows_on(&pool, "triples", over).await,
        0,
        "a triple was written"
    );
    let (status, body) = post_triples(&app, caller, items(at, 1000)).await;
    assert_eq!(status, 200, "1000 triples: {body}");
    assert_eq!(body["count"], 1000, "{body}");

    let items = |claim: Uuid, n: usize| -> Vec<serde_json::Value> {
        (0..n)
            .map(|i| mention_json(claim, e, 0.5, &format!("m{i}")))
            .collect()
    };
    let (status, body) = post_mentions(&app, caller, items(over, 1001)).await;
    assert_eq!(status, 400, "1001 mentions: {body}");
    assert_eq!(
        rows_on(&pool, "entity_mentions", over).await,
        0,
        "a mention was written"
    );
    let (status, body) = post_mentions(&app, caller, items(at, 1000)).await;
    assert_eq!(status, 200, "1000 mentions: {body}");
    assert_eq!(body["count"], 1000, "{body}");
}

/// A confidence above 1 or below 0 is refused wherever it sits in the batch
/// (here LAST, after valid items), and nothing is written. The bounds
/// themselves, 0.0 and 1.0, are accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn an_out_of_range_confidence_is_refused_and_writes_nothing(pool: PgPool) {
    let (caller, cg) = seed_agent_with_group(&pool, "591-caller").await;
    let c = claim_of(&pool, caller, cg).await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    for bad in [1.5, -0.1, 1.0000001] {
        let (status, body) = post_triples(
            &app,
            caller,
            vec![triple_json(c, e, 0.9, "ok"), triple_json(c, e, bad, "bad")],
        )
        .await;
        assert_eq!(status, 400, "triple confidence {bad}: {body}");
        assert_eq!(rows_on(&pool, "triples", c).await, 0, "confidence {bad}");

        let (status, body) = post_mentions(
            &app,
            caller,
            vec![
                mention_json(c, e, 0.9, "ok"),
                mention_json(c, e, bad, "bad"),
            ],
        )
        .await;
        assert_eq!(status, 400, "mention confidence {bad}: {body}");
        assert_eq!(
            rows_on(&pool, "entity_mentions", c).await,
            0,
            "confidence {bad}"
        );
    }

    let (status, body) = post_triples(
        &app,
        caller,
        vec![triple_json(c, e, 0.0, "lo"), triple_json(c, e, 1.0, "hi")],
    )
    .await;
    assert_eq!(status, 200, "the bounds are valid: {body}");
    let (status, body) = post_mentions(
        &app,
        caller,
        vec![mention_json(c, e, 0.0, "lo"), mention_json(c, e, 1.0, "hi")],
    )
    .await;
    assert_eq!(status, 200, "the bounds are valid: {body}");
}

// ── NaN and infinity: handler calls on the application role ──

async fn app_role_state(pool: &PgPool) -> AppState {
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

/// NaN and +/-infinity are refused on both endpoints. The CALIBRATION arm
/// first commits a finite batch through the same state, so a refusal below is
/// the validation and not a broken harness.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_finite_confidence_is_refused_and_writes_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (owner, og) = seed_agent_with_group(&pool, "591-app-owner").await;
    let ok_claim = claim_of(&pool, owner, og).await;
    let c = claim_of(&pool, owner, og).await;
    let e = entity(&pool).await;
    let viewer =
        || async { ViewerExtractor(Viewer::resolve(&pool, owner).await.expect("resolve")) };
    let triple = |claim: Uuid, confidence: f64| BatchTripleItem {
        claim_id: claim,
        subject_id: e,
        predicate: "is_a".to_string(),
        object_id: None,
        object_literal: Some("probe".to_string()),
        confidence,
        extractor: "591b2f6f-test".to_string(),
        properties: None,
    };
    let mention = |claim: Uuid, confidence: f64| BatchMentionItem {
        entity_id: e,
        claim_id: claim,
        surface_form: "probe".to_string(),
        mention_role: "subject".to_string(),
        confidence,
        extractor: "591b2f6f-test".to_string(),
        span_start: None,
        span_end: None,
    };

    let Json(t) = batch_create_triples(
        State(state.clone()),
        write_scope(owner),
        viewer().await,
        Json(BatchTriplesRequest {
            triples: vec![triple(ok_claim, 0.5)],
        }),
    )
    .await
    .unwrap_or_else(|err| panic!("CALIBRATION: a finite triple must commit: {err:?}"));
    assert_eq!(t.count, 1, "CALIBRATION");

    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = batch_create_triples(
            State(state.clone()),
            write_scope(owner),
            viewer().await,
            Json(BatchTriplesRequest {
                triples: vec![triple(c, 0.5), triple(c, bad)],
            }),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("a triple with confidence {bad} was accepted"));
        assert_eq!(err.into_response().status().as_u16(), 400, "triple {bad}");
        assert_eq!(rows_on(&pool, "triples", c).await, 0, "triple {bad}");

        let err = batch_create_mentions(
            State(state.clone()),
            write_scope(owner),
            viewer().await,
            Json(BatchMentionsRequest {
                mentions: vec![mention(c, 0.5), mention(c, bad)],
            }),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("a mention with confidence {bad} was accepted"));
        assert_eq!(err.into_response().status().as_u16(), 400, "mention {bad}");
        assert_eq!(
            rows_on(&pool, "entity_mentions", c).await,
            0,
            "mention {bad}"
        );
    }
}

/// The batch returns one id per item IN REQUEST ORDER, and each id is the row
/// built from that item (backlog 591b2f6f: the rows are now written by one
/// statement instead of one round trip each). Items alternate between two
/// claims and every field that varies is checked against the row its id names,
/// so a statement that returns ids in table, claim or id order is caught.
#[sqlx::test(migrations = "../../migrations")]
async fn a_batch_returns_its_ids_in_request_order(pool: PgPool) {
    let (caller, cg) = seed_agent_with_group(&pool, "591-caller").await;
    let c1 = claim_of(&pool, caller, cg).await;
    let c2 = claim_of(&pool, caller, cg).await;
    let e = entity(&pool).await;
    let object = entity(&pool).await;
    let app = app(&pool).await;

    let mut items = Vec::new();
    for i in 0..6usize {
        let claim = if i % 2 == 0 { c2 } else { c1 };
        let mut t = triple_json(claim, e, 0.1 * (6 - i) as f64, &format!("t{i}"));
        if i == 3 {
            t["object_literal"] = serde_json::Value::Null;
            t["object_id"] = serde_json::json!(object);
            t["properties"] = serde_json::json!({ "n": i });
        }
        items.push(t);
    }
    let (status, body) = post_triples(&app, caller, items.clone()).await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<Uuid> = serde_json::from_value(body["ids"].clone()).expect("ids");
    assert_eq!(ids.len(), items.len(), "{body}");
    for (i, (id, item)) in ids.iter().zip(&items).enumerate() {
        let (claim, literal, object_id, confidence, properties): (
            Uuid,
            Option<String>,
            Option<Uuid>,
            f64,
            serde_json::Value,
        ) = sqlx::query_as(
            "SELECT claim_id, object_literal, object_id, confidence, properties \
             FROM triples WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("triple {i} ({id}) not found: {e}"));
        assert_eq!(
            claim.to_string(),
            item["claim_id"].as_str().unwrap(),
            "item {i}"
        );
        assert_eq!(
            literal.as_deref(),
            item["object_literal"].as_str(),
            "item {i}"
        );
        assert_eq!(
            object_id.map(|o| o.to_string()).as_deref(),
            item["object_id"].as_str(),
            "item {i}"
        );
        assert_eq!(confidence, item["confidence"].as_f64().unwrap(), "item {i}");
        let want_props = item
            .get("properties")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        assert_eq!(properties, want_props, "item {i}");
    }

    let mut items = Vec::new();
    for i in 0..6usize {
        let claim = if i % 2 == 0 { c1 } else { c2 };
        let mut m = mention_json(claim, e, 0.1 * i as f64, &format!("m{i}"));
        if i % 3 == 1 {
            m["span_start"] = serde_json::json!(i as i32);
            m["span_end"] = serde_json::json!(i as i32 + 10);
            m["mention_role"] = serde_json::json!("object");
        }
        items.push(m);
    }
    let (status, body) = post_mentions(&app, caller, items.clone()).await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<Uuid> = serde_json::from_value(body["ids"].clone()).expect("ids");
    assert_eq!(ids.len(), items.len(), "{body}");
    for (i, (id, item)) in ids.iter().zip(&items).enumerate() {
        let (claim, surface, role, confidence, span_start, span_end): (
            Uuid,
            String,
            String,
            f64,
            Option<i32>,
            Option<i32>,
        ) = sqlx::query_as(
            "SELECT claim_id, surface_form, mention_role::text, confidence, span_start, span_end \
             FROM entity_mentions WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("mention {i} ({id}) not found: {e}"));
        assert_eq!(
            claim.to_string(),
            item["claim_id"].as_str().unwrap(),
            "item {i}"
        );
        assert_eq!(surface, item["surface_form"].as_str().unwrap(), "item {i}");
        assert_eq!(role, item["mention_role"].as_str().unwrap(), "item {i}");
        assert_eq!(confidence, item["confidence"].as_f64().unwrap(), "item {i}");
        assert_eq!(
            span_start,
            item.get("span_start")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
            "item {i}"
        );
        assert_eq!(
            span_end,
            item.get("span_end")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
            "item {i}"
        );
    }
}

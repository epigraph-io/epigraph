//! `POST /api/v1/edges` honours `EPIGRAPH_CONTRADICT_COMPOUND_GUARD`
//! (backlog 73317662), the REST twin of MCP `link_epistemic`
//! (`epigraph-mcp/tests/link_epistemic_contradiction_guard.rs`, backlog
//! b4c2fc2f). A `contradicts` / `refutes` edge onto a claim whose text asserts
//! several independent things and that has NOT been decomposed disputes all
//! of them at once:
//!
//! - `warn` (the default): the edge is written as before, the response adds
//!   `partial_contradiction_risk {conjuncts, hint}`, and the caller (never the
//!   content) is logged under `epigraph::contradiction_guard`;
//! - `refuse`: 422 `compound_contradiction_target`, and no edge is written;
//! - an atomic target, a decomposed target and a positive relationship are
//!   unaffected, in either mode.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest, CreateEdgeResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::belief_modes::ContradictCompoundGuard;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group, seed_public_claim};

/// One sentence joining two independent clauses: `conjunct_screen` counts 2.
const COMPOUND_TEXT: &str =
    "rest guard: the catalyst raised the yield, but it shortened the column life.";

/// A letters-only nonce: claims are seeded with a content-derived hash, so
/// each needs distinct text, and digits could count as quantities in
/// `conjunct_screen`.
fn nonce() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .map(|c| match c.to_digit(10) {
            Some(d) => char::from(b'g' + d as u8),
            None => c,
        })
        .collect()
}

/// A public claim by `agent` whose text is `text` behind a nonce word.
async fn claim(pool: &PgPool, agent: Uuid, text: &str) -> Uuid {
    seed_public_claim(pool, agent, &format!("{} {text}", nonce())).await
}

async fn state(pool: &PgPool, mode: ContradictCompoundGuard) -> AppState {
    let url = database_url_for(pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("connect a scoped pool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
        .with_contradict_compound_guard(mode);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["edges:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

fn claim_edge(source: Uuid, target: Uuid, relationship: &str) -> CreateEdgeRequest {
    CreateEdgeRequest {
        source_id: source,
        target_id: target,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: relationship.to_string(),
        properties: None,
        labels: None,
        valid_from: None,
        valid_to: None,
        if_not_exists: false,
    }
}

async fn post(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    req: CreateEdgeRequest,
) -> Result<(StatusCode, CreateEdgeResponse), ApiError> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(agent),
        Json(req),
    )
    .await
    .map(|(status, Json(body))| (status, body))
}

async fn edges_between(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges \
          WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to");
}

#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn warn_writes_the_edge_and_flags_the_partial_contradiction_risk(pool: PgPool) {
    let (agent, _) = seed_agent_with_group(&pool, "73317662-warn").await;
    let state = state(&pool, ContradictCompoundGuard::Warn).await;
    let source = claim(&pool, agent, "rest source").await;
    let target = claim(&pool, agent, COMPOUND_TEXT).await;

    for relationship in ["CONTRADICTS", "refutes"] {
        let (status, body) = post(
            &pool,
            &state,
            agent,
            claim_edge(source, target, relationship),
        )
        .await
        .unwrap_or_else(|e| panic!("warn writes the {relationship} edge: {e:?}"));
        assert_eq!(status, StatusCode::CREATED, "{relationship}");
        let wire = serde_json::to_value(&body).expect("response JSON");
        let risk = wire
            .get("partial_contradiction_risk")
            .unwrap_or_else(|| panic!("warn must flag the {relationship} edge: {wire}"));
        assert_eq!(risk["conjuncts"], 2, "{wire}");
        assert!(
            risk["hint"]
                .as_str()
                .is_some_and(|h| h.contains("decompose the target")),
            "{wire}"
        );
    }
    assert_eq!(
        edges_between(&pool, source, target).await,
        2,
        "both written"
    );

    // One journal line per accepted edge, naming the caller.
    let caller_id = agent.to_string();
    logs_assert(|lines: &[&str]| {
        let accepted = lines
            .iter()
            .filter(|l| l.contains("contradiction onto an undecomposed compound accepted"))
            .collect::<Vec<_>>();
        if accepted.len() != 2 {
            return Err(format!("expected 2 accepted lines, got {accepted:?}"));
        }
        if accepted.iter().all(|l| l.contains(&caller_id)) {
            Ok(())
        } else {
            Err(format!(
                "an accepted line lacks the caller {caller_id}: {accepted:?}"
            ))
        }
    });
    assert!(
        !logs_contain("shortened the column life"),
        "the guard must never log the claim's content"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn refuse_answers_422_and_writes_nothing(pool: PgPool) {
    let (agent, _) = seed_agent_with_group(&pool, "73317662-refuse").await;
    let state = state(&pool, ContradictCompoundGuard::Refuse).await;
    let source = claim(&pool, agent, "rest source").await;
    let target = claim(&pool, agent, COMPOUND_TEXT).await;

    for relationship in ["contradicts", "Refutes"] {
        let err = post(
            &pool,
            &state,
            agent,
            claim_edge(source, target, relationship),
        )
        .await
        .expect_err("refuse must refuse a contradiction onto an undecomposed compound");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON body");
        assert_eq!(body["error"], "compound_contradiction_target", "{body}");
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("nothing was written")),
            "{body}"
        );
        assert_eq!(body["details"]["claim_id"], target.to_string(), "{body}");
        assert_eq!(body["details"]["conjuncts"], 2, "{body}");
        assert_eq!(
            body["details"]["flag"], "EPIGRAPH_CONTRADICT_COMPOUND_GUARD",
            "{body}"
        );
    }
    assert_eq!(edges_between(&pool, source, target).await, 0, "no edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_atomic_target_a_decomposed_target_and_a_positive_edge_are_unaffected(pool: PgPool) {
    let (agent, _) = seed_agent_with_group(&pool, "73317662-unaffected").await;
    for mode in [
        ContradictCompoundGuard::Refuse,
        ContradictCompoundGuard::Warn,
    ] {
        let state = state(&pool, mode).await;
        let source = claim(&pool, agent, "rest source").await;
        let atom = claim(&pool, agent, "the catalyst raised the yield.").await;
        let decomposed = claim(&pool, agent, COMPOUND_TEXT).await;
        let part_a = claim(&pool, agent, "part a.").await;
        let part_b = claim(&pool, agent, "part b.").await;
        decomposes_to(&pool, decomposed, part_a).await;
        decomposes_to(&pool, decomposed, part_b).await;
        let compound = claim(&pool, agent, COMPOUND_TEXT).await;

        for (target, relationship) in [
            (atom, "contradicts"),
            (decomposed, "refutes"),
            (compound, "supports"),
        ] {
            let (status, body) = post(
                &pool,
                &state,
                agent,
                claim_edge(source, target, relationship),
            )
            .await
            .unwrap_or_else(|e| panic!("{mode:?} {relationship}: {e:?}"));
            assert_eq!(status, StatusCode::CREATED, "{mode:?} {relationship}");
            let wire = serde_json::to_value(&body).expect("response JSON");
            assert!(
                wire.get("partial_contradiction_risk").is_none(),
                "{mode:?} {relationship}: {wire}"
            );
            assert_eq!(edges_between(&pool, source, target).await, 1);
        }
    }
}

#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/assess` records WHO wrote each assessment, and
//! whether it replaced and contested the owner's earlier one, durably
//! (backlog 4a7f90f8, part 1).
//!
//! # What was wrong, measured on the branch before this file
//!
//! The slot row stores the OWNER (the caller's human) as `source_agent_id`.
//! The agent that actually made the call appeared only in the response
//! (`assessed_by`), and the replacement and contest only in
//! `replaced_assessments`. Once the response was gone nothing said which of
//! a human's agents wrote the slot's current masses, which one wrote the
//! masses it overwrote, or that the overwrite reversed the verdict.
//!
//! # The oracle
//!
//! Two agents of ONE human, so the writer is never the owner: an
//! implementation that recorded the owner (what the row already holds) as
//! the writer fails the `actor_id` assertions. The first agent supports, the
//! second refutes (a contest), then the first refutes too, agreeing with the
//! second (a replacement that is NOT a contest), so `contested` cannot be a
//! constant.
//! Every fact is read back from the `events` table alone, never from the
//! response, and then cross-checked against the response so the two cannot
//! disagree.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest, AssessClaimResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_human_operator, seed_public_claim};

fn request(supports: bool, confidence: f64) -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": confidence,
        "supports": supports,
    }))
    .expect("AssessClaimRequest deserializes")
}

async fn assess(
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    req: AssessClaimRequest,
) -> AssessClaimResponse {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let Json(resp) = assess_claim(
        write_scope(),
        ViewerExtractor(viewer),
        State(state),
        Path(claim),
        Json(req),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

/// The assessment events naming `claim`, in write order. `graph_version` is
/// drawn under the slot lock, so it orders one slot's writes; `created_at`
/// does not (it is not commit-ordered).
async fn assessment_events(pool: &PgPool, claim: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT actor_id, payload FROM events \
          WHERE event_type = 'claim.assessed' AND payload->>'claim_id' = $1::text \
          ORDER BY graph_version",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read assessment events")
}

fn uuid_at(payload: &serde_json::Value, key: &str) -> Option<Uuid> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn bool_at(payload: &serde_json::Value, key: &str) -> bool {
    payload
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| panic!("payload has no boolean {key:?}: {payload}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_assessment_records_its_writer_and_any_contest_durably(pool: PgPool) {
    let (author, _) = seed_agent_with_group(&pool, "assess-writer-author").await;
    let (human, _) = seed_human_operator(&pool, "assess-writer-human").await;
    let (one, _) = seed_agent_with_group(&pool, "assess-writer-one").await;
    let (two, _) = seed_agent_with_group(&pool, "assess-writer-two").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let claim = seed_public_claim(&pool, author, "assess writer record").await;

    let first = assess(&pool, one, claim, request(true, 0.9)).await;
    let second = assess(&pool, two, claim, request(false, 0.6)).await;
    let third = assess(&pool, one, claim, request(false, 0.7)).await;
    assert_eq!(
        first.mass_function_id, second.mass_function_id,
        "PREMISE: one human, one slot row"
    );
    assert_eq!(second.mass_function_id, third.mass_function_id);
    assert_eq!(
        first.owner_agent_id,
        Some(human),
        "PREMISE: the owner is the human"
    );
    assert!(
        second.replaced_assessments[0].contested,
        "PREMISE: the sibling's refutation reverses the first verdict"
    );
    assert!(
        !third.replaced_assessments[0].contested,
        "PREMISE: the third call agrees with the second"
    );

    let events = assessment_events(&pool, claim).await;
    assert_eq!(
        events.len(),
        3,
        "one durable record per assessment call, got {events:?}"
    );

    // Who wrote each call: the AGENT, not the owner the row already names.
    let writers: Vec<Option<Uuid>> = events.iter().map(|(actor, _)| *actor).collect();
    assert_eq!(
        writers,
        vec![Some(one), Some(two), Some(one)],
        "each record's actor is the calling agent (human {human})"
    );

    for ((_, payload), resp) in events.iter().zip([&first, &second, &third]) {
        assert_eq!(
            uuid_at(payload, "mass_function_id"),
            Some(resp.mass_function_id)
        );
        assert_eq!(uuid_at(payload, "frame_id"), Some(resp.frame_id));
        assert_eq!(uuid_at(payload, "owner_agent_id"), Some(human));
        assert_eq!(uuid_at(payload, "assessed_by"), resp.assessed_by);
        assert_eq!(
            bool_at(payload, "replaced"),
            !resp.replaced_assessments.is_empty(),
            "{payload}"
        );
        assert_eq!(
            bool_at(payload, "contested"),
            resp.replaced_assessments.iter().any(|r| r.contested),
            "the record and the response must agree on the contest: {payload}"
        );
    }
    assert!(!bool_at(&events[0].1, "replaced"));
    assert!(bool_at(&events[1].1, "replaced"));
    assert!(bool_at(&events[1].1, "contested"));
    assert!(bool_at(&events[2].1, "replaced"));
    assert!(!bool_at(&events[2].1, "contested"));

    // The prior writer of the masses the second call overwrote is the actor
    // of the record before it on the same slot row: agent one, not the human.
    let slot = second.mass_function_id;
    let prior = events[..1]
        .iter()
        .rev()
        .find(|(_, p)| uuid_at(p, "mass_function_id") == Some(slot))
        .map(|(actor, _)| *actor);
    assert_eq!(prior, Some(Some(one)), "the contested assessment's writer");
}

/// The `claims:write` scope the write handlers now take as their first
/// extractor (backlog f00d75ab). A direct handler call stands in for the
/// bearer middleware, so it supplies the scope the route checks.
fn write_scope() -> epigraph_api::middleware::bearer::RequireScopeWrite {
    let principal = uuid::Uuid::new_v4();
    epigraph_api::middleware::bearer::RequireScopeWrite(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: epigraph_api::middleware::ClientType::Service,
            scopes: vec!["claims:write".to_string()],
            jti: uuid::Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    )
}

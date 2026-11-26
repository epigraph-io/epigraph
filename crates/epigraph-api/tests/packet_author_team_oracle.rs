#![cfg(feature = "db")]
//! `POST /api/v1/submit/packet` names its author in the BODY
//! (`claim.agent_id`), and resolves the claim's visibility for that author
//! (its team lists, its defaults) before the stamped write transaction
//! exists. Without a gate in front of that resolution, any caller could name
//! another human's agent B and read B's teams off the answers: one 403 text
//! when B does not write the named team, another when B does and the caller
//! does not, and "you may write N teams" when no team is named (backlog
//! 1c5edc26, review finding on `persist_packet`).
//!
//! On the APPLICATION ROLE with the operator binding ARMED, through
//! `create_router`:
//! * a caller (the human HA; an operated agent has no HTTP authority) naming
//!   another human's agent B gets the SAME 403 (`OPL02`, no
//!   group id, no team count) whether or not B writes the named team, for a
//!   named team, for `team` without a group and for no visibility at all, and
//!   nothing is written;
//! * CONTROL: the caller naming an agent of its OWN (an agent HA operates)
//!   still reaches the visibility resolution (the 403 is the resolution's own team refusal,
//!   not `OPL02`), so the gate is not a blanket refusal of a body author.
//!
//! Red on the code before the gate: the two named-team bodies differ (and
//! carry the group ids), and the group-less write answers with B's count.

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::routes::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

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
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_writer(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed writer membership");
}

async fn linked(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = viewer_fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    agent
}

/// A packet authored by `author` with the given `visibility` / `group_id`.
fn packet(
    author: Uuid,
    content: &str,
    visibility: Option<&str>,
    group: Option<Uuid>,
) -> serde_json::Value {
    let props = serde_json::json!({"probe": content});
    let hash = epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(
        &serde_json::to_vec(&props).expect("properties"),
    ));
    let mut v = serde_json::json!({
        "claim": {
            "content": content, "initial_truth": 0.6, "agent_id": author,
            "properties": props, "labels": ["author-oracle-probe"]
        },
        "evidence": [{
            "content_hash": hash,
            "evidence_type": {
                "type": "observation", "observed_at": chrono::Utc::now().to_rfc3339(),
                "method": "author_oracle_probe", "location": null
            },
            "raw_content": null, "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive", "explanation": "author oracle probe", "confidence": 0.6,
            "inputs": [{"type": "evidence", "index": 0}]
        },
        "signature": ""
    });
    if let Some(vis) = visibility {
        v["visibility"] = serde_json::Value::String(vis.to_string());
    }
    if let Some(g) = group {
        v["group_id"] = serde_json::Value::String(g.to_string());
    }
    v
}

async fn post_packet(
    state: &AppState,
    caller: Uuid,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/submit/packet")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn rows_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_body_named_foreign_author_reveals_none_of_its_teams(pool: PgPool) {
    // The caller is the human HA (over HTTP an operated agent has no
    // authority of its own), with its agent S; human HB with its agent B.
    let (a, _) = viewer_fixture::seed_human_operator(&pool, "oracle-ha").await;
    let (hb, _) = viewer_fixture::seed_human_operator(&pool, "oracle-hb").await;
    let sibling = linked(&pool, a, "oracle-own-agent-s").await;
    let b = linked(&pool, hb, "oracle-foreign-b").await;
    // B writes G (HA does not); nobody writes G2. B writes a second team, so
    // its count would read "2 teams".
    let g = team(&pool, "oracle-g").await;
    let g2 = team(&pool, "oracle-g2").await;
    let g3 = team(&pool, "oracle-g3").await;
    add_writer(&pool, g, b).await;
    add_writer(&pool, g3, b).await;
    // S writes GS on its own (HA does not): the control's team.
    let gs = team(&pool, "oracle-gs").await;
    add_writer(&pool, gs, sibling).await;
    viewer_fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm the operator binding");
        (conn, ())
    })
    .await;
    let st = app_role_state(&pool).await;

    // CONTROL: an agent of the caller's own reaches the resolution, whose
    // refusal is about the TEAM (the caller does not write GS), not OPL02.
    // The gate admits what 122 admits.
    let control = format!("oracle control {}", Uuid::new_v4());
    let (status, body) =
        post_packet(&st, a, &packet(sibling, &control, Some("team"), Some(gs))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "CONTROL: {body}");
    assert!(
        !body.contains("OPL02") && body.contains("does not write team"),
        "CONTROL: the caller's own agent passes the gate and is refused by the resolution's team \
         check: {body}"
    );

    // B writes G; B does not write G2. Same answer for both.
    let c1 = format!("oracle g {}", Uuid::new_v4());
    let c2 = format!("oracle g2 {}", Uuid::new_v4());
    let (s1, b1) = post_packet(&st, a, &packet(b, &c1, Some("team"), Some(g))).await;
    let (s2, b2) = post_packet(&st, a, &packet(b, &c2, Some("team"), Some(g2))).await;
    assert_eq!(s1, StatusCode::FORBIDDEN, "named team B writes: {b1}");
    assert!(
        b1.contains("OPL02"),
        "refused as an author of another human: {b1}"
    );
    assert_eq!(
        (s1, &b1),
        (s2, &b2),
        "a team B writes and a team B does not write must get the same answer"
    );
    for id in [g, g2, g3] {
        assert!(
            !b1.contains(&id.to_string()),
            "no group id in the body: {b1}"
        );
    }

    // No group named, and no visibility at all: the same refusal, no count.
    let c3 = format!("oracle team-none {}", Uuid::new_v4());
    let c4 = format!("oracle default {}", Uuid::new_v4());
    let (s3, b3) = post_packet(&st, a, &packet(b, &c3, Some("team"), None)).await;
    let (s4, b4) = post_packet(&st, a, &packet(b, &c4, None, None)).await;
    for (s, body, case) in [
        (s3, &b3, "team without a group"),
        (s4, &b4, "no visibility"),
    ] {
        assert_eq!(s, StatusCode::FORBIDDEN, "{case}: {body}");
        assert_eq!(body, &b1, "{case}: the same refusal as a named team");
        assert!(!body.contains("teams"), "{case}: no team count: {body}");
    }

    for c in [&control, &c1, &c2, &c3, &c4] {
        assert_eq!(rows_with_content(&pool, c).await, 0, "nothing written: {c}");
    }
}

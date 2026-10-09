#![cfg(feature = "db")]
//! Migration 149 on the production write shape: an allowlisted SERVICE client's
//! agent submits a packet (`POST /api/v1/submit/packet`) authored by its
//! operator's live-linked agent, on the APPLICATION ROLE, armed, with NO
//! orphan permissive `claims_privacy` policy, so row security decides as it
//! does in production.
//!
//! The handler is invoked directly with the caller's `ViewerExtractor` (the
//! `claim_routes_bind_the_caller.rs` harness); both pools of the `AppState`
//! are the application role. The token path (that an allowlisted client
//! mints and keeps its viewer) is pinned separately in
//! `operated_agent_token.rs`.
//!
//! * (i) no allowance: refused `OPL01` (the writer is unbound), nothing written;
//! * (ii) an allowance, but no write membership for the agent in the
//!   operator's group: refused, and NOT by an `OPL` code (row security's
//!   WITH CHECK): an allowance grants no row-security write authority;
//! * (iii) an allowance and a writer membership in the operator's group: 201,
//!   one claim, authored as named and owned by the operator's group.
//!
//! Verified to fail: a route-layer refusal of an allowlisted principal, or the
//! `client_allowlist` arm removed from `epigraph_author_binding` -> (iii) is
//! refused.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::submit::{submit_packet, EpistemicPacket};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

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
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

fn packet(author: Uuid, content: &str) -> EpistemicPacket {
    let evidence = format!("evidence for {content}");
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence.as_bytes()),
    );
    serde_json::from_value(serde_json::json!({
        "claim": { "content": content, "initial_truth": 0.7, "agent_id": author },
        "evidence": [{
            "content_hash": evidence_hash,
            "evidence_type": {
                "type": "observation",
                "observed_at": chrono::Utc::now(),
                "method": "test",
                "location": null
            },
            "raw_content": evidence,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.7,
            "explanation": "test",
            "signature": null
        },
        "signature": "0".repeat(128)
    }))
    .expect("a well-formed packet")
}

async fn post_packet(
    state: &AppState,
    viewer: Viewer,
    author: Uuid,
    content: &str,
) -> (StatusCode, String) {
    let resp = submit_packet(
        ViewerExtractor(viewer),
        State(state.clone()),
        Ok(Json(packet(author, content))),
    )
    .await;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn claims_with_content(pool: &PgPool, content: &str) -> Vec<(Uuid, Uuid)> {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content_hash = $1")
        .bind(hash.as_slice())
        .fetch_all(pool)
        .await
        .expect("read back")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_service_client_submits_a_packet_authored_by_a_linked_agent(pool: PgPool) {
    let (h, h_group) = seed_human_operator(&pool, "human-h").await;
    let (l, _) = seed_agent_with_group(&pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let (s, _) = seed_agent_with_group(&pool, "service-s").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'host writer', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("host-writer-{}", Uuid::new_v4()))
    .bind(s)
    .fetch_one(&pool)
    .await
    .expect("the service client");
    as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    let state = app_role_state(&pool).await;

    // (i) No allowance: the writer is unbound.
    let content = format!("host packet, unbound {}", Uuid::new_v4());
    let viewer = Viewer::resolve(&pool, s).await.expect("viewer");
    let (status, body) = post_packet(&state, viewer, l, &content).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "(i): {body}");
    assert!(body.contains("OPL01"), "(i) names its code: {body}");
    assert!(claims_with_content(&pool, &content).await.is_empty(), "(i)");

    // (ii) Allowed, but S writes nothing in H's group: row security refuses.
    as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'host')")
            .bind(client)
            .bind(h)
            .execute(&mut *conn)
            .await
            .expect("allow");
        (conn, ())
    })
    .await;
    let content = format!("host packet, no membership {}", Uuid::new_v4());
    let viewer = Viewer::resolve(&pool, s).await.expect("viewer");
    let (status, body) = post_packet(&state, viewer, l, &content).await;
    assert!(
        !status.is_success() && !body.contains("OPL0"),
        "(ii): an allowance alone grants no row-security write in the operator's group, and \
         the refusal is not the binding's: {status} {body}"
    );
    assert!(
        claims_with_content(&pool, &content).await.is_empty(),
        "(ii)"
    );

    // (iii) A writer membership in H's group (the door is quiet for an
    // unlinked agent): the packet lands in H's group, authored as named.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(h_group)
    .bind(s)
    .execute(&pool)
    .await
    .expect("S writes in H's group");
    let content = format!("host packet, allowed {}", Uuid::new_v4());
    let viewer = Viewer::resolve(&pool, s).await.expect("viewer");
    let (status, body) = post_packet(&state, viewer, l, &content).await;
    assert_eq!(status, StatusCode::CREATED, "(iii): {body}");
    assert_eq!(
        claims_with_content(&pool, &content).await,
        vec![(l, h_group)],
        "(iii): one claim, authored by L, owned by H's group"
    );
}

#![cfg(feature = "db")]
//! Migration 149 on the production write shape: an allowlisted SERVICE client's
//! agent submits a packet (`POST /api/v1/submit/packet`) authored by its
//! operator's live-linked agent, on the APPLICATION ROLE, armed, with NO
//! orphan permissive `claims_privacy` policy, so row security decides as it
//! does in production.
//!
//! Sub-cases (i) and (ii) invoke the handler directly with the caller's
//! `ViewerExtractor` (the `claim_routes_bind_the_caller.rs` harness). Sub-case
//! (iii), the one that writes, runs the whole production path: a real
//! `client_credentials` token minted for the allowlisted service client,
//! then `POST /api/v1/submit/packet` through `create_router` with that bearer,
//! so the bearer middleware, the viewer build and the write route all see the
//! allowlisted principal. Both pools of the write router's `AppState` are the
//! application role; the token is minted on a superuser-pool router (the mint
//! is not under test here; `operated_agent_token.rs` pins it).
//!
//! * (i) no allowance: refused `OPL01` (the writer is unbound), nothing written;
//! * (ii) an allowance, but no write membership for the agent in the
//!   operator's group: refused by row security's WITH CHECK on `claims`, not
//!   by an `OPL` code: an allowance grants no row-security write authority.
//!   (The handler maps that refusal to a 500 "DatabaseError", which predates
//!   migration 149 and is pinned here as observed.)
//! * (iii) an allowance and a writer membership in the operator's group: the
//!   client's real token gets 201, one claim, authored as named and owned by
//!   the operator's group.
//!
//! Verified to fail: the `client_allowlist` arm removed from
//! `epigraph_author_binding` -> (ii) is refused OPL01 (the writer is unbound
//! again) instead of by row security. Should fail if a route-layer check
//! refused an allowlisted principal, or the bearer or the viewer build keyed a
//! refusal on the token or its principal ((iii) would be refused).

mod viewer_fixture;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::Json;
use epigraph_api::create_router;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::submit::{submit_packet, EpistemicPacket};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
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
    serde_json::from_value(packet_json(author, content)).expect("a well-formed packet")
}

fn packet_json(author: Uuid, content: &str) -> serde_json::Value {
    let evidence = format!("evidence for {content}");
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence.as_bytes()),
    );
    serde_json::json!({
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
    })
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

/// `POST /api/v1/submit/packet` through the full router of `state`, with
/// `bearer`: `(status, body)`.
async fn post_packet_with_token(
    state: &AppState,
    bearer: &str,
    author: Uuid,
    content: &str,
) -> (StatusCode, String) {
    let body = serde_json::to_vec(&packet_json(author, content)).expect("packet json");
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/submit/packet")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A `client_credentials` access token for the service client `client_id`,
/// minted on a superuser-pool router.
async fn client_credentials_token(pool: &PgPool, client_id: &str, secret: &str) -> String {
    let resp = create_router(AppState::with_db(pool.clone(), ApiConfig::default()))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": secret,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("token body is JSON");
    assert_eq!(
        status,
        StatusCode::OK,
        "the allowlisted client mints: {body}"
    );
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("an access token: {body}"))
        .to_string()
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
    // A service client with a known secret (`identity_provisioning.rs`'s
    // shape), its agent already S.
    let secret_bytes: [u8; 32] = *blake3::hash(b"allowlisted host writer").as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'host writer', 'service', ARRAY['claims:write'], \
                 ARRAY['claims:write'], 'active', $3, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
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
        status == StatusCode::INTERNAL_SERVER_ERROR
            && body.contains("row-level security policy for table \\\"claims\\\"")
            && !body.contains("OPL0"),
        "(ii): an allowance alone grants no row-security write in the operator's group, and \
         the refusal is row security's, not the binding's: {status} {body}"
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
    let bearer = client_credentials_token(&pool, &client_id, &secret).await;
    let (status, body) = post_packet_with_token(&state, &bearer, l, &content).await;
    assert_eq!(status, StatusCode::CREATED, "(iii): {body}");
    assert_eq!(
        claims_with_content(&pool, &content).await,
        vec![(l, h_group)],
        "(iii): one claim, authored by L, owned by H's group"
    );
}

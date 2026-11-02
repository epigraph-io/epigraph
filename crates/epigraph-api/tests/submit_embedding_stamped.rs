#![cfg(feature = "db")]
//! The post-commit embedding of the HTTP claim-write routes, on the
//! APPLICATION ROLE, for a bound writer that is not the claim's owner.
//!
//! `POST /api/v1/submit/packet`, `POST /api/v1/claims` and
//! `POST /api/v1/claims/batch` write the claim on a transaction stamped with
//! the CALLER's viewer (`AppState::begin_claim_write`), then embed it
//! best-effort after the commit. When that embed ran on the unstamped
//! `state.db_pool`, migration 077's `claims_tenancy` let the session see the
//! public row (`USING ... visibility = 'public'`) but refused the new row
//! (`WITH CHECK owner_group_id = ANY(epigraph_writable_groups())`, and the
//! unstamped writable set is empty). The refusal was only WARN-logged
//! ("Failed to store claim embedding ... new row violates row-level security
//! policy for table \"claims\""), the route answered 201, and the claim kept
//! `embedding IS NULL`, invisible to dense recall against CLAUDE.md's
//! "Embedding policy". The packet route's figure-evidence embed had the same
//! shape on `evidence`.
//!
//! The packet arm's writer is the production shape that surfaced it: a SERVICE OAuth client
//! allowlisted by migration 149 for a human operator H, with a writer
//! membership in H's group, submitting with its real `client_credentials`
//! token through `create_router`, a claim authored by H's live-linked agent and
//! therefore owned by H's group. Both pools of the `AppState` are separate
//! `epigraph_app` pools and no orphan permissive `claims_privacy` policy is
//! installed: with one (`USING (true)`), the unstamped `UPDATE` would be
//! admitted and these arms would prove nothing. The `create_claim` and batch
//! arms use a registered human operator writing as itself (see
//! [`human_writer`] for why not the allowlisted client).
//!
//! # Verified to fail
//!
//! At origin/main 7dd79226 (embed on `state.db_pool`), every arm fails: the
//! claim (and the figure evidence) keeps `embedding IS NULL`, and the server
//! log carries the row-security refusal.

mod viewer_fixture;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::{Extension, Json};
use epigraph_api::create_router;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use tracing_test::traced_test;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

/// An application-role `AppState` with a mock embedder: `scoped` and `db_pool`
/// are two separate `epigraph_app` pools, so a write on `db_pool` is an
/// unstamped write that row security governs.
async fn app_role_state_with_embedder(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let orphan: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE tablename IN ('claims', 'evidence') \
            AND policyname LIKE '%privacy%'",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_policies");
    assert_eq!(
        orphan, 0,
        "an orphan permissive *_privacy policy admits the unstamped UPDATE: vacuous"
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
    let embedder: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    state.with_embedding_service(embedder)
}

/// The writer under test: `(state, bearer, author L, H's group)`.
///
/// H is a registered human operator; L is H's live-linked agent; S is the
/// agent of an ACTIVE service client allowlisted for H (migration 149) and
/// holds a writer membership in H's group. The database is armed. `bearer` is
/// S's real `client_credentials` access token.
async fn allowlisted_writer(pool: &PgPool) -> (AppState, String, Uuid, Uuid) {
    let (h, h_group) = seed_human_operator(pool, "human-h").await;
    let (l, _) = seed_agent_with_group(pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let (s, _) = seed_agent_with_group(pool, "service-s").await;
    let secret_bytes: [u8; 32] = *blake3::hash(b"allowlisted embedding writer").as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'service writer', 'service', ARRAY['claims:write'], \
                 ARRAY['claims:write'], 'active', $3, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
    .bind(s)
    .fetch_one(pool)
    .await
    .expect("the service client");
    as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        sqlx::query(
            "SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'service writer')",
        )
        .bind(client)
        .bind(h)
        .execute(&mut *conn)
        .await
        .expect("allow");
        (conn, ())
    })
    .await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(h_group)
    .bind(s)
    .execute(pool)
    .await
    .expect("S writes in H's group");

    let state = app_role_state_with_embedder(pool).await;
    let bearer = client_credentials_token(pool, &client_id, &secret).await;
    (state, bearer, l, h_group)
}

/// A `client_credentials` access token for the service client `client_id`,
/// minted on a superuser-pool router (the mint is not under test here).
async fn client_credentials_token(pool: &PgPool, client_id: &str, secret: &str) -> String {
    let (status, body) = send(
        &AppState::with_db(pool.clone(), ApiConfig::default()),
        None,
        "/oauth/token",
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
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

/// `POST uri` with a JSON body through the full router of `state`.
async fn send(
    state: &AppState,
    bearer: Option<&str>,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(b) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    let resp = create_router(state.clone())
        .oneshot(
            req.body(Body::from(serde_json::to_vec(&body).expect("json")))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, json)
}

/// `(agent_id, owner_group_id, embedding IS NOT NULL)` for every claim with
/// `content`. Read on the harness superuser, so row security hides nothing.
async fn claim_rows(pool: &PgPool, content: &str) -> Vec<(Uuid, Uuid, bool)> {
    sqlx::query_as(
        "SELECT agent_id, owner_group_id, embedding IS NOT NULL FROM claims WHERE content = $1",
    )
    .bind(content)
    .fetch_all(pool)
    .await
    .expect("read back")
}

/// No embedding store was refused or logged as failed: no WARN or ERROR line
/// names a row-security refusal, a failed store, or a store that matched no
/// row. Passed to `logs_assert` (injected into each `#[traced_test]` body).
///
/// Filtered to WARN/ERROR lines because the capture also holds the DEBUG
/// `sqlx::query` lines of the test database's migrations, whose SQL comments
/// discuss row security.
fn no_store_refusal(lines: &[&str]) -> Result<(), String> {
    let refusals: Vec<&&str> = lines
        .iter()
        .filter(|l| l.contains(" WARN ") || l.contains(" ERROR "))
        .filter(|l| {
            l.contains("row-level security")
                || l.contains("Failed to store")
                || l.contains("embedding matched no row")
        })
        .collect();
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(format!("embedding store refused or failed: {refusals:#?}"))
    }
}

/// `POST /api/v1/submit/packet` by the allowlisted service client: the claim
/// lands in H's group (the insert's authority) AND carries a vector, and the
/// packet's figure evidence carries one too.
#[sqlx::test(migrations = "../../migrations")]
#[traced_test]
async fn packet_by_an_allowlisted_service_client_embeds_claim_and_figure(pool: PgPool) {
    let (state, bearer, l, h_group) = allowlisted_writer(&pool).await;

    let content = format!("allowlisted packet embedding {}", Uuid::new_v4());
    let figure = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk";
    let figure_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(figure.as_bytes()),
    );
    let packet = serde_json::json!({
        // No telemetry `event` property: the route skips embedding those.
        "claim": { "content": content, "initial_truth": 0.7, "agent_id": l },
        "evidence": [{
            "content_hash": figure_hash,
            "evidence_type": {
                "type": "figure",
                "doi": "10.1000/test-figure",
                "figure_id": "Figure 1",
                "caption": "a fixture figure caption",
                "mime_type": "image/png",
                "page": 1
            },
            "raw_content": figure,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "visual_inspection",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.7,
            "explanation": "test",
            "signature": null
        },
        "signature": "0".repeat(128)
    });
    let (status, body) = send(&state, Some(&bearer), "/api/v1/submit/packet", packet).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        claim_rows(&pool, &content).await,
        vec![(l, h_group, true)],
        "one claim, authored by L, owned by H's group, and carrying an embedding after a 201"
    );
    let evidence_id: Uuid = body["evidence_ids"][0]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("an evidence id in {body}"));
    let evidence_embedded: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM evidence WHERE id = $1")
            .bind(evidence_id)
            .fetch_one(&pool)
            .await
            .expect("read the figure evidence");
    assert!(
        evidence_embedded,
        "the packet's figure evidence carries an embedding after a 201"
    );
    logs_assert(no_store_refusal);
}

/// The `AuthContext` the bearer middleware injects for a human operator's
/// `claims:write` token.
fn human_token(agent: Uuid) -> Extension<AuthContext> {
    Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
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

/// A registered human operator writing as itself on an armed, application-role
/// state with an embedder: `(state, the operator, its personal group)`.
///
/// Not the allowlisted service client of the packet arm: `create_claim_core`
/// owns a public claim by the AUTHENTICATED principal's personal group, which
/// an allowlisted agent's operator does not write, so that principal is
/// refused `OPL02` on this route by design (migration 149) and never reaches
/// the embed. The unstamped store was refused for every writer, so the
/// simplest bound writer exercises the same defect.
async fn human_writer(pool: &PgPool) -> (AppState, Uuid, Uuid) {
    let (h, h_group) = seed_human_operator(pool, "human-h").await;
    as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    (app_role_state_with_embedder(pool).await, h, h_group)
}

/// `POST /api/v1/claims`: `create_claim_core`'s post-commit embed stores on
/// the caller's stamp, and the claim carries a vector.
#[sqlx::test(migrations = "../../migrations")]
#[traced_test]
async fn create_claim_embeds_the_claim_on_the_callers_stamp(pool: PgPool) {
    let (state, h, h_group) = human_writer(&pool).await;

    let content = format!("create_claim embedding {}", Uuid::new_v4());
    let req: epigraph_api::routes::claims::CreateClaimRequest = serde_json::from_value(
        serde_json::json!({ "content": content, "agent_id": h, "initial_truth": 0.6 }),
    )
    .expect("request");
    let resp = epigraph_api::routes::claims::create_claim(
        ViewerExtractor(Viewer::resolve(&pool, h).await.expect("viewer")),
        State(state),
        Some(human_token(h)),
        Json(req),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("create_claim succeeds");
    assert_eq!(resp.0.content, content);
    assert_eq!(
        claim_rows(&pool, &content).await,
        vec![(h, h_group, true)],
        "one claim, H's, in H's group, and carrying an embedding"
    );
    logs_assert(no_store_refusal);
}

/// `POST /api/v1/claims/batch` shares `create_claim_core`, one call per item:
/// every created item carries a vector.
#[sqlx::test(migrations = "../../migrations")]
#[traced_test]
async fn batch_create_claims_embeds_every_claim_on_the_callers_stamp(pool: PgPool) {
    let (state, h, h_group) = human_writer(&pool).await;

    let tag = Uuid::new_v4();
    let contents = [
        format!("batch embedding one {tag}"),
        format!("batch embedding two {tag}"),
    ];
    let req: epigraph_api::routes::batch::BatchClaimRequest =
        serde_json::from_value(serde_json::json!({
            "claims": contents
                .iter()
                .map(|c| serde_json::json!({ "content": c, "truth_value": 0.6 }))
                .collect::<Vec<_>>()
        }))
        .expect("request");
    let Json(body) = epigraph_api::routes::batch::batch_create_claims(
        ViewerExtractor(Viewer::resolve(&pool, h).await.expect("viewer")),
        State(state),
        Some(human_token(h)),
        Json(req),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("batch_create_claims succeeds");
    assert_eq!(body.created, 2, "{body:?}");
    for content in &contents {
        assert_eq!(
            claim_rows(&pool, content).await,
            vec![(h, h_group, true)],
            "{content:?}: H's, in H's group, and carrying an embedding"
        );
    }
    logs_assert(no_store_refusal);
}

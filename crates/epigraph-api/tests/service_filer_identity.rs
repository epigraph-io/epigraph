#![cfg(feature = "db")]
//! A non-interactive SERVICE FILER, end to end over kernel REST (backlog
//! d654d46c; the path `docs/tenancy.md` "Non-interactive service filer"
//! describes).
//!
//! The filer is an unlinked `service` OAuth client. Its agent is put on the
//! migration-149 author-binding allowlist for a named registered human H and
//! holds a writer membership of one team G. It never holds an operator link,
//! because a link makes an agent stdio-only (107, `operated_agent_token.rs`).
//! Everything runs on the APPLICATION ROLE, with the operator binding ARMED,
//! through the full router, with the token the client really mints:
//!
//! * the first `client_credentials` mint materializes the client's agent
//!   (that is how the agent comes to exist, and why an allowance needs one
//!   mint first);
//! * CONTROL: before the allowance the filer is unbound: its packet is refused
//!   `OPL01` with nothing written, and the team verb will not add it to G
//!   (`GRP04`);
//! * after it, `POST /api/v1/submit/packet` (a claim with one evidence row)
//!   with `group_id = G` lands in G, authored by the filer's agent, and
//!   `GET /api/v1/claims/:id` names that agent and H in `authored_by`;
//! * a team the filer is a writer of but H does not write is refused `OPL02`,
//!   and H's personal group is refused 403 (a personal group is never a team);
//! * the token exchanges for the `episcience` audience, for the same
//!   principal and scopes, and the exchanged token is refused on the kernel;
//! * revoking the allowance unbinds the filer at once (`OPL01`), with the same
//!   token and the membership still in place.
//!
//! PINNED AS OBSERVED, not defended: a team H writes that the filer is NOT a
//! member of (G2) ADMITS the filer's claim. Migration 206's
//! `epigraph_writable_teams` gives an agent every team its live human writes
//! (`via = 'operator'`, owner decision D-V3), and `epigraph_human_of` returns
//! H for an allowlisted agent (149), so the packet route stamps G2 into the
//! write. The writer membership of G therefore does NOT confine the filer's
//! CLAIMS: 149 scopes them to "groups its operator writes". It bounds the
//! non-claim writes the binding does not gate (149's door gap). Whether D-V3
//! should exclude allowlisted agents is an open operator question; if it is
//! narrowed, the G2 arm flips to a refusal and this pin must change with it.
//!
//! Verified to fail: without the allowance the team verb refuses S (`GRP04`);
//! with `authored_by`'s filer human dropped (`authored_by.rs`), the read-back
//! names no human.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::oauth::token_exchange::TokenExchangeAudiences;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

/// The one extension audience this server exchanges for.
const EXT: &str = "episcience";
/// The filer's scopes: read back, write claims, evidence and edges. No admin
/// scope, no extension scope.
const FILER_SCOPES: &[&str] = &[
    "claims:read",
    "claims:write",
    "evidence:write",
    "edges:write",
];

/// Both pools the application role; the router exchanges for [`EXT`] only.
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
    let mut state = AppState::with_db(raw, ApiConfig::default())
        .with_token_exchange_audiences(TokenExchangeAudiences::parse(Some(EXT)));
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// `req` through the full router of `state`: `(status, body)`.
async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// A claim with one observation as its evidence, authored by `author`, for
/// team `group`.
fn packet(author: Uuid, group: Uuid, content: &str) -> Value {
    let evidence = format!("evidence for {content}");
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence.as_bytes()),
    );
    json!({
        "claim": { "content": content, "initial_truth": 0.7, "agent_id": author },
        "evidence": [{
            "content_hash": evidence_hash,
            "evidence_type": {
                "type": "observation",
                "observed_at": chrono::Utc::now(),
                "method": "instrument run",
                "location": null
            },
            "raw_content": evidence,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.7,
            "explanation": "filed from the run's result file",
            "signature": null
        },
        "signature": "0".repeat(128),
        "group_id": group,
    })
}

/// `POST /api/v1/submit/packet` with `bearer`, a fresh claim of `label` by
/// `author` for `group`: `(status, body, content)`.
async fn file(
    state: &AppState,
    bearer: &str,
    author: Uuid,
    group: Uuid,
    label: &str,
) -> (StatusCode, Value, String) {
    let content = format!("service filer: {label} {}", Uuid::new_v4());
    let (status, body) = send(
        state,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/submit/packet")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::from(packet(author, group, &content).to_string()))
            .expect("request"),
    )
    .await;
    (status, body, content)
}

/// `(agent_id, owner_group_id)` of every claim with `content`, read on the
/// harness (superuser) pool, so a row the caller could not see is counted.
async fn claims_with_content(pool: &PgPool, content: &str) -> Vec<(Uuid, Uuid)> {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content_hash = $1")
        .bind(hash.as_slice())
        .fetch_all(pool)
        .await
        .expect("read back")
}

/// A refusal that names `code` and leaves nothing written.
async fn assert_refused(
    pool: &PgPool,
    (status, body, content): (StatusCode, Value, String),
    want: StatusCode,
    code: &str,
    arm: &str,
) {
    assert_eq!(status, want, "{arm}: {body}");
    assert!(
        body.to_string().contains(code),
        "{arm} names {code}: {body}"
    );
    assert!(
        claims_with_content(pool, &content).await.is_empty(),
        "{arm}: nothing written"
    );
}

/// One row's first column of `sql`, run with `binds` on a session downgraded
/// to `epigraph_maintenance` (the operator CLI's role).
async fn maintenance<T>(pool: &PgPool, sql: &'static str, binds: &[Uuid]) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
    T: 'static,
{
    let binds = binds.to_vec();
    as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let mut q = sqlx::query_scalar::<_, T>(sql);
        for b in binds {
            q = q.bind(b);
        }
        let v = q.fetch_one(&mut *conn).await.expect(sql);
        (conn, v)
    })
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_service_filer_writes_its_team_over_rest_as_its_own_agent(pool: PgPool) {
    // H, a registered human; G and G2, teams H administers; G3, a team of
    // another human that H does not write.
    let (h, h_personal) = viewer_fixture::seed_human_operator(&pool, "filer-operator").await;
    let (h2, _) = viewer_fixture::seed_human_operator(&pool, "other-operator").await;
    let g = viewer_fixture::verb_team_group(&pool, "filer target", h).await;
    let g2 = viewer_fixture::verb_team_group(&pool, "operator's other team", h).await;
    let g3 = viewer_fixture::verb_team_group(&pool, "another human's team", h2).await;

    // The filer: a `service` client with a known secret and NO agent yet.
    let secret_bytes: [u8; 32] = *blake3::hash(b"service filer identity").as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let scopes: Vec<String> = FILER_SCOPES.iter().map(|s| (*s).to_string()).collect();
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'service filer', 'service', $3, $3, 'active', 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
    .bind(&scopes)
    .fetch_one(&pool)
    .await
    .expect("the service client");
    let armed: bool = maintenance::<bool>(
        &pool,
        "SELECT armed_now FROM public.epigraph_arm_operator_binding()",
        &[],
    )
    .await;
    assert!(armed, "CALIBRATION: this call armed the binding");
    let state = app_role_state(&pool).await;

    // The mint materializes the client's agent S; the token carries exactly
    // the filer's scopes.
    let (status, body) = send(
        &state,
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"grant_type": "client_credentials", "client_id": client_id,
                       "client_secret": secret})
                .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    assert_eq!(body["scope"], json!(FILER_SCOPES.join(" ")), "{body}");
    let bearer = body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let s: Uuid = sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(client)
        .fetch_one(&pool)
        .await
        .expect("the first mint pins the client's agent");
    assert!(
        !viewer_fixture::has_unrevoked_row(&pool, g, s).await,
        "CALIBRATION"
    );
    // A writer row of S in G3, a team H does not write. The team verb refuses
    // to add one (GRP04 while S is unbound, GRP03 after), so it is written
    // directly: it stands for a FOREIGN-WRITE row the allowance lists and an
    // operator left in place.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(g3)
    .bind(s)
    .execute(&pool)
    .await
    .expect("S writes in G3");

    // CONTROL: no allowance, so S is unbound and armed refuses it.
    assert_refused(
        &pool,
        file(&state, &bearer, s, g3, "before the allowance").await,
        StatusCode::FORBIDDEN,
        "OPL01",
        "unbound",
    )
    .await;

    // The allowance, on the maintenance role (`epigraph-operator
    // allow-author-binding-client`'s definer).
    let binding: String = maintenance::<String>(
        &pool,
        "SELECT effective_binding \
           FROM public.epigraph_allow_author_binding_client($1, $2, 'service filer')",
        &[client, h],
    )
    .await;
    assert_eq!(binding, "client_allowlist", "the allowance binds S");
    // Only now may the team verb add S to G: it needs S's live human, and
    // that H writes G.
    viewer_fixture::verb_team_group_add(&pool, g, s, "writer").await;

    // Into G: written, one evidence row, authored by S, owned by G.
    let (status, body, content) = file(&state, &bearer, s, g, "team G").await;
    assert_eq!(status, StatusCode::CREATED, "G: {body}");
    assert_eq!(body["owner_group_id"], json!(g), "{body}");
    assert_eq!(body["visibility"], json!("team"), "{body}");
    assert_eq!(claims_with_content(&pool, &content).await, vec![(s, g)]);
    let claim: Uuid = serde_json::from_value(body["claim_id"].clone()).expect("claim_id");
    let evidence = body["evidence_ids"].as_array().expect("evidence_ids");
    assert_eq!(evidence.len(), 1, "{body}");
    let evidence_claim: Uuid = sqlx::query_scalar("SELECT claim_id FROM evidence WHERE id = $1")
        .bind(Uuid::parse_str(evidence[0].as_str().expect("an id")).expect("uuid"))
        .fetch_one(&pool)
        .await
        .expect("the evidence row");
    assert_eq!(evidence_claim, claim, "the evidence is the claim's");

    // Read back with the filer's own token: S filed it, for H.
    let (status, body) = send(
        &state,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/claims/{claim}"))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read back: {body}");
    let authored = &body["authored_by"];
    assert_eq!(authored["source"], json!("agent"), "{authored}");
    assert_eq!(authored["agent"]["id"], json!(s), "{authored}");
    assert_eq!(authored["human"]["id"], json!(h), "{authored}");

    // Outside what H writes: refused by the binding, nothing written.
    assert_refused(
        &pool,
        file(&state, &bearer, s, g3, "a team H does not write").await,
        StatusCode::FORBIDDEN,
        "OPL02",
        "G3",
    )
    .await;
    // H's personal group is never a team.
    assert_refused(
        &pool,
        file(&state, &bearer, s, h_personal, "H's personal group").await,
        StatusCode::FORBIDDEN,
        "is not a team you may write",
        "H personal",
    )
    .await;

    // PINNED AS OBSERVED (see the module doc): a team H writes, S not a
    // member, admits the claim through H (D-V3).
    assert!(
        !viewer_fixture::has_unrevoked_row(&pool, g2, s).await,
        "CALIBRATION: S holds no row in G2"
    );
    let (status, body, content) = file(&state, &bearer, s, g2, "H's other team").await;
    assert_eq!(status, StatusCode::CREATED, "G2: {body}");
    assert_eq!(claims_with_content(&pool, &content).await, vec![(s, g2)]);

    // The token exchange for the extension: same principal, same scopes, at
    // most five minutes, and refused on the kernel.
    let pairs = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", bearer.as_str()),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", EXT),
    ];
    let (status, body) = send(
        &state,
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                serde_urlencoded::to_string(pairs).expect("form"),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let exchanged = body["access_token"].as_str().expect("access_token");
    let subject = state.jwt_config.validate_token(&bearer).expect("subject");
    let got = state
        .jwt_config
        .validate_token_for_audience(exchanged, EXT)
        .expect("the extension admits it");
    assert_eq!(got.aud, EXT);
    assert_eq!((got.sub, got.agent_id), (client, Some(s)));
    assert_eq!(got.scopes, subject.scopes);
    assert!(
        (1..=300).contains(&body["expires_in"].as_i64().expect("expires_in")),
        "{body}"
    );
    let (status, body, content) = file(&state, exchanged, s, g, "with the exchanged token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "kernel refuses: {body}");
    assert!(claims_with_content(&pool, &content).await.is_empty());

    // Incident response: revoking the allowance unbinds S at once.
    let revoked: bool = maintenance::<bool>(
        &pool,
        "SELECT revoked_now \
           FROM public.epigraph_revoke_author_binding_client($1, 'incident drill')",
        &[client],
    )
    .await;
    assert!(revoked, "CALIBRATION: the allowance is revoked");
    assert!(viewer_fixture::has_unrevoked_row(&pool, g, s).await);
    assert_refused(
        &pool,
        file(&state, &bearer, s, g, "after the revoke").await,
        StatusCode::FORBIDDEN,
        "OPL01",
        "revoked",
    )
    .await;
}

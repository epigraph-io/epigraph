#![cfg(feature = "db")]
//! `grant_type=urn:epigraph:grant:run-token`: a host DELEGATOR client mints a
//! short-lived token for an operated LLM agent, named by its identity public
//! key, that the server admits as that agent through the delegation check the
//! bearer middlewares already run (`dlg`; `delegated_run_token_viewer.rs`).
//!
//! What these tests pin:
//!
//! * the SERVER decides what the token may see: the agent's own memberships,
//!   resolved per request. Nothing the delegator puts in its request (group
//!   ids, scopes it holds, another principal) widens it;
//! * the token's shape is the one the admission sites were proved against: an
//!   `agent` token for the principal, `sub` the delegator client, `dlg` the
//!   delegator's agent, at most 15 minutes, no refresh token, scopes inside
//!   the delegated ceiling;
//! * every reason the delegation is not live refuses the MINT too, and no
//!   refusal creates an agent;
//! * every mint and every refusal (once the grant is on) leaves one
//!   `security_events` row;
//! * a minted token reaches a tool on the MCP streamable-HTTP transport.
//!
//! Every pool the routes run on is the APPLICATION role (row security
//! applies); seeding and read-backs use the harness's superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use delegation::Delegation;
use epigraph_api::oauth::run_token::RunTokenModels;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::RunTokens;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const GRANT: &str = "urn:epigraph:grant:run-token";

/// The model every test principal records (`agents.properties`).
const MODEL: &str = "test-run-token-model";

/// The delegator's client secret (32 bytes; hex on the wire).
const SECRET: [u8; 32] = [0x5a; 32];

/// The scopes the test delegator client is GRANTED: the delegated ceiling's
/// read/write scopes and, deliberately, scopes outside it.
const DELEGATOR_GRANTED: &[&str] = &[
    "claims:read",
    "claims:write",
    "evidence:read",
    "edges:read",
    "agents:read",
    "groups:read",
    "groups:manage",
    "agents:write",
    "claims:admin",
];

/// Scopes no run token may carry, whatever is granted or asked for.
const NEVER: &[&str] = &[
    "groups:read",
    "groups:manage",
    "agents:write",
    "claims:admin",
];

fn secret_hex() -> String {
    hex::encode(SECRET)
}

// ─────────────────────────────────────────────────────────────────────────────
// World
// ─────────────────────────────────────────────────────────────────────────────

/// An application-role `AppState` with a scoped pool, as `bin/server.rs`
/// builds it, with the run-token switch and model list as given.
async fn app_state(pool: &PgPool, run_tokens: RunTokens, models: &[&str]) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "PREMISE: epigraph_app is subject to row security"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default())
        .with_run_tokens(run_tokens)
        .with_run_token_models(RunTokenModels::parse(Some(&models.join(","))));
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// Give the delegator client `client` the known [`SECRET`] and `scopes`
/// (granted and allowed). Its `client_id`.
async fn arm_client(pool: &PgPool, client: Uuid, scopes: &[&str]) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query_scalar(
        "UPDATE oauth_clients SET client_secret_hash = $2, granted_scopes = $3, \
                                  allowed_scopes = $3 \
          WHERE id = $1 RETURNING client_id",
    )
    .bind(client)
    .bind(blake3::hash(&SECRET).as_bytes().as_slice())
    .bind(&scopes)
    .fetch_one(pool)
    .await
    .expect("arm the delegator client")
}

/// Record `model` as `agent`'s LLM model; its identity public key, hex.
async fn identify(pool: &PgPool, agent: Uuid, model: &str) -> String {
    let pk: Vec<u8> = sqlx::query_scalar(
        "UPDATE agents SET properties = COALESCE(properties, '{}'::jsonb) \
                                        || jsonb_build_object('llm_model', $2::text) \
          WHERE id = $1 RETURNING public_key",
    )
    .bind(agent)
    .bind(model)
    .fetch_one(pool)
    .await
    .expect("record the principal's model");
    hex::encode(pk)
}

/// A live delegation whose delegator is armed with [`DELEGATOR_GRANTED`] and
/// whose principal records [`MODEL`]: `(delegation, client_id, principal key)`.
async fn world(pool: &PgPool, label: &str) -> (Delegation, String, String) {
    let d = delegation::live_delegation(pool, label).await;
    let client_id = arm_client(pool, d.delegator_client, DELEGATOR_GRANTED).await;
    let key = identify(pool, d.principal, MODEL).await;
    (d, client_id, key)
}

/// The grant's request body; `extra` is merged in (and may override).
fn request(client_id: &str, key: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": GRANT,
        "client_id": client_id,
        "client_secret": secret_hex(),
        "agent_public_key": key,
        "run_label": "schedule:test-run",
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    body
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()));
    (status, body)
}

/// `POST /oauth/token` with a JSON body.
async fn mint(state: &AppState, body: &Value) -> (StatusCode, Value) {
    send(
        state,
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

/// The access token of a successful mint, or a panic naming the answer.
fn token_of(what: &str, (status, body): &(StatusCode, Value)) -> String {
    assert_eq!(
        *status,
        StatusCode::OK,
        "{what}: the mint must succeed: {body}"
    );
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: an access token: {body}"))
        .to_string()
}

/// A refused mint: 400 with `error`, and no token.
fn assert_refused(what: &str, (status, body): &(StatusCode, Value), error: &str) {
    assert_eq!(*status, StatusCode::BAD_REQUEST, "{what}: refused: {body}");
    assert_eq!(body["error"], json!(error), "{what}: error code: {body}");
    assert!(
        body.get("access_token").is_none(),
        "{what}: no token: {body}"
    );
}

/// `GET /api/v1/claims/{claim}` (with `?group_id=` when given) under `token`.
async fn read_claim(
    state: &AppState,
    token: &str,
    claim: Uuid,
    group: Option<Uuid>,
) -> (StatusCode, Value) {
    let uri = match group {
        Some(g) => format!("/api/v1/claims/{claim}?group_id={g}"),
        None => format!("/api/v1/claims/{claim}"),
    };
    send(
        state,
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

fn scopes_of(body: &Value) -> Vec<String> {
    body["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

async fn agent_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(pool)
        .await
        .expect("count agents")
}

async fn events(pool: &PgPool, event_type: &str) -> Vec<(Option<Uuid>, Option<bool>, Value)> {
    sqlx::query_as(
        "SELECT agent_id, success, details FROM security_events \
          WHERE event_type = $1 ORDER BY created_at",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("read security events")
}

// ─────────────────────────────────────────────────────────────────────────────
// The server resolves what the token sees
// ─────────────────────────────────────────────────────────────────────────────

/// THE property the grant exists for. Group X is written by the delegator and
/// by the operator, but the principal is not a member. The delegator asks for
/// a token naming X every way a request could (`group_ids`, `groups`,
/// `owner_group_id`) and for scopes outside the ceiling that it holds. The
/// token it gets reads the principal's own group G (calibration: it is
/// admitted, as the principal) and cannot read X, nor pass a group check
/// naming X, nor carry any of the out-of-ceiling scopes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_token_cannot_read_a_group_its_agent_is_not_in_even_when_the_request_names_it(
    pool: PgPool,
) {
    let (d, client_id, key) = world(&pool, "run-token-read").await;
    let (outsider, group_x) = delegation::agent_with_group(&pool, "run-token-x").await;
    delegation::membership(&pool, group_x, d.delegator, "writer").await;
    delegation::membership(&pool, group_x, d.operator, "writer").await;
    let claim_g =
        fixture::seed_group_claim(&pool, d.operator, d.operator_group, "run token own group").await;
    let claim_x = fixture::seed_group_claim(&pool, outsider, group_x, "run token group x").await;

    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    let asked = mint(
        &st,
        &request(
            &client_id,
            &key,
            json!({
                "scope": "claims:read groups:read groups:manage agents:write claims:admin",
                "group_ids": [group_x],
                "groups": [group_x],
                "owner_group_id": group_x,
            }),
        ),
    )
    .await;
    let token = token_of("a request naming group X", &asked);
    let scopes = scopes_of(&asked.1);
    assert_eq!(
        scopes,
        ["claims:read"],
        "only the in-ceiling scope asked for: {}",
        asked.1
    );
    for never in NEVER {
        assert!(
            !scopes.iter().any(|s| s == never),
            "{never} must never be minted"
        );
    }

    let (status, body) = read_claim(&st, &token, claim_g, None).await;
    assert!(
        status == StatusCode::OK && body.to_string().contains(&claim_g.to_string()),
        "CALIBRATION: the token reads the principal's own group: {status} {body}"
    );
    let (status, body) = read_claim(&st, &token, claim_x, None).await;
    assert!(
        status == StatusCode::NOT_FOUND && !body.to_string().contains("run token group x"),
        "group X is not readable by the run token (an invisible claim is not found): \
         {status} {body}"
    );
    let (status, body) = read_claim(&st, &token, claim_x, Some(group_x)).await;
    assert!(
        status == StatusCode::FORBIDDEN && !body.to_string().contains("run token group x"),
        "a group check naming X refuses the run token: {status} {body}"
    );

    // CONTROL: the refusal above is the principal's MEMBERSHIP, resolved by
    // the server on each request, and nothing else. Give the principal a
    // reader membership of X and the SAME token (minted before it existed)
    // reads claim X: the claim exists, and the token carries no group set of
    // its own.
    delegation::membership(&pool, group_x, d.principal, "reader").await;
    let (status, body) = read_claim(&st, &token, claim_x, None).await;
    assert!(
        status == StatusCode::OK && body.to_string().contains("run token group x"),
        "CONTROL: once the principal is a member of X, the same token reads claim X: \
         {status} {body}"
    );
}

/// A run token's scopes are bounded by what the DELEGATOR is granted, not
/// only by the delegated ceiling: a delegator granted `claims:read` alone
/// cannot mint `claims:write` (which is inside the ceiling) by asking for it,
/// and a request naming only ungranted scopes is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_token_never_carries_a_scope_its_delegator_is_not_granted(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-granted").await;
    assert!(
        epigraph_auth::DELEGATED_SCOPE_CEILING.contains(&"claims:write"),
        "PREMISE: claims:write is inside the ceiling, so only the grant can cut it"
    );
    arm_client(&pool, d.delegator_client, &["claims:read"]).await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;

    let minted = mint(
        &st,
        &request(
            &client_id,
            &key,
            json!({"scope": "claims:read claims:write"}),
        ),
    )
    .await;
    token_of("a request for a granted and an ungranted scope", &minted);
    assert_eq!(
        scopes_of(&minted.1),
        ["claims:read"],
        "only the granted scope is minted: {}",
        minted.1
    );

    let refused = mint(
        &st,
        &request(&client_id, &key, json!({"scope": "claims:write"})),
    )
    .await;
    assert_refused(
        "a request for an ungranted scope only",
        &refused,
        "invalid_scope",
    );
    let rows = events(&pool, "oauth_run_token_refused").await;
    assert_eq!(rows.len(), 1, "one refusal row: {rows:?}");
    assert_eq!(rows[0].2["reason"], json!("no_scope"), "{rows:?}");
}

/// The minted token is the shape the admission sites were proved against.
#[sqlx::test(migrations = "../../migrations")]
async fn a_minted_run_token_is_a_short_delegated_agent_token_with_no_refresh_token(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-shape").await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    // No `scope`: the client's granted scopes, cut to the ceiling.
    let minted = mint(&st, &request(&client_id, &key, json!({}))).await;
    let token = token_of("a plain request", &minted);
    let body = &minted.1;
    assert!(
        body.get("refresh_token").is_none(),
        "no refresh token: {body}"
    );
    let expires_in = body["expires_in"].as_i64().expect("expires_in");
    assert!(
        (1..=900).contains(&expires_in),
        "at most 15 minutes: {body}"
    );
    let scopes = scopes_of(body);
    assert!(!scopes.is_empty(), "some scope: {body}");
    for s in &scopes {
        assert!(
            epigraph_auth::DELEGATED_SCOPE_CEILING.contains(&s.as_str()),
            "{s} is inside the delegated ceiling"
        );
    }
    for never in NEVER {
        assert!(
            !scopes.iter().any(|s| s == never),
            "{never} is never minted"
        );
    }

    let claims = st.jwt_config.validate_token(&token).expect("a valid token");
    assert_eq!(
        claims.sub, d.delegator_client,
        "sub is the delegator client"
    );
    assert_eq!(
        claims.agent_id,
        Some(d.principal),
        "the principal is the agent"
    );
    assert_eq!(
        claims.dlg,
        Some(d.delegator),
        "dlg names the delegator's agent"
    );
    assert_eq!(claims.client_type, "agent");
    assert_eq!(claims.owner_id, None);
    assert_eq!(claims.fam, None);
    assert_eq!(claims.elv, None);
    assert!(claims.exp - claims.iat <= 900, "lifetime at most 900 s");

    // Refreshable by the HOST: a second mint is a new token, not a renewal.
    let again = token_of(
        "a second mint",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
    );
    let again = st.jwt_config.validate_token(&again).expect("valid");
    assert_ne!(again.jti, claims.jti, "each mint is its own token");
}

/// Dormant until armed: with the switch off the grant does not exist (and,
/// being dormant, writes no audit row).
#[sqlx::test(migrations = "../../migrations")]
async fn the_grant_is_unsupported_while_run_tokens_are_off(pool: PgPool) {
    let (_d, client_id, key) = world(&pool, "run-token-off").await;
    let st = app_state(&pool, RunTokens::Off, &[MODEL]).await;
    let answer = mint(&st, &request(&client_id, &key, json!({}))).await;
    assert_refused("switch off", &answer, "unsupported_grant_type");
    assert!(events(&pool, "oauth_run_token_refused").await.is_empty());
    assert!(events(&pool, "oauth_run_token_minted").await.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusals
// ─────────────────────────────────────────────────────────────────────────────

/// Every way the delegation is not live refuses the mint, before any token
/// exists; an unknown identity is refused without creating an agent; each
/// refusal is one audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mint_whose_delegation_is_not_live_is_refused(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-refusals").await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    token_of(
        "CALIBRATION: the world mints",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
    );

    // An identity key no agent has.
    let before = agent_count(&pool).await;
    let unknown = hex::encode([0x11u8; 32]);
    assert_refused(
        "unknown identity",
        &mint(&st, &request(&client_id, &unknown, json!({}))).await,
        "invalid_grant",
    );
    assert_eq!(agent_count(&pool).await, before, "no agent is created");

    // An LLM agent with no operator link.
    let (unlinked, _) = delegation::agent_with_group(&pool, "run-token-unlinked").await;
    let unlinked_key = identify(&pool, unlinked, MODEL).await;
    assert_refused(
        "unlinked principal",
        &mint(&st, &request(&client_id, &unlinked_key, json!({}))).await,
        "invalid_grant",
    );

    // A principal linked to ANOTHER operator.
    let other = delegation::live_delegation(&pool, "run-token-other-operator").await;
    let other_key = identify(&pool, other.principal, MODEL).await;
    assert_refused(
        "another operator's principal",
        &mint(&st, &request(&client_id, &other_key, json!({}))).await,
        "invalid_grant",
    );

    // A delegator that is not on the allowlist.
    let (c, _) =
        delegation::delegator(&pool, d.operator, d.operator_group, Some("writer"), false).await;
    let not_allowed = arm_client(&pool, c, DELEGATOR_GRANTED).await;
    assert_refused(
        "a delegator not on the allowlist",
        &mint(&st, &request(&not_allowed, &key, json!({}))).await,
        "invalid_grant",
    );

    // An allowlisted delegator that holds no writer membership of G.
    let (c, _) = delegation::delegator(&pool, d.operator, d.operator_group, None, true).await;
    let no_membership = arm_client(&pool, c, DELEGATOR_GRANTED).await;
    assert_refused(
        "a delegator without writer membership",
        &mint(&st, &request(&no_membership, &key, json!({}))).await,
        "invalid_grant",
    );

    // The wrong secret.
    assert_refused(
        "wrong secret",
        &mint(
            &st,
            &request(
                &client_id,
                &key,
                json!({"client_secret": hex::encode([0x5bu8; 32])}),
            ),
        )
        .await,
        "invalid_client",
    );

    // A human client cannot delegate.
    let human: String =
        sqlx::query_scalar("SELECT client_id FROM oauth_clients WHERE agent_id = $1")
            .bind(d.operator)
            .fetch_one(&pool)
            .await
            .expect("the operator's human client");
    assert_refused(
        "a human client",
        &mint(&st, &request(&human, &key, json!({}))).await,
        "invalid_client",
    );

    // A suspended delegator client.
    delegation::set_client_status(&pool, d.delegator_client, "suspended").await;
    assert_refused(
        "a suspended delegator",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
        "invalid_client",
    );
    delegation::set_client_status(&pool, d.delegator_client, "active").await;

    // A retired link.
    delegation::retire_link(&pool, d.principal).await;
    assert_refused(
        "a retired link",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
        "invalid_grant",
    );

    // Unknown identity, unlinked, other operator, not allowed, no membership,
    // wrong secret, human, suspended, retired: one row each.
    let refused = events(&pool, "oauth_run_token_refused").await;
    assert_eq!(refused.len(), 9, "one audit row per refusal: {refused:?}");
    assert!(refused.iter().all(|(_, ok, _)| *ok == Some(false)));
}

/// The model list: a principal whose model is not listed is refused, and an
/// unset list refuses every mint.
#[sqlx::test(migrations = "../../migrations")]
async fn a_model_outside_the_allowlist_is_refused(pool: PgPool) {
    let (_d, client_id, key) = world(&pool, "run-token-models").await;
    let listed = app_state(&pool, RunTokens::On, &[MODEL]).await;
    token_of(
        "CALIBRATION: a listed model mints",
        &mint(&listed, &request(&client_id, &key, json!({}))).await,
    );
    let other = app_state(&pool, RunTokens::On, &["another-model"]).await;
    assert_refused(
        "a model not listed",
        &mint(&other, &request(&client_id, &key, json!({}))).await,
        "invalid_grant",
    );
    let none = app_state(&pool, RunTokens::On, &[]).await;
    assert_refused(
        "no model listed",
        &mint(&none, &request(&client_id, &key, json!({}))).await,
        "invalid_grant",
    );
}

/// A malformed request is `invalid_request`: a run label over 64 characters,
/// an identity key that is not 32 bytes of hex, a missing key.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_run_token_request_is_invalid_request(pool: PgPool) {
    let (_d, client_id, key) = world(&pool, "run-token-malformed").await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    assert_refused(
        "a long run label",
        &mint(
            &st,
            &request(&client_id, &key, json!({"run_label": "x".repeat(65)})),
        )
        .await,
        "invalid_request",
    );
    assert_refused(
        "a short key",
        &mint(&st, &request(&client_id, "abcd", json!({}))).await,
        "invalid_request",
    );
    let mut no_key = request(&client_id, &key, json!({}));
    no_key
        .as_object_mut()
        .expect("object")
        .remove("agent_public_key");
    assert_refused("no key", &mint(&st, &no_key).await, "invalid_request");
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit
// ─────────────────────────────────────────────────────────────────────────────

/// A mint leaves exactly one `oauth_run_token_minted` row, written on the
/// application role: the principal as `agent_id`, and details naming the
/// delegator, the operator, the token's jti and expiry, its scopes and the run
/// label. The secret appears nowhere in it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mint_writes_one_audit_row_naming_the_token(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-audit").await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    let token = token_of(
        "mint",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
    );
    let claims = st.jwt_config.validate_token(&token).expect("valid");

    let minted = events(&pool, "oauth_run_token_minted").await;
    assert_eq!(minted.len(), 1, "one row: {minted:?}");
    let (agent, ok, details) = &minted[0];
    assert_eq!(*agent, Some(d.principal));
    assert_eq!(*ok, Some(true));
    assert_eq!(details["jti"], json!(claims.jti), "{details}");
    assert_eq!(details["exp"], json!(claims.exp), "{details}");
    assert_eq!(details["delegator"], json!(d.delegator), "{details}");
    assert_eq!(
        details["delegator_client"],
        json!(d.delegator_client),
        "{details}"
    );
    assert_eq!(details["operator"], json!(d.operator), "{details}");
    assert_eq!(
        details["run_label"],
        json!("schedule:test-run"),
        "{details}"
    );
    let text = details.to_string();
    assert!(!text.contains(&secret_hex()), "the secret is never audited");
    assert!(!text.contains(&token), "the token is never audited");
    assert!("oauth_run_token_minted".len() < 50 && "oauth_run_token_refused".len() < 50);
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP streamable HTTP
// ─────────────────────────────────────────────────────────────────────────────

/// The MCP listener `epigraph-mcp --listen` builds, behind the production
/// bearer middleware, verifying with `jwt`, with the switch as given.
async fn mcp_listener(pool: &PgPool, jwt: std::sync::Arc<epigraph_auth::JwtConfig>) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    let scoped = fixture::scoped_pool(pool).await;
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let revocation = Arc::new(epigraph_mcp::auth::DbAccessTokenRevocation::new(
        app.clone(),
    ));
    let signer = Arc::new(epigraph_crypto::AgentSigner::from_bytes(&[0x77; 32]).expect("signer"));
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(app.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let template = epigraph_mcp::EpiGraphMcpFull::new_shared(app, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(RunTokens::On);
    let sessions = epigraph_mcp::SessionFactory::new(template);
    let service = StreamableHttpService::new(
        move || Ok(sessions.session()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: jwt,
        resource_metadata_url: None,
        revocation,
    };
    let router = axum08::Router::new().nest_service("/mcp", service).layer(
        axum08::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = tcp.local_addr().expect("addr");
    tokio::spawn(async move {
        axum08::serve(tcp, router).await.expect("serve");
    });
    format!("http://{addr}/mcp")
}

async fn mcp_post(url: &str, token: &str, session: Option<&str>, body: Value) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header("Mcp-Session-Id", s);
    }
    req.send().await.expect("POST")
}

/// The first complete SSE `data:` payload of `resp`, parsed.
async fn sse_data(mut resp: reqwest::Response) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acc = String::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.push_str(&String::from_utf8_lossy(&bytes));
        if let Some(line) = acc
            .lines()
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            if let Ok(v) = serde_json::from_str(line.trim_start_matches("data:").trim()) {
                return v;
            }
        }
    }
    panic!("no SSE data: {acc}");
}

/// `initialize`, `notifications/initialized`, then `tools/call get_claim`.
async fn mcp_get_claim(url: &str, token: &str, claim: Uuid) -> Value {
    let init = mcp_post(
        url,
        token,
        None,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "run-token-grant-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(init.status().as_u16(), 200, "initialize");
    let session = init
        .headers()
        .get("Mcp-Session-Id")
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = sse_data(init).await;
    let notif = mcp_post(
        url,
        token,
        Some(&session),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    let call = mcp_post(
        url,
        token,
        Some(&session),
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_claim", "arguments": {"claim_id": claim.to_string()}}
        }),
    )
    .await;
    sse_data(call).await
}

/// A token MINTED by the grant (not hand-signed) reaches a tool on the MCP
/// streamable-HTTP transport as the principal. The MCP read tools read on the
/// server's unstamped pool (a stated gap, `elevation_acceptance.rs`), so a
/// group-private refusal there would prove nothing about the token; this test
/// pins admission and reads a public claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_minted_run_token_reaches_a_tool_over_mcp_streamable_http(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-mcp").await;
    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    let token = token_of(
        "mint",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
    );
    let claim = fixture::seed_public_claim(&pool, d.operator, "run token over mcp").await;
    let url = mcp_listener(&pool, st.jwt_config.clone()).await;
    let answer = mcp_get_claim(&url, &token, claim).await;
    assert!(
        answer.get("error").is_none()
            && answer["result"]["isError"] != json!(true)
            && answer.to_string().contains(&claim.to_string()),
        "the minted run token reads the claim over MCP: {answer}"
    );
}

/// The MCP twin of the group-X refusal: over the streamable-HTTP transport the
/// containers will use, a MINTED run token does not read a group-private claim
/// of a group its agent is not in, although the delegator and the operator
/// both write that group.
///
/// The MCP read tools read on the server's unstamped pool today (see the test
/// above), so the principal's own group is not readable over MCP either and
/// there is no membership control on this transport; the public read is the
/// calibration that `get_claim` answers claim content here. This test is the
/// REGRESSION GUARD for the day the MCP pool is stamped: stamped from the
/// delegator (`dlg`) or the client (`sub`) instead of the principal, it reads
/// claim X and this goes red.
#[sqlx::test(migrations = "../../migrations")]
async fn a_minted_run_token_cannot_read_a_group_its_agent_is_not_in_over_mcp(pool: PgPool) {
    let (d, client_id, key) = world(&pool, "run-token-mcp-x").await;
    let (outsider, group_x) = delegation::agent_with_group(&pool, "run-token-mcp-x-group").await;
    delegation::membership(&pool, group_x, d.delegator, "writer").await;
    delegation::membership(&pool, group_x, d.operator, "writer").await;
    let claim_x =
        fixture::seed_group_claim(&pool, outsider, group_x, "run token group x over mcp").await;
    let public = fixture::seed_public_claim(&pool, d.operator, "run token public over mcp").await;

    let st = app_state(&pool, RunTokens::On, &[MODEL]).await;
    let token = token_of(
        "mint",
        &mint(&st, &request(&client_id, &key, json!({}))).await,
    );
    let url = mcp_listener(&pool, st.jwt_config.clone()).await;

    let answer = mcp_get_claim(&url, &token, public).await;
    assert!(
        answer.get("error").is_none()
            && answer["result"]["isError"] != json!(true)
            && answer.to_string().contains("run token public over mcp"),
        "CALIBRATION: get_claim answers claim content over MCP: {answer}"
    );
    let answer = mcp_get_claim(&url, &token, claim_x).await;
    assert!(
        (answer.get("error").is_some() || answer["result"]["isError"] == json!(true))
            && !answer.to_string().contains("run token group x over mcp"),
        "group X is not readable by the run token over MCP: {answer}"
    );
}

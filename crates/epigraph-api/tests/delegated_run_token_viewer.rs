//! A delegated run token on the REST surface.
//!
//! An operated agent (migration 107) is stdio-only: its writer membership in
//! its operator's group would otherwise ride any HTTP token onto the surface.
//! A DELEGATED run token is the one carve-out. It names its delegator (`dlg`),
//! the agent of an OAuth client on migration 149's allowlist for the same
//! operator. The bearer middleware checks it on EVERY request that carries
//! one, whether or not the route resolves a viewer, and admits it only while
//! ALL of these hold:
//!
//! * it carries no scope outside the delegated ceiling
//!   (`epigraph_auth::DELEGATED_SCOPE_CEILING`);
//! * the delegator's allowance is live (row not revoked, client `active`, the
//!   agent's only client);
//! * the principal's operator link is acting (not retired, writer row live)
//!   and names the delegator's operator;
//! * the delegator itself holds a live `writer`/`admin` membership in that
//!   operator's group (a precondition; what the token may WRITE is bounded by
//!   the database's operator-scope rule, `OPL02`);
//! * the process read `EPIGRAPH_RUN_TOKENS=on` at boot.
//!
//! A token carrying `dlg` whose delegation is not live is refused whatever the
//! principal's link state: an unlinked principal cannot be delegated to. The
//! viewer reuses the middleware's answer and is the principal's own
//! membership set.
//!
//! Tokens are hand-signed with the state's own `JwtConfig` (no grant mints
//! them yet). Passing the viewer shows as the handler's own "scoped
//! connection" 500 on this harness (`AppState::with_db` builds no scoped
//! pool), as in `operated_agent_token.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::Duration;
use delegation::Delegation;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::AccessTokenBinding;
use epigraph_db::RunTokens;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        allow_all_identities: true,
    }
}

fn state(pool: &PgPool, run_tokens: RunTokens) -> AppState {
    AppState::with_db(pool.clone(), config()).with_run_tokens(run_tokens)
}

/// An `agent`-type access token for `principal`, `sub` = `client`, carrying
/// `dlg = delegated_by` when `Some`. 15 minutes, `claims:read`.
fn token(state: &AppState, client: Uuid, principal: Uuid, delegated_by: Option<Uuid>) -> String {
    token_with(state, client, principal, delegated_by, &["claims:read"])
}

/// [`token`] with the given scopes.
fn token_with(
    state: &AppState,
    client: Uuid,
    principal: Uuid,
    delegated_by: Option<Uuid>,
    scopes: &[&str],
) -> String {
    state
        .jwt_config
        .issue_access_token(
            client,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(principal),
            Duration::minutes(15),
            AccessTokenBinding {
                delegated_by,
                ..AccessTokenBinding::NONE
            },
        )
        .expect("mint")
        .0
}

/// The delegated token of `d`.
fn dlg_token(state: &AppState, d: &Delegation) -> String {
    token(state, d.delegator_client, d.principal, Some(d.delegator))
}

/// `GET /api/v1/evidence` with `access` on `state`'s router: `(status, body)`.
async fn read(state: &AppState, access: &str) -> (StatusCode, String) {
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/evidence")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn assert_admitted(what: &str, (status, body): (StatusCode, String)) {
    assert!(
        status != StatusCode::FORBIDDEN
            && status != StatusCode::UNAUTHORIZED
            && body.contains("scoped connection"),
        "{what}: the token must pass the viewer extractor: {status} {body}"
    );
}

/// A delegated token refused AS A DELEGATION: 403 with the delegation's own
/// reason, never the operated-principal refusal a token without `dlg` gets
/// (which a skipped delegation check would fall through to).
fn assert_refused(what: &str, (status, body): (StatusCode, String)) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{what}: the token must be refused: {body}"
    );
    assert!(
        body.contains("delegation is not live") && !body.contains("stdio-only"),
        "{what}: refused as a delegation that is not live: {body}"
    );
}

/// `POST /api/v1/evidence` with `access` and a body the handler itself refuses
/// (an `evidence_type` no variant matches): a route that resolves NO viewer,
/// where reaching the handler shows as its own 400 and nothing is written.
async fn submit_evidence(state: &AppState, access: &str) -> (StatusCode, String) {
    let body = serde_json::json!({
        "agent_id": Uuid::new_v4(),
        "claim_id": Uuid::new_v4(),
        "raw_content": "delegated evidence probe",
        "evidence_type": {"no_such_variant": {}},
    });
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/evidence")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
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

/// The delegation is checked on EVERY request that carries `dlg`, in the
/// bearer middleware, not only where a viewer is resolved. `POST
/// /api/v1/evidence` resolves none: a live delegation reaches its handler
/// (which refuses the body itself, 400), and the same token is refused there
/// with the switch off and on the next request after the link retires.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dead_delegation_is_refused_at_a_route_that_resolves_no_viewer(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "viewerless").await;
    let st = state(&pool, RunTokens::On);
    let access = token_with(
        &st,
        d.delegator_client,
        d.principal,
        Some(d.delegator),
        &["claims:read", "evidence:submit"],
    );
    let (status, body) = submit_evidence(&st, &access).await;
    assert!(
        status == StatusCode::BAD_REQUEST && body.contains("evidence_type"),
        "CALIBRATION: a live delegation reaches the handler, which refuses the body: \
         {status} {body}"
    );
    assert_refused(
        "switch off",
        submit_evidence(&AppState::with_db(pool.clone(), config()), &access).await,
    );
    delegation::retire_link(&pool, d.principal).await;
    assert_refused(
        "after the link was retired",
        submit_evidence(&st, &access).await,
    );
}

/// A live delegation is admitted, and it is the DELEGATION that admits: the
/// same principal's token without `dlg` is refused as an operated principal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_for_a_live_linked_agent_passes_the_rest_viewer(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "admit").await;
    let st = state(&pool, RunTokens::On);
    assert_admitted("live delegation", read(&st, &dlg_token(&st, &d)).await);

    let (status, body) = read(&st, &token(&st, d.delegator_client, d.principal, None)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "CALIBRATION: without `dlg` the operated principal is refused: {body}"
    );
    assert!(body.contains("stdio-only"), "{body}");
}

/// A principal with NO operator link cannot be delegated to: a `dlg` token for
/// it is refused, although that principal's own token without `dlg` passes.
/// The delegator is live for its operator, so only the principal differs.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_for_an_unlinked_agent_is_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "unlinked").await;
    let (unlinked, _) = delegation::agent_with_group(&pool, "unlinked-principal").await;
    let st = state(&pool, RunTokens::On);

    assert_admitted(
        "CALIBRATION: the unlinked agent's own token",
        read(&st, &token(&st, d.delegator_client, unlinked, None)).await,
    );
    assert_admitted(
        "CALIBRATION: the live delegation",
        read(&st, &dlg_token(&st, &d)).await,
    );
    assert_refused(
        "a dlg token for an unlinked principal",
        read(
            &st,
            &token(&st, d.delegator_client, unlinked, Some(d.delegator)),
        )
        .await,
    );
}

/// The switch is read per process: the same token is admitted by a router
/// built ON and refused by one built OFF (the default).
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_is_refused_when_the_switch_is_off(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "switch").await;
    let on = state(&pool, RunTokens::On);
    let access = dlg_token(&on, &d);
    assert_admitted("CALIBRATION: switch on", read(&on, &access).await);
    assert_refused(
        "switch off",
        read(&AppState::with_db(pool.clone(), config()), &access).await,
    );
}

/// The principal's link retired AFTER the token was minted: the next request
/// with the same token, on the same router, is refused. No restart, no cache.
#[sqlx::test(migrations = "../../migrations")]
async fn retiring_the_agents_link_refuses_its_next_request_without_restart(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "retire").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted("CALIBRATION: before the retire", read(&st, &access).await);
    delegation::retire_link(&pool, d.principal).await;
    assert_refused("after the link was retired", read(&st, &access).await);
}

/// The operator ends the principal's authority with an ordinary revoke of its
/// writer row: the link stops acting, and the next request is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_agents_operator_membership_refuses_its_next_request(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "revoke-agent").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted("CALIBRATION: before the revoke", read(&st, &access).await);
    delegation::revoke_membership(&pool, d.principal, d.operator_group).await;
    assert_refused(
        "after the principal's writer row was revoked",
        read(&st, &access).await,
    );
}

/// Suspending the delegator client refuses every token it delegated, on the
/// next request (reversible: re-activating admits again).
#[sqlx::test(migrations = "../../migrations")]
async fn suspending_the_delegator_client_refuses_the_next_request(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "suspend").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted(
        "CALIBRATION: before the suspension",
        read(&st, &access).await,
    );
    delegation::set_client_status(&pool, d.delegator_client, "suspended").await;
    assert_refused("delegator suspended", read(&st, &access).await);
    delegation::set_client_status(&pool, d.delegator_client, "active").await;
    assert_admitted("delegator re-activated", read(&st, &access).await);
}

/// Revoking the delegator's allowance (migration 149, final) refuses the next
/// request.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_registry_row_refuses_the_next_request(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "registry").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted("CALIBRATION: before the revoke", read(&st, &access).await);
    delegation::revoke_allowance(&pool, d.delegator_client).await;
    assert_refused("allowance revoked", read(&st, &access).await);
}

/// The delegator must itself be a live writer of the operator's group (a
/// precondition of admission). Revoking its row refuses the next request.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_delegators_membership_refuses_the_next_request(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "revoke-delegator").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted("CALIBRATION: before the revoke", read(&st, &access).await);
    delegation::revoke_membership(&pool, d.delegator, d.operator_group).await;
    assert_refused(
        "after the delegator's writer row was revoked",
        read(&st, &access).await,
    );
}

/// A delegator holding only a `reader` row in the operator's group delegates
/// nothing, while a `writer` delegator for the same principal does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegator_without_writer_membership_in_the_operator_group_is_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "reader").await;
    let (reader_client, reader) =
        delegation::delegator(&pool, d.operator, d.operator_group, Some("reader"), true).await;
    let (bare_client, bare) =
        delegation::delegator(&pool, d.operator, d.operator_group, None, true).await;
    let st = state(&pool, RunTokens::On);
    assert_admitted(
        "CALIBRATION: the writer delegator",
        read(&st, &dlg_token(&st, &d)).await,
    );
    assert_refused(
        "a reader delegator",
        read(&st, &token(&st, reader_client, d.principal, Some(reader))).await,
    );
    assert_refused(
        "a delegator with no membership",
        read(&st, &token(&st, bare_client, d.principal, Some(bare))).await,
    );
}

/// A delegator that is not on the allowlist delegates nothing, although it is
/// a writer of the operator's group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_whose_delegator_is_not_allowlisted_is_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "not-allowed").await;
    let (client, agent) =
        delegation::delegator(&pool, d.operator, d.operator_group, Some("writer"), false).await;
    let st = state(&pool, RunTokens::On);
    assert_admitted(
        "CALIBRATION: the allowlisted delegator",
        read(&st, &dlg_token(&st, &d)).await,
    );
    assert_refused(
        "a delegator not on the allowlist",
        read(&st, &token(&st, client, d.principal, Some(agent))).await,
    );
}

/// The allowlist conjunct, pinned where it alone decides. An agent
/// LIVE-LINKED to the same operator passes every other conjunct (its human is
/// that operator; its link gives it a writer row of the operator's group), and
/// so does the human operator ITSELF (its own human; admin of its personal
/// group). Neither is on migration 149's allowlist, so neither delegates.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_or_the_operator_itself_cannot_be_a_delegator(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "allowlist-conjunct").await;
    let sibling = delegation::linked_principal(&pool, d.operator, "allowlist-sibling").await;
    let st = state(&pool, RunTokens::On);
    assert_admitted(
        "CALIBRATION: the allowlisted delegator",
        read(&st, &dlg_token(&st, &d)).await,
    );
    // Both requests run before either is asserted, so a failure shows both.
    let as_sibling = read(
        &st,
        &token(&st, d.delegator_client, d.principal, Some(sibling)),
    )
    .await;
    let as_operator = read(
        &st,
        &token(&st, d.delegator_client, d.principal, Some(d.operator)),
    )
    .await;
    assert!(
        as_sibling.0 == StatusCode::FORBIDDEN && as_operator.0 == StatusCode::FORBIDDEN,
        "a linked agent of the same operator {as_sibling:?} and the operator itself \
         {as_operator:?} must both be refused as delegators"
    );
    assert_refused("a delegator live-linked to the same operator", as_sibling);
    assert_refused("the operator itself as the delegator", as_operator);
}

/// Migration 149 binds an agent through its ONE non-revoked client. A second
/// active client for the delegator's agent unbinds it, so the next request is
/// refused. And the delegator cannot gain an operator link of its own: the
/// link door refuses an allowlisted agent, and the delegation is unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegator_that_gains_a_second_client_is_refused_and_cannot_gain_a_link(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "second-client").await;
    let st = state(&pool, RunTokens::On);
    let access = dlg_token(&st, &d);
    assert_admitted("CALIBRATION: one client", read(&st, &access).await);

    let mut conn = pool.acquire().await.expect("acquire");
    let link =
        epigraph_db::AgentRepository::link_operator(&mut conn, d.delegator, d.operator).await;
    drop(conn);
    assert!(
        link.is_err(),
        "the link door must refuse an allowlisted delegator: {link:?}"
    );
    assert_admitted("the refused link changed nothing", read(&st, &access).await);

    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, \
                                    legal_contact_email) \
         VALUES ($1, 'second delegator client', 'service', ARRAY['claims:read'], 'active', $2, \
                 'Delegation Fixture', 'ops@example.test')",
    )
    .bind(format!("delegation-fixture-second-{}", d.delegator))
    .bind(d.delegator)
    .execute(&pool)
    .await
    .expect("a second client for the delegator's agent");
    assert_refused(
        "the delegator's agent holds a second client",
        read(&st, &access).await,
    );
}

/// The single-token kill: revoking a delegated token by its `jti` (migration
/// 141's denylist, what `/oauth/revoke` writes) refuses its next request,
/// while its delegation stays live.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_tokens_jti_refuses_its_next_request(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "jti").await;
    let st = state(&pool, RunTokens::On);
    let (access, jti) = st
        .jwt_config
        .issue_access_token(
            d.delegator_client,
            vec!["claims:read".to_string()],
            "agent",
            None,
            Some(d.principal),
            Duration::minutes(15),
            AccessTokenBinding {
                delegated_by: Some(d.delegator),
                ..AccessTokenBinding::NONE
            },
        )
        .expect("mint");
    assert_admitted("CALIBRATION: before the revoke", read(&st, &access).await);
    let revoked = epigraph_db::RevokedAccessTokenRepository::revoke(
        &pool,
        jti,
        d.delegator_client,
        chrono::Utc::now() + Duration::minutes(15),
    )
    .await
    .expect("revoke the jti");
    assert!(revoked, "PREMISE: the jti was recorded");
    let (status, body) = read(&st, &access).await;
    assert!(
        status == StatusCode::UNAUTHORIZED && body.contains("revoked"),
        "a revoked delegated token must be refused: {status} {body}"
    );
    assert!(
        delegation_is_live(&pool, &d).await,
        "PREMISE: the delegation itself is still live"
    );
}

async fn delegation_is_live(pool: &PgPool, d: &Delegation) -> bool {
    epigraph_db::AgentRepository::delegated_principal_pool(
        pool,
        RunTokens::On,
        d.delegator,
        d.principal,
    )
    .await
    .expect("the check")
    .is_some()
}

/// A delegator allowlisted for one operator cannot delegate to an agent linked
/// to ANOTHER operator, even when it is also a writer of that operator's group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_for_an_agent_of_another_operator_is_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "operator-one").await;
    let (other, other_group) = delegation::human_operator(&pool, "operator-two").await;
    let foreign = delegation::linked_principal(&pool, other, "operator-two-principal").await;
    delegation::membership(&pool, other_group, d.delegator, "writer").await;
    let st = state(&pool, RunTokens::On);
    assert_admitted(
        "CALIBRATION: same operator",
        read(&st, &dlg_token(&st, &d)).await,
    );
    assert_refused(
        "a principal of another operator",
        read(
            &st,
            &token(&st, d.delegator_client, foreign, Some(d.delegator)),
        )
        .await,
    );
}

/// A delegated token is refused at admission when it carries ANY scope outside
/// the delegated ceiling (no group or agent management, no webhooks, no client
/// or admin scope), with a reason naming the ceiling. Calibration: a token
/// carrying exactly the ceiling, for the same live delegation, is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_with_a_scope_outside_the_ceiling_is_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "ceiling").await;
    let st = state(&pool, RunTokens::On);
    let ceiling = [
        "claims:read",
        "claims:write",
        "claims:challenge",
        "evidence:read",
        "evidence:submit",
        "edges:read",
        "edges:write",
        "agents:read",
    ];
    assert_admitted(
        "CALIBRATION: exactly the ceiling",
        read(
            &st,
            &token_with(
                &st,
                d.delegator_client,
                d.principal,
                Some(d.delegator),
                &ceiling,
            ),
        )
        .await,
    );
    for extra in [
        "claims:admin",
        "webhooks:write",
        "groups:write",
        "groups:admin",
        "agents:write",
        "clients:admin",
    ] {
        let (status, body) = read(
            &st,
            &token_with(
                &st,
                d.delegator_client,
                d.principal,
                Some(d.delegator),
                &["claims:read", extra],
            ),
        )
        .await;
        assert!(
            status == StatusCode::FORBIDDEN
                && body.contains("scope ceiling")
                && body.contains(extra),
            "a delegated token carrying {extra} must be refused at admission: {status} {body}"
        );
    }
}

/// `POST /api/v1/webhooks` with `access` and an EMPTY url, which the handler
/// itself refuses (400) before storing anything.
async fn register_webhook(state: &AppState, access: &str) -> (StatusCode, String) {
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/webhooks")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"url": " ", "event_types": [], "secret": SECRET})
                        .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// A delegated identity never REGISTERS a webhook: a `dlg` token carrying
/// `webhooks:write` is refused before the registration handler runs, and
/// nothing is stored. Calibration: an unlinked agent's own token with the same
/// scope and body reaches the handler (its own 400 for the empty url).
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_cannot_register_a_webhook(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "webhook-register").await;
    let (unlinked, _) = delegation::agent_with_group(&pool, "webhook-register-unlinked").await;
    let st = state(&pool, RunTokens::On);
    let (status, body) = register_webhook(
        &st,
        &token_with(&st, d.delegator_client, unlinked, None, &["webhooks:write"]),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST && body.contains("must not be empty"),
        "CALIBRATION: a plain token reaches the registration handler: {status} {body}"
    );
    let (status, body) = register_webhook(
        &st,
        &token_with(
            &st,
            d.delegator_client,
            d.principal,
            Some(d.delegator),
            &["claims:read", "webhooks:write"],
        ),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN && body.contains("scope ceiling"),
        "a delegated token must never reach webhook registration: {status} {body}"
    );
    assert!(
        st.webhook_store.read().await.is_empty(),
        "nothing may be registered"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A delegated token's `sub` is the DELEGATOR's client row (a `service` row),
// while its `client_type` claim says `agent`. Nothing on the request path may
// decide on that row's type: the static half finds every place that loads the
// token's own client row or branches on a request's client type; the
// behavioural half sends the same delegation under three different `sub` rows.
// ─────────────────────────────────────────────────────────────────────────────

/// Every `.rs` file under `root`, recursively.
fn rust_files(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(root).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(file relative to crates/, byte offset)` of every occurrence of `needle`
/// whose statement (up to the next `;`, at most 200 bytes) satisfies `hit`, in
/// the API and MCP request-serving sources.
fn sites(needle: &str, hit: impl Fn(&str) -> bool) -> Vec<(String, usize)> {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();
    let mut files = Vec::new();
    for krate in ["epigraph-api", "epigraph-mcp"] {
        rust_files(&crates.join(krate).join("src"), &mut files);
    }
    let mut found = Vec::new();
    for file in files {
        let src = std::fs::read_to_string(&file).expect("read source");
        for (i, _) in src.match_indices(needle) {
            let rest = &src[i..];
            let end = rest.find(';').unwrap_or(rest.len()).min(200);
            if hit(&rest[..end]) {
                let rel = file
                    .strip_prefix(&crates)
                    .expect("under crates/")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((rel, i));
            }
        }
    }
    found.sort();
    found
}

/// No request-path code decides on the type of a delegated token's `sub` row.
///
/// Static: the ONLY load of the token's own client row by its `sub`
/// (`OAuthClientRepository::get_by_id*(.., auth.client_id)`) is the elevation
/// ticket route, which first refuses a token without a refresh family (a
/// delegated token carries none); and the ONLY branch on a request's
/// `client_type` is the MCP elevation tools' human check, which refuses an
/// `agent` token. Each scan is calibrated by the site it must find.
///
/// Behavioural: the same delegation, with `sub` set to the delegator's
/// `service` row, to the operator's `human` row, and to an id with no row at
/// all, gets the same answer on a viewer route and on a route without one.
#[sqlx::test(migrations = "../../migrations")]
async fn no_code_path_branches_on_the_client_type_of_sub_for_a_dlg_token(pool: PgPool) {
    let by_sub = |stmt: &str| {
        [
            "auth.client_id",
            "ctx.client_id",
            "auth_ctx.client_id",
            "claims.sub",
        ]
        .iter()
        .any(|arg| stmt.contains(arg))
    };
    let loads: Vec<String> = sites("OAuthClientRepository::get_by_id", by_sub)
        .into_iter()
        .map(|(f, _)| f)
        .collect();
    assert_eq!(
        loads,
        vec!["epigraph-api/src/routes/elevation.rs".to_string()],
        "the token's own client row is loaded only by the elevation ticket route (the \
         scan is calibrated by finding it)"
    );
    let elevation = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes/elevation.rs"),
    )
    .expect("elevation.rs");
    let gate = elevation
        .find("auth.family_id.ok_or_else")
        .expect("the family gate");
    let load = elevation
        .find("OAuthClientRepository::get_by_id_conn(&mut tx, auth.client_id)")
        .expect("the client load");
    assert!(
        gate < load,
        "the elevation route refuses a token without a refresh family before it loads the \
         client row"
    );
    let branches: Vec<String> = sites(".client_type ==", |stmt| {
        stmt.starts_with(".client_type == ClientType::")
    })
    .into_iter()
    .map(|(f, _)| f)
    .collect();
    assert_eq!(
        branches,
        vec!["epigraph-mcp/src/tools/elevation.rs".to_string()],
        "a request's client type is branched on only by the MCP elevation tools (the scan \
         is calibrated by finding them)"
    );

    let d = delegation::live_delegation(&pool, "sub-type").await;
    let human_row: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(d.operator)
    .fetch_one(&pool)
    .await
    .expect("the operator's human client row");
    let st = state(&pool, RunTokens::On);
    let mut answers = Vec::new();
    for (row, sub) in [
        ("the delegator's service row", d.delegator_client),
        ("the operator's human row", human_row),
        ("no row at all", Uuid::new_v4()),
    ] {
        let access = token_with(
            &st,
            sub,
            d.principal,
            Some(d.delegator),
            &["claims:read", "evidence:submit"],
        );
        let viewer = read(&st, &access).await;
        assert_admitted(&format!("sub = {row}: the viewer route"), viewer.clone());
        let (status, body) = submit_evidence(&st, &access).await;
        assert!(
            status == StatusCode::BAD_REQUEST && body.contains("evidence_type"),
            "sub = {row}: the route without a viewer reaches its handler: {status} {body}"
        );
        answers.push((row, viewer.0, status));
    }
    assert!(
        answers
            .windows(2)
            .all(|w| (w[0].1, w[0].2) == (w[1].1, w[1].2)),
        "the same answer whatever `sub` row the token names: {answers:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// What a delegated token may WRITE is bounded by the database, not by the
// delegator: migration 122's operator-scope rule (`OPL02`, armed) refuses a
// claim its writing principal's operator does not write. Over HTTP, on the
// application role, as in production.
// ─────────────────────────────────────────────────────────────────────────────

/// An app-role `AppState` with a scoped pool, as `bin/server.rs` builds it,
/// with the run-token switch as given.
async fn app_role_state(pool: &PgPool, run_tokens: RunTokens) -> AppState {
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
    let mut state = AppState::with_db(raw, ApiConfig::default()).with_run_tokens(run_tokens);
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// A claim packet authored by `author` (filed in the AUTHOR's operator group).
fn packet(author: Uuid, content: &str) -> serde_json::Value {
    let props = serde_json::json!({"probe": content});
    let hash = epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(
        &serde_json::to_vec(&props).expect("properties"),
    ));
    serde_json::json!({
        "claim": {
            "content": content, "initial_truth": 0.6, "agent_id": author,
            "properties": props, "labels": ["delegated-probe"]
        },
        "evidence": [{
            "content_hash": hash,
            "evidence_type": {
                "type": "observation", "observed_at": chrono::Utc::now().to_rfc3339(),
                "method": "delegated_probe", "location": null
            },
            "raw_content": null, "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive", "explanation": "delegated probe", "confidence": 0.6,
            "inputs": [{"type": "evidence", "index": 0}]
        },
        "signature": ""
    })
}

async fn post_packet(
    state: &AppState,
    access: &str,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/submit/packet")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
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

async fn owners_of(pool: &PgPool, content: &str) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_all(pool)
        .await
        .expect("read back")
}

/// A delegated token writes ONLY into its operator's groups. Armed, on the
/// application role: a packet authored by the delegated principal lands in
/// the operator's group (calibration); a packet authored by an agent of
/// ANOTHER operator, which would be filed in that operator's group, is refused
/// `OPL02` and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_write_outside_the_operators_groups_is_refused_opl02(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "opl02").await;
    let (other, _) = delegation::human_operator(&pool, "opl02-other-operator").await;
    let foreign = delegation::linked_principal(&pool, other, "opl02-foreign").await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm the operator binding");
        (conn, ())
    })
    .await;
    let st = app_role_state(&pool, RunTokens::On).await;
    let access = token_with(
        &st,
        d.delegator_client,
        d.principal,
        Some(d.delegator),
        &["claims:read", "claims:write", "evidence:submit"],
    );

    let inside = format!("delegated packet inside {}", Uuid::new_v4());
    let (status, body) = post_packet(&st, &access, &packet(d.principal, &inside)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "CALIBRATION: a delegated write into the operator's group: {body}"
    );
    assert_eq!(owners_of(&pool, &inside).await, vec![d.operator_group]);

    let outside = format!("delegated packet outside {}", Uuid::new_v4());
    let (status, body) = post_packet(&st, &access, &packet(foreign, &outside)).await;
    assert!(
        status == StatusCode::FORBIDDEN && body.contains("OPL02"),
        "a delegated write outside the operator's groups must be refused OPL02: {status} {body}"
    );
    assert!(
        owners_of(&pool, &outside).await.is_empty(),
        "the refused write left a row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhooks stay refused. A subscription is keyed on its PRINCIPAL, not on the
// token that registered it, so a delegated identity must never receive
// long-lived deliveries: `routes/webhooks.rs::agent_is_not_operated` keeps
// suppressing an operated principal whatever token it holds.
// ─────────────────────────────────────────────────────────────────────────────

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

fn unreachable_sub(agent_id: Uuid) -> epigraph_api::state::WebhookSubscription {
    epigraph_api::state::WebhookSubscription {
        id: Uuid::new_v4(),
        url: "http://127.0.0.1:1/nonexistent".to_string(),
        event_types: vec![],
        created_at: chrono::Utc::now(),
        active: true,
        secret: SECRET.to_string(),
        agent_id: Some(agent_id),
    }
}

/// A subscription whose principal is a DELEGATED principal gets no delivery
/// while that principal's delegated token IS admitted by the viewer (the
/// calibration that makes this a pin and not a tautology). Control in the
/// same store and event: an unlinked agent's subscription is attempted.
/// `deliver_event` returns an entry only for an ATTEMPTED delivery.
#[sqlx::test(migrations = "../../migrations")]
async fn a_webhook_subscription_for_a_dlg_principal_is_still_refused(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "webhook").await;
    let st = state(&pool, RunTokens::On);
    assert_admitted(
        "CALIBRATION: the principal's delegated token is admitted",
        read(&st, &dlg_token(&st, &d)).await,
    );
    let (bystander, _) = delegation::agent_with_group(&pool, "webhook-bystander").await;
    let claim = fixture::seed_public_claim(&pool, d.operator, "delegated webhook pin").await;

    let delegated_sub = unreachable_sub(d.principal);
    let control_sub = unreachable_sub(bystander);
    let store: epigraph_api::state::WebhookStore = std::sync::Arc::new(tokio::sync::RwLock::new(
        [delegated_sub.clone(), control_sub.clone()]
            .into_iter()
            .map(|s| (s.id, s))
            .collect(),
    ));
    let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
        claim_id: epigraph_core::ClaimId::from_uuid(claim),
        agent_id: epigraph_core::AgentId::from(d.operator),
        initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
    };
    let attempted: Vec<Uuid> = epigraph_api::routes::webhooks::deliver_event(
        &epigraph_jobs::egress::EgressGuard::with_resolver(std::sync::Arc::new(
            epigraph_jobs::egress::StubResolver::new(),
        )),
        &pool,
        &store,
        &event,
        &epigraph_api::routes::webhooks::WebhookDeliveryConfig {
            timeout: std::time::Duration::from_millis(100),
            max_retries: 0,
        },
    )
    .await
    .iter()
    .map(|r| r.subscription_id)
    .collect();
    assert!(
        attempted.contains(&control_sub.id),
        "control: an unlinked subscriber receives the public event: {attempted:?}"
    );
    assert!(
        !attempted.contains(&delegated_sub.id),
        "a delegated principal's subscription was delivered to: {attempted:?}"
    );
}

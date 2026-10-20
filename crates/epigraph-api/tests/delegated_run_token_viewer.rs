//! A delegated run token at the REST viewer.
//!
//! An operated agent (migration 107) is stdio-only: its writer membership in
//! its operator's group would otherwise ride any HTTP token onto the surface.
//! A DELEGATED run token is the one carve-out. It names its delegator (`dlg`),
//! the agent of an OAuth client on migration 149's allowlist for the same
//! operator, and the viewer admits it only while ALL of these hold, checked on
//! every request:
//!
//! * the delegator's allowance is live (row not revoked, client `active`);
//! * the principal's operator link is acting (not retired, writer row live)
//!   and names the delegator's operator;
//! * the delegator itself holds a live `writer`/`admin` membership in that
//!   operator's group (so the token hands out nothing the delegator lacks);
//! * the process read `EPIGRAPH_RUN_TOKENS=on` at boot.
//!
//! A token carrying `dlg` whose delegation is not live is refused whatever the
//! principal's link state: an unlinked principal cannot be delegated to.
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
    state
        .jwt_config
        .issue_access_token(
            client,
            vec!["claims:read".to_string()],
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

fn assert_refused(what: &str, (status, body): (StatusCode, String)) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{what}: the token must get no viewer: {body}"
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

/// The no-escalation conjunct: the delegator must itself be a live writer of
/// the operator's group. Revoking its row refuses the next request.
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

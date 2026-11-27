#![cfg(feature = "db")]
//! Webhooks are principal-only: a delegate acting under a delegated run token
//! gets no webhook authority (backlog 9cd4592b).
//!
//! A delegated run token is an `agent` token for an OPERATED agent `A` whose
//! `dlg` claim names the delegator `D`, an allowlisted client agent of `A`'s
//! operator `O`. The bearer middleware admits it within the delegated scope
//! ceiling, which holds no `webhooks:*` scope. The three webhook routes that
//! take no `webhooks:write` (list, get) or check it late (delete) resolve no
//! viewer, so no viewer extractor ever looked at the delegation for them: a
//! delegated token listed and read `A`'s own subscriptions (in production,
//! such a subscription can only have been registered before the link). Now
//! each route refuses a delegated request before it reads the store.
//!
//! The world: `O`, `D` and `A` each own one subscription. For each route, the
//! live delegated token is refused 403 with the principal-only reason (never
//! the middleware's "delegation is not live", which would mean the token never
//! reached the route), and every subscription is still in the store and the
//! table. POSITIVE CONTROL in the same world: `O`'s own plain token lists and
//! reads its own subscription, so the routes are not refusing everyone.
//!
//! Verified to fail with `routes/webhooks.rs::refuse_delegated` mutated to
//! admit: list answers `A`'s subscription, get answers it 200, and delete
//! answers the scope refusal instead of the principal-only one.

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use delegation::Delegation;
use epigraph_api::state::WebhookSubscription;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::AccessTokenBinding;
use epigraph_db::RunTokens;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The refusal the routes answer an operated principal with.
const PRINCIPAL_ONLY: &str = "webhooks are principal-only";

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        allow_all_identities: true,
    }
}

/// An `agent` token for `principal`, `sub` = `client`, `dlg` = `delegated_by`.
fn token(
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
            chrono::Duration::minutes(15),
            AccessTokenBinding {
                delegated_by,
                ..AccessTokenBinding::NONE
            },
        )
        .expect("mint")
        .0
}

/// A subscription owned by `owner`, in the process store and the table.
async fn seed_subscription(state: &AppState, pool: &PgPool, owner: Uuid, label: &str) -> Uuid {
    let sub = WebhookSubscription {
        id: Uuid::new_v4(),
        url: format!("https://hooks.example.test/{label}"),
        event_types: Vec::new(),
        created_at: chrono::Utc::now(),
        active: true,
        secret: "s".repeat(32),
        agent_id: Some(owner),
    };
    epigraph_db::WebhookSubscriptionRepository::insert(
        pool,
        &epigraph_db::WebhookSubscriptionRow {
            id: sub.id,
            agent_id: owner,
            url: sub.url.clone(),
            event_types: sub.event_types.clone(),
            secret: sub.secret.clone(),
            active: sub.active,
            created_at: sub.created_at,
        },
    )
    .await
    .expect("persist the subscription");
    let id = sub.id;
    state.webhook_store.write().await.insert(id, sub);
    id
}

/// Whether subscription `id` is still in the store AND the table.
async fn still_exists(state: &AppState, pool: &PgPool, id: Uuid) -> bool {
    let in_store = state.webhook_store.read().await.contains_key(&id);
    let in_table: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM webhook_subscriptions WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the table");
    in_store && in_table
}

async fn call(state: &AppState, method: Method, uri: &str, access: &str) -> (StatusCode, String) {
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Refused by THIS rule: 403 with the principal-only reason, and not the
/// middleware's delegation refusal (which would mean the token never reached
/// the route, and the test proved nothing about it).
fn assert_principal_only(what: &str, (status, body): (StatusCode, String)) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{what}: refused: {body}");
    assert!(
        body.contains(PRINCIPAL_ONLY) && !body.contains("delegation is not live"),
        "{what}: refused by the principal-only rule: {body}"
    );
}

struct World {
    state: AppState,
    pool: PgPool,
    d: Delegation,
    /// The live delegated run token for `d.principal`, inside the ceiling.
    dlg: String,
    /// The operator's subscription.
    operator_sub: Uuid,
    /// The delegator's subscription.
    delegator_sub: Uuid,
    /// The operated agent's OWN subscription (in production, one registered
    /// before its link).
    principal_sub: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let d = delegation::live_delegation(pool, "webhooks").await;
    let state = AppState::with_db(pool.clone(), config()).with_run_tokens(RunTokens::On);
    let operator_sub = seed_subscription(&state, pool, d.operator, "operator").await;
    let delegator_sub = seed_subscription(&state, pool, d.delegator, "delegator").await;
    let principal_sub = seed_subscription(&state, pool, d.principal, "principal").await;
    let dlg = token(
        &state,
        d.delegator_client,
        d.principal,
        Some(d.delegator),
        &["claims:read", "claims:write"],
    );
    World {
        state,
        pool: pool.clone(),
        d,
        dlg,
        operator_sub,
        delegator_sub,
        principal_sub,
    }
}

impl World {
    async fn all_still_exist(&self) -> bool {
        let mut all = true;
        for id in [self.operator_sub, self.delegator_sub, self.principal_sub] {
            all &= still_exist_one(self, id).await;
        }
        all
    }

    /// POSITIVE CONTROL: the operator's own plain token lists and reads its
    /// own subscription, so a refusal below is not a route refusing everyone.
    async fn operator_reads_its_own(&self) {
        let own = token(&self.state, Uuid::new_v4(), self.d.operator, None, &[]);
        let (status, body) = call(&self.state, Method::GET, "/api/v1/webhooks", &own).await;
        assert!(
            status == StatusCode::OK && body.contains(&self.operator_sub.to_string()),
            "CONTROL: the operator lists its own subscription: {status} {body}"
        );
        let (status, body) = call(
            &self.state,
            Method::GET,
            &format!("/api/v1/webhooks/{}", self.operator_sub),
            &own,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "CONTROL: the operator reads its own subscription: {body}"
        );
    }
}

async fn still_exist_one(w: &World, id: Uuid) -> bool {
    still_exists(&w.state, &w.pool, id).await
}

/// `GET /api/v1/webhooks` under a delegated run token is refused: it does not
/// list the operated agent's own subscription, nor anyone else's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_run_token_cannot_list_webhooks(pool: PgPool) {
    let w = world(&pool).await;
    w.operator_reads_its_own().await;
    let (status, body) = call(&w.state, Method::GET, "/api/v1/webhooks", &w.dlg).await;
    for sub in [w.operator_sub, w.delegator_sub, w.principal_sub] {
        assert!(
            !body.contains(&sub.to_string()),
            "no subscription is listed to a delegate: {status} {body}"
        );
    }
    assert_principal_only("list", (status, body));
    assert!(w.all_still_exist().await, "nothing was removed");
}

/// `GET /api/v1/webhooks/:id` under a delegated run token is refused for every
/// subscription: the operator's, the delegator's and the operated agent's own.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_run_token_cannot_get_a_webhook(pool: PgPool) {
    let w = world(&pool).await;
    w.operator_reads_its_own().await;
    for (what, sub) in [
        ("the operator's", w.operator_sub),
        ("the delegator's", w.delegator_sub),
        ("the operated agent's own", w.principal_sub),
    ] {
        let (status, body) = call(
            &w.state,
            Method::GET,
            &format!("/api/v1/webhooks/{sub}"),
            &w.dlg,
        )
        .await;
        assert!(
            !body.contains("hooks.example.test"),
            "get {what}: no subscription body is disclosed: {body}"
        );
        assert_principal_only(&format!("get {what}"), (status, body));
    }
    assert!(w.all_still_exist().await, "nothing was removed");
}

/// `DELETE /api/v1/webhooks/:id` under a delegated run token is refused by the
/// principal-only rule (before the scope check), and every subscription is
/// still in the store and the table.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_run_token_cannot_delete_a_webhook(pool: PgPool) {
    let w = world(&pool).await;
    w.operator_reads_its_own().await;
    for (what, sub) in [
        ("the operator's", w.operator_sub),
        ("the delegator's", w.delegator_sub),
        ("the operated agent's own", w.principal_sub),
    ] {
        assert_principal_only(
            &format!("delete {what}"),
            call(
                &w.state,
                Method::DELETE,
                &format!("/api/v1/webhooks/{sub}"),
                &w.dlg,
            )
            .await,
        );
        assert!(
            still_exist_one(&w, sub).await,
            "delete {what}: the subscription still exists in the store and the table"
        );
    }
    assert!(w.all_still_exist().await, "nothing was removed");
}

#![cfg(feature = "db")]
//! `GET /api/v1/agents/:id` and `GET /api/v1/agents` honour the agent's
//! profile visibility (backlog 761c2b05).
//!
//! `orcid` and `ror_id` are profile DETAILS. `get_public_profile` and
//! `find_agent` show them only to a caller who may see the profile (a public
//! profile, the agent itself, a caller sharing a live group with it, an
//! admin), "so a private ORCID is never an oracle". The two older routes
//! copied them into every response, so a human who set a private profile still
//! had their ORCID and ROR id disclosed to every authenticated caller.
//!
//! Through the full router (bearer middleware, viewer extractor, `read_as`)
//! with both pools on the APPLICATION ROLE, as in `agent_search_route.rs`: on
//! the superuser pool `epigraph_bypass()` is true and every caller would see
//! everything, so an outsider assertion could not fail. Every refusal has a
//! positive control (the agent itself, a group colleague, a public profile).

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn get(state: &AppState, caller: Uuid, uri: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An agent with an ORCID, a ROR id and the `person` label, whose profile is
/// `visibility`.
async fn profiled(
    pool: &PgPool,
    label: &str,
    visibility: &str,
    orcid: &str,
    ror: &str,
) -> (Uuid, Uuid) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, label).await;
    sqlx::query(
        "UPDATE agents SET orcid = $2, ror_id = $3, profile_visibility = $4, \
                labels = ARRAY['person'] WHERE id = $1",
    )
    .bind(agent)
    .bind(orcid)
    .bind(ror)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("profile");
    (agent, group)
}

/// The list item for `id` in a `GET /api/v1/agents` page.
fn item(body: &Value, id: Uuid) -> Value {
    body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items: {body}"))
        .iter()
        .find(|i| i["id"] == id.to_string())
        .unwrap_or_else(|| panic!("{id} listed: {body}"))
        .clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_profiles_orcid_and_ror_id_reach_only_those_who_may_see_it(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (private, private_group) = profiled(
        &pool,
        "private",
        "group",
        "0000-0002-1825-0097",
        "03yrm5c26",
    )
    .await;
    let (public, _) = profiled(
        &pool,
        "public",
        "public",
        "0000-0001-5109-3700",
        "00f54p054",
    )
    .await;
    // A colleague: a live member of the private agent's group.
    let (colleague, _) = viewer_fixture::seed_agent_with_group(&pool, "colleague").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(private_group)
    .bind(colleague)
    .execute(&pool)
    .await
    .expect("colleague membership");

    let one = format!("/api/v1/agents/{private}");

    // The outsider: the row, with no detail.
    let (status, body) = get(&state, outsider, &one).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], private.to_string(), "the agent is still served");
    assert!(
        body["orcid"].is_null() && body["ror_id"].is_null(),
        "an outsider read a private profile's ORCID / ROR id: {body}"
    );

    // Positive controls: the agent itself, and a colleague, see both.
    for (who, caller) in [("self", private), ("colleague", colleague)] {
        let (status, body) = get(&state, caller, &one).await;
        assert_eq!(status, StatusCode::OK, "{who}: {body}");
        assert_eq!(body["orcid"], "0000-0002-1825-0097", "{who}: {body}");
        assert_eq!(body["ror_id"], "03yrm5c26", "{who}: {body}");
    }
    // A public profile's detail reaches the outsider.
    let (status, body) = get(&state, outsider, &format!("/api/v1/agents/{public}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["orcid"], "0000-0001-5109-3700", "{body}");

    // The list, unfiltered and label-filtered: same rule per item.
    for uri in [
        "/api/v1/agents?limit=100",
        "/api/v1/agents?limit=100&label=person",
    ] {
        let (status, body) = get(&state, outsider, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        let p = item(&body, private);
        assert!(
            p["orcid"].is_null() && p["ror_id"].is_null(),
            "{uri}: an outsider's list carried a private profile's detail: {p}"
        );
        assert_eq!(
            item(&body, public)["orcid"],
            "0000-0001-5109-3700",
            "{uri}: CALIBRATION: a public profile keeps its ORCID in the list"
        );

        // The agent itself, and a colleague (the shared-live-group arm, which
        // only a viewer-stamped read can see), keep the detail in the list.
        for (who, caller) in [("self", private), ("colleague", colleague)] {
            let (status, body) = get(&state, caller, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} {who}: {body}");
            let p = item(&body, private);
            assert_eq!(p["orcid"], "0000-0002-1825-0097", "{uri} {who}: {p}");
            assert_eq!(p["ror_id"], "03yrm5c26", "{uri} {who}: {p}");
        }
    }
}

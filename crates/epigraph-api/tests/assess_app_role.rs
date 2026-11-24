//! `POST /api/v1/claims/:id/assess` over HTTP on the APPLICATION ROLE
//! (backlog 74feb76b).
//!
//! Every other assess test runs on the `#[sqlx::test]` superuser pool, where
//! row security never refuses anything. On prod the server's raw `db_pool` is
//! the application pool (`AppState::with_scoped_pool` aliases it to
//! `ScopedPool::inner`), so a write the handler sends there runs UNSTAMPED
//! under FORCE row security. These arms build exactly that state: the raw pool
//! and the stamped `ScopedPool` are both `epigraph_app`.
//!
//! * A standalone claim the caller owns assesses: 200, its assessment row,
//!   its `claim.assessed` record and its cached belief all land.
//! * The compound guard (migration 193, backlog 0dc20fad) holds on the HTTP
//!   route: a compound whose only child (and the edge to it) the caller cannot
//!   read is assessed (200, the row lands) but its cache is not refolded from
//!   its own BBA, while a standalone twin's is.
//!
//! * An agent that assessed while bound to no human, then was linked to one,
//!   leaves that human ONE assessment when it assesses again (backlog
//!   840bc5ed): its own pre-link row is retracted (audited) and reported.
//!   When that retraction is refused, the assessment still lands and the old
//!   row is kept and not reported.
//! * A member who may only READ a group-private claim is answered 403 with
//!   nothing written, not the opaque 500 the row-security refusal used to
//!   surface as.
//!
//! Expected cache values are sentinels no fold produces.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{RunTokens, ScopedPool, SessionGucMode};
use serde_json::Value;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The app with BOTH pools on `epigraph_app`, as on prod.
async fn spawn_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let (addr, shutdown, _) = spawn_app_with(pool, RunTokens::Off).await;
    (addr, shutdown)
}

/// [`spawn_app`] with delegated run tokens `run_tokens`; also returns the
/// state's token signer.
async fn spawn_app_with(
    pool: &PgPool,
    run_tokens: RunTokens,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    Arc<epigraph_api::oauth::JwtConfig>,
) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default()).with_run_tokens(run_tokens);
    state.scoped = Some(scoped);
    let jwt = Arc::clone(&state.jwt_config);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx, jwt)
}

async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("74feb76b assess {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// `parent -decomposes_to-> child`, in force, its tenancy forced to
/// `(visibility, group)`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

/// A cache no fold of an assessment produces, recorded on `frame`.
async fn sentinel(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                belief_frame_id = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
}

const SENTINEL: (Option<f64>, Option<f64>, Option<f64>) = (Some(0.613), Some(0.887), Some(0.741));

/// `(belief, plausibility, pignistic_prob, belief_frame_id)` of the cache.
async fn cache(
    pool: &PgPool,
    claim: Uuid,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// POST an assessment of `claim` as `agent`; insist on 200.
async fn assess(addr: SocketAddr, agent: Uuid, claim: Uuid) -> Value {
    let token = common::mint_token_with_agent(&["claims:write"], agent);
    assess_with(addr, &token, claim).await
}

/// POST an assessment of `claim` with bearer `token`; insist on 200.
async fn assess_with(addr: SocketAddr, token: &str, claim: Uuid) -> Value {
    let (status, text) = assess_status(addr, token, claim).await;
    assert_eq!(status, 200, "POST assess must be 200: {text}");
    serde_json::from_str(&text).expect("json body")
}

/// POST an assessment of `claim` with bearer `token`; the status and body.
async fn assess_status(addr: SocketAddr, token: &str, claim: Uuid) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/assess"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "evidence_type": "empirical",
            "methodology": "instrumental",
            "confidence": 0.9,
            "supports": true,
        }))
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (status, text)
}

/// Live assessment rows on (claim, canonical frame), by source agent.
async fn rows(pool: &PgPool, claim: Uuid) -> Vec<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT source_agent_id FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND retracted_at IS NULL",
    )
    .bind(claim)
    .bind(epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID)
    .fetch_all(pool)
    .await
    .expect("read assessment rows")
}

async fn assessed_events(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE event_type = 'claim.assessed' \
           AND payload->>'claim_id' = $1::text",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("count claim.assessed")
}

/// A standalone claim the caller owns assesses on the application role: the
/// response is 200 and the row, the writer record and the cache all land.
#[sqlx::test(migrations = "../../migrations")]
async fn a_standalone_claim_assesses_on_the_application_role(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "74feb76b-caller").await;
    let standalone = claim(&pool, caller, mine, "public", "standalone").await;
    let (addr, _shutdown) = spawn_app(&pool).await;

    let resp = assess(addr, caller, standalone).await;

    assert_eq!(rows(&pool, standalone).await, vec![Some(caller)], "{resp}");
    assert_eq!(assessed_events(&pool, standalone).await, 1, "{resp}");
    let (belief, _, betp, frame) = cache(&pool, standalone).await;
    assert_eq!(
        frame,
        Some(epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID),
        "the cache records the canonical frame: {resp}"
    );
    assert!(
        belief.is_some() && betp.is_some(),
        "the cache was written: {resp}"
    );
}

/// The compound guard on the HTTP route, under row security: the caller's
/// public compound, whose only child (and the edge to it) is private to
/// another group, is assessed but its sentinel cache is not refolded from its
/// own BBA. CALIBRATION: a standalone twin with the same sentinel IS refolded
/// by the same call shape, so the session can write a cache.
#[sqlx::test(migrations = "../../migrations")]
async fn assess_leaves_a_compound_whose_decomposition_the_caller_cannot_see(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "74feb76b-c-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "74feb76b-c-other").await;
    let frame = epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID;
    let hidden = claim(&pool, caller, mine, "public", "compound").await;
    let child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, child, "group", theirs).await;
    let twin = claim(&pool, caller, mine, "public", "standalone twin").await;
    for c in [hidden, twin] {
        sentinel(&pool, c, frame).await;
    }
    let (addr, _shutdown) = spawn_app(&pool).await;

    let twin_resp = assess(addr, caller, twin).await;
    let twin_after = cache(&pool, twin).await;
    assert_ne!(
        (twin_after.0, twin_after.1, twin_after.2),
        SENTINEL,
        "calibration: assess refolds a standalone claim's cache: {twin_resp}"
    );

    let resp = assess(addr, caller, hidden).await;
    assert_eq!(rows(&pool, hidden).await, vec![Some(caller)], "{resp}");
    let after = cache(&pool, hidden).await;
    assert_eq!(
        (after.0, after.1, after.2),
        SENTINEL,
        "0dc20fad: assess refolded a compound's cache from its own BBA: {resp}"
    );
    assert_eq!(after.3, Some(frame), "the recorded owner is untouched");
}

/// Backlog 840bc5ed: an agent's assessment written while it was bound to no
/// human sits on the agent's own slot. Once the agent is linked to a human,
/// its next assessment goes to the human's slot, and the old row must not
/// stay beside it as a second assessment of the same human: it is retracted
/// on the caller's stamped transaction (one `mass_functions.retract` audit
/// row, by the caller) and reported in `replaced_assessments`.
///
/// Over HTTP a linked (operated) agent is admitted only on a DELEGATED run
/// token from a client allowlisted for its human, so the second call uses
/// one (`delegated_run_token_viewer.rs`'s shape).
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_retires_its_pre_link_assessment(pool: PgPool) {
    let (agent, mine) = fixture::seed_agent_with_group(&pool, "840bc5ed-agent").await;
    let (human, human_group) = delegation::human_operator(&pool, "840bc5ed-human").await;
    let (delegator_client, delegator) =
        delegation::delegator(&pool, human, human_group, Some("writer"), true).await;
    let (author, theirs) = fixture::seed_agent_with_group(&pool, "840bc5ed-author").await;
    let target = claim(&pool, author, theirs, "public", "pre-link assessment").await;
    let (addr, _shutdown, jwt) = spawn_app_with(&pool, RunTokens::On).await;
    let delegated = jwt
        .issue_access_token(
            delegator_client,
            vec!["claims:write".to_string()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding {
                delegated_by: Some(delegator),
                ..epigraph_auth::AccessTokenBinding::NONE
            },
        )
        .expect("mint the delegated run token")
        .0;
    let _ = mine;

    let before = assess(addr, agent, target).await;
    assert_eq!(
        before["owner_agent_id"],
        serde_json::json!(agent),
        "PREMISE: unlinked, the agent owns its slot: {before}"
    );
    let old_row: Uuid =
        serde_json::from_value(before["mass_function_id"].clone()).expect("the pre-link row");

    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
    drop(conn);

    let after = assess_with(addr, &delegated, target).await;
    assert_eq!(
        after["owner_agent_id"],
        serde_json::json!(human),
        "linked, the human owns the slot: {after}"
    );
    assert_eq!(
        rows(&pool, target).await,
        vec![Some(human)],
        "840bc5ed: one live assessment for the human, not the agent's pre-link row beside \
         the human's: {after}"
    );
    let replaced = after["replaced_assessments"]
        .as_array()
        .expect("replaced_assessments");
    assert_eq!(replaced.len(), 1, "{after}");
    assert_eq!(replaced[0]["mass_function_id"], serde_json::json!(old_row));
    assert_eq!(replaced[0]["source_agent_id"], serde_json::json!(agent));
    assert_eq!(replaced[0]["retired"], serde_json::json!(true));
    let audit: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT agent_id, details->>'arm' FROM security_events \
          WHERE event_type = 'mass_functions.retract' \
            AND details->>'mass_function_id' = $1::text",
    )
    .bind(old_row)
    .fetch_all(&pool)
    .await
    .expect("read the retract audit");
    assert_eq!(
        audit,
        vec![(Some(agent), Some("owner".to_string()))],
        "the retraction is audited once, as the caller's own"
    );
    let retracted: bool =
        sqlx::query_scalar("SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
            .bind(old_row)
            .fetch_one(&pool)
            .await
            .expect("the pre-link row is kept for audit");
    assert!(retracted);

    // A further assessment overwrites the human's slot in place and retires
    // nothing more.
    let again = assess_with(addr, &delegated, target).await;
    let replaced = again["replaced_assessments"]
        .as_array()
        .expect("replaced_assessments");
    assert_eq!(replaced.len(), 1, "{again}");
    assert_eq!(replaced[0]["retired"], serde_json::json!(false), "{again}");
    assert_eq!(rows(&pool, target).await, vec![Some(human)]);
}

/// A member who may only READ a group-private claim's group can see the claim
/// but not write its assessment: row security refuses the slot row (its owner
/// is the claim's group), and the call answers 403 with nothing written, not
/// the opaque 500 DatabaseError that refusal surfaced as (backlog 74feb76b's
/// error class). CALIBRATION: the same caller assesses a public claim of the
/// same group with 200, so the refusal is the group-private write, not the
/// caller or the route.
#[sqlx::test(migrations = "../../migrations")]
async fn a_read_only_member_is_refused_a_group_claims_assessment(pool: PgPool) {
    let (reader, _mine) = fixture::seed_agent_with_group(&pool, "74feb76b-r-reader").await;
    let (owner, theirs) = fixture::seed_agent_with_group(&pool, "74feb76b-r-owner").await;
    let private = claim(&pool, owner, theirs, "group", "group-private").await;
    let public = claim(&pool, owner, theirs, "public", "public calibration").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(theirs)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("seed the read-only membership");
    let (addr, _shutdown) = spawn_app(&pool).await;
    let token = common::mint_token_with_agent(&["claims:write"], reader);

    let ok = assess_with(addr, &token, public).await;
    assert_eq!(rows(&pool, public).await, vec![Some(reader)], "{ok}");

    let (status, text) = assess_status(addr, &token, private).await;
    assert_eq!(
        status, 403,
        "a refused assessment write must answer 403, not 500: {text}"
    );
    assert!(
        text.contains("nothing was written"),
        "the body says nothing was written: {text}"
    );
    assert!(rows(&pool, private).await.is_empty(), "{text}");
    assert_eq!(assessed_events(&pool, private).await, 0, "{text}");
}

/// Backlog 840bc5ed, the refused arm: when the agent may no longer write the
/// group that owns its pre-link row, the retraction is refused under its
/// savepoint. The assessment must still land (200, the human's row written),
/// the pre-link row stays live, and it is NOT reported as retired. Without the
/// savepoint the refusal aborts the transaction and the call fails.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_pre_link_retraction_still_lands_the_assessment(pool: PgPool) {
    let (agent, _mine) = fixture::seed_agent_with_group(&pool, "840bc5ed-r-agent").await;
    let (human, human_group) = delegation::human_operator(&pool, "840bc5ed-r-human").await;
    let (delegator_client, delegator) =
        delegation::delegator(&pool, human, human_group, Some("writer"), true).await;
    let (author, theirs) = fixture::seed_agent_with_group(&pool, "840bc5ed-r-author").await;
    let target = claim(&pool, author, theirs, "public", "refused retraction").await;
    let (addr, _shutdown, jwt) = spawn_app_with(&pool, RunTokens::On).await;
    let delegated = jwt
        .issue_access_token(
            delegator_client,
            vec!["claims:write".to_string()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding {
                delegated_by: Some(delegator),
                ..epigraph_auth::AccessTokenBinding::NONE
            },
        )
        .expect("mint the delegated run token")
        .0;

    let before = assess(addr, agent, target).await;
    let old_row: Uuid =
        serde_json::from_value(before["mass_function_id"].clone()).expect("the pre-link row");

    // The pre-link row now belongs to a group the agent cannot write (the
    // claim author's), on the superuser harness, as a re-own would leave it.
    sqlx::query("UPDATE mass_functions SET owner_group_id = $2 WHERE id = $1")
        .bind(old_row)
        .bind(theirs)
        .execute(&pool)
        .await
        .expect("re-own the pre-link row");

    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
    drop(conn);

    let after = assess_with(addr, &delegated, target).await;
    assert_eq!(after["owner_agent_id"], serde_json::json!(human), "{after}");
    let mut live = rows(&pool, target).await;
    live.sort();
    let mut expected = vec![Some(agent), Some(human)];
    expected.sort();
    assert_eq!(
        live, expected,
        "the refused retraction keeps the pre-link row beside the human's: {after}"
    );
    let replaced = after["replaced_assessments"]
        .as_array()
        .expect("replaced_assessments");
    assert!(
        replaced
            .iter()
            .all(|r| r["retired"] != serde_json::json!(true)),
        "a refused retraction is not reported as retired: {after}"
    );
    let retracted: bool =
        sqlx::query_scalar("SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
            .bind(old_row)
            .fetch_one(&pool)
            .await
            .expect("read the pre-link row");
    assert!(!retracted, "the pre-link row stays live");
}

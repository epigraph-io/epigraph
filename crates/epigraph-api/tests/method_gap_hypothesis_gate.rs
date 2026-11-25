#![cfg(feature = "db")]
//! `GET /api/v1/methods/gap-analysis?hypothesis_id=` on the APPLICATION ROLE
//! (backlog b6273fb9).
//!
//! Both of the route's answers (the no-capabilities early return and the full
//! analysis) name `hypothesis_id` as their subject. The handler echoed it
//! without reading it, so a hypothesis the caller cannot see answered 200,
//! while its sibling `POST /api/v1/experiments/design` answers such a
//! hypothesis as a missing one. Now it reads the hypothesis through the
//! caller's viewer first, before either answer: hidden and missing are one
//! identical 404.
//!
//! The first two arms drive the no-capabilities answer. The full analysis was
//! not reachable over HTTP when they were written: `required_capabilities` was
//! an `Option<Vec<String>>` read by axum's `Query`, whose urlencoded decoder
//! takes no sequence, so any value for it was a 400 before the handler ran.
//! Backlog 97381982 made it one comma-separated value; the arms at the end of
//! this file drive the full analysis with two capabilities, re-check the
//! hidden-hypothesis 404 with capabilities named, and pin the input bound.
//!
//! Both pools of the `AppState` are `epigraph_app` (no BYPASSRLS, `claims` row
//! security FORCEd), as in production. Fixtures are seeded on the superuser
//! `#[sqlx::test]` pool. The hidden-hypothesis arm carries a calibration call
//! by the hypothesis's owner that must answer 200 and echo the id, so a 404
//! cannot come from a broken fixture; the public-hypothesis arm expects 200
//! outright.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

async fn app_role_router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
          WHERE relnamespace = 'public'::regnamespace AND relname = 'claims'",
    )
    .fetch_one(pool)
    .await
    .expect("read row security flags");
    assert!(
        enabled && forced,
        "claims: row security enabled={enabled} forced={forced}; every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    create_router(state)
}

fn token(agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn gaps(app: axum::Router, caller: Uuid, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", token(caller)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn uri(hypothesis: Uuid) -> String {
    format!("/api/v1/methods/gap-analysis?hypothesis_id={hypothesis}")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_hypothesis_is_the_missing_hypothesis_404(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "b627-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "b627-stranger").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("b6273fb9 hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;

    // Calibration: the owner reads its own hypothesis and gets the analysis.
    let (status, body) = gaps(app.clone(), owner, &uri(hypothesis)).await;
    assert_eq!(status, StatusCode::OK, "the owner analyses: {body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["hypothesis_id"], hypothesis.to_string(), "{body}");

    let (hidden_status, hidden_body) = gaps(app.clone(), stranger, &uri(hypothesis)).await;
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = gaps(app.clone(), stranger, &uri(missing)).await;
    assert_eq!(
        hidden_status,
        StatusCode::NOT_FOUND,
        "a hypothesis the caller cannot read is 404, got {hidden_status} {hidden_body}"
    );
    assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
    assert_eq!(
        hidden_body.replace(&hypothesis.to_string(), "<id>"),
        missing_body.replace(&missing.to_string(), "<id>"),
        "a hidden hypothesis answers exactly as a missing one"
    );
}

/// The gate asks for READ access, not write: a stranger analysing a public
/// hypothesis another group owns gets the answer. A gate that asked for write
/// access would refuse it (403), and the hidden-hypothesis arm above cannot
/// tell the two apart, since a private hypothesis is refused either way and
/// the owner may do both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_hypothesis_of_another_group_is_analysed_for_a_reader(pool: PgPool) {
    let (owner, _) = viewer_fixture::seed_agent_with_group(&pool, "b627-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "b627-stranger").await;
    let hypothesis = viewer_fixture::seed_public_claim(
        &pool,
        owner,
        &format!("b6273fb9 public hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;

    let (status, body) = gaps(app, stranger, &uri(hypothesis)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a reader of a public hypothesis it cannot write analyses it: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["hypothesis_id"], hypothesis.to_string(), "{body}");
}

// ── `required_capabilities` is reachable (backlog 97381982) ──
//
// The parameter is ONE comma-separated value (`?required_capabilities=a,b`);
// each entry is trimmed and empty entries are dropped. Before 97381982 the field
// was an `Option<Vec<String>>` read by axum's plain `Query`, whose urlencoded
// decoder takes no sequence, so every request that named a capability was a
// 400 before the handler ran and only the empty early return was reachable.

/// A method whose single capability is `capability`, grounded in `claim`
/// through one paper that `asserts` it, so a gap analysis that asks for the
/// capability finds the method AND reads its source paper.
async fn seed_method_with_capability(pool: &PgPool, capability: &str, claim: Uuid) {
    seed_ranked_method(pool, capability, claim, 1).await;
}

/// [`seed_method_with_capability`] with a chosen `evidence_count`, the rank
/// the per-capability bound keeps the highest of. Returns the method id.
async fn seed_ranked_method(
    pool: &PgPool,
    capability: &str,
    claim: Uuid,
    evidence_count: i32,
) -> Uuid {
    let method: Uuid = sqlx::query_scalar(
        "INSERT INTO methods (id, name, canonical_name, technique_type, source_claim_ids) \
         VALUES (gen_random_uuid(), $1, $1, 'measurement', $2) RETURNING id",
    )
    .bind(format!("97381982 method for {capability}"))
    .bind(vec![claim])
    .fetch_one(pool)
    .await
    .expect("seed method");
    sqlx::query(
        "INSERT INTO method_capabilities (method_id, capability, specificity, evidence_count) \
         VALUES ($1, $2, 1, $3)",
    )
    .bind(method)
    .bind(capability)
    .bind(evidence_count)
    .execute(pool)
    .await
    .expect("seed method capability");
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (id, doi, title) \
         VALUES (gen_random_uuid(), '10.97381982/' || gen_random_uuid()::text, $1) \
         RETURNING id",
    )
    .bind(format!("97381982 paper for {capability}"))
    .fetch_one(pool)
    .await
    .expect("seed paper");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed asserts edge");
    method
}

fn uri_with_capabilities(hypothesis: Uuid, encoded: &str) -> String {
    format!(
        "/api/v1/methods/gap-analysis?hypothesis_id={hypothesis}&required_capabilities={encoded}"
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_capabilities_are_each_analysed(pool: PgPool) {
    let (owner, _) = viewer_fixture::seed_agent_with_group(&pool, "9738-owner").await;
    let (reader, _) = viewer_fixture::seed_agent_with_group(&pool, "9738-reader").await;
    let hypothesis = viewer_fixture::seed_public_claim(
        &pool,
        owner,
        &format!("97381982 hypothesis {}", Uuid::new_v4()),
    )
    .await;
    // One capability a method covers, one nobody covers.
    let covered = format!("cap-covered-{}", Uuid::new_v4().simple());
    let missing = format!("cap-missing-{}", Uuid::new_v4().simple());
    let grounding = viewer_fixture::seed_public_claim(
        &pool,
        owner,
        &format!("97381982 method grounding {}", Uuid::new_v4()),
    )
    .await;
    seed_method_with_capability(&pool, &covered, grounding).await;
    let app = app_role_router(&pool).await;

    // `%20` around the second entry: entries are trimmed, so the leading space
    // does not become part of the `ILIKE` pattern.
    let (status, body) = gaps(
        app,
        reader,
        &uri_with_capabilities(hypothesis, &format!("{covered},%20{missing}")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "two capabilities are analysed: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["hypothesis_id"], hypothesis.to_string(), "{body}");
    assert_eq!(v["summary"]["total_capabilities"], 2, "{body}");
    assert_eq!(
        v["summary"]["gaps"], 1,
        "only the uncovered one is a gap: {body}"
    );
    let caps = v["required_capabilities"].as_array().expect("array");
    assert_eq!(caps.len(), 2, "{body}");
    assert_eq!(caps[0]["capability"], covered.as_str(), "{body}");
    assert_eq!(
        caps[0]["methods_found"].as_array().map(Vec::len),
        Some(1),
        "the covered capability finds its method: {body}"
    );
    assert_eq!(
        caps[0]["methods_found"][0]["source_count"], 1,
        "and reads the paper that grounds it: {body}"
    );
    assert_eq!(
        caps[0]["methods_truncated"], false,
        "one method is under the per-capability bound: {body}"
    );
    assert_eq!(caps[1]["capability"], missing.as_str(), "trimmed: {body}");
    assert_eq!(
        caps[1]["gap_flags"],
        serde_json::json!(["no_method"]),
        "{body}"
    );
}

/// The hypothesis gate still precedes the analysis when capabilities are named:
/// a hidden hypothesis answers exactly as a missing one.
#[sqlx::test(migrations = "../../migrations")]
async fn with_capabilities_a_hidden_hypothesis_is_still_the_missing_404(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "9738-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "9738-stranger").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("97381982 private hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;
    let caps = "cap-a,cap-b";

    // Calibration: the owner gets the analysis with the same capabilities.
    let (status, body) = gaps(app.clone(), owner, &uri_with_capabilities(hypothesis, caps)).await;
    assert_eq!(status, StatusCode::OK, "the owner analyses: {body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["summary"]["total_capabilities"], 2, "{body}");

    let (hidden_status, hidden_body) = gaps(
        app.clone(),
        stranger,
        &uri_with_capabilities(hypothesis, caps),
    )
    .await;
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) =
        gaps(app, stranger, &uri_with_capabilities(missing, caps)).await;
    assert_eq!(hidden_status, StatusCode::NOT_FOUND, "{hidden_body}");
    assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
    assert_eq!(
        hidden_body.replace(&hypothesis.to_string(), "<id>"),
        missing_body.replace(&missing.to_string(), "<id>"),
        "a hidden hypothesis answers exactly as a missing one"
    );
}

/// The bound still holds, and is counted on the PARSED list: 33 entries is a
/// 400, 32 is not.
#[sqlx::test(migrations = "../../migrations")]
async fn more_than_the_bound_is_a_400_and_the_bound_itself_is_not(pool: PgPool) {
    let (owner, _) = viewer_fixture::seed_agent_with_group(&pool, "9738-owner").await;
    let hypothesis = viewer_fixture::seed_public_claim(
        &pool,
        owner,
        &format!("97381982 bound hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;
    let list = |n: usize| {
        (0..n)
            .map(|i| format!("cap-{i}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let max = epigraph_api::routes::experiments::MAX_REQUIRED_CAPABILITIES;

    let (status, body) = gaps(
        app.clone(),
        owner,
        &uri_with_capabilities(hypothesis, &list(max)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exactly the bound is analysed: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["summary"]["total_capabilities"], max, "{body}");

    let (status, body) = gaps(
        app,
        owner,
        &uri_with_capabilities(hypothesis, &list(max + 1)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("required_capabilities"), "{body}");
}

/// The repeated-key spelling is refused whole (a duplicate field), not read as
/// its first or last value, so a client using it learns the encoding rather
/// than getting an analysis of half its list.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repeated_capabilities_key_is_a_400(pool: PgPool) {
    let (owner, _) = viewer_fixture::seed_agent_with_group(&pool, "9738-owner").await;
    let hypothesis = viewer_fixture::seed_public_claim(
        &pool,
        owner,
        &format!("97381982 repeated-key hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;
    let (status, body) = gaps(
        app,
        owner,
        &format!(
            "{}&required_capabilities=cap-b",
            uri_with_capabilities(hypothesis, "cap-a")
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// A public hypothesis and a public claim the seeded methods are grounded in.
async fn bound_fixture(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let (owner, _) = viewer_fixture::seed_agent_with_group(pool, "9738-owner").await;
    let hypothesis = viewer_fixture::seed_public_claim(
        pool,
        owner,
        &format!("97381982 bounded hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let grounding = viewer_fixture::seed_public_claim(
        pool,
        owner,
        &format!("97381982 bounded grounding {}", Uuid::new_v4()),
    )
    .await;
    (owner, hypothesis, grounding)
}

/// A capability more than `MAX_METHODS_PER_CAPABILITY` methods match analyses
/// exactly that many, the highest evidence counts, and says it cut the list.
#[sqlx::test(migrations = "../../migrations")]
async fn a_capability_analyses_at_most_the_bound_of_methods_and_says_so(pool: PgPool) {
    let (owner, hypothesis, grounding) = bound_fixture(&pool).await;
    let max = epigraph_api::routes::experiments::MAX_METHODS_PER_CAPABILITY;
    // `max + 2` methods share the prefix, evidence counts 1..=max+2, so the
    // two lowest (1 and 2) are the ones the bound must drop.
    let prefix = format!("capbound-{}", Uuid::new_v4().simple());
    let mut by_rank = Vec::new();
    for rank in 1..=(max + 2) {
        let rank = i32::try_from(rank).expect("small");
        let m = seed_ranked_method(&pool, &format!("{prefix}-{rank}"), grounding, rank).await;
        by_rank.push((rank, m));
    }
    let app = app_role_router(&pool).await;

    let (status, body) = gaps(app, owner, &uri_with_capabilities(hypothesis, &prefix)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    let found = v["required_capabilities"][0]["methods_found"]
        .as_array()
        .expect("methods_found");
    assert_eq!(found.len(), max, "bounded per capability: {body}");
    assert_eq!(
        v["required_capabilities"][0]["methods_truncated"], true,
        "{body}"
    );
    let got: std::collections::BTreeSet<String> = found
        .iter()
        .map(|m| m["method_id"].as_str().expect("id").to_string())
        .collect();
    for (rank, m) in &by_rank {
        assert_eq!(
            got.contains(&m.to_string()),
            *rank > 2,
            "rank {rank} kept iff it is among the top {max}: {body}"
        );
    }
}

/// An entry is a LITERAL substring: `%` and `_` match only themselves. No
/// seeded capability contains either, so each is a gap, although as `ILIKE`
/// wildcards both would match every seeded method.
#[sqlx::test(migrations = "../../migrations")]
async fn like_metacharacters_in_a_capability_match_only_themselves(pool: PgPool) {
    let (owner, hypothesis, grounding) = bound_fixture(&pool).await;
    for i in 0..3 {
        seed_method_with_capability(&pool, &format!("capliteral-{i}"), grounding).await;
    }
    let app = app_role_router(&pool).await;

    // Calibration: a real substring of the seeded names does match.
    let (status, body) = gaps(
        app.clone(),
        owner,
        &uri_with_capabilities(hypothesis, "capliteral"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        v["required_capabilities"][0]["methods_found"]
            .as_array()
            .map(Vec::len),
        Some(3),
        "calibration: {body}"
    );

    for (entry, encoded) in [("%", "%25"), ("_", "_")] {
        let (status, body) = gaps(
            app.clone(),
            owner,
            &uri_with_capabilities(hypothesis, encoded),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{entry}: {body}");
        let v: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(v["required_capabilities"][0]["capability"], entry, "{body}");
        assert_eq!(
            v["required_capabilities"][0]["gap_flags"],
            serde_json::json!(["no_method"]),
            "`{entry}` matched as a wildcard: {body}"
        );
    }
}

/// A repeated entry is one capability, analysed once, in first-seen order.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repeated_capability_entry_is_analysed_once(pool: PgPool) {
    let (owner, hypothesis, grounding) = bound_fixture(&pool).await;
    let a = format!("caprepeat-a-{}", Uuid::new_v4().simple());
    let b = format!("caprepeat-b-{}", Uuid::new_v4().simple());
    seed_method_with_capability(&pool, &a, grounding).await;
    let app = app_role_router(&pool).await;

    let (status, body) = gaps(
        app,
        owner,
        &uri_with_capabilities(hypothesis, &format!("{a},{b},{a},%20{a},{b}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["summary"]["total_capabilities"], 2, "{body}");
    let caps = v["required_capabilities"].as_array().expect("array");
    assert_eq!(caps.len(), 2, "{body}");
    assert_eq!(caps[0]["capability"], a.as_str(), "{body}");
    assert_eq!(caps[1]["capability"], b.as_str(), "{body}");
    assert_eq!(v["summary"]["gaps"], 1, "{body}");
}

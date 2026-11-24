#![cfg(feature = "db")]
//! The HTTP twins of five MCP read tools (backlog fff61b9e, Explorer spec
//! 2026-09-15 section 8.2) answer exactly what the tool answers, for the same
//! application-role viewer, and refuse what it refuses.
//!
//! | route | MCP tool |
//! |---|---|
//! | `POST /api/v1/ingest/structure-source` | `structure_source` |
//! | `GET /api/v1/ingest/already-ingested` | `check_already_ingested` |
//! | `GET /api/v1/claims/undecomposed` | `query_undecomposed_claims` |
//! | `GET /api/v1/claims/:id/verify` | `verify_claim` |
//! | `GET /api/v1/alternative-sets/suggestions` | `suggest_alternative_sets` |
//!
//! Both surfaces run on ONE `epigraph_app` `ScopedPool` (`SET SESSION
//! AUTHORIZATION epigraph_app`, so row security is live) against the same
//! fixture. The comparison is on the wire JSON of each surface: the tool's
//! text block parsed, against the route's body. Each tenancy-sensitive route
//! is driven as a member of the group that owns a private row AND as a
//! stranger, so "both surfaces return the same thing" cannot pass by both
//! returning the public corpus only (or both leaking).

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::tools;
use epigraph_mcp::EpiGraphMcpFull;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The router and the MCP server, both over one app-role `ScopedPool`.
async fn surfaces(pool: &PgPool) -> (Router, EpiGraphMcpFull) {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw.clone(), ApiConfig::default());
    state.scoped = Some(scoped.clone());
    let router = create_router(state);

    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5Bu8; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(raw.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(raw, signer, embedder, false).with_scoped_pool(scoped);
    (router, server)
}

/// A bearer for `agent` carrying `scopes`.
fn bearer(agent: Uuid, scopes: &[&str]) -> String {
    common::mint_token_with_agent(scopes, agent)
}

/// The viewer the MCP HTTP transport resolves for `agent`'s token: the same
/// claims `mint_token_with_agent` issues (an agent client, no owner).
async fn mcp_viewer(server: &EpiGraphMcpFull, agent: Uuid) -> Viewer {
    let auth = epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Agent,
        scopes: vec!["claims:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    };
    tools::viewer::request_viewer(server, Some(&auth))
        .await
        .expect("the MCP viewer")
}

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

async fn get(router: &Router, path: &str, token: &str) -> (StatusCode, Value) {
    call(router, Method::GET, path, Some(token), None).await
}

/// A tool's JSON answer.
fn tool_json(out: &rmcp::model::CallToolResult) -> Value {
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("the tool answers with a text block");
    serde_json::from_str(&text).expect("the tool's text is JSON")
}

/// The caller-facing message of a 400 from the route, which must be the
/// tool's `invalid_params` message verbatim.
fn bad_request_message(status: StatusCode, body: &Value) -> String {
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected a 400, got {body}"
    );
    assert_eq!(body["error"], "BadRequest", "{body}");
    body["details"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("a 400 carries details.message: {body}"))
        .to_string()
}

// ── structure_source ───────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn structure_source_twin_answers_and_refuses_as_the_tool(pool: PgPool) {
    let (router, server) = surfaces(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "structure").await;
    let token = bearer(agent, &["claims:read"]);
    let args = json!({
        "text": "# Intro\n\nAlpha para.\n\nBeta para.\n\n## Method\n\nGamma para.",
        "source": { "title": "Doc", "doi": "10.1/x" },
        "format": "markdown",
    });

    let tool =
        tools::ingestion::structure_source(&server, serde_json::from_value(args.clone()).unwrap())
            .await
            .expect("structure_source");
    let (status, body) = call(
        &router,
        Method::POST,
        "/api/v1/ingest/structure-source",
        Some(&token),
        Some(args.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, tool_json(&tool), "the route and the tool disagree");
    assert_eq!(body["sections"][1]["title"], "Method", "{body}");

    // An unknown format: the tool's invalid_params, the route's 400, one text.
    let mut bad = args;
    bad["format"] = json!("html");
    let refused =
        tools::ingestion::structure_source(&server, serde_json::from_value(bad.clone()).unwrap())
            .await
            .expect_err("the tool refuses an unknown format");
    let (status, body) = call(
        &router,
        Method::POST,
        "/api/v1/ingest/structure-source",
        Some(&token),
        Some(bad),
    )
    .await;
    assert_eq!(bad_request_message(status, &body), refused.message);
}

// ── query_undecomposed_claims ──────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn undecomposed_twin_returns_the_tool_page_for_member_and_stranger(pool: PgPool) {
    let (router, server) = surfaces(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "undecomposed-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "undecomposed-stranger").await;
    let public = fixture::seed_public_claim(&pool, member, "a public claim, not yet split").await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "a group-private claim, not yet split")
            .await;

    for (who, agent, sees_private) in [("member", member, true), ("stranger", stranger, false)] {
        let viewer = mcp_viewer(&server, agent).await;
        let tool = tools::claims::query_undecomposed_claims(
            &server,
            &viewer,
            serde_json::from_value(json!({ "limit": 1000 })).unwrap(),
        )
        .await
        .expect("query_undecomposed_claims");
        let (status, body) = get(
            &router,
            "/api/v1/claims/undecomposed?limit=1000",
            &bearer(agent, &["claims:read"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{who}: {body}");
        assert_eq!(
            body,
            tool_json(&tool),
            "{who}: the route and the tool disagree"
        );

        let ids: Vec<&str> = body
            .as_array()
            .unwrap_or_else(|| panic!("{who}: a JSON array: {body}"))
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert!(ids.contains(&public.to_string().as_str()), "{who}: {body}");
        assert_eq!(
            ids.contains(&private.to_string().as_str()),
            sees_private,
            "{who}: the group-private claim is listed only for its group: {body}"
        );
    }
}

// ── verify_claim ───────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn verify_twin_reports_as_the_tool_and_hides_an_unreadable_claim(pool: PgPool) {
    let (router, server) = surfaces(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "verify-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "verify-stranger").await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "a private claim to verify").await;

    let viewer = mcp_viewer(&server, member).await;
    let tool = tools::claims::verify_claim(
        &server,
        &viewer,
        serde_json::from_value(json!({ "claim_id": private.to_string() })).unwrap(),
    )
    .await
    .expect("verify_claim");
    let (status, body) = get(
        &router,
        &format!("/api/v1/claims/{private}/verify"),
        &bearer(member, &["claims:read"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, tool_json(&tool), "the route and the tool disagree");
    assert_eq!(body["claim_id"], private.to_string());

    // The stranger: the tool says "not found", the route 404s, and an id that
    // names no claim at all gets the identical answer on both.
    let viewer = mcp_viewer(&server, stranger).await;
    for id in [private, Uuid::new_v4()] {
        let refused = tools::claims::verify_claim(
            &server,
            &viewer,
            serde_json::from_value(json!({ "claim_id": id.to_string() })).unwrap(),
        )
        .await
        .expect_err("the tool does not report a claim the caller cannot read");
        assert_eq!(refused.message, format!("claim {id} not found"));
        let (status, body) = get(
            &router,
            &format!("/api/v1/claims/{id}/verify"),
            &bearer(stranger, &["claims:read"]),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(
            body["details"],
            json!({ "entity": "Claim", "id": id.to_string() })
        );
    }

    // A malformed id: the tool's invalid_params text is the route's 400.
    let refused = tools::claims::verify_claim(
        &server,
        &viewer,
        serde_json::from_value(json!({ "claim_id": "not-a-uuid" })).unwrap(),
    )
    .await
    .expect_err("a malformed id");
    let (status, body) = get(
        &router,
        "/api/v1/claims/not-a-uuid/verify",
        &bearer(stranger, &["claims:read"]),
    )
    .await;
    assert_eq!(bad_request_message(status, &body), refused.message);
}

// ── check_already_ingested ─────────────────────────────────────────────────

/// The route reads the `processed_by` stamps as the CALLER, as the tool does.
///
/// Today's stamp writer makes every stamp world-owned (paper to agent is a
/// structural edge; pinned by epigraph-mcp's `dedup_probes_app_role`), so a
/// fixture that lets the writer stamp the tenancy cannot tell a route that
/// reads as the caller from one that reads as the public. The chapter stamp
/// here is therefore FORCED group-private to the member's group
/// (`seed_edge_owned_by`'s UPDATE): the member must see the document as
/// ingested and the stranger must not, on both surfaces. A route that read as
/// `Viewer::public_only()`, or as any viewer but the caller's, fails the
/// member's arm.
#[sqlx::test(migrations = "../../migrations")]
async fn already_ingested_twin_answers_and_refuses_as_the_tool(pool: PgPool) {
    let (router, server) = surfaces(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "ingest-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ingest-stranger").await;
    let doi = "10.5555/twin-gate";
    let chapter = "hierarchical_extraction_v2:ch1";
    // A PUBLIC papers row (migration 246 gives `papers` row security and a
    // declared scope): both callers can read the row, so only the
    // group-private stamp below separates their answers.
    let paper = epigraph_db::PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        Some("t"),
        None,
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("paper");
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::EdgeRepository::create_processed_by_stamp_if_absent_conn(
        &mut conn, paper, member, chapter, "test",
    )
    .await
    .expect("stamp");
    drop(conn);
    let forced = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE source_id = $1 AND relationship = 'processed_by'",
    )
    .bind(paper)
    .bind(group)
    .execute(&pool)
    .await
    .expect("force the stamp group-private");
    assert_eq!(forced.rows_affected(), 1, "exactly the one chapter stamp");

    for (who, agent, member_sees) in [("member", member, true), ("stranger", stranger, false)] {
        let viewer = mcp_viewer(&server, agent).await;
        let token = bearer(agent, &["claims:read"]);
        let cases = [
            // Default mode: the whole family, so the one chapter stamp counts.
            (json!({ "doi": doi }), format!("doi={doi}"), member_sees),
            // Exact mode, the chapter that landed.
            (
                json!({ "doi": doi, "pipeline_version": chapter }),
                format!("doi={doi}&pipeline_version={chapter}"),
                member_sees,
            ),
            // Exact mode: a chapter that did not land.
            (
                json!({ "doi": doi, "pipeline_version": "hierarchical_extraction_v2:ch2" }),
                format!("doi={doi}&pipeline_version=hierarchical_extraction_v2:ch2"),
                false,
            ),
            // A document nobody ingested.
            (
                json!({ "doi": "10.5555/never" }),
                "doi=10.5555/never".to_string(),
                false,
            ),
        ];
        for (args, query, expected) in cases {
            let tool = tools::ingestion::check_already_ingested(
                &server,
                &viewer,
                serde_json::from_value(args.clone()).unwrap(),
            )
            .await
            .expect("check_already_ingested");
            let (status, body) = get(
                &router,
                &format!("/api/v1/ingest/already-ingested?{query}"),
                &token,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{who} {args}: {body}");
            assert_eq!(
                body,
                tool_json(&tool),
                "{who} {args}: the route and the tool disagree"
            );
            assert_eq!(
                body["already_ingested"], expected,
                "{who} {args}: the group-private stamp counts for its group only: {body}"
            );
            if expected {
                assert_eq!(body["paper_id"], paper.to_string(), "{who} {args}: {body}");
                assert_eq!(
                    body["matched_pipeline_versions"],
                    json!([chapter]),
                    "{who} {args}: {body}"
                );
            }
        }
    }

    // A placeholder key is refused by both, with one text.
    let viewer = mcp_viewer(&server, member).await;
    let refused = tools::ingestion::check_already_ingested(
        &server,
        &viewer,
        serde_json::from_value(json!({ "doi": "unknown" })).unwrap(),
    )
    .await
    .expect_err("a placeholder");
    let (status, body) = get(
        &router,
        "/api/v1/ingest/already-ingested?doi=unknown",
        &bearer(member, &["claims:read"]),
    )
    .await;
    assert_eq!(bad_request_message(status, &body), refused.message);
}

// ── suggest_alternative_sets ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn alternative_sets_twin_returns_the_tool_candidates_for_member_and_stranger(pool: PgPool) {
    let (router, server) = surfaces(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "alt-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "alt-stranger").await;
    let target = fixture::seed_public_claim(&pool, member, "the shared target").await;
    let a1 = fixture::seed_group_claim(&pool, member, group, "a private supporter").await;
    let a2 = fixture::seed_public_claim(&pool, member, "a public supporter").await;
    common::insert_edge(&pool, a1, target, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a2, target, "claim", "claim", "supports").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "contradicts").await;

    for (who, agent, expected) in [("member", member, 1), ("stranger", stranger, 0)] {
        let viewer = mcp_viewer(&server, agent).await;
        let tool = tools::alternative_sets::suggest_alternative_sets(
            &server,
            &viewer,
            serde_json::from_value(json!({
                "target_claim_id": target.to_string(),
                "min_pair_strength": 0.0,
            }))
            .unwrap(),
        )
        .await
        .expect("suggest_alternative_sets");
        let (status, body) = get(
            &router,
            &format!(
                "/api/v1/alternative-sets/suggestions?target_claim_id={target}&min_pair_strength=0"
            ),
            &bearer(agent, &["claims:read"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{who}: {body}");
        assert_eq!(
            body,
            tool_json(&tool),
            "{who}: the route and the tool disagree"
        );
        assert_eq!(
            body["candidates"].as_array().map(Vec::len),
            Some(expected),
            "{who}: the pair holding a group-private claim is its group's only: {body}"
        );
    }

    // A malformed target id: one invalid_params text, a 400 over HTTP.
    let viewer = mcp_viewer(&server, member).await;
    let refused = tools::alternative_sets::suggest_alternative_sets(
        &server,
        &viewer,
        serde_json::from_value(json!({ "target_claim_id": "nope" })).unwrap(),
    )
    .await
    .expect_err("a malformed target id");
    let (status, body) = get(
        &router,
        "/api/v1/alternative-sets/suggestions?target_claim_id=nope",
        &bearer(member, &["claims:read"]),
    )
    .await;
    assert_eq!(bad_request_message(status, &body), refused.message);
}

// ── the scope every twin requires ──────────────────────────────────────────

/// Each twin requires the scope its tool requires (`claims:read`, per
/// `epigraph_mcp::scope_map`): a token without it is refused 403 before
/// anything is read, and a request with no token is refused 401 by the bearer
/// layer.
#[sqlx::test(migrations = "../../migrations")]
async fn every_twin_refuses_a_token_without_the_tools_scope(pool: PgPool) {
    let (router, _server) = surfaces(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "scope").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a public claim to verify").await;
    let wrong = bearer(agent, &["evidence:read"]);
    let structure = json!({
        "text": "# T\n\nP.",
        "source": { "title": "Doc" },
        "format": "markdown",
    });
    let routes: [(Method, String, Option<Value>); 5] = [
        (
            Method::POST,
            "/api/v1/ingest/structure-source".to_string(),
            Some(structure),
        ),
        (
            Method::GET,
            "/api/v1/ingest/already-ingested?doi=10.5555/x".to_string(),
            None,
        ),
        (Method::GET, "/api/v1/claims/undecomposed".to_string(), None),
        (Method::GET, format!("/api/v1/claims/{claim}/verify"), None),
        (
            Method::GET,
            "/api/v1/alternative-sets/suggestions".to_string(),
            None,
        ),
    ];
    for (method, path, body) in routes {
        let (status, resp) = call(&router, method.clone(), &path, Some(&wrong), body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {resp}");
        assert_eq!(
            resp["details"]["reason"], "Missing required scope: claims:read",
            "{method} {path}: {resp}"
        );
        let (status, resp) = call(&router, method.clone(), &path, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}: {resp}");
    }
}

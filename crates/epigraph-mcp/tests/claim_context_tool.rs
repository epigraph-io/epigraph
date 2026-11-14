//! MCP `claim_context` (backlog `0720d208`): a claim's structural context by
//! id, the same body as `GET /api/v1/claims/:id/context`.
//!
//! On the `epigraph_app` role so row security decides as in production. The
//! private sibling is wired while public and only then privatised, so its
//! edges keep the public stamp migration 070's trigger gave them: the claim
//! predicate alone must hide it.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claim_context::claim_context;
use epigraph_mcp::types::ClaimContextParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = app_role_scoped(pool).await;
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

async fn set_level(pool: &PgPool, id: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = properties || jsonb_build_object('level', $2::int) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

fn params(id: Uuid) -> ClaimContextParams {
    ClaimContextParams {
        claim_id: id.to_string(),
        list: None,
        after: None,
        limit: None,
    }
}

async fn ctx(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    p: ClaimContextParams,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    claim_context(server, &viewer, p)
        .await
        .map(|r| first_text(&r))
}

fn ids(page: &Value) -> Vec<String> {
    let mut v: Vec<String> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

struct Doc {
    member: Uuid,
    stranger: Uuid,
    paragraph: Uuid,
    atom: Uuid,
    sibling: Uuid,
    private_sibling: Uuid,
    supporter: Uuid,
}

/// paragraph (level 2) decomposes_to atom, sibling and private_sibling (level
/// 3); supporter supports atom.
async fn seed(pool: &PgPool) -> Doc {
    let (member, group) = fixture::seed_agent_with_group(pool, "b41ctx").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "b41ctx-stranger").await;
    let paragraph = seed_claim(pool, "the paragraph", 0.7).await;
    let atom = seed_claim(pool, "the atom", 0.7).await;
    let sibling = seed_claim(pool, "a public sibling", 0.7).await;
    let private_sibling = seed_claim(pool, "a private sibling", 0.7).await;
    let supporter = seed_claim(pool, "a supporting claim", 0.7).await;
    set_level(pool, paragraph, 2).await;
    for a in [atom, sibling, private_sibling] {
        set_level(pool, a, 3).await;
        insert_claim_edge(pool, paragraph, a, "decomposes_to").await;
    }
    insert_claim_edge(pool, supporter, atom, "supports").await;
    stamp_group_private(pool, private_sibling, group).await;
    Doc {
        member,
        stranger,
        paragraph,
        atom,
        sibling,
        private_sibling,
        supporter,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_body_is_the_engine_body_the_route_serves(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let d = seed(&pool).await;

    let via_tool = ctx(&server, &pool, d.member, params(d.atom)).await.unwrap();

    // The route's body, built by the same function on a stamped connection
    // for the same viewer: the tool reshapes nothing.
    let scoped = app_role_scoped(&pool).await;
    let viewer = Viewer::resolve(&pool, d.member).await.unwrap();
    let mut read = scoped.read_as(&viewer).await.unwrap();
    let direct = epigraph_engine::claim_context::load(&mut read, &viewer, d.atom, None)
        .await
        .unwrap()
        .expect("visible root");
    assert_eq!(via_tool, serde_json::to_value(&direct).unwrap());

    // And it is the documented full-mode shape with real content.
    assert_eq!(via_tool["claim"]["id"], d.atom.to_string());
    assert_eq!(ids(&via_tool["parents"]), vec![d.paragraph.to_string()]);
    assert_eq!(via_tool["siblings"]["parent_id"], d.paragraph.to_string());
    let edge = &via_tool["edges"]["items"][0];
    assert_eq!(edge["relationship"], "supports");
    assert_eq!(edge["direction"], "incoming");
    assert_eq!(edge["neighbor"]["id"], d.supporter.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn lookup_by_id_returns_that_claim_and_only_readable_neighbours(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let d = seed(&pool).await;

    // Every id answers with ITSELF as the root, never a neighbour.
    for id in [d.paragraph, d.atom, d.sibling, d.supporter] {
        let body = ctx(&server, &pool, d.stranger, params(id)).await.unwrap();
        assert_eq!(body["claim"]["id"], id.to_string(), "root for {id}");
    }

    // The stranger: the private sibling is in no list and no total.
    let body = ctx(&server, &pool, d.stranger, params(d.atom))
        .await
        .unwrap();
    assert_eq!(ids(&body["siblings"]), vec![d.sibling.to_string()]);
    assert_eq!(body["siblings"]["total"], 1);
    let text = body.to_string();
    assert!(
        !text.contains(&d.private_sibling.to_string())
            && !text.contains(&d.private_sibling.simple().to_string()),
        "the hidden sibling leaks into a stranger's context: {text}"
    );
    let parts = ctx(&server, &pool, d.stranger, params(d.paragraph))
        .await
        .unwrap();
    assert_eq!(parts["parts"]["total"], 2);

    // The member (calibration): its own private sibling is there.
    let body = ctx(&server, &pool, d.member, params(d.atom)).await.unwrap();
    assert_eq!(
        ids(&body["siblings"]),
        sorted(vec![d.sibling.to_string(), d.private_sibling.to_string()])
    );
    assert_eq!(body["siblings"]["total"], 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_root_is_refused_exactly_like_an_absent_one(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let d = seed(&pool).await;

    let hidden = ctx(&server, &pool, d.stranger, params(d.private_sibling))
        .await
        .expect_err("hidden root");
    let absent_id = Uuid::new_v4();
    let absent = ctx(&server, &pool, d.stranger, params(absent_id))
        .await
        .expect_err("absent root");
    assert_eq!(hidden.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert_eq!(hidden.code, absent.code);
    assert_eq!(
        hidden
            .message
            .replace(&d.private_sibling.to_string(), "<id>"),
        absent.message.replace(&absent_id.to_string(), "<id>"),
    );
    assert_eq!(hidden.data, absent.data);

    // The member reads the same id.
    let body = ctx(&server, &pool, d.member, params(d.private_sibling))
        .await
        .expect("the member reads its own claim");
    assert_eq!(body["claim"]["id"], d.private_sibling.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn page_mode_follows_the_cursor_and_bad_arguments_are_refused(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let d = seed(&pool).await;

    let page = |after: Option<String>| ClaimContextParams {
        claim_id: d.atom.to_string(),
        list: Some("siblings".to_string()),
        after,
        limit: Some(1),
    };
    let first = ctx(&server, &pool, d.member, page(None)).await.unwrap();
    assert!(first.get("edges").is_none(), "page mode returns one list");
    let first_ids = ids(&first["siblings"]);
    assert_eq!(first_ids.len(), 1);
    let cursor = first["siblings"]["next_cursor"]
        .as_str()
        .expect("a full page names its successor")
        .to_string();
    let second = ctx(&server, &pool, d.member, page(Some(cursor)))
        .await
        .unwrap();
    let mut both = first_ids;
    both.extend(ids(&second["siblings"]));
    assert_eq!(
        sorted(both),
        sorted(vec![d.sibling.to_string(), d.private_sibling.to_string()])
    );

    for bad in [
        ClaimContextParams {
            list: Some("bogus".to_string()),
            ..params(d.atom)
        },
        ClaimContextParams {
            after: Some("x".to_string()),
            ..params(d.atom)
        },
        ClaimContextParams {
            list: Some("edges".to_string()),
            after: Some("not-a-cursor".to_string()),
            ..params(d.atom)
        },
    ] {
        let err = ctx(&server, &pool, d.member, bad)
            .await
            .expect_err("refused");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }
}

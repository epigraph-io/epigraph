//! MCP `resolve_claim_id_prefix` and `lint_claim_id_citations` (backlog
//! `30d8b667`), on the `epigraph_app` role so row security decides as in
//! production.
//!
//! Claims are inserted with CHOSEN ids so two of them share an 8-hex prefix
//! (the ambiguous case) and every other prefix is known to be unique.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claim_ids::{lint_claim_id_citations, resolve_claim_id_prefix};
use epigraph_mcp::types::{LintClaimIdCitationsParams, ResolveClaimIdPrefixParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

/// A public claim with the given id, authored by `agent`.
async fn claim_with_id(pool: &PgPool, id: &str, agent: Uuid, content: &str) -> Uuid {
    let id: Uuid = id.parse().expect("uuid");
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.7, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

const AMB_A: &str = "b41b41b4-0000-4000-8000-000000000001";
const AMB_B: &str = "b41b41b4-0000-4000-8000-000000000002";
const PRIVATE: &str = "b41c0de0-0000-4000-8000-000000000003";
const WIRED: &str = "b41e1e00-0000-4000-8000-000000000004";
const UNWIRED: &str = "b41f0f00-0000-4000-8000-000000000005";
const LINTED: &str = "b41a0a00-0000-4000-8000-000000000006";
/// Names nothing.
const NOTHING: &str = "b41dead0";

struct World {
    member: Uuid,
    stranger: Uuid,
    private: Uuid,
    linted: Uuid,
}

async fn seed(pool: &PgPool) -> World {
    let (member, group) = fixture::seed_agent_with_group(pool, "b41ids").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "b41ids-stranger").await;
    claim_with_id(pool, AMB_A, member, "ambiguous one").await;
    claim_with_id(pool, AMB_B, member, "ambiguous two").await;
    let private = claim_with_id(pool, PRIVATE, member, "the member's private claim").await;
    stamp_group_private(pool, private, group).await;
    let wired = claim_with_id(pool, WIRED, member, "a wired citation").await;
    claim_with_id(pool, UNWIRED, member, "an unwired citation").await;
    let linted = claim_with_id(
        pool,
        LINTED,
        member,
        "Builds on b41e1e00 and b41f0f00; cf. b41c0de0, b41b41b4, b41dead0 and itself b41a0a00. \
         Commit 4c91bc717 is not a citation.",
    )
    .await;
    // The wired citation's edge points AT the linted claim (incoming), so a
    // one-direction lookup would miss it.
    fixture::seed_edge(pool, wired, linted).await;
    World {
        member,
        stranger,
        private,
        linted,
    }
}

async fn resolve(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    prefix: &str,
    limit: Option<i64>,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    resolve_claim_id_prefix(
        server,
        &viewer,
        ResolveClaimIdPrefixParams {
            prefix: prefix.to_string(),
            limit,
        },
    )
    .await
    .map(|r| first_text(&r))
}

async fn lint(server: &EpiGraphMcpFull, pool: &PgPool, caller: Uuid, claim: Uuid) -> Value {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let out = lint_claim_id_citations(
        server,
        &viewer,
        LintClaimIdCitationsParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("lint");
    first_text(&out)
}

fn match_ids(doc: &Value) -> Vec<String> {
    doc["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect()
}

fn status_of(doc: &Value, token: &str) -> String {
    doc["citations"]
        .as_array()
        .expect("citations")
        .iter()
        .find(|c| c["token"] == token)
        .unwrap_or_else(|| panic!("token {token} not cited: {doc}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_prefix_resolves_every_readable_match_and_nothing_hidden(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;

    // Ambiguous: both matches, in id order, flagged.
    let doc = resolve(&server, &pool, w.stranger, "B41B41B4", None)
        .await
        .unwrap();
    assert_eq!(match_ids(&doc), vec![AMB_A, AMB_B]);
    assert_eq!(doc["ambiguous"], true);
    assert_eq!(doc["truncated"], false);
    let doc = resolve(&server, &pool, w.stranger, "b41b41b4", Some(1))
        .await
        .unwrap();
    assert_eq!(match_ids(&doc), vec![AMB_A]);
    assert_eq!(doc["truncated"], true, "a cut list says so");

    // A longer prefix narrows to one; a full id names itself.
    let doc = resolve(&server, &pool, w.stranger, &AMB_B[..36], None)
        .await
        .unwrap();
    assert_eq!(match_ids(&doc), vec![AMB_B]);

    // The member reads its own private claim by prefix; the stranger's answer
    // for it is byte-identical to the answer for a prefix naming nothing.
    let doc = resolve(&server, &pool, w.member, "b41c0de0", None)
        .await
        .unwrap();
    assert_eq!(match_ids(&doc), vec![w.private.to_string()]);
    let hidden = resolve(&server, &pool, w.stranger, "b41c0de0", None)
        .await
        .unwrap();
    let nothing = resolve(&server, &pool, w.stranger, NOTHING, None)
        .await
        .unwrap();
    assert_eq!(match_ids(&hidden), Vec::<String>::new());
    assert_eq!(
        hidden.to_string().replace("b41c0de0", "<p>"),
        nothing.to_string().replace(NOTHING, "<p>")
    );
    assert!(!hidden.to_string().contains("private claim"));

    // Too short, or not hex: refused before any read.
    for bad in ["b41b41b", "b41b41bz", "b41b41b4%"] {
        let err = resolve(&server, &pool, w.stranger, bad, None)
            .await
            .expect_err(bad);
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{bad}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_lint_classifies_each_citation_per_viewer(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;

    let doc = lint(&server, &pool, w.stranger, w.linted).await;
    let tokens: Vec<&str> = doc["citations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["token"].as_str().unwrap())
        .collect();
    assert_eq!(
        tokens,
        vec!["b41e1e00", "b41f0f00", "b41c0de0", "b41b41b4", "b41dead0", "b41a0a00"],
        "the 9-digit commit sha is not a citation"
    );
    assert_eq!(status_of(&doc, "b41e1e00"), "wired", "incoming edge counts");
    assert_eq!(status_of(&doc, "b41f0f00"), "unwired");
    assert_eq!(
        status_of(&doc, "b41c0de0"),
        "unresolved",
        "hidden reads as absent"
    );
    assert_eq!(status_of(&doc, "b41b41b4"), "ambiguous");
    assert_eq!(status_of(&doc, "b41dead0"), "unresolved");
    assert_eq!(status_of(&doc, "b41a0a00"), "self");
    assert_eq!(doc["unwired"], serde_json::json!(["b41f0f00"]));
    assert!(
        !doc.to_string().contains(&w.private.to_string()),
        "a stranger's lint never prints the hidden claim's id"
    );

    // The member reads the private citation, which is not wired yet...
    let doc = lint(&server, &pool, w.member, w.linted).await;
    assert_eq!(status_of(&doc, "b41c0de0"), "unwired");
    assert_eq!(doc["unwired"], serde_json::json!(["b41f0f00", "b41c0de0"]));

    // ...until an edge joins them: the trigger stamps it with the private
    // endpoint's group, so it is wiring for the member and invisible to the
    // stranger, whose answer does not change.
    fixture::seed_edge(&pool, w.linted, w.private).await;
    let doc = lint(&server, &pool, w.member, w.linted).await;
    assert_eq!(status_of(&doc, "b41c0de0"), "wired");
    let doc = lint(&server, &pool, w.stranger, w.linted).await;
    assert_eq!(status_of(&doc, "b41c0de0"), "unresolved");
}

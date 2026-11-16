//! MCP `export_provenance_prov_o` (backlog `4ba388eb`): the PROV-O export is
//! reachable by an agent and holds exactly the claims the caller may read.
//!
//! The server's pools are downgraded to `epigraph_app`, so row security
//! decides as in production. Every edge whose claim predicate is under test is
//! FORCED public (`seed_edge_owned_by`), so the edge predicate cannot hide a
//! private endpoint on its own: only the claim predicate (and the exporter's
//! readable-set check) can, which is what is asserted.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::prov_export::export_provenance_prov_o;
use epigraph_mcp::types::ExportProvenanceProvOParams;
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

/// A `relationship` edge `source -> target` forced to `('public', world)`.
async fn public_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    let world = fixture::world_group(pool).await;
    let id = fixture::seed_edge_owned_by(pool, source, target, "public", world).await;
    sqlx::query("UPDATE edges SET relationship = $2 WHERE id = $1")
        .bind(id)
        .bind(relationship)
        .execute(pool)
        .await
        .expect("set relationship");
}

async fn export(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    export_limited(server, pool, caller, claim, None, None).await
}

async fn export_limited(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    max_nodes: Option<usize>,
    max_content_chars: Option<usize>,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    export_provenance_prov_o(
        server,
        &viewer,
        ExportProvenanceProvOParams {
            claim_id: claim.to_string(),
            max_depth: None,
            max_nodes,
            max_content_chars,
        },
    )
    .await
    .map(|r| first_text(&r))
}

fn entity_ids(doc: &Value) -> Vec<String> {
    let mut ids: Vec<String> = doc["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .map(|e| e["@id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

fn has_relation(doc: &Value, predicate: &str, generated: Uuid, used: Uuid) -> bool {
    doc["relations"]
        .as_array()
        .expect("relations")
        .iter()
        .any(|r| {
            r["predicate"] == predicate
                && r["prov:generatedEntity"] == format!("claim:{generated}")
                && r["prov:usedEntity"] == format!("claim:{used}")
        })
}

struct Graph {
    member: Uuid,
    root: Uuid,
    public_ancestor: Uuid,
    private_ancestor: Uuid,
    private_predecessor: Uuid,
}

/// `root` (public) is derived from a public and a group-private ancestor and
/// supersedes a group-private predecessor; every edge is public.
async fn seed(pool: &PgPool) -> Graph {
    let (member, group) = fixture::seed_agent_with_group(pool, "b41prov").await;
    let root = fixture::seed_public_claim(pool, member, "prov root").await;
    let public_ancestor = fixture::seed_public_claim(pool, member, "prov public ancestor").await;
    let private_ancestor =
        fixture::seed_group_claim(pool, member, group, "prov private ancestor").await;
    let private_predecessor =
        fixture::seed_group_claim(pool, member, group, "prov private predecessor").await;
    // derived_from points ancestor -> descendant; supersedes new -> old.
    public_edge(pool, public_ancestor, root, "derived_from").await;
    public_edge(pool, private_ancestor, root, "derived_from").await;
    public_edge(pool, root, private_predecessor, "supersedes").await;
    Graph {
        member,
        root,
        public_ancestor,
        private_ancestor,
        private_predecessor,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_export_names_no_private_ancestor_anywhere(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let g = seed(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "b41prov-stranger").await;

    let doc = export(&server, &pool, stranger, g.root)
        .await
        .expect("a stranger exports a public root");
    let mut want = vec![
        format!("claim:{}", g.root),
        format!("claim:{}", g.public_ancestor),
    ];
    want.sort();
    assert_eq!(entity_ids(&doc), want);
    assert!(has_relation(
        &doc,
        "prov:wasDerivedFrom",
        g.root,
        g.public_ancestor
    ));

    // Absent, not redacted: neither private id is printed anywhere, not even
    // as the endpoint of the (visible) supersedes edge that points at one.
    let text = doc.to_string();
    for hidden in [g.private_ancestor, g.private_predecessor] {
        assert!(
            !text.contains(&hidden.to_string()),
            "private claim {hidden} leaked into a stranger's export: {text}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_export_holds_its_own_private_ancestors(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let g = seed(&pool).await;

    let doc = export(&server, &pool, g.member, g.root)
        .await
        .expect("the member exports");
    let mut want = vec![
        format!("claim:{}", g.root),
        format!("claim:{}", g.public_ancestor),
        format!("claim:{}", g.private_ancestor),
        format!("claim:{}", g.private_predecessor),
    ];
    want.sort();
    assert_eq!(
        entity_ids(&doc),
        want,
        "the stamped read admits the member's own group-private rows"
    );
    assert!(has_relation(
        &doc,
        "prov:wasDerivedFrom",
        g.root,
        g.private_ancestor
    ));
    assert!(has_relation(
        &doc,
        "prov:wasRevisionOf",
        g.root,
        g.private_predecessor
    ));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_root_is_refused_exactly_like_an_absent_one(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let g = seed(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "b41prov-root").await;

    let hidden = export(&server, &pool, stranger, g.private_predecessor)
        .await
        .expect_err("a hidden root is refused");
    let absent_id = Uuid::new_v4();
    let absent = export(&server, &pool, stranger, absent_id)
        .await
        .expect_err("an absent root is refused");
    assert_eq!(hidden.code, absent.code);
    assert_eq!(
        hidden
            .message
            .replace(&g.private_predecessor.to_string(), "<id>"),
        absent.message.replace(&absent_id.to_string(), "<id>"),
        "hidden and absent must be indistinguishable"
    );
    assert_eq!(hidden.code, rmcp::model::ErrorCode::INVALID_PARAMS);
}

/// Backlog 4ba388eb review: depth alone bounds nothing on a hub claim, so the
/// tool caps the claim set nearest-first. A CHAIN (root <- near <- far), not a
/// fan, so keeping the furthest ancestors instead of the nearest fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_node_cap_keeps_the_nearest_claims_and_says_so(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "b41prov-cap").await;
    let root = fixture::seed_public_claim(&pool, member, "cap root").await;
    let near = fixture::seed_public_claim(&pool, member, "cap near ancestor").await;
    let far = fixture::seed_public_claim(&pool, member, "cap far ancestor").await;
    public_edge(&pool, near, root, "derived_from").await;
    public_edge(&pool, far, near, "derived_from").await;

    let whole = export_limited(&server, &pool, member, root, Some(3), None)
        .await
        .expect("export");
    assert_eq!(whole["truncated"], false, "nothing was cut: {whole}");
    assert_eq!(entity_ids(&whole).len(), 3);

    let doc = export_limited(&server, &pool, member, root, Some(2), None)
        .await
        .expect("export");
    let mut want = vec![format!("claim:{root}"), format!("claim:{near}")];
    want.sort();
    assert_eq!(entity_ids(&doc), want, "root and its nearest ancestor kept");
    assert_eq!(doc["truncated"], true, "a cut export says so");
    assert_eq!(doc["limits"]["max_nodes"], 2);
    assert!(has_relation(&doc, "prov:wasDerivedFrom", root, near));
    assert!(
        !doc.to_string().contains(&far.to_string()),
        "a cut claim is named nowhere, not even as a relation endpoint: {doc}"
    );
}

/// A hidden claim neither takes a slot nor sets `truncated`: the stranger's
/// candidate set holds three claims (root, public ancestor, and the hidden
/// supersedes predecessor), its readable set two, and a cap of two cuts
/// nothing it could read.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_candidate_takes_no_slot_and_sets_no_flag(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let g = seed(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "b41prov-slot").await;

    let doc = export_limited(&server, &pool, stranger, g.root, Some(2), None)
        .await
        .expect("export");
    let mut want = vec![
        format!("claim:{}", g.root),
        format!("claim:{}", g.public_ancestor),
    ];
    want.sort();
    assert_eq!(entity_ids(&doc), want);
    assert_eq!(
        doc["truncated"], false,
        "the flag must not reveal that a hidden claim was there: {doc}"
    );
}

/// Content is clipped by characters (a multibyte character sits on the
/// boundary), and the clipped entity says so with its original length.
#[sqlx::test(migrations = "../../migrations")]
async fn content_is_clipped_per_entity_and_flagged(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "b41prov-clip").await;
    let long = format!("{}{}", "a".repeat(49), "é".repeat(30));
    let root = fixture::seed_public_claim(&pool, member, &long).await;

    let doc = export_limited(&server, &pool, member, root, None, Some(50))
        .await
        .expect("export");
    let entity = &doc["entities"][0];
    assert_eq!(entity["content"], format!("{}é", "a".repeat(49)));
    assert_eq!(entity["content_truncated"], true);
    assert_eq!(entity["content_chars"], 79);

    // The default budget (500) leaves it whole and unflagged.
    let doc = export(&server, &pool, member, root).await.expect("export");
    assert_eq!(doc["entities"][0]["content"], long);
    assert!(doc["entities"][0].get("content_truncated").is_none());
}

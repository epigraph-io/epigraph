//! K12a (supersede SPEC §11 phase 1; ruling R-132 "supersedes = revision
//! only"; backlog 3ce5e00c's `supersedes` part) on MCP: no generic edge writer
//! creates a `supersedes` edge, in any spelling; only the supersession act
//! writes it, and it still does.
//!
//! The MCP generic writers that take a caller-chosen relationship are
//! `link_epistemic` and `link_hierarchical`; both already refuse every
//! spelling (each keeps its own allow-list, which never held `supersedes`), so
//! the refusals here are REGRESSION PINS, not red tests. `patch_edge` has no
//! relationship field: it cannot create an edge or change one's relationship.
//! The HTTP twins (`POST /api/v1/edges`, the staged promote) are in
//! `epigraph-api/tests/supersedes_act_only_http.rs` and
//! `admin_scope_promotions_test.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::{LinkEpistemicParams, LinkHierarchicalParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

const SPELLINGS: [&str; 3] = ["supersedes", "SUPERSEDES", "Supersedes"];

/// Every edge from `source` to `target`, whatever its relationship.
async fn edges_between(pool: &PgPool, source: Uuid, target: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2")
        .bind(source)
        .bind(target)
        .fetch_one(pool)
        .await
        .expect("count edges")
}

/// `link_epistemic` refuses `supersedes` in every spelling, and writes no edge
/// of any relationship between the pair. CONTROL: `supports` between the same
/// pair lands, so the refusal is the relationship's.
#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_refuses_supersedes_in_every_spelling(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let source = seed_claim(&pool, "the newer claim", 0.5).await;
    let target = seed_claim(&pool, "the older claim", 0.5).await;

    for rel in SPELLINGS {
        let err = do_link_epistemic(
            &server,
            &viewer,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: rel.to_string(),
                properties: None,
            },
            None,
        )
        .await
        .expect_err("supersedes is the supersession act's edge");
        assert!(
            err.message.contains("invalid relationship"),
            "{rel}: {}",
            err.message
        );
        assert_eq!(edges_between(&pool, source, target).await, 0, "{rel}");
    }

    do_link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: supports between the same pair lands: {e:?}"));
    assert_eq!(edges_between(&pool, source, target).await, 1);
}

/// `link_hierarchical` refuses `supersedes` in every spelling and writes
/// nothing. CONTROL: `decomposes_to` between the same pair lands.
#[sqlx::test(migrations = "../../migrations")]
async fn link_hierarchical_refuses_supersedes_in_every_spelling(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let source = seed_claim(&pool, "a thesis", 0.5).await;
    let target = seed_claim(&pool, "its section", 0.5).await;

    for rel in SPELLINGS {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            LinkHierarchicalParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: rel.to_string(),
                properties: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("supersedes is the supersession act's edge");
        assert!(
            err.message.contains("invalid relationship"),
            "{rel}: {}",
            err.message
        );
        assert_eq!(edges_between(&pool, source, target).await, 0, "{rel}");
    }

    do_link_hierarchical(
        &server,
        &viewer,
        LinkHierarchicalParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "decomposes_to".to_string(),
            properties: None,
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: decomposes_to lands: {e:?}"));
    assert_eq!(edges_between(&pool, source, target).await, 1);
}

/// The act still writes its lineage edge: `supersede_claim` (stdio, the server
/// agent superseding its own claim) leaves exactly one in-force
/// `new -supersedes-> old` edge, in the lower-case spelling.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_still_writes_its_lineage_edge(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(&pool, agent).await;
    let old = fixture::seed_group_claim(&pool, agent, group, "the claim to restate").await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");

    let r = supersede_claim(
        &server,
        &viewer,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: "the restated claim".to_string(),
            truth_value: 0.6,
            reason: "k12a lineage pin".to_string(),
        },
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("the author supersedes its own claim: {e:?}"));
    let new: Uuid = first_text(&r)["new_claim_id"]
        .as_str()
        .and_then(|v| v.parse().ok())
        .expect("new_claim_id");
    let lineage: Vec<String> = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND lower(relationship) = 'supersedes' AND valid_to IS NULL",
    )
    .bind(new)
    .bind(old)
    .fetch_all(&pool)
    .await
    .expect("lineage edges");
    assert_eq!(lineage, vec!["supersedes".to_string()]);
}

//! `consolidate_claims`'s three explicit modes (backlog 22602dd8).
//!
//! - `identity` is the dedup act per non-survivor source: each gets the
//!   `same_as` identity edge onto the survivor, its edges move through the
//!   dedup cascade, no claim is written, and each can be un-marked.
//! - `abstract` writes a new claim with a `generalizes` edge to each source,
//!   retires nothing, and runs no cascade.
//! - `merge` (and its alias `rewrite`) keeps the retiring merge; it is pinned
//!   in `consolidate_tool.rs` and `epigraph-db/tests/consolidate_test.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim};
use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::tools::supersede::unmark_duplicate;
use epigraph_mcp::types::{ConsolidateClaimsParams, UnmarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

fn body(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("json body")
}

fn params(
    mode: &str,
    ids: &[Uuid],
    content: &str,
    survivor: Option<Uuid>,
) -> ConsolidateClaimsParams {
    ConsolidateClaimsParams {
        source_claim_ids: ids.iter().map(ToString::to_string).collect(),
        merged_content: content.to_string(),
        mode: mode.to_string(),
        survivor_claim_id: survivor.map(|s| s.to_string()),
        reason: "consolidate modes test".to_string(),
        confidence: None,
    }
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// `(supersedes, is_current)` of a claim.
async fn standing(pool: &PgPool, id: Uuid) -> (Option<Uuid>, bool) {
    sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// In-force dedup identity edges `dup -same_as-> canonical`.
async fn identity_edges(pool: &PgPool, dup: Uuid, canonical: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'same_as' AND properties ? 'dedup' AND valid_to IS NULL",
    )
    .bind(dup)
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("identity edges")
}

async fn claim_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(pool)
        .await
        .expect("claim count")
}

/// Identity mode is `mark_duplicate` per non-survivor source: each is retired
/// onto the survivor with an identity edge, its edge moves to the survivor,
/// no claim is written, and an un-mark restores it. Before the modes, the
/// call wrote a new merged claim and retired every source, the survivor too,
/// with no identity edge and no un-mark.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_marks_each_non_survivor_and_each_can_be_unmarked(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let survivor = seed_claim(&pool, "the restated fact", 0.6).await;
    let dup_a = seed_claim(&pool, "the restated fact, again", 0.5).await;
    let dup_b = seed_claim(&pool, "the restated fact, once more", 0.5).await;
    let supporter = seed_claim(&pool, "supports a restatement", 0.5).await;
    let e = edge(&pool, supporter, dup_a).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let before = claim_count(&pool).await;

    let out = consolidate_claims(
        &server,
        &viewer,
        params("identity", &[dup_a, survivor, dup_b], "", Some(survivor)),
        Some(&auth),
    )
    .await
    .expect("identity consolidation");
    let b = body(&out);
    assert_eq!(b["mode"], "identity", "{b}");
    assert_eq!(b["survivor_claim_id"], survivor.to_string(), "{b}");
    let marked = b["marked"].as_array().expect("marked");
    assert_eq!(marked.len(), 2, "{b}");
    for m in marked {
        assert_eq!(m["canonical_id"], serde_json::json!(survivor), "{b}");
        assert_eq!(m["cascade"]["status"], "applied", "{b}");
    }

    assert_eq!(claim_count(&pool).await, before, "identity writes no claim");
    assert_eq!(
        standing(&pool, survivor).await,
        (None, true),
        "the survivor stays current"
    );
    for dup in [dup_a, dup_b] {
        assert_eq!(
            standing(&pool, dup).await,
            (Some(survivor), false),
            "{dup} marked"
        );
        assert_eq!(
            identity_edges(&pool, dup, survivor).await,
            1,
            "{dup} identity edge"
        );
    }
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        target, survivor,
        "the dedup cascade moved the edge to the survivor"
    );

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup_a.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("an identity-mode source can be un-marked");
    assert_eq!(body(&r)["cascade"]["status"], "applied");
    assert_eq!(standing(&pool, dup_a).await, (None, true), "un-marked");
    assert_eq!(identity_edges(&pool, dup_a, survivor).await, 0);
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, dup_a, "the un-mark put the edge back");
    assert_eq!(
        standing(&pool, dup_b).await,
        (Some(survivor), false),
        "the other source stays marked"
    );
}

/// Every source is checked before any is marked: one source the dedup act
/// would refuse (here a revision successor, whose `supersedes` a mark would
/// overwrite) refuses the whole call, and the markable source is untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_refuses_before_marking_any_source(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let survivor = seed_claim(&pool, "survivor", 0.6).await;
    let markable = seed_claim(&pool, "markable restatement", 0.5).await;
    let older = seed_claim(&pool, "an older version", 0.5).await;
    let successor = seed_claim(&pool, "a revision successor", 0.5).await;
    sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
        .bind(successor)
        .bind(older)
        .execute(&pool)
        .await
        .expect("make a revision successor");
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let err = consolidate_claims(
        &server,
        &viewer,
        params(
            "identity",
            &[survivor, markable, successor],
            "",
            Some(survivor),
        ),
        Some(&auth),
    )
    .await
    .expect_err("a successor source refuses the call");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains(&successor.to_string()), "{err:?}");
    assert_eq!(
        standing(&pool, markable).await,
        (None, true),
        "no source was marked"
    );
    assert_eq!(identity_edges(&pool, markable, survivor).await, 0);
}

/// Identity's parameters: it needs a survivor among the sources and takes no
/// merged content; the other modes take no survivor and need merged content
/// (an omitted one is a parameter error, not an internal one). Each refusal
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_and_survivor_parameters_are_checked(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let s1 = seed_claim(&pool, "param one", 0.5).await;
    let s2 = seed_claim(&pool, "param two", 0.5).await;
    let outsider = seed_claim(&pool, "not a source", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let before = claim_count(&pool).await;

    for (p, needle) in [
        (
            params("identity", &[s1, s2], "", None),
            "needs survivor_claim_id",
        ),
        (
            params("identity", &[s1, s2], "", Some(outsider)),
            "is not one of source_claim_ids",
        ),
        (
            params("identity", &[s1, s2], "a merged text", Some(s1)),
            "takes no merged_content",
        ),
        (
            params("merge", &[s1, s2], "a merged text", Some(s1)),
            "applies to mode 'identity' only",
        ),
        (
            params("abstract", &[s1, s2], "a general text", Some(s1)),
            "applies to mode 'identity' only",
        ),
        (params("merge", &[s1, s2], "", None), "needs merged_content"),
        (
            params("abstract", &[s1, s2], "  ", None),
            "needs merged_content",
        ),
    ] {
        let mode = p.mode.clone();
        let err = consolidate_claims(&server, &viewer, p, Some(&auth))
            .await
            .expect_err("refused");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{mode}: {err:?}"
        );
        assert!(err.message.contains(needle), "{mode}: {err:?}");
    }
    assert_eq!(claim_count(&pool).await, before, "nothing written");
    for s in [s1, s2] {
        assert_eq!(standing(&pool, s).await, (None, true));
    }
}

/// Abstract mode through the tool: a new claim with a `generalizes` edge to
/// each source; every source stays current with its edges, and no cascade
/// runs or is deferred (there is nothing to move). Before the modes, an
/// `abstract` call retired every source like a merge.
#[sqlx::test(migrations = "../../migrations")]
async fn abstract_mode_retires_nothing_and_runs_no_cascade(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let s1 = seed_claim(&pool, "abstract tool source one", 0.6).await;
    let s2 = seed_claim(&pool, "abstract tool source two", 0.8).await;
    let supporter = seed_claim(&pool, "supports source two", 0.5).await;
    let e = edge(&pool, supporter, s2).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let out = consolidate_claims(
        &server,
        &viewer,
        params(
            "abstract",
            &[s1, s2],
            "what both sources have in common",
            None,
        ),
        Some(&auth),
    )
    .await
    .expect("abstract consolidation");
    let b = body(&out);
    assert_eq!(b["mode"], "abstract", "{b}");
    assert_eq!(b["superseded_ids"], serde_json::json!([]), "{b}");
    assert!(
        b.get("cascade").is_none(),
        "an abstraction runs no cascade: {b}"
    );
    let a = Uuid::parse_str(b["merged_claim_id"].as_str().expect("id")).expect("uuid");

    assert_eq!(
        standing(&pool, a).await,
        (None, true),
        "the abstraction is current"
    );
    for s in [s1, s2] {
        assert_eq!(standing(&pool, s).await, (None, true), "{s} stays current");
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
                AND relationship = 'generalizes' AND valid_to IS NULL",
        )
        .bind(a)
        .bind(s)
        .fetch_one(&pool)
        .await
        .expect("generalizes");
        assert_eq!(n, 1, "abstraction -generalizes-> {s}");
    }
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, s2, "the source keeps its edge");
}

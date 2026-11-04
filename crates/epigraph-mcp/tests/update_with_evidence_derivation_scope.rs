//! Ruling R-22 (backlog fef24216; generalised to every claim, R-71) on MCP
//! `update_with_evidence`, whose write (`ds_auto::auto_wire_ds_update`) folds
//! the claim's stored binary BBAs and writes the result to the claim's cache
//! (`belief`, `plausibility`, `pignistic_prob`) and its `truth_value`.
//!
//! A row on a public claim is public whatever it was derived from, so a BBA
//! citing evidence later narrowed to a group (`hide-evidence`) stays visible
//! to every fold. The cache is read by everyone who can read the claim, so
//! that BBA must not enter it.
//!
//! # The oracle
//!
//! Two fresh claims of the same shape (`truth_value` 0.5, which seeds no prior
//! BBA). One carries a BBA citing narrowed evidence; the other does not. The
//! same caller then sends the same refutation (supports=false, so the
//! monotonicity clamp cannot be what equalises them) to both. Every cached
//! column and the returned values must be equal.
//!
//! # The refusal
//!
//! When even the call's own BBA cites evidence narrower than the claim,
//! nothing may be cached from the fold, and `auto_wire_ds_update` says so.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::ds_auto::{auto_wire_ds_update, ensure_binary_frame};
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

const EPS: f64 = 1e-9;

/// Evidence on `claim` narrowed to `group`, with its evidence perspective.
async fn narrowed_evidence(pool: &PgPool, claim: Uuid, group: Uuid, owner: Uuid) -> Uuid {
    let ev = fixture::seed_evidence(pool, claim, "document").await;
    // Pinned, as `epigraph-operator hide-evidence` pins it (migration 110):
    // without the pin the next evidence INSERT on the claim re-publishes it.
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(ev)
    .bind(owner)
    .execute(pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(ev)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow the evidence");
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, ev, Some(owner))
        .await
        .expect("evidence perspective");
    ev
}

/// The cached columns and `truth_value` of a claim.
async fn cache(pool: &PgPool, claim: Uuid) -> [Option<f64>; 4] {
    let row: (Option<f64>, Option<f64>, Option<f64>, f64) = sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, truth_value FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache");
    [row.0, row.1, row.2, Some(row.3)]
}

async fn refute(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
) -> serde_json::Value {
    let out = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: format!("r22 refutation {}", Uuid::new_v4()),
            source_url: None,
            supports: false,
            strength: 0.6,
            labels: Vec::new(),
        },
        None,
    )
    .await
    .expect("update_with_evidence");
    first_text(&out)
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_never_caches_a_bba_citing_narrowed_evidence(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-uwe-member").await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary_truth");

    let with_hidden = seed_claim(&pool, "r22 uwe claim with a narrowed BBA", 0.5).await;
    let control = seed_claim(&pool, "r22 uwe control claim", 0.5).await;

    // A member's earlier supporting BBA whose evidence was narrowed to its
    // group afterwards (the row stays public with its claim).
    let hidden = narrowed_evidence(&pool, with_hidden, group, member).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        with_hidden,
        frame,
        Some(member),
        Some(hidden),
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(hidden),
    )
    .await
    .expect("store the narrowed BBA");

    let a = refute(&server, &viewer, with_hidden).await;
    let b = refute(&server, &viewer, control).await;
    for key in ["belief", "plausibility", "pignistic_prob", "truth_after"] {
        let (x, y) = (a[key].as_f64(), b[key].as_f64());
        assert!(
            x.is_some() && y.is_some() && (x.unwrap() - y.unwrap()).abs() < EPS,
            "update_with_evidence returned {key} folded from a BBA citing narrowed evidence: \
             {x:?} vs {y:?}\n{a}\n{b}"
        );
    }
    let (ca, cb) = (cache(&pool, with_hidden).await, cache(&pool, control).await);
    for (i, col) in ["belief", "plausibility", "pignistic_prob", "truth_value"]
        .iter()
        .enumerate()
    {
        let (x, y) = (ca[i], cb[i]);
        assert!(
            x.is_some() && y.is_some() && (x.unwrap() - y.unwrap()).abs() < EPS,
            "the claim's cached {col} folded a BBA citing narrowed evidence: {x:?} vs {y:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_write_whose_own_evidence_is_narrower_than_the_claim_caches_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-uwe-refusal").await;
    let claim = seed_claim(&pool, "r22 uwe refusal claim", 0.5).await;
    let hidden = narrowed_evidence(&pool, claim, group, member).await;
    let before = cache(&pool, claim).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let err = auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim,
        member,
        0.7,
        1.0,
        true,
        Some("empirical"),
        Some(hidden),
        false,
    )
    .await
    .expect_err("a fold with no admissible BBA must not be cached");
    drop(conn);
    assert!(
        err.contains("no cached belief can be written"),
        "the refusal names its reason: {err}"
    );
    assert_eq!(
        cache(&pool, claim).await,
        before,
        "nothing was cached from the refused fold"
    );
}

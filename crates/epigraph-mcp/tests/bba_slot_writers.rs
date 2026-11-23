//! Backlog 1777638e (migration 267): the edge factor and the DS evidence
//! auto-wire key their BBAs on `mass_functions`' own slot, and write no
//! `perspectives` row.
//!
//! Before 267 each writer first wrote a pseudo-perspective (`ensure_edge_
//! perspective`, type `edge`, id = the edge; `ensure_evidence_perspective`,
//! type `evidence`, id = the evidence row) so the BBA could be keyed through
//! the `perspective_id` foreign key. Every perspective read then had to filter
//! those rows out, and a reader that forgot treated an edge as a viewpoint.
//!
//! Both tests drive the real writers (`epigraph_engine::edge_factor::
//! auto_wire_ds_for_edge`, `epigraph_mcp::tools::ds_auto::auto_wire_ds_update`)
//! on a fresh database and assert, FIRST, that no slot-shaped `perspectives`
//! row exists, then the slot the BBA is keyed on. On the code before 267 the
//! first assertion fails (the writer wrote the row).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::MassFunctionRepository;
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, EdgeFactorOutcome};
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_update, ensure_binary_frame};
use sqlx::PgPool;
use uuid::Uuid;

/// `perspectives` rows that are slot-shaped: typed `edge` / `evidence`, or
/// carrying one of `ids`.
async fn slot_shaped_perspectives(pool: &PgPool, ids: &[Uuid]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM perspectives \
          WHERE perspective_type IN ('edge', 'evidence') OR id = ANY($1)",
    )
    .bind(ids)
    .fetch_one(pool)
    .await
    .expect("count slot-shaped perspectives")
}

/// `(perspective_id, slot_kind, slot_id, evidence_id)` of every BBA on `claim`,
/// ordered by slot id.
async fn keys_on(
    pool: &PgPool,
    claim: Uuid,
) -> Vec<(Option<Uuid>, Option<String>, Option<Uuid>, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT perspective_id, slot_kind, slot_id, evidence_id FROM mass_functions \
          WHERE claim_id = $1 ORDER BY slot_id NULLS FIRST",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read the BBA keys")
}

async fn evidence_on(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
         VALUES ($1, 'observation', sha256(gen_random_uuid()::text::bytea)) RETURNING id",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

/// The edge factor: one BBA on the target, keyed on the edge's slot, and no
/// `perspectives` row. Mutation: re-adding the edge perspective write to
/// `auto_wire_ds_for_edge` fails the first assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_factor_keys_its_bba_on_the_edge_slot_and_writes_no_perspective(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let source = seed_claim_with_belief(&pool, 0.8, 0.9, Some(0.85)).await;
    let target = seed_claim(&pool, "1777638e edge target", 0.5).await;
    let edge = fixture::seed_edge(&pool, source, target).await;
    let signer = seed_agent(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let outcome =
        auto_wire_ds_for_edge(&mut conn, &viewer, edge, signer, source, target, "supports")
            .await
            .expect("wire the edge");
    assert!(
        matches!(outcome, EdgeFactorOutcome::Wired),
        "PREMISE: the edge is wired ({outcome:?})"
    );
    drop(conn);

    assert_eq!(
        slot_shaped_perspectives(&pool, &[edge]).await,
        0,
        "the edge factor writes no perspectives row (no type `edge`, none with the edge's id)"
    );
    assert_eq!(
        keys_on(&pool, target).await,
        vec![(None, Some("edge".to_string()), Some(edge), None)],
        "one BBA on the target, keyed on the edge's slot with no perspective"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    assert!(
        MassFunctionRepository::exists_for_edge(&mut *conn, &viewer, edge)
            .await
            .expect("exists_for_edge"),
        "the wake-up gate finds the edge wired"
    );
}

/// The DS evidence auto-wire: one BBA per evidence row, each keyed on that
/// row's slot (C-1), a re-submission of one evidence row upserts it, and no
/// `perspectives` row. Mutation: keying on the agent's unscoped key instead
/// collapses the two evidence rows into one BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ds_evidence_wire_keys_each_bba_on_its_evidence_slot(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim = seed_claim(&pool, "1777638e evidence slots", 0.5).await;
    let agent = seed_agent(&pool).await;
    let (ev1, ev2) = (
        evidence_on(&pool, claim).await,
        evidence_on(&pool, claim).await,
    );

    let mut conn = pool.acquire().await.expect("acquire");
    ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary_truth");
    for (ev, confidence) in [(ev1, 0.7), (ev2, 0.6), (ev1, 0.8)] {
        auto_wire_ds_update(
            &mut conn,
            &viewer,
            claim,
            agent,
            confidence,
            1.0,
            true,
            Some("empirical"),
            Some(ev),
            false,
        )
        .await
        .expect("auto_wire_ds_update");
    }
    drop(conn);

    assert_eq!(
        slot_shaped_perspectives(&pool, &[ev1, ev2]).await,
        0,
        "the evidence wire writes no perspectives row (no type `evidence`, none with an \
         evidence row's id)"
    );
    let mut expected = vec![
        (None, Some("evidence".to_string()), Some(ev1), Some(ev1)),
        (None, Some("evidence".to_string()), Some(ev2), Some(ev2)),
    ];
    expected.sort_by_key(|k| k.2);
    assert_eq!(
        keys_on(&pool, claim).await,
        expected,
        "one BBA per evidence row, on its slot; the second write of ev1 replaced its row"
    );
}

/// `create_perspective` refuses the two reserved types with a validation
/// error naming the field (the database would refuse them too, as
/// `perspectives_not_bba_slot`, but as a failed query), and writes nothing.
/// Control: the same call with another type lands. On the code before 267 the
/// reserved types were accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn create_perspective_refuses_a_reserved_type(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let params = |name: &str, kind: &str| epigraph_mcp::types::CreatePerspectiveParams {
        name: name.to_string(),
        description: None,
        owner_agent_id: None,
        perspective_type: Some(kind.to_string()),
        frame_ids: None,
        extraction_method: None,
        confidence_calibration: None,
    };
    for kind in ["edge", "evidence"] {
        let name = format!("1777638e reserved {kind}");
        let err = epigraph_mcp::tools::perspectives::create_perspective(
            &server,
            &viewer,
            params(&name, kind),
            Some(&token),
        )
        .await
        .expect_err("a reserved perspective_type is refused");
        assert!(
            err.message.contains("is reserved"),
            "{kind}: {}",
            err.message
        );
        let written: i64 = sqlx::query_scalar("SELECT count(*) FROM perspectives WHERE name = $1")
            .bind(&name)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(written, 0, "{kind}: nothing was written");
    }
    epigraph_mcp::tools::perspectives::create_perspective(
        &server,
        &viewer,
        params("1777638e control", "analytical"),
        Some(&token),
    )
    .await
    .expect("CALIBRATION: another type lands");
}

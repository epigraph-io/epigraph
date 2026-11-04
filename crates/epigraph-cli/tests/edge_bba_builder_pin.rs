//! Pin: `edge_factor::build_edge_bba`, the pure core extracted from
//! `auto_wire_ds_for_edge` (R-177(4) class E design §1.10), is exactly what the
//! wire stores.
//!
//! The targeted rewire's predict builds every predicted row with the builder
//! and the apply writes through the wire, so the two must not be able to
//! disagree on a row. Each case wires a real edge and compares the stored
//! `masses` (as `jsonb`, by the database), `source_strength`,
//! `evidence_type` and `locality_tag` with the builder's output for the same
//! source interval, relationship, locality and frame factor: Positive,
//! Negative and FrameEvidence relationships, intra- and cross-source, an
//! open-world mass above `pl - bel` (clamped), and a vacuous restriction
//! (the wire stores nothing and the builder says `Vacuous`).
#![cfg(feature = "db")]

mod rewire_fixture;
mod viewer_fixture;

use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::edge_factor::{
    build_edge_bba, edge_intra_locality_factor, edge_source_is_intra, EdgeBbaBuild,
    EdgeFactorOutcome,
};
use rewire_fixture::*;
use sqlx::PgPool;
use uuid::Uuid;

struct Case {
    rel: &'static str,
    interval: (f64, f64),
    open_world: f64,
    intra: bool,
}

async fn assert_builder_matches_wire(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    case: &Case,
    tag: &str,
) {
    let author = seed_agent(pool, &format!("pin-{tag}")).await;
    let frame = binary_frame(pool, viewer).await;
    let src = seed_claim(
        pool,
        author,
        &format!("pin source {tag}"),
        Some(case.interval),
        case.open_world,
    )
    .await;
    let tgt = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("pin target {tag}"),
        TARGET_EVIDENCE,
    )
    .await;
    if case.intra {
        let doi = format!("10.pin/{tag}-{}", Uuid::new_v4());
        let paper: Uuid = sqlx::query_scalar(
            "INSERT INTO papers (id, doi, title) VALUES (gen_random_uuid(), $1, 'pin') RETURNING id",
        )
        .bind(&doi)
        .fetch_one(pool)
        .await
        .expect("paper");
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper)
        .bind(tgt)
        .execute(pool)
        .await
        .expect("asserts edge");
        sqlx::query(
            "INSERT INTO evidence (id, content_hash, evidence_type, claim_id, properties) \
             VALUES (gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 'reference', $1, \
                     jsonb_build_object('doi', $2::text))",
        )
        .bind(src)
        .bind(&doi)
        .execute(pool)
        .await
        .expect("doi evidence");
    }
    let edge = seed_edge(pool, src, tgt, case.rel).await;

    let mut conn = pool.acquire().await.expect("conn");
    let is_intra = edge_source_is_intra(&mut conn, src, tgt)
        .await
        .expect("is_intra");
    assert_eq!(is_intra, case.intra, "{tag}: locality fixture");
    let profile = BeliefProfile::served();
    let factor = edge_intra_locality_factor(&mut conn, frame, profile)
        .await
        .expect("factor");
    let ow: f64 = sqlx::query_scalar("SELECT open_world_mass FROM claims WHERE id = $1")
        .bind(src)
        .fetch_one(pool)
        .await
        .expect("ow");
    let built = build_edge_bba(
        (case.interval.0, case.interval.1, Some(ow)),
        case.rel,
        is_intra,
        factor,
        profile,
    )
    .expect("build");
    drop(conn);

    let outcome = wire(pool, viewer, edge, author, src, tgt, case.rel).await;
    let rows = edge_rows(pool, edge).await;
    match built {
        EdgeBbaBuild::Built(b) => {
            assert_eq!(outcome, EdgeFactorOutcome::Wired, "{tag}");
            assert_eq!(rows.len(), 1, "{tag}: one stored row");
            let (_, masses, ss, et, lt, _, _) = &rows[0];
            assert!(
                same_jsonb(pool, &b.masses_json, masses).await,
                "{tag}: masses: built {} stored {masses}",
                b.masses_json
            );
            assert_eq!(*ss, Some(b.source_strength), "{tag}: source_strength");
            assert_eq!(
                et.as_deref(),
                Some(b.evidence_type.as_str()),
                "{tag}: evidence_type"
            );
            assert_eq!(lt, b.locality_tag, "{tag}: locality_tag");
        }
        EdgeBbaBuild::Vacuous => {
            assert_eq!(outcome, EdgeFactorOutcome::Vacuous, "{tag}");
            assert!(rows.is_empty(), "{tag}: a vacuous wire stores nothing");
        }
        EdgeBbaBuild::NonEpistemic => {
            assert_eq!(outcome, EdgeFactorOutcome::NonEpistemic, "{tag}");
            assert!(rows.is_empty(), "{tag}");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn build_edge_bba_is_what_the_wire_stores(pool: PgPool) {
    let cases = [
        (
            "supports-cross",
            Case {
                rel: "supports",
                interval: (0.62, 0.91),
                open_world: 0.05,
                intra: false,
            },
        ),
        (
            "supports-intra",
            Case {
                rel: "supports",
                interval: (0.62, 0.91),
                open_world: 0.05,
                intra: true,
            },
        ),
        (
            "contradicts-cross",
            Case {
                rel: "contradicts",
                interval: (0.55, 0.80),
                open_world: 0.0,
                intra: false,
            },
        ),
        (
            "refutes-intra",
            Case {
                rel: "refutes",
                interval: (0.70, 0.85),
                open_world: 0.10,
                intra: true,
            },
        ),
        (
            "frame-validates",
            Case {
                rel: "frame_validates",
                interval: (0.66, 0.88),
                open_world: 0.02,
                intra: false,
            },
        ),
        (
            "elaborates",
            Case {
                rel: "elaborates",
                interval: (0.40, 0.95),
                open_world: 0.20,
                intra: false,
            },
        ),
        // open_world above pl - bel: clamped to the width by the interval.
        (
            "ow-clamped",
            Case {
                rel: "supports",
                interval: (0.40, 0.60),
                open_world: 0.50,
                intra: false,
            },
        ),
        // full ignorance restricts to a vacuous interval: nothing is stored.
        (
            "vacuous",
            Case {
                rel: "supports",
                interval: (0.0, 1.0),
                open_world: 0.0,
                intra: false,
            },
        ),
    ];
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    for (tag, case) in &cases {
        assert_builder_matches_wire(&pool, &viewer, case, tag).await;
    }
}

//! A frame get-or-create that LOSES its create must not abort the caller's
//! transaction.
//!
//! # The defect this pins (brief hard constraint #6)
//!
//! `ds_auto::ensure_axis_frame` and `edge_factor::ensure_binary_frame` are
//! get -> create -> fallback-get. The create's error is SWALLOWED into the
//! fallback read. That was safe while every statement ran on its own pooled
//! checkout; now callers hand them a TRANSACTION, and inside one a failed
//! INSERT aborts the transaction: the fallback read fails with `25P02`, and the
//! caller's eventual `COMMIT` is answered with `ROLLBACK` and no error.
//!
//! MEASURED by review on the real binary, config A, `ingest_document_inline` of
//! a document with two binary atoms and one atom on a declared axis whose frame
//! NAME already exists but is invisible to the ingesting agent:
//!
//! ```text
//! CONTROL (axis name new)      atom_bbas=3 binary_atom_bbas=2 claim_frames=3
//! TRIGGER (axis name hidden)   atom_bbas=0 binary_atom_bbas=0 claim_frames=0
//! ```
//!
//! — the binary atoms' BBAs, wired in the same post-commit DS transaction BEFORE
//! the axis entry, vanished at COMMIT, with one WARN and no error.
//!
//! # Why these reproduce under the superuser test role
//!
//! `FrameRepository::get_by_name` carries a SPLICED viewer predicate
//! (`/* {VISIBILITY:frames} */`), not only an RLS one, so a group-owned frame is
//! invisible to a public viewer even on a BYPASSRLS connection. The create then
//! hits `frames_name_key` (23505) — the same error the concurrent
//! first-creation race produces.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::common::plan::PlannedAxis;
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_batch, ensure_axis_frame, BatchDsEntry};
use sqlx::{Connection, PgPool};
use uuid::Uuid;

/// A frame named `name` that the PUBLIC viewer cannot see.
async fn seed_hidden_frame(pool: &PgPool, name: &str) {
    // A real team group (not the seed sentinel, which `frames_group_needs_real_group`
    // refuses as an owner).
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('frame owner', 'did:test:frame-owner:' || gen_random_uuid(), \
                 decode(repeat('cd', 32), 'hex'), 'team') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("owner group");
    sqlx::query(
        "INSERT INTO frames (name, description, hypotheses, visibility, owner_group_id) \
         VALUES ($1, 'hidden from the public viewer', ARRAY['low','high'], 'group', $2)",
    )
    .bind(name)
    .bind(group)
    .execute(pool)
    .await
    .expect("hidden frame");
}

/// The transaction must still accept a statement after the failed create.
async fn assert_usable(tx: &mut sqlx::PgConnection, after: &str) {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            panic!("the caller's transaction is ABORTED after {after}: {e}. Its COMMIT would be a silent ROLLBACK")
        });
    assert_eq!(one, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_lost_axis_frame_create_leaves_the_transaction_usable(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    seed_hidden_frame(&pool, "hidden_axis").await;

    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let res = ensure_axis_frame(
        &mut tx,
        &viewer,
        "hidden_axis",
        &["low".to_string(), "high".to_string()],
        None,
    )
    .await;
    assert!(
        res.is_err(),
        "a frame the viewer cannot see cannot be resolved: {res:?}"
    );
    assert_usable(&mut tx, "ensure_axis_frame's lost create").await;
    tx.commit().await.expect("commit");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_lost_binary_frame_create_leaves_the_transaction_usable(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    seed_hidden_frame(&pool, "binary_truth").await;

    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let res = epigraph_engine::edge_factor::ensure_binary_frame(&mut tx, &viewer).await;
    assert!(
        res.is_err(),
        "a hidden binary_truth cannot be resolved: {res:?}"
    );
    assert_usable(&mut tx, "the engine's ensure_binary_frame lost create").await;
    tx.commit().await.expect("commit");
}

/// The review's measurement, at the batch level: binary entries on either side
/// of an axis entry that cannot be resolved. Both binary BBAs must SURVIVE the
/// commit; the axis entry alone is skipped.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unresolvable_axis_entry_does_not_roll_back_the_rest_of_the_batch(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let before = seed_claim(&pool, "binary atom wired before the axis entry", 0.5).await;
    let axis = seed_claim(&pool, "atom on a hidden axis", 0.5).await;
    let after = seed_claim(&pool, "binary atom wired after the axis entry", 0.5).await;
    seed_hidden_frame(&pool, "hidden_axis").await;

    let entry = |claim_id: Uuid, axis: Option<PlannedAxis>| BatchDsEntry {
        claim_id,
        confidence: 0.8,
        weight: 0.9,
        evidence_type: None,
        axis,
    };
    let entries = [
        entry(before, None),
        entry(
            axis,
            Some(PlannedAxis {
                frame: "hidden_axis".to_string(),
                hypotheses: vec!["low".to_string(), "high".to_string()],
                hypothesis_index: 1,
            }),
        ),
        entry(after, None),
    ];

    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let (_frame, wired) = auto_wire_ds_batch(&mut tx, &viewer, &entries, agent)
        .await
        .expect("batch");
    tx.commit().await.expect("commit");

    let bbas = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        (bbas(before).await, bbas(axis).await, bbas(after).await),
        (1, 0, 1),
        "(before, axis, after) BBAs after COMMIT: the axis entry is skipped alone"
    );
    assert_eq!(wired, 2, "the reported count must match what persisted");
}

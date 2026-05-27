#![cfg(feature = "db")]
//! Verifies alt_set_decisions correctly classifies alt-set members by
//! their lifecycle label and surfaces alt_state_meta.
//!
//! Uses `#[sqlx::test]` so each run gets a fresh ephemeral DB with all
//! migrations applied — sidesteps shared-DB pollution and the
//! migration-038 checksum skew on `epigraph_db_repo_test`.

mod common;

use sqlx::{PgPool, Row};

#[sqlx::test(migrations = "../../migrations")]
async fn alt_set_decisions_classifies_by_label(pool: PgPool) {
    // Three claims forming an alt-set: a1 alternative_of a2, a2 alternative_of a3
    // (transitive closure collapses {a1, a2, a3} into one equivalence class).
    let a1 = common::seed_claim(&pool, "alt member 1").await;
    let a2 = common::seed_claim(&pool, "alt member 2").await;
    let a3 = common::seed_claim(&pool, "alt member 3").await;
    common::insert_edge(&pool, a1, a2, "claim", "claim", "alternative_of").await;
    common::insert_edge(&pool, a2, a3, "claim", "claim", "alternative_of").await;

    // a1 = chosen, a2 = rejected, a3 = default active
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-rejected'] WHERE id = $1")
        .bind(a2)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('alt_state_meta', \
         jsonb_build_object('state', 'chosen', 'rationale', 'cheap', 'score', \
         jsonb_build_object('cost', 0.7, 'time', 0.5))) WHERE id = $1",
    )
    .bind(a1)
    .execute(&pool)
    .await
    .unwrap();

    let rows = sqlx::query(
        "SELECT claim_id, alt_state, alt_state_meta IS NOT NULL AS has_meta \
         FROM alt_set_decisions WHERE claim_id = ANY($1) ORDER BY alt_state",
    )
    .bind(&[a1, a2, a3][..])
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 3, "expected 3 rows in the equivalence class");

    let states: Vec<(uuid::Uuid, String, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.get::<uuid::Uuid, _>("claim_id"),
                r.get::<String, _>("alt_state"),
                r.get::<bool, _>("has_meta"),
            )
        })
        .collect();

    let a1_row = states.iter().find(|(id, _, _)| *id == a1).expect("a1 row");
    let a2_row = states.iter().find(|(id, _, _)| *id == a2).expect("a2 row");
    let a3_row = states.iter().find(|(id, _, _)| *id == a3).expect("a3 row");

    assert_eq!(a1_row.1, "chosen");
    assert!(a1_row.2, "a1 has alt_state_meta");
    assert_eq!(a2_row.1, "rejected");
    assert!(!a2_row.2, "a2 has no meta");
    assert_eq!(a3_row.1, "active");
    assert!(!a3_row.2, "a3 default no meta");
}

#[sqlx::test(migrations = "../../migrations")]
async fn alt_set_decisions_priority_chosen_over_rejected(pool: PgPool) {
    // If a claim has BOTH alt-chosen AND alt-rejected (invariant violation —
    // shouldn't happen in practice), the view's CASE picks 'chosen'.
    let a = common::seed_claim(&pool, "double-labelled").await;
    let b = common::seed_claim(&pool, "other").await;
    common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;

    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen', 'alt-rejected'] WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();

    let state: String =
        sqlx::query_scalar("SELECT alt_state FROM alt_set_decisions WHERE claim_id = $1")
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "chosen", "chosen priority over rejected");
}

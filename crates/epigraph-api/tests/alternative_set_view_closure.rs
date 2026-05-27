#![cfg(feature = "db")]
//! 3-cycle (A↔B, B↔C) under alternative_of must collapse into one
//! equivalence class — every member's alt_members lists the other two.

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn alternative_set_view_transitive_closure() {
    let pool = common::test_pool().await;
    let a = common::seed_claim(&pool, "alt-closure-A").await;
    let b = common::seed_claim(&pool, "alt-closure-B").await;
    let c = common::seed_claim(&pool, "alt-closure-C").await;

    let e_ab = common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;
    let e_bc = common::insert_edge(&pool, b, c, "claim", "claim", "alternative_of").await;

    let row_a: (Vec<uuid::Uuid>,) =
        sqlx::query_as("SELECT alt_members FROM alternative_set WHERE claim_id = $1")
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        row_a.0.contains(&b),
        "A's alt_members must include B, got {:?}",
        row_a.0
    );
    assert!(
        row_a.0.contains(&c),
        "A's alt_members must include C (transitive), got {:?}",
        row_a.0
    );

    let row_c: (Vec<uuid::Uuid>,) =
        sqlx::query_as("SELECT alt_members FROM alternative_set WHERE claim_id = $1")
            .bind(c)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        row_c.0.contains(&a),
        "C's alt_members must include A (transitive), got {:?}",
        row_c.0
    );
    assert!(
        row_c.0.contains(&b),
        "C's alt_members must include B, got {:?}",
        row_c.0
    );

    let row_b: (Vec<uuid::Uuid>,) =
        sqlx::query_as("SELECT alt_members FROM alternative_set WHERE claim_id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        row_b.0.contains(&a),
        "B's alt_members must include A, got {:?}",
        row_b.0
    );
    assert!(
        row_b.0.contains(&c),
        "B's alt_members must include C, got {:?}",
        row_b.0
    );

    // Cleanup so reruns don't accumulate fixture rows; FK on edges to
    // claims doesn't cascade so we drop edges before the fixture claims age out.
    sqlx::query("DELETE FROM edges WHERE id = ANY($1)")
        .bind(&[e_ab, e_bc][..])
        .execute(&pool)
        .await
        .unwrap();
}

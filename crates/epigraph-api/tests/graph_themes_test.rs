#![cfg(feature = "db")]
//! # Why both arms take an injected `pool`
//!
//! MEASURED, not inferred. Built at `c4d3f304` and run four times against the
//! shared database with this binary and `build_from_bridges_test` as
//! CONCURRENT processes, each at `--test-threads=4`:
//! `themes_expand_returns_neighborhoods_for_seeded_theme` failed 2 of 3 runs
//! with `23503 neighborhood_edges_neighborhood_a_fkey ... Key
//! (neighborhood_a)=(...) is not present in table "graph_neighborhoods"` — the
//! other binary's unfiltered `DELETE FROM graph_neighborhoods` landing between
//! this arm's own INSERT and the edge INSERT that references it. Run alone at
//! four threads the same binary passed 4 of 4. The failure is therefore in the
//! shared corpus, not in this arm.
//!
//! The finding (`F-tests-depend-on-accumulated-shared-db-fixtures`) required
//! exactly that characterisation before conversion, because the previous
//! inventories in this series were built from grep evidence alone.
//!
//! # Both files convert together
//!
//! This binary and `build_from_bridges_test.rs` truncate the SAME three tables
//! (`neighborhood_edges`, `claim_neighborhood_membership`,
//! `graph_neighborhoods`) — and they are the same three the already-isolated
//! `graph_neighborhoods_test.rs` used to truncate. Converting one and leaving
//! the other keeps the surviving truncation alive against two isolated
//! siblings, which is the half-state that re-breaks them.
//!
//! `#[sqlx::test]` supplies the empty database the DELETEs were faking, so
//! every assertion below is unchanged and no test name is lost. `spawn_app`
//! builds its own pool from a URL, so each arm hands it
//! `fixture::database_url_for(&pool)` — the per-test database — rather than the
//! ambient `DATABASE_URL`, which would seed one database and assert against
//! another.
//!
//! These arms lost their `flavor = "multi_thread"` runtime, for the reason
//! `graph_neighborhoods_test.rs`'s header sets out at length: `#[sqlx::test]`
//! drives the future on a current-thread runtime, and nothing in this request
//! path blocks.

use serde_json::Value;
use sqlx::PgPool;

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_returns_seeded_themes(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    // FOUR themes, not two, and the counts INTERLEAVE the labels on purpose.
    //
    // Before the #[sqlx::test] conversion this arm ran on the shared database and
    // deleted only labels 'A' and 'B', so `assert_eq!(order, sorted)` ranged over
    // the whole accumulated theme corpus. On a per-test database the response is
    // exactly what this fixture seeds, and two rows make that assertion nearly
    // vacuous: with A(12), B(7) the only permutation it can reject is a full
    // reversal, so a broken secondary key or a partial mis-ordering passes.
    //
    // `routes/graph.rs::themes_overview` runs `ORDER BY claim_count DESC,
    // label ASC` with no LIMIT. C(9) sits BETWEEN A and B by count while sorting
    // after both by label, so count and label disagree about the answer; and
    // B/D tie at 7, so `label ASC` is the only thing that separates them. The
    // one correct sequence is therefore A, C, B, D — asserted by label below
    // rather than by "the list happens to be descending".
    let theme_a = uuid::Uuid::new_v4();
    let theme_b = uuid::Uuid::new_v4();
    let theme_c = uuid::Uuid::new_v4();
    let theme_d = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count) \
         VALUES ($1, 'A', '', 12), ($2, 'B', '', 7), ($3, 'C', '', 9), ($4, 'D', '', 7)",
    )
    .bind(theme_a)
    .bind(theme_b)
    .bind(theme_c)
    .bind(theme_d)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/themes/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let themes = body["themes"].as_array().unwrap();
    let by_label: std::collections::HashMap<String, &Value> = themes
        .iter()
        .filter_map(|t| t["label"].as_str().map(|l| (l.to_string(), t)))
        .collect();
    for label in ["A", "B", "C", "D"] {
        assert!(
            by_label.contains_key(label),
            "expected theme {label} in response"
        );
    }

    // Assert the EXACT sequence, not that it is sorted. Every wrong ORDER BY this
    // arm can distinguish produces a different sequence: dropping `DESC` gives
    // B, D, C, A; dropping the `label ASC` tie-break makes the B/D pair
    // nondeterministic; ordering by label alone gives A, B, C, D.
    let order: Vec<&str> = themes.iter().filter_map(|t| t["label"].as_str()).collect();
    assert_eq!(
        order,
        vec!["A", "C", "B", "D"],
        "themes must be ordered by claim_count DESC then label ASC. \
         Seeded A(12), C(9), B(7), D(7); got {order:?}"
    );

    // And the counts travel with the labels, so the sequence above is not an
    // accident of two columns being read from different rows.
    let counts: Vec<i64> = themes
        .iter()
        .filter_map(|t| t["claim_count"].as_i64())
        .collect();
    assert_eq!(
        counts,
        vec![12, 9, 7, 7],
        "claim_count must accompany its own label; got {counts:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_expand_returns_neighborhoods_for_seeded_theme(pool: PgPool) {
    use uuid::Uuid;
    let url = fixture::database_url_for(&pool).await;

    // Inline minimal seed: agent + run + theme + 2 atoms + 1 edge.
    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('BB', 32), 'hex'), 'themes-expand-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'Expand', '', 2)")
        .bind(theme_id).execute(&pool).await.unwrap();

    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    for (id, content) in [(claim_a, "atom-a"), (claim_b, "atom-b")] {
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(content)
        .bind(hash)
        .bind(agent_id)
        .bind(theme_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Seed two neighborhoods directly (skip Louvain for fast unit-test scope).
    let nbr_a = Uuid::new_v4();
    let nbr_b = Uuid::new_v4();
    for (id, label, size) in [(nbr_a, "nbr-a", 1_i32), (nbr_b, "nbr-b", 1_i32)] {
        sqlx::query(
            "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
             VALUES ($1, $2, $3, $4, $5, NULL, NULL)"
        )
        .bind(id).bind(run_id).bind(theme_id).bind(label).bind(size)
        .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_a).bind(nbr_a).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_b).bind(nbr_b).execute(&pool).await.unwrap();

    // Inter-neighborhood edge — store canonical (a < b).
    let (lo, hi) = if nbr_a < nbr_b {
        (nbr_a, nbr_b)
    } else {
        (nbr_b, nbr_a)
    };
    sqlx::query(
        "INSERT INTO neighborhood_edges (run_id, neighborhood_a, neighborhood_b, weight) \
         VALUES ($1, $2, $3, 0.7)",
    )
    .bind(run_id)
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/themes/{theme_id}/expand"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "themes/expand should return 200"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["theme_id"].as_str().unwrap(), theme_id.to_string());
    let nbrs = body["neighborhoods"].as_array().unwrap();
    assert_eq!(
        nbrs.len(),
        2,
        "expected exactly 2 neighborhoods for the seeded theme"
    );
    let edges = body["neighborhood_edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1, "expected one inter-neighborhood edge");
    assert!((edges[0]["weight"].as_f64().unwrap() - 0.7).abs() < 1e-9);
}

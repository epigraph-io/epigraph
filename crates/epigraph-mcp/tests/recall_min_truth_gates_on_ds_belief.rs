//! Backlog `14b98adc`: `recall`'s `min_truth` gated on `claims.truth_value`.
//!
//! No Dempster-Shafer write path refreshes `claims.truth_value` —
//! `link_epistemic` → `auto_wire_ds_for_edge` → `recompute_combined_belief` and
//! `recompute_beliefs` both write `claims.{belief, plausibility,
//! pignistic_prob, …}` and leave it alone. So a claim thoroughly refuted by
//! epistemic edges kept clearing a `min_truth` gate set against its pre-edge
//! authored value (production 2026-09-07: claim `8f192373`, `truth_value`
//! 1.0000 against BetP 0.1797).
//!
//! ## Why this drives `recall` end-to-end rather than the repo layer
//!
//! `effective_belief_batch.rs` in `epigraph-db` covers the SELECTION. What it
//! cannot cover is the WIRING: that `recall`'s gate reads that scalar rather
//! than the `truth_value` its `get_by_id` already has in hand. The two claims
//! below are identical on every axis retrieval can see — same embedding, same
//! content token, same `truth_value` — so ranking, tags, `since` and tenancy
//! cannot separate them. Only the DS cache can.
//!
//! ## Shared-database discipline
//!
//! Same as `recall_theme_scope.rs`: `test_pool_or_skip!` shares one DB across
//! the crate, so every fixture uses a run-unique content token, asserts only on
//! its own ids, and deletes its rows on the way out.

#[macro_use]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

#[rustfmt::skip]
use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
use epigraph_mcp::types::RecallParams;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

const DIM: usize = 1536;

/// One fixed direction, so every claim in a run is maximally similar to the
/// query and to each other — retrieval cannot be what separates them.
fn one_bucket_pgvec() -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(DIM / 8) {
        *slot = 1.0;
    }
    let inner: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
    format!("[{}]", inner.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recall-ds-gate', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A current, embedded, public claim carrying the run-unique `token`.
async fn seed_claim(pool: &PgPool, agent: Uuid, token: &str, tail: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             embedding) \
         VALUES ($1, $2, $3, $4, $5, true, $6::vector)",
    )
    .bind(id)
    .bind(format!("{token} {tail}"))
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .bind(one_bucket_pgvec())
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// Write the DS cache the edge-wiring recompute would have written. Done with
/// an UPDATE rather than by wiring a real `refutes` edge because the subject
/// under test is the READ: the gate must consult these columns however they got
/// there, and a real recompute would additionally move `classification` and
/// `updated_at`, neither of which this assertion should depend on.
async fn set_ds_cache(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .expect("seed DS cache");
}

async fn cleanup(pool: &PgPool, claims: &[Uuid]) {
    sqlx::query("DELETE FROM recall_events WHERE returned_claim_ids && $1")
        .bind(claims)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
        .bind(claims)
        .execute(pool)
        .await
        .expect("cleanup claims");
}

fn returned_ids(body: &Value) -> HashSet<String> {
    body.get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.get("claim_id").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn row_for(body: &Value, claim: Uuid) -> Option<&Value> {
    body.get("results")?
        .as_array()?
        .iter()
        .find(|r| r.get("claim_id").and_then(Value::as_str) == Some(claim.to_string().as_str()))
}

/// Two claims, both authored at `truth_value` 1.0, both top hits. One carries a
/// DS cache whose BetP is 0.1797; the other has never had a DS write. At the
/// default `min_truth` of 0.3 the refuted one must be dropped and the other
/// kept.
///
/// Pre-fix this fails on the first assertion: the gate read `truth_value` 1.0
/// for both, so the refuted claim came back.
#[tokio::test]
async fn a_ds_refuted_claim_is_dropped_by_min_truth_though_its_truth_value_passes() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let token = format!("dsgate{}", Uuid::new_v4().simple());

    let refuted = seed_claim(&pool, agent, &token, "refuted", 1.0).await;
    let intact = seed_claim(&pool, agent, &token, "intact", 1.0).await;
    // The production shape from the item: belief 0.0, plausibility 0.3594,
    // BetP 0.1797 — below the 0.3 default, while truth_value stays at 1.0.
    set_ds_cache(&pool, refuted, 0.0, 0.3594, 0.1797).await;

    let pgvec = one_bucket_pgvec();

    // Control: with the gate wide open BOTH claims are reachable, so the
    // absence below is the gate working rather than the fixture being
    // unretrievable.
    let open: RecallParams =
        serde_json::from_value(json!({ "query": token, "limit": 10, "min_truth": 0.0 }))
            .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, open, Some(pgvec.clone()))
            .await
            .expect("recall"),
    );
    let ids = returned_ids(&body);
    assert!(
        ids.contains(&refuted.to_string()) && ids.contains(&intact.to_string()),
        "control: both claims must be retrievable at min_truth=0.0, got {ids:?}"
    );

    // The gate, at the tool's own default.
    let gated: RecallParams =
        serde_json::from_value(json!({ "query": token, "limit": 10, "min_truth": 0.3 }))
            .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, gated, Some(pgvec))
            .await
            .expect("recall"),
    );
    let ids = returned_ids(&body);

    assert!(
        !ids.contains(&refuted.to_string()),
        "a claim whose cached BetP is 0.1797 came back through a min_truth=0.3 gate. \
         Its truth_value is 1.0 and no DS write path refreshes that column, so the \
         gate is still reading the stale scalar (backlog 14b98adc). Returned: {ids:?}"
    );
    assert!(
        ids.contains(&intact.to_string()),
        "the claim with NO DS state must still pass at its authored truth_value of \
         1.0. Dropping it would mean the gate reads 0.0/NULL as refuted, which would \
         empty recall for the entire un-assessed corpus. Returned: {ids:?}"
    );

    cleanup(&pool, &[refuted, intact]).await;
}

/// `truth_value` keeps reporting the authored scalar; `belief_score` reports
/// what the gate compared against. A caller must be able to see the divergence
/// — that is what makes the drop above auditable instead of mysterious.
#[tokio::test]
async fn each_hit_reports_both_the_authored_truth_value_and_the_gated_belief() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let token = format!("dsrep{}", Uuid::new_v4().simple());

    // Above the gate, but well below its authored truth_value.
    let moved = seed_claim(&pool, agent, &token, "moved", 0.95).await;
    let untouched = seed_claim(&pool, agent, &token, "untouched", 0.88).await;
    set_ds_cache(&pool, moved, 0.40, 0.72, 0.56).await;

    let params: RecallParams =
        serde_json::from_value(json!({ "query": token, "limit": 10, "min_truth": 0.0 }))
            .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, params, Some(one_bucket_pgvec()))
            .await
            .expect("recall"),
    );

    let row = row_for(&body, moved).expect("the DS-cached claim must be in the page");
    let tv = row.get("truth_value").and_then(Value::as_f64).expect("tv");
    let bs = row
        .get("belief_score")
        .and_then(Value::as_f64)
        .expect("belief_score must be present on every hit");
    assert!(
        (tv - 0.95).abs() < 1e-9,
        "truth_value must keep reporting the AUTHORED scalar unchanged, got {tv}. \
         Overwriting it with the DS value would let a third party's refutes edge \
         silently rewrite an operator-set field."
    );
    assert!(
        (bs - 0.56).abs() < 1e-9,
        "belief_score must report the cached BetP the gate used, got {bs}"
    );

    let row = row_for(&body, untouched).expect("the un-cached claim must be in the page");
    let tv = row.get("truth_value").and_then(Value::as_f64).expect("tv");
    let bs = row
        .get("belief_score")
        .and_then(Value::as_f64)
        .expect("belief_score");
    assert!(
        (tv - 0.88).abs() < 1e-9 && (bs - 0.88).abs() < 1e-9,
        "with no DS state the two fields must be EQUAL ({tv} vs {bs}) — that equality \
         is how a caller reads 'this claim has no DS cache, the gate fell back'."
    );

    cleanup(&pool, &[moved, untouched]).await;
}

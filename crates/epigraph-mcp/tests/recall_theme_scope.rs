//! Theme-scoped `recall` (backlog `c95a2509-619a-44d0-90ee-cf0ac4ac645b`):
//! `theme_id` / `theme_label` narrow the candidate pool to one theme's members
//! in SQL, on EVERY claims retrieval surface, with `offset` paging so a caller
//! can walk that theme to exhaustion.
//!
//! ## Why every params struct here is built from `serde_json::from_value`
//!
//! Same reason as `recall_temporal.rs`: this file must compile against the
//! branch point, where `theme_id` / `theme_label` / `offset` do not exist.
//! `RecallParams` does not use `deny_unknown_fields`, so those keys
//! deserialise fine on both sides — they are simply IGNORED before the fix.
//! Every assertion below is therefore behavioural: pre-fix these fail on an
//! assertion (an off-theme claim comes back), not on a compile error. A compile
//! error would prove nothing about behaviour.
//!
//! ## The three candidate-producing surfaces a claims-only recall has
//!
//! | Test | Surface |
//! |---|---|
//! | `theme_scope_excludes_off_theme_hits_on_hybrid` | `search_hybrid_scoped_since_in_theme` dense + lex CTEs |
//! | `theme_scope_holds_when_the_embedder_is_down`   | `search_lexical_scoped_since_in_theme` (degrade path) |
//! | `include_workflows_with_a_theme_is_rejected`    | `WorkflowRepository::search_by_goal_embedding_since` — the surface a theme filter CANNOT be pushed into |
//!
//! ## Shared-database discipline
//!
//! `test_pool_or_skip!` shares one DB across the whole crate's tests. Every
//! fixture below uses a run-unique content token so the lexical leg can only
//! match its own rows, asserts only on its own claim ids, and deletes its rows
//! on the way out (leftover `claim_themes` rows would break
//! `theme_cluster_test` and `recall_temporal::no_leak_s6_diverse_themes`,
//! both of which depend on a near-empty theme table).

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

/// Unit-ish vector concentrated in `bucket`; same-bucket vectors are highly
/// cosine-similar, different-bucket vectors orthogonal.
fn cluster_pgvec(bucket: usize) -> String {
    let stride = DIM / 8;
    let mut v = vec![0.0f32; DIM];
    for slot in v
        .iter_mut()
        .take((bucket + 1) * stride)
        .skip(bucket * stride)
    {
        *slot = 1.0;
    }
    let inner: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
    format!("[{}]", inner.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recall-theme-scope', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'recall_theme_scope') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

/// Insert a current, embedded claim assigned to `theme`. Every claim's content
/// carries the run-unique `token`, so the lexical leg matches this run's rows
/// and nothing else in the shared corpus.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    theme: Option<Uuid>,
    token: &str,
    tail: &str,
    pgvec: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             theme_id, embedding) \
         VALUES ($1, $2, $3, $4, 0.8, true, $5, $6::vector)",
    )
    .bind(id)
    .bind(format!("{token} {tail}"))
    .bind(hash)
    .bind(agent)
    .bind(theme)
    .bind(pgvec)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn cleanup(pool: &PgPool, claims: &[Uuid], themes: &[Uuid]) {
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
    sqlx::query("DELETE FROM claim_themes WHERE id = ANY($1)")
        .bind(themes)
        .execute(pool)
        .await
        .expect("cleanup themes");
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

/// S1 + S2: the hybrid dense CTE and the hybrid lexical CTE.
///
/// The off-theme claim is seeded with the SAME embedding bucket and the SAME
/// content token as the in-theme ones, so it is a top hit on both legs. Only a
/// SQL theme predicate keeps it out; a filter applied after ranking, or not at
/// all, returns it.
#[tokio::test]
async fn theme_scope_excludes_off_theme_hits_on_hybrid() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let token = format!("thscope{}", Uuid::new_v4().simple());

    let theme = seed_theme(&pool, &format!("ttest-recall-{token}")).await;
    let pgvec = cluster_pgvec(0);

    let inside_a = seed_claim(&pool, agent, Some(theme), &token, "alpha", &pgvec).await;
    let inside_b = seed_claim(&pool, agent, Some(theme), &token, "beta", &pgvec).await;
    let outside = seed_claim(&pool, agent, None, &token, "gamma", &pgvec).await;

    // Unscoped control: the off-theme claim IS reachable, so its absence below
    // is the filter working rather than the fixture being unreachable.
    let unscoped: RecallParams =
        serde_json::from_value(json!({ "query": token, "limit": 10, "min_truth": 0.0 }))
            .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, unscoped, Some(pgvec.clone()))
            .await
            .expect("unscoped recall"),
    );
    let unscoped_ids = returned_ids(&body);
    assert!(
        unscoped_ids.contains(&outside.to_string()),
        "control failed: the off-theme claim must be reachable WITHOUT the filter, \
         otherwise the scoped assertion below proves nothing: {body}"
    );
    assert!(
        body.get("theme_scope").is_none(),
        "an unscoped recall must not grow a theme_scope field: {body}"
    );
    assert!(
        body.get("paging").is_none(),
        "an unscoped recall must not grow a paging field: {body}"
    );

    // Scoped by id.
    let scoped: RecallParams = serde_json::from_value(json!({
        "query": token,
        "limit": 10,
        "min_truth": 0.0,
        "theme_id": theme.to_string(),
    }))
    .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, scoped, Some(pgvec.clone()))
            .await
            .expect("scoped recall"),
    );
    let ids = returned_ids(&body);
    assert!(
        !ids.contains(&outside.to_string()),
        "off-theme claim leaked into a theme-scoped recall: {body}"
    );
    assert!(
        ids.contains(&inside_a.to_string()) && ids.contains(&inside_b.to_string()),
        "both in-theme claims must still be returned: {body}"
    );
    assert_eq!(
        body.pointer("/theme_scope/theme_id")
            .and_then(Value::as_str),
        Some(theme.to_string().as_str()),
        "the resolved theme must be echoed so the scope is not opaque: {body}"
    );
    assert_eq!(
        body.pointer("/theme_scope/member_count")
            .and_then(Value::as_i64),
        Some(2),
        "member_count bounds how far a walk can go: {body}"
    );

    // Scoped by label resolves to the same theme.
    let by_label: RecallParams = serde_json::from_value(json!({
        "query": token,
        "limit": 10,
        "min_truth": 0.0,
        "theme_label": format!("ttest-recall-{token}"),
    }))
    .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, by_label, Some(pgvec.clone()))
            .await
            .expect("label-scoped recall"),
    );
    assert!(
        !returned_ids(&body).contains(&outside.to_string()),
        "theme_label must scope as tightly as theme_id: {body}"
    );

    cleanup(&pool, &[inside_a, inside_b, outside], &[theme]).await;
}

/// S3: the embedder-down degrade path. `pgvec = None` sends `recall` through
/// `search_lexical_scoped_since_in_theme`. A theme filter wired only into the
/// hybrid query would silently widen to the whole corpus exactly here.
#[tokio::test]
async fn theme_scope_holds_when_the_embedder_is_down() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let token = format!("thlex{}", Uuid::new_v4().simple());

    let theme = seed_theme(&pool, &format!("ttest-recall-{token}")).await;
    let pgvec = cluster_pgvec(1);
    let inside = seed_claim(&pool, agent, Some(theme), &token, "delta", &pgvec).await;
    let outside = seed_claim(&pool, agent, None, &token, "epsilon", &pgvec).await;

    // Control on the SAME degrade path: unscoped, the off-theme claim comes back.
    let unscoped: RecallParams =
        serde_json::from_value(json!({ "query": token, "limit": 10, "min_truth": 0.0 }))
            .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, unscoped, None)
            .await
            .expect("unscoped lexical recall"),
    );
    assert!(
        returned_ids(&body).contains(&outside.to_string()),
        "control failed: the off-theme claim must be lexically reachable with no filter: {body}"
    );

    let scoped: RecallParams = serde_json::from_value(json!({
        "query": token,
        "limit": 10,
        "min_truth": 0.0,
        "theme_id": theme.to_string(),
    }))
    .expect("params");
    let body = common::first_text(
        &recall_with_pgvec(&server, &viewer, scoped, None)
            .await
            .expect("scoped lexical recall"),
    );
    let ids = returned_ids(&body);
    assert!(
        !ids.contains(&outside.to_string()),
        "the theme scope widened on the embedder-down path: {body}"
    );
    assert!(
        ids.contains(&inside.to_string()),
        "the in-theme claim must still be found lexically: {body}"
    );

    cleanup(&pool, &[inside, outside], &[theme]).await;
}

/// The stated requirement: walk one theme to exhaustion via `offset`, seeing
/// each member exactly once, with a termination signal that does not depend on
/// getting an empty page.
#[tokio::test]
async fn offset_walks_a_theme_to_exhaustion_without_repeats() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let token = format!("thpage{}", Uuid::new_v4().simple());

    let theme = seed_theme(&pool, &format!("ttest-recall-{token}")).await;
    // All five share ONE embedding vector and ONE content token, so their dense
    // distances and their ts_rank_cd scores are all tied — the fused rrf_score
    // is identical across the five. That is precisely the case a non-total
    // ORDER BY permutes between pages.
    let pgvec = cluster_pgvec(2);
    let mut seeded = Vec::new();
    for i in 0..5 {
        seeded.push(seed_claim(&pool, agent, Some(theme), &token, "same", &pgvec).await);
        let _ = i;
    }

    let mut seen: Vec<String> = Vec::new();
    let mut offset = 0i64;
    loop {
        let params: RecallParams = serde_json::from_value(json!({
            "query": token,
            "limit": 2,
            "min_truth": 0.0,
            "theme_id": theme.to_string(),
            "offset": offset,
        }))
        .expect("params");
        let body = common::first_text(
            &recall_with_pgvec(&server, &viewer, params, Some(pgvec.clone()))
                .await
                .expect("paged recall"),
        );

        let paging = body.get("paging").unwrap_or_else(|| {
            panic!("a paged recall must report paging state; got {body}");
        });
        assert_eq!(
            paging.get("offset").and_then(Value::as_i64),
            Some(offset),
            "paging must echo the offset it served: {body}"
        );

        let page: Vec<String> = body
            .get("results")
            .and_then(Value::as_array)
            .expect("results array")
            .iter()
            .filter_map(|r| r.get("claim_id").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect();
        seen.extend(page);

        let more = paging
            .get("more_available")
            .and_then(Value::as_bool)
            .expect("more_available");
        let next = paging
            .get("next_offset")
            .and_then(Value::as_i64)
            .expect("next_offset");
        if !more {
            break;
        }
        assert!(next > offset, "next_offset must advance: {body}");
        offset = next;
        assert!(offset <= 20, "the walk failed to terminate");
    }

    let unique: HashSet<&String> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a claim was served on more than one page: {seen:?}"
    );
    let expected: HashSet<String> = seeded.iter().map(ToString::to_string).collect();
    assert_eq!(
        unique.into_iter().cloned().collect::<HashSet<String>>(),
        expected,
        "the walk must enumerate every theme member exactly once"
    );

    cleanup(&pool, &seeded, &[theme]).await;
}

/// S4, and the two combinations that cannot be honoured.
///
/// `workflows` rows carry no `theme_id`, so a theme-scoped recall that still
/// ran the workflows leg would return unthemed hits inside a scoped result —
/// the same silent-filter-leak class `recall_temporal` enumerates. And an
/// offset applied to the claims leg alone would re-serve the same workflows on
/// every page. Both are rejected rather than silently degraded.
#[tokio::test]
async fn include_workflows_with_a_theme_or_an_offset_is_rejected() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let token = format!("thwf{}", Uuid::new_v4().simple());
    let theme = seed_theme(&pool, &format!("ttest-recall-{token}")).await;

    let with_theme: RecallParams = serde_json::from_value(json!({
        "query": token,
        "theme_id": theme.to_string(),
        "include_workflows": true,
    }))
    .expect("params");
    let err = recall_with_pgvec(&server, &viewer, with_theme, Some(cluster_pgvec(3)))
        .await
        .expect_err("theme + include_workflows must be rejected, not silently unscoped");
    assert!(
        format!("{err:?}").contains("include_workflows"),
        "the rejection must name the incompatible option: {err:?}"
    );

    let with_offset: RecallParams = serde_json::from_value(json!({
        "query": token,
        "offset": 5,
        "include_workflows": true,
    }))
    .expect("params");
    recall_with_pgvec(&server, &viewer, with_offset, Some(cluster_pgvec(3)))
        .await
        .expect_err("offset + include_workflows must be rejected");

    cleanup(&pool, &[], &[theme]).await;
}

/// The selector fails CLOSED. A dropped scope filter widens recall to the whole
/// corpus while the caller believes the result is scoped — strictly worse than
/// a rejected call. Same rule `parse_agent_filter` already applies to
/// `agent_id`.
#[tokio::test]
async fn unresolvable_theme_selectors_are_rejected_not_ignored() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let token = format!("thbad{}", Uuid::new_v4().simple());
    let pgvec = cluster_pgvec(4);

    for bad in [
        json!({ "query": token, "theme_id": "not-a-uuid" }),
        json!({ "query": token, "theme_id": Uuid::new_v4().to_string() }),
        json!({ "query": token, "theme_label": format!("ttest-absent-{token}") }),
    ] {
        let params: RecallParams = serde_json::from_value(bad.clone()).expect("params");
        let outcome = recall_with_pgvec(&server, &viewer, params, Some(pgvec.clone())).await;
        assert!(
            outcome.is_err(),
            "{bad} must be rejected, not silently treated as unscoped; got Ok"
        );
    }
}

//! T19: smoke tests for the cross-source matching MCP tools.

#[path = "viewer_fixture.rs"]
mod fixture;

#[macro_use]
mod common;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    DecideMatchCandidateParams, FindCrossSourceMatchesParams, ListMatchCandidatesParams,
    RetireMatchCandidateParams,
};
use epigraph_mcp::{embed::McpEmbedder, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::types::Json;
use sqlx::PgPool;
use uuid::Uuid;

async fn build_server(pool: PgPool, read_only: bool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x19u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, read_only)
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t19 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Insert a claim with `is_current = false` — a retired endpoint (superseded
/// or marked-duplicate) that the `are_all_current` guard must refuse to
/// promote an edge onto.
async fn insert_retired_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t19 retired {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, false)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("retired claim");
    id
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_candidate(pool: &PgPool, a: Uuid, b: Uuid, score: f32, status: &str) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(score)
    .bind(Json(serde_json::json!({"embed_cosine": 0.99})))
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("insert candidate");
    id
}

/// Same as [`insert_candidate`] but sets `verifier_verdict` — the column the
/// promote path must branch on. `verdict` must be one of the five values
/// allowed by `match_candidates_verdict_valid` (migration 036).
async fn insert_candidate_with_verdict(
    pool: &PgPool,
    a: Uuid,
    b: Uuid,
    score: f32,
    status: &str,
    verdict: &str,
) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates
             (claim_a, claim_b, score, features, status, verifier_verdict, verifier_rationale)
         VALUES ($1, $2, $3, $4, $5, $6, 'test rationale') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(score)
    .bind(Json(serde_json::json!({"embed_cosine": 0.99})))
    .bind(status)
    .bind(verdict)
    .fetch_one(pool)
    .await
    .expect("insert candidate with verdict");
    id
}

/// Every claim→claim edge relationship between the pair, either direction.
/// Relationships of the edges between `a` and `b` that are currently IN FORCE.
///
/// The `valid_to IS NULL` filter matters since retirement switched from DELETE to
/// retraction: the row survives a retire, so an unfiltered count can no longer
/// distinguish "retired" from "never created". Creation-path tests are unaffected —
/// a freshly written edge has `valid_to` NULL.
async fn edge_relationships(pool: &PgPool, a: Uuid, b: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT relationship FROM edges
         WHERE ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))
           AND valid_to IS NULL
         ORDER BY relationship",
    )
    .bind(a)
    .bind(b)
    .fetch_all(pool)
    .await
    .expect("edge relationships")
}

fn result_text(out: rmcp::model::CallToolResult) -> String {
    let first = out.content.first().cloned().expect("first content");
    match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_returns_only_status_filter(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let c = insert_claim(&pool, agent).await;

    let pending_id = insert_candidate(&pool, a, b, 0.9, "pending").await;
    let _rejected = insert_candidate(&pool, a, c, 0.4, "rejected").await;

    let out = tools::matching::list_match_candidates(
        &server,
        ListMatchCandidatesParams {
            status: Some("pending".into()),
            limit: Some(10),
        },
    )
    .await
    .expect("list");
    let text = result_text(out);

    assert!(
        text.contains(&pending_id.to_string()),
        "missing pending row"
    );
    assert!(
        !text.contains("\"rejected\""),
        "rejected row leaked into pending filter: {text}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_rejects_invalid_status(pool: PgPool) {
    let server = build_server(pool, false).await;
    let err = tools::matching::list_match_candidates(
        &server,
        ListMatchCandidatesParams {
            status: Some("garbage".into()),
            limit: None,
        },
    )
    .await
    .expect_err("should reject");
    assert!(
        format!("{err:?}").contains("pending|promoted|rejected|stale"),
        "error should explain valid options: {err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_returns_candidates_and_edges(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let cand = insert_candidate(&pool, a, b, 0.92, "promoted").await;

    // Pre-existing CORROBORATES edge (simulating a prior apply).
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(Json(serde_json::json!({"score": 0.92, "source": "cross_source_matcher"})))
    .execute(&pool)
    .await
    .expect("edge insert");

    let out = tools::matching::find_cross_source_matches(
        &server,
        FindCrossSourceMatchesParams {
            claim_id: a.to_string(),
        },
    )
    .await
    .expect("find");
    let text = result_text(out);
    assert!(text.contains(&cand.to_string()));
    assert!(text.contains(&b.to_string()));
    assert!(text.contains("CORROBORATES") || text.contains("corroborates"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_writes_edge_and_updates_status(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("decide");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "promoted");

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edge_count.0, 1, "promote must write exactly one edge");

    // Second decide is idempotent at the edge layer.
    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("decide again");
    let edge_count2: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        edge_count2.0, 1,
        "duplicate promote must NOT duplicate edges"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_reject_marks_status_and_skips_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.6, "pending").await;

    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "reject".into(),
        },
    )
    .await
    .expect("decide");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");
    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges WHERE relationship = 'CORROBORATES'
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edge_count.0, 0, "reject must NOT write an edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_rejected_in_read_only_mode(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), true).await; // read_only=true
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect_err("read-only must refuse writes");
    assert!(
        format!("{err:?}").to_lowercase().contains("read-only"),
        "expected read-only refusal: {err:?}"
    );
}

/// Guard survives the refactor: `are_all_current` lives at the MCP call site,
/// NOT inside `EdgeRepository::create_symmetric_if_absent`. When one endpoint
/// is `is_current = false`, promote must refuse and write NO edge. If a future
/// edit folded the guard into the repo method (or dropped it), this catches it
/// because the repo method has no notion of current-ness — backlog bug
/// 5c7fc645 would re-open.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_blocked_when_endpoint_not_current(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await; // write-enabled
    let agent = insert_agent(&pool).await;
    let live = insert_claim(&pool, agent).await;
    let retired = insert_retired_claim(&pool, agent).await; // is_current = false
    let cand = insert_candidate(&pool, live, retired, 0.97, "pending").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect_err("promote must be refused when an endpoint is not current");
    assert!(
        format!("{err:?}").to_lowercase().contains("current"),
        "refusal must cite the current-ness guard: {err:?}"
    );

    // The guard must short-circuit BEFORE any edge write.
    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges WHERE relationship = 'CORROBORATES'
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(live)
    .bind(retired)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        edge_count.0, 0,
        "no CORROBORATES edge may be written onto a retired claim"
    );
}

/// Promoting a candidate the verifier judged CONTRADICTORY must record a
/// `contradicts` edge, not a corroboration.
///
/// The promote arm used to write `"CORROBORATES"` unconditionally, treating
/// `verifier_verdict` as an opaque props key. Approving a contradiction then
/// asserted the exact inverse of what the verifier found, and the directional
/// factor graph read it as `evidential_support` 0.85 instead of
/// `mutual_exclusion` 0.0 — belief propagated the wrong way.
///
/// The relationship literal is asserted as lowercase `contradicts` on purpose:
/// `epigraph_engine::matching::policy`'s `WriteContradicts` arm writes exactly
/// that string, and `EdgeRepository::create_symmetric_if_absent` dedups on an
/// exact `relationship =` match. A different casing here would double-write
/// every pair the auto path had already handled.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_contradicts_writes_contradicts_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate_with_verdict(&pool, a, b, 0.88, "pending", "contradicts").await;

    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("promoting a contradicts candidate must succeed");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "promoted");

    let rels = edge_relationships(&pool, a, b).await;
    assert_eq!(
        rels.len(),
        1,
        "promote must write exactly one edge, got {rels:?}"
    );
    assert_eq!(
        rels[0], "contradicts",
        "a 'contradicts' verdict must record a contradiction, not a corroboration"
    );
}

/// `distinct` means the verifier found the pair unrelated: there is no edge
/// worth writing in either polarity. Promoting must be refused outright rather
/// than fabricating a relationship, and must leave the row decidable
/// (`pending`) so the operator can still reject it.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_distinct_is_refused_and_writes_no_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate_with_verdict(&pool, a, b, 0.31, "pending", "distinct").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect_err("promoting a 'distinct' candidate must be refused");
    assert!(
        format!("{err:?}").contains("distinct"),
        "refusal must name the verdict that blocked it: {err:?}"
    );

    let rels = edge_relationships(&pool, a, b).await;
    assert!(rels.is_empty(), "refused promote wrote edges: {rels:?}");

    // The refusal must short-circuit BEFORE set_status, or the row is left
    // `promoted` with no edge — the half-state the policy layer already fixed.
    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "pending",
        "a refused promote must not mark the row decided"
    );
}

/// Corroborating verdicts keep the historical relationship. Pins the
/// unchanged half of the branch so a future edit can't collapse both arms.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_paraphrase_still_writes_corroborates(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate_with_verdict(&pool, a, b, 0.91, "pending", "paraphrase").await;

    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("promote");

    let rels = edge_relationships(&pool, a, b).await;
    assert_eq!(rels, vec!["CORROBORATES".to_string()]);
}

/// The reported gap: no MCP surface could retract a promotion, so an agent
/// that promoted a bad pair had to escalate to a human running the
/// `retire_match_candidates` binary on the host. `retire` closes that, and it
/// must take the derived `factors` row with the edge — an orphan factor keeps
/// corroborating in the belief graph with no edge to explain it.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_retire_retracts_edge_and_deletes_derived_factor(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    tools::matching::decide_match_candidate(
        &server,
        &fixture::public_viewer(&pool).await,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("promote");

    let factors_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factors f
         JOIN edges e ON e.id::text = f.properties->>'source_edge_id'
         WHERE e.properties->>'source' = 'cross_source_matcher'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        factors_before, 1,
        "the edges_auto_factor trigger must have derived a factor — without \
         one this test cannot prove the factor is cleaned up"
    );

    let out = tools::matching::retire_match_candidate(
        &server,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
    )
    .await
    .expect("retire");
    let body: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json body");
    assert_eq!(body["candidate"]["status"], "stale");
    assert_eq!(body["retirement"]["previous_status"], "promoted");
    assert_eq!(body["retirement"]["edges_retracted"], 1);
    assert_eq!(body["retirement"]["factors_deleted"], 1);

    assert!(
        edge_relationships(&pool, a, b).await.is_empty(),
        "retire must take the matcher edge OUT OF FORCE"
    );
    // ...but the row itself must survive, carrying the promotion's provenance.
    // Under the previous DELETE this could not hold: `properties.decided_by`
    // vanished with the row, and `match_candidates.decided_by` is overwritten
    // with the retirer, so nothing persisted recorded the original promoter.
    let (present, closed): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE valid_to IS NOT NULL)
         FROM edges
         WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(present, 1, "the edge row must survive retraction");
    assert_eq!(closed, 1, "the surviving row must carry valid_to");
    let factors_after: i64 = sqlx::query_scalar("SELECT count(*) FROM factors")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        factors_after, 0,
        "retire must delete the factor derived from the edge, not just the edge"
    );
}

/// `retire` is a write, so it must sit behind the same read-only gate as
/// `promote`/`reject` — a read-only server must not be able to retract edges.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_retire_rejected_in_read_only_mode(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    // Promote with a writable server, then attempt the retire read-only.
    let writable = build_server(pool.clone(), false).await;
    tools::matching::decide_match_candidate(
        &writable,
        &fixture::public_viewer(&pool).await,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("promote");

    let read_only = build_server(pool.clone(), true).await;
    tools::matching::retire_match_candidate(
        &read_only,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
    )
    .await
    .expect_err("retire must be refused in read-only mode");

    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "a refused retire must leave the edge in place"
    );
}

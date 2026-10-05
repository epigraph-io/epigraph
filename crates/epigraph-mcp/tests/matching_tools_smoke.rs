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

/// A server with NO maintenance pool, the only shape a request-serving MCP
/// server has under operator decision D9 (batch W12a): the retirement's
/// administrative cascade (migrations 117/118) is recorded as a deferred
/// request, and [`replay`] -- the replay timer's function, on a maintenance
/// connection -- carries it out.
async fn build_server(pool: PgPool, read_only: bool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    build_server_with(pool, read_only, scoped)
}

/// Run the deferred-cascade replay once, as `epigraph-cascade-replay.timer`
/// does: `replay_deferred` on a connection that runs as
/// `epigraph_maintenance` (not a superuser).
async fn replay(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(pool)
        .await
        .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the replay's connection is privileged");
    let (conn, viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        viewer,
        "w12a-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

fn build_server_with(
    pool: PgPool,
    read_only: bool,
    scoped: epigraph_db::ScopedPool,
) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x19u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, read_only).with_scoped_pool(scoped)
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
        &fixture::public_viewer(&pool).await,
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
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_server(pool, false).await;
    let err = tools::matching::list_match_candidates(
        &server,
        &viewer,
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
        &fixture::public_viewer(&pool).await,
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
        None,
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

    // A second promote is now REFUSED rather than silently replayed —
    // transport parity with the HTTP route's `reject_if_decided` (backlog
    // b3f95bea). The invariant this half of the test protects is unchanged
    // (one decided pair, one edge); only the mechanism moved, from
    // "`create_symmetric_if_absent` deduped the second write" to "the
    // already-decided gate refused it before any write".
    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
        None,
    )
    .await
    .expect_err("a second promote must be refused as already decided");
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
        "a refused duplicate promote must leave exactly one edge"
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        &fixture::public_viewer(&pool).await,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
        None,
    )
    .await
    .expect("retire");
    let body: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json body");
    // D9: the request-serving server defers the whole retirement...
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    assert_eq!(body["candidate"]["status"], "promoted", "{body}");
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "nothing is retracted before the replay"
    );
    // ...and the replay, on the maintenance connection, carries it out.
    let report = replay(&pool).await;
    assert_eq!(
        (report.pending, report.applied, report.failed),
        (1, 1, 0),
        "{report:?}"
    );
    let (applied_counts, replay_of): (serde_json::Value, Option<String>) = sqlx::query_as(
        "SELECT details->'touched', details#>>'{replay_of,deferred_event_id}' \
           FROM security_events \
          WHERE event_type = 'cascade.admin_applied' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(cand)
    .fetch_one(&pool)
    .await
    .expect("the replay's applied row");
    assert_eq!(
        replay_of.as_deref(),
        body["cascade"]["audit_event_id"].as_str(),
        "the applied row names the deferral it replays"
    );
    assert_eq!(applied_counts["edges_retracted_now"], 1, "{applied_counts}");
    assert_eq!(applied_counts["factors_deleted"], 1, "{applied_counts}");
    assert_eq!(
        applied_counts["previous_status"], "promoted",
        "{applied_counts}"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "stale");

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
        None,
    )
    .await
    .expect("promote");

    let read_only = build_server(pool.clone(), true).await;
    tools::matching::retire_match_candidate(
        &read_only,
        &fixture::public_viewer(&pool).await,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
        None,
    )
    .await
    .expect_err("retire must be refused in read-only mode");

    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "a refused retire must leave the edge in place"
    );
}

/// Transport-parity gate (backlog b3f95bea): `reject` on an ALREADY-PROMOTED
/// row must be refused, not applied.
///
/// Without the gate `reject` just called `set_status(..., "rejected", ...)`.
/// That leaves the promotion's `CORROBORATES` edge live while the row that
/// owns it reads `rejected` — an edge whose only link back to a candidate is
/// the informal, unenforced `properties->>'candidate_id'`, and whose derived
/// `factors` row keeps corroborating in the belief graph. Nothing downstream
/// can then distinguish it from an edge nobody ever decided.
///
/// The HTTP route has refused this since a3927179 (`reject_if_decided`, 409
/// Conflict, pinned by
/// `cross_source_route_tests::promote_and_reject_still_refuse_an_already_decided_candidate`);
/// this pins the MCP transport to the same contract. Asserted on the DURABLE
/// state (row status + in-force edge), not just the error string, so the test
/// fails if the gate is bypassed by any future refactor of either.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_reject_refuses_an_already_promoted_row(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
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
        None,
    )
    .await
    .expect("promote");
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "precondition: the promotion wrote the matcher edge"
    );

    let err = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "reject".into(),
        },
        None,
    )
    .await
    .expect_err("reject on a promoted row must be refused");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("already decided") && msg.contains("retire_match_candidate"),
        "the refusal must name the state AND point at the real undo: {msg}"
    );

    // The refusal must be total: status untouched, edge still in force.
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "promoted",
        "a refused reject must NOT flip the row out of `promoted` — that is \
         exactly the state that orphans the edge"
    );
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "the matcher edge must still be in force"
    );
}

/// The other half of the same gate: `promote` on a RETIRED (`stale`) row must
/// be refused.
///
/// `retire_match_candidate` retracts the matcher edge (`valid_to` closed) and
/// deletes the `factors` the `edges_auto_factor` trigger derived from it. An
/// ungated re-`promote` calls `create_symmetric_if_absent`, whose existence
/// check does NOT filter on `valid_to` — so the retracted row does not dedup
/// and a SECOND, live edge is inserted, re-asserting in the belief graph the
/// exact link an admin-scoped retirement just retracted. Asserting on the
/// in-force edge count is what makes this load-bearing: an error-string-only
/// test would pass against a gate that ran after the write.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_refuses_a_retired_row(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
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
        None,
    )
    .await
    .expect("promote");
    tools::matching::retire_match_candidate(
        &server,
        &fixture::public_viewer(&pool).await,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
        None,
    )
    .await
    .expect("retire");
    // D9: the retirement is deferred on the request server and carried out by
    // the replay on the maintenance connection.
    let report = replay(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert!(
        edge_relationships(&pool, a, b).await.is_empty(),
        "precondition: retirement took the edge out of force"
    );

    tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
        None,
    )
    .await
    .expect_err("promote on a retired row must be refused");

    assert!(
        edge_relationships(&pool, a, b).await.is_empty(),
        "a refused promote must NOT resurrect the retracted matcher edge"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "stale", "the retirement must stand");
}

/// `retire` is not a `decide_match_candidate` verdict — it is a separate tool
/// carrying `claims:admin` instead of `claims:write`. The rejection message
/// used to list `'retire'` among the valid verdicts while refusing it, which
/// sent callers in a circle. It must now name the tool that actually does it.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_unknown_verdict_points_at_the_retire_tool(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "retire".into(),
        },
        None,
    )
    .await
    .expect_err("`retire` is not a decide verdict");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("retire_match_candidate"),
        "must name the tool that performs a retirement: {msg}"
    );
    assert!(
        !msg.contains("'retire'"),
        "must no longer advertise 'retire' as a valid verdict: {msg}"
    );
}

// ── Sweep coverage (backlog 4194b4a7 ask 3 / 9a513d47) ──────────────────────
//
// `find_cross_source_matches` returned `{claim_id, candidates, corroborates}`
// and nothing else, so `candidates: []` was ambiguous between "the matcher
// scanned this claim and found nothing" and "the matcher has never looked at
// it". Only the second is actionable. The per-claim marker already existed
// (`claims.last_match_scan_at`, migration 037, stamped by the
// `cross_source_sweep` CLI); the read never surfaced it.

/// Never-scanned claim: `never_swept: true`, `last_swept_at: null`.
///
/// This is the state the backlog was filed from — empty candidates on a
/// freshly-ingested claim — and the whole point is that the response now says
/// which of the two states it is in.
#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_reports_never_swept_for_an_unscanned_claim(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;

    let out = tools::matching::find_cross_source_matches(
        &server,
        &fixture::public_viewer(&pool).await,
        FindCrossSourceMatchesParams {
            claim_id: a.to_string(),
        },
    )
    .await
    .expect("find");
    let json: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json");

    assert_eq!(
        json["candidates"],
        serde_json::json!([]),
        "precondition: no candidates, which is exactly the ambiguous case"
    );
    assert_eq!(
        json["never_swept"],
        serde_json::json!(true),
        "a claim with last_match_scan_at IS NULL has never been swept; without \
         this field the empty candidate list above is uninterpretable: {json}"
    );
    assert_eq!(
        json["last_swept_at"],
        serde_json::Value::Null,
        "never swept means no timestamp: {json}"
    );
}

/// Scanned claim with no matches: `never_swept: false` plus the stamp. Same
/// empty `candidates` as the test above — the two responses must differ.
#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_reports_last_swept_at_for_a_scanned_claim(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;

    // What `cross_source_sweep.rs` does to every seed it scans.
    sqlx::query(
        "UPDATE claims SET last_match_scan_at = TIMESTAMPTZ '2026-09-01 12:00:00+00' \
         WHERE id = $1",
    )
    .bind(a)
    .execute(&pool)
    .await
    .expect("stamp");

    let out = tools::matching::find_cross_source_matches(
        &server,
        &fixture::public_viewer(&pool).await,
        FindCrossSourceMatchesParams {
            claim_id: a.to_string(),
        },
    )
    .await
    .expect("find");
    let json: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json");

    assert_eq!(
        json["candidates"],
        serde_json::json!([]),
        "precondition: the matcher ran and found nothing"
    );
    assert_eq!(
        json["never_swept"],
        serde_json::json!(false),
        "this claim WAS swept — reporting it as unswept would send an agent to \
         re-run a sweep that already covered it: {json}"
    );
    assert!(
        json["last_swept_at"]
            .as_str()
            .is_some_and(|s| s.starts_with("2026-09-01")),
        "must report the stamp the sweep wrote, got {json}"
    );
}

/// A claim the viewer cannot read yields NEITHER coverage field.
///
/// The fail-open this pins: treating "no visible row" as "never swept". That
/// arm is reachable for every private claim id a stranger can guess, and it
/// would (a) assert something false — a group claim may well have been swept,
/// the sweep runs corpus-wide on a maintenance pool — and (b) be an existence
/// signal about a row the caller has no right to. The pre-existing contract for
/// an unreadable claim is empty arrays and no error; the coverage fields must
/// not break it.
#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_omits_sweep_coverage_for_an_invisible_claim(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let (owner, group) = fixture::seed_agent_with_group(&pool, "xsm-coverage").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "private xsm claim").await;

    // Swept, so a leaking implementation has a real timestamp to hand back.
    sqlx::query("UPDATE claims SET last_match_scan_at = now() WHERE id = $1")
        .bind(private)
        .execute(&pool)
        .await
        .expect("stamp");

    let out = tools::matching::find_cross_source_matches(
        &server,
        // Public-only viewer: not a member of `group`.
        &fixture::public_viewer(&pool).await,
        FindCrossSourceMatchesParams {
            claim_id: private.to_string(),
        },
    )
    .await
    .expect("an unreadable claim is empty, not an error");
    let json: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json");

    assert!(
        json.get("never_swept").is_none(),
        "must not answer a sweep-coverage question about a claim this viewer \
         cannot read: {json}"
    );
    assert!(
        json.get("last_swept_at").is_none(),
        "must not leak the sweep stamp of an invisible claim: {json}"
    );
    assert_eq!(
        json["candidates"],
        serde_json::json!([]),
        "the pre-existing non-leaking shape is preserved: {json}"
    );
}

/// Migrations 117 and 118: with NO administrative connection nothing about the
/// candidate changes -- it stays `promoted`, the matcher edge stays in force --
/// and the whole retirement is recorded as a deferred request under the acting
/// agent, carrying the status it was requested against.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_without_an_admin_connection_defers_the_whole_retirement(pool: PgPool) {
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
        None,
    )
    .await
    .expect("promote");

    let out = tools::matching::retire_match_candidate(
        &server,
        &fixture::public_viewer(&pool).await,
        RetireMatchCandidateParams {
            candidate_id: cand.to_string(),
        },
        None,
    )
    .await
    .expect("the request is recorded");
    let body: serde_json::Value = serde_json::from_str(&result_text(out)).expect("json body");
    assert_eq!(body["candidate"]["status"], "promoted", "{body}");
    assert_eq!(body["retired"], false, "{body}");
    assert!(body["retirement"].is_null(), "{body}");
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let event = body["cascade"]["audit_event_id"]
        .as_str()
        .expect("a deferral carries its audit row id")
        .to_string();
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "the deferred cascade retracted nothing"
    );
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (et, who, cause, requested): (String, Option<Uuid>, String, Option<String>) =
        sqlx::query_as(
            "SELECT event_type::text, agent_id, details->>'cause', \
                    details#>>'{trigger,candidate_status}' \
               FROM security_events WHERE id = $1::uuid",
        )
        .bind(&event)
        .fetch_one(&pool)
        .await
        .expect("the deferral row");
    assert_eq!(
        (et.as_str(), who, cause.as_str(), requested.as_deref()),
        (
            "cascade.deferred",
            Some(server_agent),
            "match_retire",
            Some("promoted")
        )
    );
}

// ---------------------------------------------------------------------------
// Concurrent decides (backlog b3f95bea's end state, reached by a race).
//
// The already-decided gate above is check-then-act: it reads the row, gates on
// the in-memory status, then writes. These tests interleave a second writer
// BETWEEN the read and the write with real Postgres row locks -- no sleeps, no
// mocks -- and pin what the write must do when it finally runs.
// ---------------------------------------------------------------------------

/// Wait until another backend of this test database is blocked on a lock while
/// running a statement matching `pattern` (an ILIKE pattern). This is what makes
/// the race tests deterministic: it proves the decide under test read its row
/// BEFORE the competing transaction commits.
async fn wait_until_blocked(watcher: &mut sqlx::PgConnection, pattern: &str, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database()
               AND pid <> pg_backend_pid()
               AND wait_event_type = 'Lock'
               AND query ILIKE $1",
        )
        .bind(pattern)
        .fetch_one(&mut *watcher)
        .await
        .expect("pg_stat_activity");
        if waiting >= 1 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "calibration: {what} never blocked on a lock (pattern {pattern})"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Interleaving A: a promote and a reject on the same pending row. The reject
/// reads `pending` and passes the gate; a concurrent promote commits `promoted`
/// and its matcher edge; then the reject's write runs.
///
/// An unconditional `UPDATE ... WHERE id = $1` waits for the promote's row lock
/// and then overwrites it to `rejected`, leaving a live matcher edge under a
/// rejected candidate -- the orphan of b3f95bea. The write must instead be
/// conditional on the row still being `pending` and refuse the loser.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reject_racing_a_committed_promote_does_not_overwrite_it(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;
    let mut watcher = pool.acquire().await.expect("watcher connection");

    // A promote that has already passed its gate, mid-flight: status flipped
    // and the edge written (same shape `create_symmetric_if_absent` writes),
    // NOT committed. It holds the candidate's row lock; the committed version
    // is still `pending`.
    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "UPDATE match_candidates SET status = 'promoted', decided_at = now() WHERE id = $1",
    )
    .bind(cand)
    .execute(&mut *other)
    .await
    .expect("competing promote: status");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(Json(serde_json::json!({
        "source": "cross_source_matcher",
        "candidate_id": cand,
    })))
    .execute(&mut *other)
    .await
    .expect("competing promote: edge");

    let reject = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "reject".into(),
        },
        None,
    );
    let commit_once_blocked = async {
        wait_until_blocked(&mut watcher, "%UPDATE match_candidates%", "the reject").await;
        other.commit().await.expect("commit the competing promote");
    };
    let (result, ()) = tokio::join!(reject, commit_once_blocked);

    let err = result.expect_err(
        "a reject that lost the race to a committed promote must be refused, not overwrite it",
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("already decided"),
        "the race loser gets the same refusal as a sequential replay: {msg}"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "promoted",
        "the committed promotion stands; `rejected` here is the orphan state"
    );
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "the promotion's matcher edge is still in force"
    );
}

/// Interleaving B: a promote must not publish `promoted` before its matcher
/// edge exists.
///
/// When the status flip and the edge INSERT are two autocommit statements, a
/// promote whose INSERT is still in flight has already committed `promoted`
/// with no edge -- and holds no lock on the candidate, so a retirement
/// (`mark_retired_on`'s `SELECT ... FOR UPDATE`) runs straight through, finds
/// no edge to retract, and the edge lands afterwards under a `stale` row.
///
/// The promote's edge INSERT is held mid-flight deterministically: a competing
/// transaction holds an uncommitted copy of the same matcher edge, so the
/// INSERT waits on migration 090's `edges_symmetric_relationship_uniq`. While
/// it waits, another connection must see the candidate still `pending` and
/// still row-locked. Rolling the competitor back lets the promote finish.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promote_does_not_publish_promoted_before_its_edge_commits(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;
    let mut watcher = pool.acquire().await.expect("watcher connection");
    let mut observer = pool.acquire().await.expect("observer connection");

    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(Json(serde_json::json!({"source": "cross_source_matcher"})))
    .execute(&mut *other)
    .await
    .expect("competing uncommitted matcher edge");

    let promote = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
        None,
    );
    let observe_then_release = async {
        wait_until_blocked(
            &mut watcher,
            "%INSERT INTO edges%",
            "the promote's edge write",
        )
        .await;
        let status_mid: String =
            sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
                .bind(cand)
                .fetch_one(&mut *observer)
                .await
                .expect("status mid-promote");
        let lock_mid =
            sqlx::query("SELECT 1 FROM match_candidates WHERE id = $1 FOR UPDATE NOWAIT")
                .bind(cand)
                .execute(&mut *observer)
                .await;
        other.rollback().await.expect("release the competing edge");
        (status_mid, lock_mid.map(|_| ()))
    };
    let (result, (status_mid, lock_mid)) = tokio::join!(promote, observe_then_release);

    assert_eq!(
        status_mid, "pending",
        "while its edge INSERT is in flight the promote must not have published `promoted`: \
         a committed `promoted` with no edge is the window a retirement slips through"
    );
    let lock_err = lock_mid.expect_err(
        "the in-flight promote must hold the candidate's row lock until its edge commits, so a \
         retirement's SELECT ... FOR UPDATE waits for it",
    );
    let code = lock_err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("55P03"),
        "lock_not_available: {lock_err}"
    );

    result.expect("the promote completes once the competing edge is rolled back");
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "promoted");
    assert_eq!(
        edge_relationships(&pool, a, b).await,
        vec!["CORROBORATES".to_string()],
        "exactly one matcher edge, written by the promote itself"
    );
}

/// Interleaving A, roles swapped: a promote that read the row as `pending`
/// loses the race to a reject that commits first.
///
/// The conditional write leaves the database safe on its own (no edge is
/// written for a row that is no longer `pending`), so what this pins is the
/// tool's answer: the loser must be told it lost, with the same refusal as a
/// sequential replay. An unconditional write instead overwrites the operator's
/// reject to `promoted` and writes a matcher edge over a pair just rejected; a
/// dropped outcome check reports success for a promotion that never happened.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promote_racing_a_committed_reject_is_refused(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;
    let mut watcher = pool.acquire().await.expect("watcher connection");

    // An operator's reject that has passed its gate and written, NOT committed.
    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "UPDATE match_candidates SET status = 'rejected', decided_at = now() WHERE id = $1",
    )
    .bind(cand)
    .execute(&mut *other)
    .await
    .expect("competing reject");

    let promote = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
        None,
    );
    let commit_once_blocked = async {
        wait_until_blocked(&mut watcher, "%UPDATE match_candidates%", "the promote").await;
        other.commit().await.expect("commit the competing reject");
    };
    let (result, ()) = tokio::join!(promote, commit_once_blocked);

    let err = result.expect_err(
        "a promote that lost the race to a committed reject must be refused, not reported done",
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("already decided (status=rejected)"),
        "the race loser gets the same refusal as a sequential replay: {msg}"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected", "the operator's reject stands");
    assert!(
        edge_relationships(&pool, a, b).await.is_empty(),
        "no matcher edge may be written over a rejected pair"
    );
}

/// Interleaving B end to end: a retirement that arrives while a promote is in
/// flight must still retract the promote's edge.
///
/// The promote is held at its edge INSERT (a competing transaction holds an
/// uncommitted copy of the same matcher edge, so the INSERT waits on migration
/// 090's `edges_symmetric_relationship_uniq`); the retirement is started
/// against that state, and only then is the competitor rolled back.
///
/// When the status flip and the edge INSERT are two autocommit statements, the
/// retirement finds `promoted` with no edge yet, flips it to `stale` having
/// retracted nothing, and the promote's edge then lands in force under a
/// `stale` row. With one transaction the retirement's `SELECT ... FOR UPDATE`
/// waits for the promote, then retracts the edge it wrote.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retirement_during_an_in_flight_promote_retracts_its_edge(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;
    let mut watcher = pool.acquire().await.expect("watcher connection");

    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(Json(serde_json::json!({"source": "cross_source_matcher"})))
    .execute(&mut *other)
    .await
    .expect("competing uncommitted matcher edge");

    let promote = tools::matching::decide_match_candidate(
        &server,
        &viewer,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
        None,
    );
    let retire_mid_promote = async {
        wait_until_blocked(
            &mut watcher,
            "%INSERT INTO edges%",
            "the promote's edge write",
        )
        .await;
        // The retirement as the replay runs it: the repo's own transaction on a
        // privileged session (the test pool is a superuser).
        let retirement = tokio::spawn({
            let pool = pool.clone();
            async move {
                epigraph_db::MatchCandidateRepo::new(pool)
                    .retire(cand, None)
                    .await
            }
        });
        // It either waits on the promote's row lock or, with no lock to wait
        // on, runs to completion; either way it has acted before the promote's
        // edge is released.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database()
                   AND pid <> pg_backend_pid()
                   AND wait_event_type = 'Lock'
                   AND query ILIKE '%FROM match_candidates%FOR UPDATE%'",
            )
            .fetch_one(&mut *watcher)
            .await
            .expect("pg_stat_activity");
            if waiting >= 1 || retirement.is_finished() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "calibration: the retirement neither blocked nor finished"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        other.rollback().await.expect("release the competing edge");
        retirement.await.expect("retirement task")
    };
    let (promoted, retired) = tokio::join!(promote, retire_mid_promote);

    promoted.expect("the promote completes once the competing edge is rolled back");
    let retired = retired.expect("the retirement completes");
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "stale", "the retirement is the last decision");
    assert!(
        edge_relationships(&pool, a, b).await.is_empty(),
        "a `stale` candidate must leave no matcher edge in force; one here is the edge the \
         in-flight promote wrote after the retirement had already run"
    );
    assert_eq!(
        (retired.previous_status.as_str(), retired.edges_retracted),
        ("promoted", 1),
        "the retirement waited for the promote and retracted the edge it wrote"
    );
}

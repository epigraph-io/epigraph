//! The rationale a verifier produces must survive into
//! `match_candidates.verifier_rationale` byte-for-byte.
//!
//! Every other test of the rationale strings asserts on an in-memory
//! `Verdict`. That leaves the link that actually matters untested: PR #381's
//! adversarial review flagged that nothing proved the string reaches the
//! column, and the column is what analysts and agents read as evidence. This
//! drives the real mapping (`verdicts_for_pairs`) into the real persistence
//! layer (`matching::policy::Policy`) and reads the row back.
//!
//! Skips when `DATABASE_URL` is unset, matching the pattern in
//! `epigraph-engine/tests/blocker_*.rs`. Point it at a scratch database
//! (`epigraph_db_repo_test`) — it inserts an agent, two claims and a
//! match-candidate row, and deletes them again.

#![cfg(feature = "genai")]

use epigraph_cli::matching_client::{verdicts_for_pairs, RATIONALE_REJECTED_PREFIX};
use epigraph_cli::rerank::PerPairVerdict;
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use epigraph_engine::matching::policy::{Policy, PolicyAction};
use epigraph_engine::matching::scorer::MatchFeatures;
use sqlx::PgPool;
use uuid::Uuid;

async fn pool_or_skip() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    match PgPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("Skipping DB test: cannot connect: {e}");
            None
        }
    }
}

fn features() -> MatchFeatures {
    MatchFeatures {
        embed_cosine: 0.7,
        triple_overlap: 0.0,
        entity_jaccard: 0.0,
        method_match: false,
        nbhd_overlap: 0.0,
        citation_overlap: 0.0,
        graph_overlap: 0.0,
        belief_alignment: 0.5,
        theme_proximity: 0.5,
        temporal_dist_days: 0,
        score: 0.7,
    }
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("rationale-persistence {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

#[tokio::test]
async fn explicit_rejection_rationale_reaches_the_match_candidates_column() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("Skipping DB test: DATABASE_URL not set");
        return;
    };

    let agent = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .expect("agent");

    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    // The model answered and rejected the pair. This is the one rationale the
    // verifier writes that is a statement about the pair, so it is the one
    // whose exact text has to survive the round trip.
    let per_pair = vec![PerPairVerdict {
        source_id: a,
        target_id: b,
        valid: false,
        relationship: None,
        strength: None,
        rationale: "shared vocabulary only".to_string(),
    }];
    let verdicts = verdicts_for_pairs(&[(a, b)], &per_pair);
    let expected = format!("{RATIONALE_REJECTED_PREFIX}shared vocabulary only");
    assert_eq!(verdicts[0].rationale, expected);

    let policy = Policy::new(
        pool.clone(),
        MatchCandidateRepo::new(pool.clone()),
        Uuid::new_v4(),
        false,
    );
    policy
        .act(
            PolicyAction::Reject,
            a,
            b,
            &features(),
            Some(verdicts[0].clone()),
        )
        .await
        .expect("policy act");

    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let (verdict, rationale): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT verifier_verdict, verifier_rationale FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate row");

    assert_eq!(
        rationale.as_deref(),
        Some(expected.as_str()),
        "the prefixed rationale must land in the column verbatim"
    );
    // Unchanged by this PR: an explicit rejection is still `distinct`.
    assert_eq!(verdict.as_deref(), Some("distinct"));

    // Cleanup: match_candidates cascades from claims.
    sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
        .bind(vec![a, b])
        .execute(&pool)
        .await
        .expect("cleanup claims");
    sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("cleanup agent");
}

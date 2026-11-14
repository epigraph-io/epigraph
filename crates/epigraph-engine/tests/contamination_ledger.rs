//! ba25c292: the contamination ledger lists exactly the `match_candidates`
//! rows that already carry a decision, so a precision sweep can exclude them
//! from its headline figure.
//!
//! Requires a live PostgreSQL database reachable via `DATABASE_URL`.

use epigraph_engine::matching::contamination::{contamination_ledger, partition_by_ledger};
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

async fn insert_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// Insert a candidate row for the canonical pair; returns that pair.
async fn insert_candidate(
    pool: &PgPool,
    a: Uuid,
    b: Uuid,
    status: &str,
    verdict: Option<&str>,
    decided: bool,
) -> (Uuid, Uuid) {
    let (lo, hi) = (a.min(b), a.max(b));
    sqlx::query(
        "INSERT INTO match_candidates
             (claim_a, claim_b, score, features, verifier_verdict, status, decided_at)
         VALUES ($1, $2, 0.9, '{}'::jsonb, $3, $4,
                 CASE WHEN $5 THEN now() ELSE NULL END)",
    )
    .bind(lo)
    .bind(hi)
    .bind(verdict)
    .bind(status)
    .bind(decided)
    .execute(pool)
    .await
    .expect("insert match_candidate");
    (lo, hi)
}

#[sqlx::test(migrations = "../../migrations")]
async fn ledger_flags_every_already_decided_candidate_and_nothing_else(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let mut c = Vec::new();
    for _ in 0..8 {
        c.push(insert_claim(&pool, agent).await);
    }
    // Untouched: pending, no verdict, no decision. Must stay CLEAN.
    let untouched = insert_candidate(&pool, c[0], c[1], "pending", None, false).await;
    // Verifier already answered, still pending human review.
    let verdict_only =
        insert_candidate(&pool, c[2], c[3], "pending", Some("paraphrase"), false).await;
    // A human already decided it.
    let human = insert_candidate(&pool, c[4], c[5], "promoted", Some("same"), true).await;
    // Legacy terminal row with neither verdict nor decided_at.
    let legacy = insert_candidate(&pool, c[6], c[7], "rejected", None, false).await;

    let ledger = contamination_ledger(&pool).await.expect("ledger");
    let mut flagged: Vec<((Uuid, Uuid), String)> = ledger
        .iter()
        .map(|e| ((e.claim_a, e.claim_b), e.reason.clone()))
        .collect();
    flagged.sort();
    let mut expected = vec![
        (verdict_only, "verifier_verdict".to_string()),
        (human, "human_decision".to_string()),
        (legacy, "status:rejected".to_string()),
    ];
    expected.sort();
    assert_eq!(
        flagged, expected,
        "ledger must list exactly the decided rows"
    );

    // A sweep's pairs, one of them REVERSED relative to the table's canonical
    // order: the decided ones are split out, the untouched one stays clean.
    let sweep = vec![untouched, (human.1, human.0), verdict_only];
    let (clean, dirty) = partition_by_ledger(&sweep, &ledger);
    assert_eq!(clean, vec![untouched]);
    assert_eq!(dirty, vec![(human.1, human.0), verdict_only]);
}

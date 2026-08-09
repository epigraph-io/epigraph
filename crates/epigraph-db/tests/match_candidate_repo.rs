use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test");
                return;
            }
        }
    };
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

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
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

#[sqlx::test(migrations = "../../migrations")]
async fn upsert_inserts_then_updates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id1 = repo
        .upsert(
            lo,
            hi,
            0.7,
            serde_json::json!({}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("first upsert")
        .id;
    let id2 = repo
        .upsert(
            lo,
            hi,
            0.9,
            serde_json::json!({"x": 1}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("second upsert")
        .id;
    assert_eq!(id1, id2, "upsert must reuse the row");

    let row = repo.get(id1).await.expect("get");
    assert!((row.score - 0.9).abs() < 1e-6);
    assert_eq!(row.features.get("x").and_then(|v| v.as_i64()), Some(1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_status_promotes_and_records_decided_fields(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id = repo
        .upsert(
            lo,
            hi,
            0.9,
            serde_json::json!({}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("upsert")
        .id;
    repo.set_status(id, "promoted", Some(agent))
        .await
        .expect("set_status");

    let row = repo.get(id).await.expect("get");
    assert_eq!(row.status, "promoted");
    assert_eq!(row.decided_by, Some(agent));
    assert!(row.decided_at.is_some());
}

/// A nightly matcher re-scan must NOT revert an operator's ruling.
///
/// The matcher re-touches 50-99.7% of pairs per run and always upserts with
/// `status = "pending"`. Before the `decided_at` guard, the unconditional
/// `status = EXCLUDED.status` in `ON CONFLICT DO UPDATE` silently un-decided
/// human rulings — observed on prod as 7 rows with `decided_at IS NOT NULL`
/// but `status = 'pending'`, clobbered 2, 9 and 17 days after the decision.
///
/// The contract has three parts and all are asserted: the *decision*
/// (status / decided_at / decided_by) freezes, the *verdict* the decision was
/// based on (verifier_verdict / verifier_rationale) freezes with it, while
/// matcher *telemetry* (score / features / matcher_run_id) still refreshes.
///
/// The verdict half was originally unguarded — it was written by a separate
/// `UPDATE` in the engine's policy layer, outside this statement — so a
/// re-scan preserved the ruling but destroyed the verdict behind it. That is
/// how 6 prod `CORROBORATES` edges whose candidate row said `contradicts`
/// escaped a polarity audit keyed on the column.
#[sqlx::test(migrations = "../../migrations")]
async fn upsert_does_not_revert_a_decided_candidate(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    // Night 1: matcher stages the pair for human review.
    let run1 = Uuid::new_v4();
    let id = repo
        .upsert(
            lo,
            hi,
            0.70,
            serde_json::json!({"n": 1}),
            "pending",
            Some(run1),
            Some("contradicts"),
            Some("night 1: the claims negate each other"),
        )
        .await
        .expect("first upsert")
        .id;

    // Operator rules on it via the Telegram / MCP review queue.
    repo.set_status(id, "promoted", Some(agent))
        .await
        .expect("set_status");
    let decided = repo.get(id).await.expect("get after decision");
    let decided_at = decided
        .decided_at
        .expect("set_status must stamp decided_at");

    // Night 2: the same pair is re-scanned and upserted as "pending" again.
    let run2 = Uuid::new_v4();
    let outcome = repo
        .upsert(
            lo,
            hi,
            0.85,
            serde_json::json!({"n": 2}),
            "pending",
            Some(run2),
            Some("distinct"),
            Some("night 2: verifier returned no verdict for this pair"),
        )
        .await
        .expect("re-scan upsert");
    assert_eq!(outcome.id, id, "upsert must reuse the row");
    assert!(
        outcome.verdict_write_suppressed(Some("distinct")),
        "the caller must be able to observe that its verdict write was refused — \
         gating the rationale removes the only trace such an overwrite used to leave"
    );

    let row = repo.get(id).await.expect("get after re-scan");

    // Half 1 — the decision is frozen.
    assert_eq!(
        row.status, "promoted",
        "a re-scan must not revert an operator decision to pending"
    );
    assert_eq!(
        row.decided_at,
        Some(decided_at),
        "decided_at must survive a re-scan unchanged"
    );
    assert_eq!(
        row.decided_by,
        Some(agent),
        "decided_by must survive a re-scan unchanged"
    );

    // Half 1b — the verdict the decision was based on freezes with it.
    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("contradicts"),
        "the verdict a human ruled on must survive a re-scan — \
         `promotion_disposition_for_column` reads this column to pick edge polarity"
    );
    assert_eq!(
        row.verifier_rationale.as_deref(),
        Some("night 1: the claims negate each other"),
        "verdict and rationale must freeze together"
    );

    // Half 2 — matcher telemetry still refreshes.
    assert!(
        (row.score - 0.85).abs() < 1e-6,
        "score is matcher telemetry and must refresh on a decided row; got {}",
        row.score
    );
    assert_eq!(
        row.features.get("n").and_then(|v| v.as_i64()),
        Some(2),
        "features are matcher telemetry and must refresh on a decided row"
    );
    assert_eq!(
        row.matcher_run_id,
        Some(run2),
        "matcher_run_id must refresh so the last run that saw the pair is known"
    );
}

/// The guard keys on `decided_at`, not on `status != 'pending'`, because
/// `PolicyAction::Reject` upserts `status = 'rejected'` with `decided_at`
/// NULL. A status-based guard would freeze matcher-set rejections forever and
/// break re-scoring; this test pins that an undecided row stays mutable.
#[sqlx::test(migrations = "../../migrations")]
async fn upsert_still_overwrites_an_undecided_row(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    // Matcher rejected it on its own — no operator involved, decided_at NULL.
    let id = repo
        .upsert(
            lo,
            hi,
            0.30,
            serde_json::json!({}),
            "rejected",
            None,
            None,
            None,
        )
        .await
        .expect("first upsert")
        .id;
    assert!(
        repo.get(id).await.expect("get").decided_at.is_none(),
        "a matcher-set status must not stamp decided_at"
    );

    // Re-scoring the pair upward must be able to move it back into review.
    repo.upsert(
        lo,
        hi,
        0.95,
        serde_json::json!({}),
        "pending",
        None,
        None,
        None,
    )
    .await
    .expect("re-scan upsert");

    let row = repo.get(id).await.expect("get after re-scan");
    assert_eq!(
        row.status, "pending",
        "an undecided row must remain freely overwritable by the matcher"
    );
}

/// A `None` verdict means "this pair was not verified on this pass", not
/// "erase the verdict on file".
///
/// `Policy::act` takes `Option<Verdict>` and the pre-fix code preserved an
/// existing verdict only by skipping its `UPDATE` entirely. Folding the columns
/// into one always-executing statement would bind NULL and blank the row, so
/// the `COALESCE` in the ELSE branch is load-bearing, not defensive style.
#[sqlx::test(migrations = "../../migrations")]
async fn upsert_with_no_verdict_preserves_the_stored_one(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id = repo
        .upsert(
            lo,
            hi,
            0.70,
            serde_json::json!({}),
            "pending",
            None,
            Some("same"),
            Some("identical finding"),
        )
        .await
        .expect("verdict upsert")
        .id;

    // Re-touch with no verdict — the pair never reached the verifier.
    let outcome = repo
        .upsert(
            lo,
            hi,
            0.72,
            serde_json::json!({}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("no-verdict upsert");

    let row = repo.get(id).await.expect("get");
    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("same"),
        "an unverified re-touch must not erase a stored verdict"
    );
    assert_eq!(
        row.verifier_rationale.as_deref(),
        Some("identical finding"),
        "an unverified re-touch must not erase a stored rationale"
    );
    assert!(
        !outcome.verdict_write_suppressed(None),
        "not attempting a verdict is not a suppression — counting it would \
         make the telemetry fire on every unverified pair"
    );
}

/// The verdict gate keys on `decided_at`, so an *undecided* row stays freely
/// re-verdictable — `PolicyAction::Reject` writes `status='rejected'` with
/// `decided_at` NULL, and re-scoring such a pair must be able to correct both
/// its status and its verdict.
#[sqlx::test(migrations = "../../migrations")]
async fn upsert_still_overwrites_the_verdict_of_an_undecided_row(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id = repo
        .upsert(
            lo,
            hi,
            0.30,
            serde_json::json!({}),
            "rejected",
            None,
            Some("distinct"),
            Some("unrelated"),
        )
        .await
        .expect("first upsert")
        .id;

    let outcome = repo
        .upsert(
            lo,
            hi,
            0.95,
            serde_json::json!({}),
            "pending",
            None,
            Some("same"),
            Some("re-scored: identical finding"),
        )
        .await
        .expect("re-scan upsert");

    let row = repo.get(id).await.expect("get");
    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("same"),
        "an undecided row must remain freely re-verdictable"
    );
    assert_eq!(
        row.verifier_rationale.as_deref(),
        Some("re-scored: identical finding")
    );
    assert!(
        !outcome.verdict_write_suppressed(Some("same")),
        "no suppression should be reported when the write actually landed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_orders_by_score_desc(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claims: Vec<Uuid> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(insert_claim(&pool, agent).await);
        }
        v
    };
    let repo = MatchCandidateRepo::new(pool.clone());
    // Three pending candidates with descending scores.
    let scores = [0.5_f32, 0.9, 0.7];
    for i in 0..3 {
        let (lo, hi) = {
            let (a, b) = (claims[i], claims[(i + 1) % 3]);
            if a < b {
                (a, b)
            } else {
                (b, a)
            }
        };
        repo.upsert(
            lo,
            hi,
            scores[i],
            serde_json::json!({}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("upsert");
    }
    let rows = repo.list_pending(10).await.expect("list");
    let our: Vec<f32> = rows
        .iter()
        .filter(|r| claims.contains(&r.claim_a) && claims.contains(&r.claim_b))
        .map(|r| r.score)
        .collect();
    assert!(
        our.len() >= 3,
        "expected at least 3 of our rows in list_pending"
    );
    // Each consecutive pair must satisfy score[i] >= score[i+1].
    for w in our.windows(2) {
        assert!(
            w[0] >= w[1],
            "list_pending must be desc by score; got {:?}",
            our
        );
    }
}

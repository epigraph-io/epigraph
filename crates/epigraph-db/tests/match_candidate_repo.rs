use epigraph_db::repos::match_candidate::{DecisionOutcome, MatchCandidateRepo};
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

// ===========================================================================
// promote / reject: the decision and its edge in one transaction, under the
// candidate's row lock (deferred-commitment key match-candidate-promote-tx).
// ===========================================================================

/// A `pending` candidate over two fresh claims, carrying `verdict`.
async fn pending_candidate(
    pool: &PgPool,
    agent: Uuid,
    verdict: Option<&str>,
) -> (Uuid, Uuid, Uuid) {
    let a = insert_claim(pool, agent).await;
    let b = insert_claim(pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let id = MatchCandidateRepo::new(pool.clone())
        .upsert(
            lo,
            hi,
            0.91,
            serde_json::json!({"embed_cosine": 0.91}),
            "pending",
            None,
            verdict,
            None,
        )
        .await
        .expect("upsert")
        .id;
    (lo, hi, id)
}

/// Matcher edges between the pair that are currently IN FORCE, either
/// direction. Keyed like `MatchCandidateRepo::retire` (pair + marker), and
/// filtered on `valid_to IS NULL` because retirement retracts rather than
/// deletes.
async fn matcher_edges_in_force(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges
         WHERE ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))
           AND properties->>'source' = 'cross_source_matcher'
           AND valid_to IS NULL",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count matcher edges")
}

async fn status_of(pool: &PgPool, id: Uuid) -> (String, Option<Uuid>) {
    sqlx::query_as("SELECT status, decided_by FROM match_candidates WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("status")
}

/// Block until at least `n` backends connected to THIS test's database are
/// waiting on a heavyweight lock. `#[sqlx::test]` gives every test its own
/// database, so the `datname` filter isolates it from tests running in
/// parallel. This is what makes the race tests below deterministic: they do
/// not sleep and hope, they observe the contender parked on the lock.
async fn wait_for_lock_waiters(pool: &PgPool, n: i64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity");
        if waiting >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {n} lock waiter(s); saw {waiting}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The happy path, and where the edge's provenance comes from: the status
/// flip, `decided_by`, and ONE matcher edge whose properties are built from the
/// locked row — including the `source` marker migration 090's index and
/// `retire` both key on, which the repo now stamps itself.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_flips_status_and_writes_the_edge_from_the_locked_row(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, Some("contradicts")).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let outcome = repo
        .promote(id, Some(agent), Some("contradicts"), "contradicts")
        .await
        .expect("promote");
    let DecisionOutcome::Decided(row) = outcome else {
        panic!("a pending row must be decided, got {outcome:?}");
    };
    assert_eq!(row.status, "promoted");
    assert_eq!(row.decided_by, Some(agent));
    assert!(row.decided_at.is_some());

    let (relationship, props): (String, serde_json::Value) = sqlx::query_as(
        "SELECT relationship, properties FROM edges
         WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))
           AND valid_to IS NULL",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("exactly one edge");
    assert_eq!(relationship, "contradicts");
    assert_eq!(props["source"], "cross_source_matcher");
    assert_eq!(props["candidate_id"], id.to_string());
    assert_eq!(props["decided_by"], agent.to_string());
    assert_eq!(props["verifier_verdict"], "contradicts");
    assert_eq!(props["features"]["embed_cosine"], 0.91);
}

/// THE RACE THIS CHANGE CLOSES, retire-second ordering: a promote is in
/// flight (status flipped, edge not yet written) when a retirement starts.
///
/// Before: the promote's `set_status` and edge INSERT were two autocommit
/// statements, so `retire`'s row lock did not hold the promote. `retire` saw
/// `promoted` with no edge, retracted nothing, wrote `stale` — and the edge
/// landed afterwards: a `stale` row with a live matcher edge whose derived
/// factor kept biasing belief propagation.
///
/// After: the promote holds the candidate's row lock until its edge commits,
/// so `retire` waits and then retracts that edge.
///
/// Parking the promote mid-transaction: a separate transaction holds one
/// endpoint claim `FOR UPDATE`, so the promote takes the candidate lock and
/// then waits at its `FOR SHARE` current-ness re-check. The retire is started
/// only once the promote is observed parked, and the claim lock is released
/// only once the retire is observed parked behind it.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_waits_for_an_in_flight_promote_and_retracts_its_edge(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, Some("same")).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let mut claim_holder = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE")
        .bind(lo)
        .execute(&mut *claim_holder)
        .await
        .unwrap();

    let promote = tokio::spawn({
        let repo = repo.clone();
        async move {
            repo.promote(id, Some(agent), Some("same"), "CORROBORATES")
                .await
        }
    });
    wait_for_lock_waiters(&pool, 1).await;

    let retirer = Uuid::new_v4();
    let retire = tokio::spawn({
        let repo = repo.clone();
        async move { repo.retire(id, Some(retirer)).await }
    });
    wait_for_lock_waiters(&pool, 2).await;

    claim_holder.rollback().await.unwrap();

    let promoted = promote.await.unwrap().expect("promote");
    assert!(
        matches!(promoted, DecisionOutcome::Decided(ref r) if r.status == "promoted"),
        "the promote was first to the candidate lock and must succeed: {promoted:?}"
    );
    let retired = retire.await.unwrap().expect("retire");
    assert_eq!(
        retired.previous_status, "promoted",
        "retire must have run AFTER the promote committed"
    );
    assert_eq!(
        retired.edges_retracted, 1,
        "retire must see — and retract — the edge the in-flight promote wrote"
    );
    assert_eq!(
        matcher_edges_in_force(&pool, lo, hi).await,
        0,
        "no live matcher edge may survive under a `stale` row"
    );
    assert_eq!(
        status_of(&pool, id).await,
        ("stale".to_string(), Some(retirer))
    );
}

/// Retire-first ordering: a retirement holds the row lock and commits `stale`
/// while a promote is waiting for that lock. The promote must re-read the
/// status under the lock and refuse — not overwrite `stale` with `promoted`
/// and resurrect the edge, which is what an unlocked read-then-write does.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_refuses_when_a_retire_commits_while_it_waits_for_the_lock(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, Some("same")).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let mut retire_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM match_candidates WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *retire_tx)
        .await
        .unwrap();

    let promote = tokio::spawn({
        let repo = repo.clone();
        async move {
            repo.promote(id, Some(agent), Some("same"), "CORROBORATES")
                .await
        }
    });
    wait_for_lock_waiters(&pool, 1).await;

    sqlx::query(
        "UPDATE match_candidates SET status = 'stale', decided_at = now(), decided_by = NULL
         WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *retire_tx)
    .await
    .unwrap();
    retire_tx.commit().await.unwrap();

    let outcome = promote.await.unwrap().expect("promote");
    assert!(
        matches!(outcome, DecisionOutcome::AlreadyDecided { ref status } if status == "stale"),
        "the promote must observe the retirement under the lock: {outcome:?}"
    );
    assert_eq!(matcher_edges_in_force(&pool, lo, hi).await, 0);
    assert_eq!(status_of(&pool, id).await, ("stale".to_string(), None));
}

/// Two concurrent promotes of one row: exactly one decides it. The loser
/// blocks on the lock, then reads `promoted` and is refused, so it cannot
/// overwrite the winner's `decided_by`.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_promotes_decide_the_row_exactly_once(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let other = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, None).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let (r1, r2) = tokio::join!(
        repo.promote(id, Some(agent), None, "CORROBORATES"),
        repo.promote(id, Some(other), None, "CORROBORATES"),
    );
    let outcomes = [r1.expect("promote 1"), r2.expect("promote 2")];
    let winners: Vec<Uuid> = outcomes
        .iter()
        .filter_map(|o| match o {
            DecisionOutcome::Decided(r) => r.decided_by,
            _ => None,
        })
        .collect();
    let losers = outcomes
        .iter()
        .filter(|o| matches!(o, DecisionOutcome::AlreadyDecided { status } if status == "promoted"))
        .count();
    assert_eq!(
        winners.len(),
        1,
        "exactly one promote decides: {outcomes:?}"
    );
    assert_eq!(
        losers, 1,
        "the other is refused as already promoted: {outcomes:?}"
    );
    assert_eq!(
        status_of(&pool, id).await,
        ("promoted".to_string(), Some(winners[0])),
        "the loser must not overwrite the winner's decided_by"
    );
    assert_eq!(matcher_edges_in_force(&pool, lo, hi).await, 1);
}

/// A failed edge write rolls the status flip back with it. The relationship is
/// whitespace, which only the database refuses (`edges_relationship_not_empty`
/// CHECK) — so the statement genuinely runs AFTER the status UPDATE, and the
/// row must still read `pending` with no decision recorded. Two autocommit
/// statements left it `promoted` with no edge.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_whose_edge_write_fails_leaves_the_row_pending(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, None).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let err = repo
        .promote(id, Some(agent), None, "   ")
        .await
        .expect_err("a CHECK-violating edge must fail the promote");
    assert!(
        matches!(err, epigraph_db::DbError::CheckViolation { .. }),
        "expected the edge CHECK violation, got {err:?}"
    );

    let row = repo.get(id).await.expect("get");
    assert_eq!(row.status, "pending", "the status flip must roll back");
    assert!(row.decided_at.is_none() && row.decided_by.is_none());
    let any_edge: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges
         WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(any_edge, 0);
}

/// The relationship a caller resolved from a verdict is only valid for that
/// verdict. If the locked row carries a different one — `upsert` rewrites the
/// verdict of an undecided row — writing it would record a polarity the row
/// no longer supports.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_refuses_when_the_verdict_changed_since_the_callers_read(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, Some("contradicts")).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    // The caller resolved CORROBORATES from a `same` it read earlier.
    let outcome = repo
        .promote(id, Some(agent), Some("same"), "CORROBORATES")
        .await
        .expect("promote");
    assert!(
        matches!(outcome, DecisionOutcome::VerdictChanged { current: Some(ref v) } if v == "contradicts"),
        "{outcome:?}"
    );
    assert_eq!(status_of(&pool, id).await, ("pending".to_string(), None));
    assert_eq!(matcher_edges_in_force(&pool, lo, hi).await, 0);
}

/// An endpoint retired while the promote waits on it: the `FOR SHARE`
/// re-check blocks behind the supersede's row lock, then re-reads the
/// committed `is_current = false` and refuses — no edge onto a retired claim.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_refuses_when_an_endpoint_is_retired_while_it_waits(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, None).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    let mut supersede_tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(hi)
        .execute(&mut *supersede_tx)
        .await
        .unwrap();

    let promote = tokio::spawn({
        let repo = repo.clone();
        async move { repo.promote(id, Some(agent), None, "CORROBORATES").await }
    });
    wait_for_lock_waiters(&pool, 1).await;
    supersede_tx.commit().await.unwrap();

    let outcome = promote.await.unwrap().expect("promote");
    assert!(
        matches!(outcome, DecisionOutcome::ClaimsNotCurrent),
        "{outcome:?}"
    );
    assert_eq!(status_of(&pool, id).await, ("pending".to_string(), None));
    assert_eq!(matcher_edges_in_force(&pool, lo, hi).await, 0);
}

/// `reject` on a promoted row is refused under the lock: flipping it to
/// `rejected` would leave the promotion's matcher edge in force under a row
/// that says it was never accepted (backlog b3f95bea).
#[sqlx::test(migrations = "../../migrations")]
async fn reject_refuses_a_promoted_row_and_leaves_its_edge(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let (lo, hi, id) = pending_candidate(&pool, agent, None).await;
    let repo = MatchCandidateRepo::new(pool.clone());

    repo.promote(id, Some(agent), None, "CORROBORATES")
        .await
        .expect("promote");
    let outcome = repo.reject(id, Some(agent)).await.expect("reject");
    assert!(
        matches!(outcome, DecisionOutcome::AlreadyDecided { ref status } if status == "promoted"),
        "{outcome:?}"
    );
    assert_eq!(status_of(&pool, id).await.0, "promoted");
    assert_eq!(matcher_edges_in_force(&pool, lo, hi).await, 1);

    // …and on a pending row it decides.
    let (_, _, pending) = pending_candidate(&pool, agent, None).await;
    let outcome = repo.reject(pending, Some(agent)).await.expect("reject");
    assert!(
        matches!(outcome, DecisionOutcome::Decided(ref r) if r.status == "rejected" && r.decided_by == Some(agent)),
        "{outcome:?}"
    );
}

//! `Policy::act` must not rewrite the verifier verdict of a *decided* candidate.
//!
//! PR #380 froze `status` on rows with `decided_at IS NOT NULL`, but the
//! verdict columns were written by a separate, ungated `UPDATE` in
//! `Policy::patch_verdict`. PR #382 then made `verifier_verdict` determine edge
//! polarity (`promotion_disposition_for_column`), so an overwrite between the
//! verifier run and the operator's tap changes what edge a human approval
//! produces.
//!
//! These tests exercise `Policy::act` (not the repo directly) because that is
//! the caller whose observable behaviour regressed, and they assert on the
//! PERSISTED row read back through `MatchCandidateRepo::get`.

use epigraph_db::repos::match_candidate::MatchCandidateRepo;

#[path = "viewer_fixture.rs"]
mod fixture;
use epigraph_engine::matching::policy::{Policy, PolicyAction};
use epigraph_engine::matching::scorer::MatchFeatures;
use epigraph_engine::matching::verifier::Verdict;
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
    let content = format!("claim {id}");
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

fn features(score: f32) -> MatchFeatures {
    MatchFeatures {
        embed_cosine: score,
        triple_overlap: 0.0,
        entity_jaccard: 0.0,
        method_match: false,
        nbhd_overlap: 0.0,
        citation_overlap: 0.0,
        graph_overlap: 0.0,
        belief_alignment: 0.5,
        theme_proximity: 0.5,
        temporal_dist_days: 0,
        score,
    }
}

fn verdict(a: Uuid, b: Uuid, relationship: &str, rationale: &str) -> Verdict {
    Verdict {
        source_id: a,
        target_id: b,
        relationship: relationship.to_string(),
        strength: 0.9,
        rationale: rationale.to_string(),
    }
}

/// The regression this PR fixes.
///
/// Night 1: the matcher stages a `contradicts` pair for human review.
/// The operator promotes it — `decide_candidate` resolves the edge polarity
/// from `verifier_verdict`, so a lowercase `contradicts` edge is written and
/// the row is stamped `decided_at`.
///
/// Night 2: the nightly `--dry-run` sweep re-touches the same pair (it reaches
/// `Policy::act` on every run; `--dry-run` only clears `auto_promote`, which
/// gates the *edge* write, not the row write) and the verifier now answers
/// `derives_from` → `MatchVerdict::Distinct`. Before the fix, `patch_verdict`
/// rewrote the decided row's verdict to `distinct`, destroying the record of
/// what the human actually approved — and, on prod, leaving 6 `CORROBORATES`
/// edges whose candidate row no longer says `contradicts` so the polarity
/// audit could not find them.
#[sqlx::test(migrations = "../../migrations")]
async fn act_does_not_rewrite_the_verdict_of_a_decided_candidate(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    // Night 1 — staged for review with a `contradicts` verdict.
    let policy1 = Policy::new(pool.clone(), repo.clone(), Uuid::new_v4(), false);
    policy1
        .act(
            PolicyAction::WriteContradicts,
            a,
            b,
            &features(0.70),
            Some(verdict(
                a,
                b,
                "contradicts",
                "the two claims negate each other",
            )),
        )
        .await
        .expect("night 1 act");

    let staged = repo
        .list_for_claim(&fixture::public_viewer(&pool).await, lo)
        .await
        .expect("list")
        .into_iter()
        .find(|r| r.claim_a == lo && r.claim_b == hi)
        .expect("night 1 must have staged a row");
    assert_eq!(
        staged.verifier_verdict.as_deref(),
        Some("contradicts"),
        "precondition: night 1 must persist the contradicts verdict"
    );

    // Operator promotes it via the Telegram / MCP review queue.
    repo.set_status(staged.id, "promoted", Some(agent))
        .await
        .expect("set_status");

    // Night 2 — the verifier now answers `derives_from` (→ Distinct → Reject).
    let policy2 = Policy::new(pool.clone(), repo.clone(), Uuid::new_v4(), false);
    policy2
        .act(
            PolicyAction::Reject,
            a,
            b,
            &features(0.55),
            Some(verdict(
                a,
                b,
                "derives_from",
                "verifier returned no verdict for this pair",
            )),
        )
        .await
        .expect("night 2 act");

    let row = repo.get(staged.id).await.expect("get after re-scan");

    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("contradicts"),
        "a re-scan must not rewrite the verdict a human already decided on; \
         #382 made this column determine edge polarity"
    );
    assert_eq!(
        row.verifier_rationale.as_deref(),
        Some("the two claims negate each other"),
        "verdict and rationale freeze together — a row whose rationale \
         describes a verdict it no longer carries is worse than either alone"
    );
    // #380's half of the contract still holds.
    assert_eq!(row.status, "promoted", "status must stay frozen too");
    // Matcher telemetry still refreshes — this gate freezes the *decision*,
    // not the description of the pair.
    assert!(
        (row.score - 0.55).abs() < 1e-6,
        "score is matcher telemetry and must still refresh; got {}",
        row.score
    );

    // The counter is the deliberate replacement for the detector this gate
    // destroys: before the gate, every such overwrite left a trace in
    // `verifier_rationale`, which is how the 123 corrupted prod rows were
    // found. Silence here would mean shipping the destruction without the
    // replacement.
    assert_eq!(
        policy2.verdict_writes_suppressed(),
        1,
        "a suppressed verdict write must be counted so the nightly RunReport \
         can surface that the verifier is re-scoring decided pairs"
    );
    assert_eq!(
        policy1.verdict_writes_suppressed(),
        0,
        "night 1 wrote its verdict to an undecided row — nothing was suppressed"
    );
}

/// The gate keys on `decided_at`, so an *undecided* row must stay freely
/// re-verdictable — the matcher's own `status='rejected'` leaves `decided_at`
/// NULL, and re-scoring such a pair upward must be able to update its verdict.
#[sqlx::test(migrations = "../../migrations")]
async fn act_still_updates_the_verdict_of_an_undecided_candidate(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let policy = Policy::new(pool.clone(), repo.clone(), Uuid::new_v4(), false);
    policy
        .act(
            PolicyAction::Reject,
            a,
            b,
            &features(0.30),
            Some(verdict(a, b, "derives_from", "unrelated")),
        )
        .await
        .expect("first act");

    let id = repo
        .list_for_claim(&fixture::public_viewer(&pool).await, lo)
        .await
        .expect("list")
        .into_iter()
        .find(|r| r.claim_a == lo && r.claim_b == hi)
        .expect("row")
        .id;
    assert!(
        repo.get(id).await.expect("get").decided_at.is_none(),
        "a matcher-set status must not stamp decided_at"
    );

    policy
        .act(
            PolicyAction::AutoPromote,
            a,
            b,
            &features(0.95),
            Some(verdict(a, b, "supports", "same finding")),
        )
        .await
        .expect("second act");

    let row = repo.get(id).await.expect("get");
    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("same"),
        "an undecided row must remain freely re-verdictable by the matcher"
    );
    assert_eq!(row.verifier_rationale.as_deref(), Some("same finding"));
}

/// `Policy::act` takes `Option<Verdict>` and is called with `None` when the
/// pair never reached the verifier (high/low band short-circuits). A `None`
/// must LEAVE an existing verdict alone, not blank it — the pre-fix code got
/// this right only by skipping the UPDATE entirely, so folding the columns
/// into a single always-executing statement must preserve it explicitly.
#[sqlx::test(migrations = "../../migrations")]
async fn act_with_no_verdict_preserves_an_existing_one(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let policy = Policy::new(pool.clone(), repo.clone(), Uuid::new_v4(), false);
    policy
        .act(
            PolicyAction::AutoPromote,
            a,
            b,
            &features(0.80),
            Some(verdict(a, b, "supports", "same finding")),
        )
        .await
        .expect("verdict act");

    let id = repo
        .list_for_claim(&fixture::public_viewer(&pool).await, lo)
        .await
        .expect("list")
        .into_iter()
        .find(|r| r.claim_a == lo && r.claim_b == hi)
        .expect("row")
        .id;

    policy
        .act(PolicyAction::AutoPromote, a, b, &features(0.81), None)
        .await
        .expect("no-verdict act");

    let row = repo.get(id).await.expect("get");
    assert_eq!(
        row.verifier_verdict.as_deref(),
        Some("same"),
        "an unverified re-touch must not erase a verdict the verifier produced"
    );
    assert_eq!(row.verifier_rationale.as_deref(), Some("same finding"));
    assert_eq!(
        policy.verdict_writes_suppressed(),
        0,
        "not attempting a verdict is not a suppression — counting it would make \
         the telemetry fire on every unverified pair and drown the real signal"
    );
}

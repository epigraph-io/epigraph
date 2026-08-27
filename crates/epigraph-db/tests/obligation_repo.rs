//! `ObligationRepository` — the obligation layer (backlog 4b48ffb5).
//!
//! The property these tests exist for is not "a row was written" but "the
//! verdict is RE-DERIVED from the live graph rather than replayed from a
//! stored number". Coverage decays: an anchor that is superseded or deleted
//! stops counting, and a contract that read `satisfied` on Tuesday must read
//! `breach` on Friday without anyone editing the row.

use epigraph_core::obligation::{
    evaluate, CoverageContract, CoverageStandard, FIELD_DECLARED_UNIT_KEYS,
};
use epigraph_db::{NewObligation, ObligationRepository, ANCHOR_KIND_CLAIM};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-obligation', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels)
         VALUES ($1, sha256(convert_to($1, 'UTF8')), 0.5, $2, true, ARRAY[]::text[])
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// Build an exhaustive contract over `anchors.len()` claims and record the
/// verdict `evaluate` produces for it — i.e. exactly what the batch call site
/// does.
fn exhaustive_over(agent: Uuid, anchors: &[Uuid], declared: u32) -> NewObligation {
    let contract = CoverageContract {
        standard: CoverageStandard::Exhaustive,
        unit: "claim".to_string(),
        declared_total: declared,
    };
    let assessment = evaluate(&contract, u32::try_from(anchors.len()).unwrap());
    NewObligation {
        agent_id: Some(agent),
        standard: contract.standard,
        unit: contract.unit,
        declared_total: i32::try_from(declared).unwrap(),
        anchors: anchors.to_vec(),
        anchor_kind: ANCHOR_KIND_CLAIM.to_string(),
        observed_total: i32::try_from(assessment.observed_total).unwrap(),
        verdict: assessment.verdict.as_str().to_string(),
        verdict_reason: Some(assessment.reason),
        missing_contract_fields: assessment.missing_contract_fields,
        source_tool: "obligation_repo_test".to_string(),
    }
}

/// Every column survives the round trip, including the two array columns.
/// `anchors` is compared as a SET: the column is a `UUID[]` with no ordering
/// guarantee anyone should depend on.
#[sqlx::test(migrations = "../../migrations")]
async fn obligation_roundtrips_through_postgres(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "roundtrip anchor A").await;
    let b = seed_claim(&pool, agent, "roundtrip anchor B").await;
    let c = seed_claim(&pool, agent, "roundtrip anchor C").await;

    // native_complete so the TEXT[] column carries a non-empty value — an
    // always-empty array would not prove it round-trips.
    let contract = CoverageContract {
        standard: CoverageStandard::NativeComplete,
        unit: "section".to_string(),
        declared_total: 3,
    };
    let assessment = evaluate(&contract, 3);
    assert_eq!(
        assessment.missing_contract_fields,
        vec![FIELD_DECLARED_UNIT_KEYS]
    );

    let id = ObligationRepository::record(
        &pool,
        NewObligation {
            agent_id: Some(agent),
            standard: contract.standard,
            unit: contract.unit.clone(),
            declared_total: 3,
            anchors: vec![a, b, c],
            anchor_kind: ANCHOR_KIND_CLAIM.to_string(),
            observed_total: 3,
            verdict: assessment.verdict.as_str().to_string(),
            verdict_reason: Some(assessment.reason.clone()),
            missing_contract_fields: assessment.missing_contract_fields.clone(),
            source_tool: "obligation_repo_test".to_string(),
        },
    )
    .await
    .expect("record");

    let row = ObligationRepository::get(&pool, id)
        .await
        .expect("get")
        .expect("row exists");

    assert_eq!(row.id, id);
    assert_eq!(row.agent_id, Some(agent));
    assert_eq!(row.standard, "native_complete");
    assert_eq!(row.unit, "section");
    assert_eq!(row.declared_total, 3);
    assert_eq!(row.anchor_kind, ANCHOR_KIND_CLAIM);
    assert_eq!(row.observed_total, 3);
    assert_eq!(row.verdict, "satisfied");
    assert_eq!(
        row.verdict_reason.as_deref(),
        Some(assessment.reason.as_str())
    );
    assert_eq!(row.missing_contract_fields, vec![FIELD_DECLARED_UNIT_KEYS]);
    assert_eq!(row.source_tool, "obligation_repo_test");

    let stored: std::collections::BTreeSet<Uuid> = row.anchors.into_iter().collect();
    let expected: std::collections::BTreeSet<Uuid> = [a, b, c].into_iter().collect();
    assert_eq!(stored, expected, "anchors must survive as a set");

    // A missing id is None, not an error.
    assert!(ObligationRepository::get(&pool, Uuid::new_v4())
        .await
        .expect("get missing")
        .is_none());
}

/// The fail-closed vocabulary is enforced by Postgres, not only by Rust.
/// Without the CHECK constraints, a caller bypassing `CoverageStandard` (a raw
/// INSERT, a migration backfill, a future HTTP route) could store a standard
/// that owes nothing and a verdict nothing knows how to read.
#[sqlx::test(migrations = "../../migrations")]
async fn obligation_standard_vocabulary_is_enforced_by_check_constraint(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let bad_standard = sqlx::query(
        "INSERT INTO obligations
             (agent_id, standard, unit, declared_total, observed_total, verdict, source_tool)
         VALUES ($1, 'vibes', 'claim', 1, 1, 'satisfied', 'test')",
    )
    .bind(agent)
    .execute(&pool)
    .await;
    let err = bad_standard.expect_err("standard='vibes' must be rejected");
    assert!(
        err.to_string().contains("obligations_standard_vocab"),
        "expected the standard CHECK constraint to fire; got: {err}"
    );

    let bad_verdict = sqlx::query(
        "INSERT INTO obligations
             (agent_id, standard, unit, declared_total, observed_total, verdict, source_tool)
         VALUES ($1, 'exhaustive', 'claim', 1, 1, 'probably', 'test')",
    )
    .bind(agent)
    .execute(&pool)
    .await;
    let err = bad_verdict.expect_err("verdict='probably' must be rejected");
    assert!(
        err.to_string().contains("obligations_verdict_vocab"),
        "expected the verdict CHECK constraint to fire; got: {err}"
    );
}

/// COVERAGE DECAYS. Retiring an anchor (`is_current = false`, what both
/// `supersede` and `mark_duplicate` do) must move a satisfied contract to
/// breach on the next recheck — the arithmetic is re-derived from the graph,
/// never replayed from `observed_total`.
#[sqlx::test(migrations = "../../migrations")]
async fn recheck_recounts_only_is_current_anchors(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "decay anchor A").await;
    let b = seed_claim(&pool, agent, "decay anchor B").await;
    let c = seed_claim(&pool, agent, "decay anchor C").await;

    let id = ObligationRepository::record(&pool, exhaustive_over(agent, &[a, b, c], 3))
        .await
        .expect("record");
    let before = ObligationRepository::get(&pool, id).await.unwrap().unwrap();
    assert_eq!(before.verdict, "satisfied");
    assert_eq!(before.observed_total, 3);

    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("retire one anchor");

    let after = ObligationRepository::recheck(&pool, id)
        .await
        .expect("recheck")
        .expect("row exists");

    assert_eq!(after.observed_total, 2, "retired anchor must stop counting");
    assert_eq!(after.verdict, "breach", "{:?}", after.verdict_reason);
    assert!(
        after.checked_at > before.checked_at,
        "checked_at must advance: {:?} -> {:?}",
        before.checked_at,
        after.checked_at
    );
    // The contract itself is untouched — only the verdict moved.
    assert_eq!(after.declared_total, 3);
    assert_eq!(after.anchors.len(), 3);
    assert_eq!(after.created_at, before.created_at);

    // Rechecking an id that does not exist is None, not an error.
    assert!(ObligationRepository::recheck(&pool, Uuid::new_v4())
        .await
        .expect("recheck missing")
        .is_none());
}

/// The no-FK decision, exercised. Postgres cannot FK an array element, so a
/// deleted anchor leaves a dangling UUID in the column. `recheck` must simply
/// not match it — dropping it is the correct arithmetic (a deleted claim
/// covers nothing), not an error and not a lost referent.
#[sqlx::test(migrations = "../../migrations")]
async fn recheck_tolerates_a_vanished_anchor(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "vanish anchor A").await;
    let b = seed_claim(&pool, agent, "vanish anchor B").await;
    let c = seed_claim(&pool, agent, "vanish anchor C").await;

    let id = ObligationRepository::record(&pool, exhaustive_over(agent, &[a, b, c], 3))
        .await
        .expect("record");

    sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("delete one anchor outright");

    let after = ObligationRepository::recheck(&pool, id)
        .await
        .expect("recheck must not error on a dangling array element")
        .expect("row exists");

    assert_eq!(after.observed_total, 2);
    assert_eq!(after.verdict, "breach", "{:?}", after.verdict_reason);
    // The anchor id is still recorded — the obligation remembers what it was
    // told to count, even though one referent is gone.
    assert!(after.anchors.contains(&c));
}

/// `list_unmet` returns breaches and indeterminates and excludes the closed
/// verdicts. Repo-only in this MVP (no tool reads it), but the filter is the
/// contract a future sweeper will depend on.
#[sqlx::test(migrations = "../../migrations")]
async fn list_unmet_returns_only_open_verdicts(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "unmet anchor A").await;

    // satisfied
    let closed = ObligationRepository::record(&pool, exhaustive_over(agent, &[a], 1))
        .await
        .unwrap();
    // breach: declared 3, one anchor
    let breached = ObligationRepository::record(&pool, exhaustive_over(agent, &[a], 3))
        .await
        .unwrap();
    // indeterminate: the zero-denominator rule
    let indeterminate = ObligationRepository::record(&pool, exhaustive_over(agent, &[], 0))
        .await
        .unwrap();

    let unmet = ObligationRepository::list_unmet(&pool, Some(agent), 50)
        .await
        .expect("list_unmet");
    let ids: Vec<Uuid> = unmet.iter().map(|r| r.id).collect();

    assert!(ids.contains(&breached), "breach must be listed: {ids:?}");
    assert!(
        ids.contains(&indeterminate),
        "indeterminate must be listed: {ids:?}"
    );
    assert!(
        !ids.contains(&closed),
        "satisfied must NOT be listed: {ids:?}"
    );
}

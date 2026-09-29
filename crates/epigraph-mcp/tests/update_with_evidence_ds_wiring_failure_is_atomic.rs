//! `update_with_evidence` is ONE transaction — evidence -> BBA -> truth_value ->
//! labels — and a DS-wiring failure must be a RETURNED ERROR that rolls every
//! one of those writes back. It must never be swallowed into a committed
//! evidence row.
//!
//! # History: why this file used to assert the opposite
//!
//! It was introduced by #497 as `update_with_evidence_ds_wiring_is_best_effort.rs`.
//! On that tree the evidence INSERT self-committed on the unstamped pool (it had
//! to: migration 046 gives `mass_functions.evidence_id` a FK to `evidence(id)`
//! and the wiring ran on a SIBLING pool connection that could not see an
//! uncommitted row), and the wiring itself was then refused in production at
//! `claim_frames`. A fatal error there reported total failure for a call whose
//! evidence row the database had kept, so #497 made the failure best-effort and
//! disclosed it as `belief_wired: false` / `bba_stored` / `ds_wire_error`.
//!
//! D2 (Unit E, PR #498) removes both premises. The wiring takes the tool's
//! author-stamped transaction, so the FK is satisfied by the uncommitted row in
//! the same snapshot and the evidence INSERT no longer commits on its own. A
//! failure now leaves NOTHING behind, which makes an error the complete and
//! truthful answer — and makes the swallow harmful: it would commit exactly the
//! BBA-less evidence row that `evidence_content_hash_claim_unique` then uses to
//! refuse the identical re-submission (#497's own measurement, the fourth arm
//! below).
//!
//! # What each of #497's arms became, and why its INTENT survives
//!
//! #497's intent was: a DS failure is VISIBLE to the caller, and names the step
//! that failed. That is kept — more strongly, as an `Err` whose message is the
//! step-prefixed wire error — while the "evidence commits anyway" half is
//! inverted, because under one transaction it is the defect, not the fix.
//!
//! * First-step drop (`assign_claim` refused): was "succeeds, `belief_wired:
//!   false`, `bba_stored: false`, evidence attached, labels merged". Now: `Err`
//!   starting `assign_claim:`, and evidence / `mass_functions` / labels /
//!   `truth_value` all unchanged. Labels are not SILENTLY lost (backlog
//!   f14592cb's concern) — the caller is told the whole submission failed.
//! * Success: unchanged. `belief_wired` and `bba_stored` are still reported,
//!   `true`, for clients of #497, and the measures are present.
//! * Late-step drop (`update_claim_belief` refused after the BBA was written):
//!   was "succeeds, `bba_stored: true`, framed `get_belief` already sees the
//!   BBA". Now: `Err` starting `update_claim_belief:`, and the BBA written
//!   earlier in the same transaction is ROLLED BACK with everything else.
//! * Re-submit after a first-step drop: was "identical re-submit refused as a
//!   duplicate; re-worded one adds a SECOND evidence row; original stays
//!   BBA-less". Now: the identical re-submit is ADMITTED and wires, leaving
//!   exactly one evidence row and one BBA keyed to it. This arm pins the
//!   recovery guidance in the tool description and in `UpdateResponse`.
//!
//! # Why this is not vacuous under a BYPASSRLS superuser
//!
//! `#[sqlx::test]` connects as a superuser with `BYPASSRLS`, so production's
//! `claim_frames` RLS refusal cannot be reproduced here. The failure is injected
//! through a mechanism a superuser does NOT bypass — a table `CHECK` constraint —
//! so the `Err` path is reached on any host, as any role. These arms pin the
//! ERROR-HANDLING and ATOMICITY contract; they say nothing about which RLS
//! policy admits the stamped writes (that is `scripts/e2e/probe-unit-e.sh` and
//! `scripts/e2e/probe-tools.sh`, on a `rolbypassrls = false` role).
//!
//! Load-bearing check — MEASURED. Re-introducing #497's best-effort shape on the
//! D2 tree (the wire under a SAVEPOINT; on `Err`, roll the savepoint back, merge
//! the labels, COMMIT the evidence row and return `belief_wired: false`) gives
//! `1 passed; 3 failed`: both drop arms and the re-submit arm fail at their
//! first `expect_err`, because the swallowed call returns success. Only the
//! success arm keeps passing, as it should — the mutation does not touch the
//! wired path. Restoring the atomic `?` returns all four to passing.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;
use tracing_test::traced_test;

fn json_of(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("tool returned a text content block");
    serde_json::from_str(&text).expect("tool response is JSON")
}

fn params(claim_id: uuid::Uuid, data: &str, labels: &[&str]) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim_id.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.7,
        labels: labels.iter().map(|l| l.to_string()).collect(),
    }
}

/// Everything a failed call must leave exactly as it found it.
#[derive(Debug, PartialEq)]
struct ClaimState {
    evidence_on_claim: i64,
    mass_functions: i64,
    truth_value: f64,
    cached_pignistic: Option<f64>,
    labels: Vec<String>,
}

async fn state_of(pool: &PgPool, claim_id: uuid::Uuid) -> ClaimState {
    let (evidence_on_claim,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("count evidence on the claim");
    let (mass_functions,): (i64,) = sqlx::query_as("SELECT count(*) FROM mass_functions")
        .fetch_one(pool)
        .await
        .expect("count mass_functions");
    let (truth_value, cached_pignistic, labels): (f64, Option<f64>, Vec<String>) =
        sqlx::query_as("SELECT truth_value, pignistic_prob, labels FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("read the claim");
    ClaimState {
        evidence_on_claim,
        mass_functions,
        truth_value,
        cached_pignistic,
        labels,
    }
}

/// Make `ds_auto::auto_wire_ds_update` fail at its FIRST write for a
/// role-independent reason.
///
/// `CHECK (false)` on `claim_frames`, the table `assign_claim` writes first. A
/// superuser bypasses RLS and GRANTs; it does not bypass a CHECK constraint.
/// `NOT VALID` so an already-populated table does not block the DDL — the
/// constraint only has to reject NEW rows.
async fn deny_all_writes_to_claim_frames(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE claim_frames \
         ADD CONSTRAINT ds_wiring_denied_for_test CHECK (false) NOT VALID",
    )
    .execute(pool)
    .await
    .expect("install the CHECK(false) failure injector");
}

/// Make ONLY the last step of the wire fail: `update_claim_belief` sets
/// `claims.belief_frame_id`, so a `CHECK (belief_frame_id IS NULL)` refuses it
/// AFTER `store_with_perspective` has written the BBA in the same transaction.
/// `NOT VALID` so existing rows do not block the DDL.
async fn deny_the_cached_belief_write(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE claims \
         ADD CONSTRAINT cached_belief_denied_for_test CHECK (belief_frame_id IS NULL) NOT VALID",
    )
    .execute(pool)
    .await
    .expect("install the late-step failure injector");
}

/// A first-step drop is an ERROR naming the step, and writes nothing.
#[traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_first_step_ds_failure_is_an_error_and_commits_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id =
        seed_claim_with_labels(&pool, "claim whose DS wire will drop", &["keeper"]).await;
    let before = state_of(&pool, claim_id).await;

    deny_all_writes_to_claim_frames(&pool).await;

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        params(
            claim_id,
            "Corroboration submitted while DS wiring is refused.",
            &["run-tag-0923"],
        ),
        None,
    )
    .await
    .expect_err(
        "a refused DS wire must be a RETURNED ERROR: under D2 the evidence row is in the same \
         transaction, so a success here could only mean the failure was swallowed and the \
         evidence committed without its BBA",
    );

    // #497's intent, kept: the failure is visible to the caller and names the
    // step that failed.
    assert!(
        err.message.starts_with("assign_claim:"),
        "the error must carry the failing step as its prefix; got {err:?}"
    );

    // And visible to the operator, not only the caller: `internal_error` does
    // not log, so the warn at the `auto_wire_ds_update` call site is the only
    // server-log record of this dropped wire. #497 added it so one log query
    // ("ds auto-wire failed") finds every dropped wire across tools; the suffix
    // asserted here is unique to this site.
    assert!(
        logs_contain("Rolled back; nothing from this submission was stored"),
        "a dropped DS wire in update_with_evidence must be logged as well as returned"
    );

    // And the atomicity half: nothing at all landed — no evidence row, no BBA,
    // no truth write, no label merge.
    assert_eq!(
        state_of(&pool, claim_id).await,
        before,
        "a failed call must leave the claim exactly as it found it"
    );
}

/// The complement, so the contract is pinned in both directions: when the wire
/// lands, the call succeeds and #497's fields report the landed wire.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successful_ds_wire_reports_belief_wired_true_with_its_measures(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim_with_labels(&pool, "claim whose DS wire lands", &["keeper"]).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let body = json_of(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            params(
                claim_id,
                "Corroboration submitted with DS wiring available.",
                &["run-tag-0923"],
            ),
            None,
        )
        .await
        .expect("update_with_evidence on a wired path"),
    );

    assert_eq!(
        body["belief_wired"],
        serde_json::json!(true),
        "the wiring landed, and #497's clients read this flag; got {body}"
    );
    assert_eq!(
        body["bba_stored"],
        serde_json::json!(true),
        "a completed wire stored its BBA; got {body}"
    );
    assert!(
        body.get("ds_wire_error").is_none(),
        "`ds_wire_error` must be absent when the wire completed; got {body}"
    );
    for present in ["belief", "plausibility", "pignistic_prob"] {
        assert!(
            body[present].is_f64(),
            "`{present}` must be reported when a fresh BBA exists; got {body}"
        );
    }

    // The whole unit committed: one evidence row (the one reported), one BBA
    // keyed to it, and the labels merged.
    let evidence_id: uuid::Uuid = body["evidence_id"]
        .as_str()
        .expect("evidence_id is reported")
        .parse()
        .expect("evidence_id is a UUID");
    let (bbas_for_evidence,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM mass_functions WHERE evidence_id = $1")
            .bind(evidence_id)
            .fetch_one(&pool)
            .await
            .expect("count this evidence's BBAs");
    assert_eq!(
        bbas_for_evidence, 1,
        "`belief_wired: true` must mean a mass function keyed to the reported evidence was \
         actually written"
    );
    let after = state_of(&pool, claim_id).await;
    assert_eq!(after.evidence_on_claim, 1);
    assert_eq!(after.mass_functions, 1);
    assert!(
        after.labels.contains(&"keeper".to_string())
            && after.labels.contains(&"run-tag-0923".to_string()),
        "labels merge additively on success; got {:?}",
        after.labels
    );
}

/// A LATE-step drop: the BBA is written, then the cached-belief write fails.
/// Under #497 the BBA stayed persisted (`bba_stored: true`); under D2 it is in
/// the same transaction and must be rolled back with everything else.
#[sqlx::test(migrations = "../../migrations")]
async fn a_late_step_ds_failure_rolls_back_the_bba_it_had_already_written(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id =
        seed_claim_with_labels(&pool, "claim whose DS wire drops late", &["keeper"]).await;
    let (frame_before,): (Option<uuid::Uuid>,) =
        sqlx::query_as("SELECT belief_frame_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read claim before");
    assert!(
        frame_before.is_none(),
        "precondition: the seeded claim must have NULL belief_frame_id, or the injector would \
         refuse an earlier `UPDATE claims` and this arm would test the wrong failure"
    );
    let before = state_of(&pool, claim_id).await;

    deny_the_cached_belief_write(&pool).await;

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        params(
            claim_id,
            "Corroboration whose cached-belief write is refused.",
            &["run-tag-late"],
        ),
        None,
    )
    .await
    .expect_err("a late-step DS failure is a returned error too");

    assert!(
        err.message.starts_with("update_claim_belief:"),
        "the error must name the LATE step — proving the BBA write before it was reached; got \
         {err:?}"
    );
    assert_eq!(
        state_of(&pool, claim_id).await,
        before,
        "the BBA written before the failing step must be rolled back with the evidence row, \
         the truth write and the labels — a surviving `mass_functions` row here is the \
         half-landed state #497 had to disclose as `bba_stored: true`"
    );
}

/// The recovery a failed call now HAS, pinned so the documented guidance
/// cannot drift back to #497's "re-submitting is not a recovery".
///
/// Under #497 a first-step drop committed a BBA-less evidence row, and
/// `evidence_content_hash_claim_unique UNIQUE (content_hash, claim_id)`
/// (migration 001, `content_hash = blake3(evidence_data)`) then refused the
/// identical re-submit as a duplicate. Under D2 the failed call committed
/// nothing, so the identical re-submit is admitted and lands exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn after_a_ds_failure_an_identical_resubmit_lands_exactly_once(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim_with_labels(&pool, "claim whose first wire drops", &[]).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let wording = "The assertion, first wording.";

    deny_all_writes_to_claim_frames(&pool).await;
    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        params(claim_id, wording, &[]),
        None,
    )
    .await
    .expect_err("the first call's DS wire is refused");
    assert_eq!(
        state_of(&pool, claim_id).await.evidence_on_claim,
        0,
        "the failed call left no evidence row to block the retry"
    );

    // The cause is fixed: the injector goes away.
    sqlx::query("ALTER TABLE claim_frames DROP CONSTRAINT ds_wiring_denied_for_test")
        .execute(&pool)
        .await
        .expect("drop the injector");

    let retried = json_of(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            params(claim_id, wording, &[]),
            None,
        )
        .await
        .expect(
            "an IDENTICAL re-submit after a failed call must be admitted — if it is refused as a \
             duplicate, the failed call committed its evidence row and the atomicity is broken",
        ),
    );
    assert_eq!(
        retried["belief_wired"],
        serde_json::json!(true),
        "got {retried}"
    );

    let evidence_id: uuid::Uuid = retried["evidence_id"]
        .as_str()
        .expect("evidence_id")
        .parse()
        .expect("uuid");
    let after = state_of(&pool, claim_id).await;
    assert_eq!(
        after.evidence_on_claim, 1,
        "exactly one evidence row for the assertion — the retry, not a second copy"
    );
    let (bbas_for_evidence,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM mass_functions WHERE evidence_id = $1")
            .bind(evidence_id)
            .fetch_one(&pool)
            .await
            .expect("count the retried row's BBAs");
    assert_eq!(
        bbas_for_evidence, 1,
        "the retried evidence row carries its BBA — nothing is left BBA-less"
    );
    assert_eq!(after.mass_functions, 1);
}

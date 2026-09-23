//! `update_with_evidence` must treat a DS-wiring failure the way `submit_claim`
//! does — best-effort — and must DISCLOSE it as `belief_wired: false` rather
//! than returning either a bare error or a bare success.
//!
//! # The defect
//!
//! `tools/claims.rs::update_with_evidence` commits its evidence row (it has to:
//! migration 046 gives `mass_functions.evidence_id` a FK to `evidence(id)` and
//! the wiring runs on a sibling pool connection that cannot see an uncommitted
//! row), and then used to treat a DS-wiring failure as FATAL via
//! `.map_err(internal_error)?`. `submit_claim`, on the identical failure of the
//! identical helper, `tracing::warn!`s and calls `ds_result.ok()`. So the
//! canonical write path tolerated what this one rejected, and the caller got an
//! error for work that had PARTLY SUCCEEDED and stayed committed.
//!
//! # WHY THIS TEST IS NOT VACUOUS, WHICH IS THE WHOLE DESIGN PROBLEM
//!
//! `#[sqlx::test]` connects as `epigraph` — superuser, `BYPASSRLS`, owner of
//! every protected table. In production the DS wiring fails because
//! `claim_frames` is refused by migration 077's tenancy `WITH CHECK` on the
//! unstamped pool (`new row violates row-level security policy for table
//! "claim_frames"`; `mass_functions`' last successful production write was
//! 2026-09-22). **That refusal cannot be reproduced here at all** — a
//! `BYPASSRLS` superuser is not bound by any policy, so an arm shaped "the DS
//! wiring fails" would silently become an arm where it SUCCEEDS, and
//! `belief_wired` could only ever be observed as `true`. Such an arm would pass
//! identically on the unfixed tree and prove nothing.
//!
//! So the failure is injected through a mechanism **superuser does not bypass**:
//! a `CHECK (false)` constraint on `claim_frames`. Grants and RLS are bypassed by
//! a superuser; table constraints are not. `auto_wire_ds_update`'s first write is
//! `assign_claim` into `claim_frames`, so the constraint makes the wiring fail
//! deterministically, for a reason that has nothing to do with the connecting
//! role — which is precisely what makes the arm reach the `Err` branch on any
//! host, in CI, as any user.
//!
//! What this buys, and what it does not: it pins the ERROR-HANDLING CONTRACT
//! (best-effort + disclosed + evidence still attached + labels still merged). It
//! does NOT prove that production's specific `claim_frames` refusal is the one
//! being handled — that is measured end-to-end by `scripts/e2e/probe-tools.sh`
//! against a `rolbypassrls = false` role on the prod-faithful schema
//! configuration, where the unfixed binary answers
//! `{"error":{"code":-32603,"message":"assign_claim: … row-level security policy
//! for table \"claim_frames\""}}` and the fixed one answers
//! `{"truth_before":0.9,"truth_after":0.9,"evidence_id":"…","belief_wired":false}`.
//! The two instruments are complementary: this one is role-independent and
//! always-on, that one is role-faithful and needs a deployed schema.
//!
//! # Load-bearing check — MEASURED, one mutation per arm
//!
//! * Revert ONLY the policy — the `Err` arm of the `match` on
//!   `auto_wire_ds_update` made `return Err(internal_error(e))` again, i.e. the
//!   old `.map_err(internal_error)?`, with the `belief_wired` field left in so
//!   the tree still compiles — gives `1 passed; 1 failed`:
//!   [`a_dropped_ds_wire_still_attaches_the_evidence_and_reports_belief_wired_false`]
//!   fails on its FIRST assertion with the tool's propagated error,
//!   `assign_claim: Check constraint ds_wiring_denied_for_test violated`. That is
//!   the defect itself — an error returned for a call whose evidence row the
//!   database kept. The success arm keeps passing, as it should: the revert does
//!   not touch the wired path.
//! * Hardcode `belief_wired: false` instead: `1 passed; 1 failed`, the other way
//!   round — [`a_successful_ds_wire_reports_belief_wired_true_with_its_measures`]
//!   fails at its `belief_wired == true` assertion. That arm exists so the flag
//!   cannot be satisfied by a constant.
//!
//! Restoring the change returns both of those arms to passing.
//!
//! # `bba_stored` — which failure it was
//!
//! `belief_wired: false` alone cannot tell a FIRST-step drop (no BBA stored —
//! production's `claim_frames` refusal) from a LATE-step drop (BBA stored, then
//! e.g. `update_claim_belief` refused), and the two need opposite recoveries.
//! [`a_late_step_drop_reports_the_bba_it_already_stored`] injects the late
//! failure with `CHECK (belief_frame_id IS NULL) NOT VALID` on `claims`, which
//! refuses only the cached-belief write, and pins `bba_stored: true`, one
//! `mass_functions` row keyed to the reported evidence, untouched
//! `truth_value` / cached `pignistic_prob`, and a framed `get_belief` that
//! already reads `source: "recomputed"`. MEASURED, one mutation each, on the
//! response field in `update_with_evidence`:
//!
//! * `bba_stored: true` hardcoded — `2 passed; 1 failed`: the first-step arm
//!   fails with `got {"bba_stored":true,…,"ds_wire_error":"assign_claim: Check
//!   constraint ds_wiring_denied_for_test violated…`.
//! * `bba_stored: false` hardcoded — `1 passed; 2 failed`: the late arm
//!   (`"ds_wire_error":"update_claim_belief: Check constraint
//!   cached_belief_denied_for_test…`) and the success arm both fail.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;

fn json_of(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("tool returned a text content block");
    serde_json::from_str(&text).expect("tool response is JSON")
}

/// Make `ds_auto::auto_wire_ds_update` fail for a role-independent reason.
///
/// `CHECK (false)` on `claim_frames`, the table `assign_claim` writes first. A
/// superuser bypasses RLS and GRANTs; it does not bypass a CHECK constraint, so
/// this fails the wiring on every host and for every connecting role. `NOT
/// VALID` so an already-populated table does not block the DDL — the constraint
/// only has to reject NEW rows.
async fn deny_all_writes_to_claim_frames(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE claim_frames \
         ADD CONSTRAINT ds_wiring_denied_for_test CHECK (false) NOT VALID",
    )
    .execute(pool)
    .await
    .expect("install the CHECK(false) failure injector");
}

/// The arm the fix exists for: the wiring is refused, and the tool must still
/// succeed, still attach the evidence, still merge the labels, and say plainly
/// that the claim's truth_value and cached belief were not updated and that no
/// BBA was stored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_ds_wire_still_attaches_the_evidence_and_reports_belief_wired_false(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id =
        seed_claim_with_labels(&pool, "claim whose DS wire will drop", &["keeper"]).await;
    let (truth_before,): (f64,) = sqlx::query_as("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("read truth_value before");

    deny_all_writes_to_claim_frames(&pool).await;

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let result = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Corroboration submitted while DS wiring is refused.".into(),
            source_url: None,
            supports: true,
            strength: 0.7,
            labels: vec!["run-tag-0923".into()],
        },
    )
    .await;

    // THE DISCRIMINATING ASSERTION. On the unfixed tree the wiring's `Err` is
    // `?`-propagated and this is an `Err(McpError)` carrying the constraint
    // violation — even though the evidence row below is committed either way.
    let out = result.expect(
        "a refused DS wire must not fail the call: the evidence row is already committed, so an \
         error here reports total failure for work the database kept (submit_claim treats the \
         identical failure of the identical helper as best-effort)",
    );
    let body = json_of(out);

    assert_eq!(
        body["belief_wired"],
        serde_json::json!(false),
        "the dropped wire must be DISCLOSED, not swallowed — bare success here is the \
         silent-failure mode this change exists to remove; got {body}"
    );
    // And WHICH drop it was: the first step failed, so no BBA was stored. This is
    // the production case, and the one whose recovery differs from a late drop.
    assert_eq!(
        body["bba_stored"],
        serde_json::json!(false),
        "the wire failed at `assign_claim`, before any BBA was stored; got {body}"
    );
    assert!(
        body["ds_wire_error"]
            .as_str()
            .is_some_and(|e| e.starts_with("assign_claim:")),
        "`ds_wire_error` must name the failing step; got {body}"
    );

    // The belief numbers must reflect that NOTHING changed, rather than echoing
    // the persisted columns (which would manufacture a delta out of a previous
    // call's state).
    assert_eq!(
        body["truth_before"], body["truth_after"],
        "the wire did not complete, so truth_after must equal truth_before; got {body}"
    );
    assert_eq!(
        body["truth_after"],
        serde_json::json!(truth_before),
        "truth_after must be the claim's UNCHANGED stored truth_value; got {body}"
    );
    for absent in ["belief", "plausibility", "pignistic_prob"] {
        assert!(
            body.get(absent).is_none(),
            "`{absent}` must be ABSENT (not null, not stale) when the wire did not complete; \
             got {body}"
        );
    }

    // The evidence row is the half that genuinely succeeded, and the response
    // has to be able to point at it.
    let evidence_id = body["evidence_id"]
        .as_str()
        .expect("evidence_id is reported")
        .parse::<uuid::Uuid>()
        .expect("evidence_id is a UUID");
    let (attached,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM evidence WHERE id = $1 AND claim_id = $2")
            .bind(evidence_id)
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("count the reported evidence row");
    assert_eq!(
        attached, 1,
        "the evidence row the response names must actually be attached to the claim"
    );

    // And the truth_value must NOT have moved in the database either — a
    // response that says `truth_after == truth_before` while the row was
    // rewritten would be a different kind of lie.
    let (truth_after_db,): (f64,) = sqlx::query_as("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("read truth_value after");
    assert!(
        (truth_after_db - truth_before).abs() < f64::EPSILON,
        "the wire did not complete, so the stored truth_value must be untouched: {truth_before} -> \
         {truth_after_db}"
    );

    // `bba_stored: false` must match the tables. (This is a property of a
    // FIRST-step drop, not of `belief_wired: false` in general — the late-step arm
    // below stores a BBA and still reports `belief_wired: false`.)
    let (masses,): (i64,) = sqlx::query_as("SELECT count(*) FROM mass_functions")
        .fetch_one(&pool)
        .await
        .expect("count mass_functions");
    assert_eq!(
        masses, 0,
        "`bba_stored: false` must mean no mass function was written"
    );

    // Labels are deliberately NOT gated on the wire's success. Gating them would
    // reintroduce backlog f14592cb (run-tag labels silently dropped) through a
    // different door, trading one silent loss for another.
    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("read labels");
    assert!(
        labels.contains(&"keeper".to_string()) && labels.contains(&"run-tag-0923".to_string()),
        "a dropped DS wire must not drop the submitted labels — they were accepted independently \
         of the belief computation; got {labels:?}"
    );
}

/// The complement, so `belief_wired` is pinned in BOTH directions and cannot be
/// satisfied by a constant. No injector here: as a `BYPASSRLS` superuser the
/// wiring genuinely lands, which is exactly why this arm cannot stand in for the
/// one above.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successful_ds_wire_reports_belief_wired_true_with_its_measures(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim_with_labels(&pool, "claim whose DS wire lands", &["keeper"]).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let out = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Corroboration submitted with DS wiring available.".into(),
            source_url: None,
            supports: true,
            strength: 0.7,
            labels: vec!["run-tag-0923".into()],
        },
    )
    .await
    .expect("update_with_evidence on a wired path");
    let body = json_of(out);

    assert_eq!(
        body["belief_wired"],
        serde_json::json!(true),
        "the wiring landed here, so the flag must say so — a hardcoded `false` would pass the \
         dropped-wire arm and fail this one; got {body}"
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
    let (masses,): (i64,) = sqlx::query_as("SELECT count(*) FROM mass_functions")
        .fetch_one(&pool)
        .await
        .expect("count mass_functions");
    assert_eq!(
        masses, 1,
        "`belief_wired: true` must mean a mass function was actually written"
    );
}

/// Make ONLY the last step of the wire fail: `update_claim_belief` sets
/// `claims.belief_frame_id`, so a `CHECK (belief_frame_id IS NULL)` refuses it
/// after `store_with_perspective` has already committed the BBA. `NOT VALID` so
/// existing rows do not block the DDL; a seeded claim's `belief_frame_id` is
/// NULL, so the label-merge `UPDATE claims` later in the tool still passes it.
async fn deny_the_cached_belief_write(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE claims \
         ADD CONSTRAINT cached_belief_denied_for_test CHECK (belief_frame_id IS NULL) NOT VALID",
    )
    .execute(pool)
    .await
    .expect("install the late-step failure injector");
}

/// A LATE-step drop: the BBA is stored, then the cached-belief write fails.
/// `belief_wired` is `false` exactly as in the first-step arm, and without
/// `bba_stored` the two responses would be indistinguishable — while needing
/// opposite recoveries (here, submitting the evidence again would count it
/// twice).
#[sqlx::test(migrations = "../../migrations")]
async fn a_late_step_drop_reports_the_bba_it_already_stored(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id =
        seed_claim_with_labels(&pool, "claim whose DS wire drops late", &["keeper"]).await;
    let (truth_before, frame_before): (f64, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT truth_value, belief_frame_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read claim before");
    assert!(
        frame_before.is_none(),
        "precondition: the seeded claim must have NULL belief_frame_id, or the injector would \
         also refuse the label merge and this arm would test the wrong failure"
    );

    deny_the_cached_belief_write(&pool).await;

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let body = json_of(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            UpdateWithEvidenceParams {
                canonical_name: None,
                step_index: None,
                claim_id: claim_id.to_string(),
                evidence_type: "empirical".into(),
                evidence_data: "Corroboration whose cached-belief write is refused.".into(),
                source_url: None,
                supports: true,
                strength: 0.7,
                labels: vec!["run-tag-late".into()],
            },
        )
        .await
        .expect("a late-step drop is best-effort too"),
    );

    assert_eq!(body["belief_wired"], serde_json::json!(false), "got {body}");
    assert_eq!(
        body["bba_stored"],
        serde_json::json!(true),
        "the BBA was stored before `update_claim_belief` failed, and the response must say so; \
         got {body}"
    );
    assert!(
        body["ds_wire_error"]
            .as_str()
            .is_some_and(|e| e.starts_with("update_claim_belief:")),
        "`ds_wire_error` must name the failing step; got {body}"
    );
    assert_eq!(body["truth_before"], body["truth_after"], "got {body}");

    // The tables agree with `bba_stored: true`: exactly one BBA, keyed to the
    // evidence row the response names.
    let evidence_id: uuid::Uuid = body["evidence_id"]
        .as_str()
        .expect("evidence_id is reported")
        .parse()
        .expect("evidence_id is a UUID");
    let (masses_for_evidence,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM mass_functions WHERE evidence_id = $1")
            .bind(evidence_id)
            .fetch_one(&pool)
            .await
            .expect("count this evidence's BBAs");
    assert_eq!(
        masses_for_evidence, 1,
        "the stored BBA is keyed to the evidence row"
    );

    // `claims.truth_value` and the cached columns were not updated...
    let (truth_after_db, cached_betp): (f64, Option<f64>) =
        sqlx::query_as("SELECT truth_value, pignistic_prob FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read claim after");
    assert!((truth_after_db - truth_before).abs() < f64::EPSILON);
    assert!(
        cached_betp.is_none(),
        "the cached pignistic_prob must not have been written; got {cached_betp:?}"
    );

    // ...but a framed read, which recomputes live from stored BBAs, already
    // reflects the evidence. This is why the old "belief_wired=false moved NO
    // belief" wording was false.
    let (frame_id,): (uuid::Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_one(&pool)
            .await
            .expect("binary_truth frame exists after the wire's first step");
    let framed =
        epigraph_engine::belief_query::get_belief(&pool, &viewer, claim_id, Some(frame_id))
            .await
            .expect("framed get_belief");
    assert_eq!(
        framed.source, "recomputed",
        "a framed read must see the stored BBA; got {framed:?}"
    );

    // Labels still merge on this path too.
    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("read labels");
    assert!(
        labels.contains(&"run-tag-late".to_string()),
        "got {labels:?}"
    );
}

/// The recovery a first-step drop does NOT have, pinned so the documented
/// guidance cannot drift back to prescribing it.
///
/// After a first-step drop the evidence row is committed with no BBA. Once the
/// wire works again, re-submitting the SAME `evidence_data` is refused —
/// `evidence_content_hash_claim_unique UNIQUE (content_hash, claim_id)`
/// (migration 001), with `content_hash = blake3(evidence_data)` — so the
/// orphaned row blocks the obvious retry. A RE-WORDED submission is admitted,
/// but it is a second evidence row for the same assertion, and the original row
/// still has no BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn after_a_first_step_drop_an_identical_resubmit_is_refused_and_a_reworded_one_adds_a_row(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim_with_labels(&pool, "claim whose first wire drops", &[]).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let params = |data: &str| UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim_id.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.7,
        labels: vec![],
    };
    let evidence_on_claim = || async {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("count evidence");
        n
    };

    deny_all_writes_to_claim_frames(&pool).await;
    let first = json_of(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            params("The assertion, first wording."),
        )
        .await
        .expect("first-step drop is best-effort"),
    );
    assert_eq!(first["bba_stored"], serde_json::json!(false), "got {first}");
    let original: uuid::Uuid = first["evidence_id"]
        .as_str()
        .expect("evidence_id")
        .parse()
        .expect("uuid");

    // "The wiring is converted": the injector goes away.
    sqlx::query("ALTER TABLE claim_frames DROP CONSTRAINT ds_wiring_denied_for_test")
        .execute(&pool)
        .await
        .expect("drop the injector");

    let identical = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        params("The assertion, first wording."),
    )
    .await;
    let refusal = identical.expect_err(
        "an identical re-submit must be refused by evidence_content_hash_claim_unique — if this \
         now succeeds, the recovery guidance in UpdateResponse::bba_stored is stale",
    );
    assert!(
        refusal.message.contains("Duplicate"),
        "refused as a duplicate, not for some other reason; got {refusal:?}"
    );
    assert_eq!(
        evidence_on_claim().await,
        1,
        "the refused re-submit wrote no row"
    );

    let reworded = json_of(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            params("The assertion, second wording."),
        )
        .await
        .expect("a re-worded submission is admitted"),
    );
    assert_eq!(
        reworded["belief_wired"],
        serde_json::json!(true),
        "got {reworded}"
    );
    assert_eq!(
        evidence_on_claim().await,
        2,
        "a re-worded re-submit is a SECOND evidence row for the same assertion"
    );
    let (original_bbas,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM mass_functions WHERE evidence_id = $1")
            .bind(original)
            .fetch_one(&pool)
            .await
            .expect("count the original row's BBAs");
    assert_eq!(
        original_bbas, 0,
        "the original evidence row stays BBA-less: nothing mints one from an existing row"
    );
}

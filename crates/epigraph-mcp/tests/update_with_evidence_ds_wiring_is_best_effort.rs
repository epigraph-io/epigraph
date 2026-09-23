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
//! Restoring the change returns the file to `2 passed`.

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
/// that no belief moved.
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

    // The belief numbers must reflect that NOTHING changed, rather than echoing
    // the persisted columns (which would manufacture a delta out of a previous
    // call's state).
    assert_eq!(
        body["truth_before"], body["truth_after"],
        "no BBA was materialized, so truth_after must equal truth_before; got {body}"
    );
    assert_eq!(
        body["truth_after"],
        serde_json::json!(truth_before),
        "truth_after must be the claim's UNCHANGED stored truth_value; got {body}"
    );
    for absent in ["belief", "plausibility", "pignistic_prob"] {
        assert!(
            body.get(absent).is_none(),
            "`{absent}` must be ABSENT (not null, not stale) when there is no fresh BBA behind \
             it; got {body}"
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
        "no BBA landed, so the stored truth_value must be untouched: {truth_before} -> \
         {truth_after_db}"
    );

    // No BBA means no BBA: the response's honesty must match the tables.
    let (masses,): (i64,) = sqlx::query_as("SELECT count(*) FROM mass_functions")
        .fetch_one(&pool)
        .await
        .expect("count mass_functions");
    assert_eq!(
        masses, 0,
        "`belief_wired: false` must mean no mass function was written"
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

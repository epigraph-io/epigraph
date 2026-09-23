//! The MCP canonical write path: ONE author-stamped transaction, or nothing.
//!
//! # The two defects these arms pin, and why they are one change
//!
//! `submit_claim` and `memorize` used to do each step on its own pool checkout:
//! `create_claim_idempotent` (which committed), then the `reasoning_traces`
//! INSERT, then `evidence`, then `update_trace_id`. Two failures followed from
//! that single fact.
//!
//! 1. **`42501`.** `apply_session_gucs` is private to `epigraph-db` with exactly
//!    two callers, `ScopedPool::acquire_as` and `ScopedPool::begin_as`, so a
//!    process holding only a `PgPool` cannot stamp a connection at all. Once the
//!    deployed DSN moved to `epigraph_app`, `epigraph_writable_groups` was `{}`
//!    on every MCP connection and migration 077's strict `WITH CHECK` on
//!    `reasoning_traces` refused the trace — on a connection where the claim had
//!    already been admitted.
//! 2. **Non-atomic writes.** The refusal arrived *after* the claim's own commit,
//!    so it left a claim row with no trace, no evidence and no AUTHORED edge, and
//!    returned an error carrying no claim id. The caller could not find what it
//!    had created, and a retry took the content-hash dedup path and reported
//!    success for the still-provenance-less row.
//!
//! # WHY THESE ARMS DO NOT ASSERT ANYTHING ABOUT RLS, AND THAT IS DELIBERATE
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` and
//! the owner of every protected table — so **no policy filters anything here**.
//! An arm shaped "the write now succeeds" would pass identically on the
//! unconverted tree: vacuous. The SQL-level half of the claim belongs to, and is
//! asserted by,
//! `epigraph-db/tests/rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`,
//! which reaches a genuinely non-bypassing role through
//! `SET SESSION AUTHORIZATION`.
//!
//! What IS non-vacuous under superuser is TRANSACTION SEMANTICS. A failure
//! injected into the trace INSERT either takes the claim with it or does not, and
//! that differs before and after the change regardless of which role is
//! connected. So the atomicity arms inject a deterministic failure with a trigger
//! rather than relying on a policy to refuse anything.
//!
//! The fail-closed arms are non-vacuous for a third reason: they assert a REFUSAL
//! that only exists after the change.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::ScopedPool;
use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

/// A server WITH a stamped pool — the shape `main` now builds.
async fn server_with_scoped(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, ScopedPool) {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let server = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false)
        .with_scoped_pool(scoped.clone());
    (server, scoped)
}

/// A server WITHOUT one — the shape every constructor but `with_scoped_pool`
/// produces, and the shape the deployed binary had.
fn server_without_scoped(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool.clone(), signer, embedder, false)
}

fn submit_params(content: &str) -> SubmitClaimParams {
    submit_params_with_evidence(content, "evidence for the write-path atomicity arms")
}

/// `submit_claim` with caller-chosen evidence text.
///
/// MEASURED, and it is a PRE-EXISTING constraint rather than anything this change
/// introduced: migration 001 carries
/// `evidence_content_hash_claim_unique UNIQUE (content_hash, claim_id)`, so a
/// resubmit whose `evidence_data` is byte-identical to a previous submission's
/// always fails on the `evidence` INSERT with `Duplicate entity already exists`.
/// An arm that wants to exercise the resubmit BRANCH therefore has to vary the
/// evidence text; one that uses `submit_params` twice is testing that constraint
/// instead.
///
/// One thing the transaction does change about it, in the right direction: the
/// fresh `reasoning_traces` row this submission wrote is now rolled back with the
/// failure, where before it was left behind unreferenced.
fn submit_params_with_evidence(content: &str, evidence: &str) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "direct_observation".to_string(),
        evidence_data: evidence.to_string(),
        evidence_type: "empirical".to_string(),
        confidence: 0.8,
        source_url: None,
        reasoning: Some("write-path atomicity test".to_string()),
        labels: Vec::new(),
        // 0.0 = always insert. The semantic novelty gate is orthogonal to this
        // file and would otherwise make an arm's outcome depend on whatever else
        // happens to be embedded in the fixture database.
        novelty_threshold: Some(0.0),
    }
}

fn memorize_params(content: &str) -> MemorizeParams {
    MemorizeParams {
        content: content.to_string(),
        confidence: Some(0.7),
        tags: Some(vec!["write-path-atomicity".to_string()]),
        novelty_threshold: Some(0.0),
    }
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claims WHERE content_hash = $1")
        .bind(ContentHasher::hash(content.as_bytes()).as_slice())
        .fetch_one(pool)
        .await
        .expect("count claims by content hash")
}

async fn claim_id_for(pool: &PgPool, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE content_hash = $1")
        .bind(ContentHasher::hash(content.as_bytes()).as_slice())
        .fetch_one(pool)
        .await
        .expect("the claim row must exist")
}

async fn trace_id_of(pool: &PgPool, claim: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT trace_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read trace_id")
}

async fn counts_for(pool: &PgPool, claim: Uuid) -> (i64, i64) {
    let traces =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reasoning_traces WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("count traces");
    let evidence =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("count evidence");
    (traces, evidence)
}

/// Make every `reasoning_traces` INSERT fail, deterministically.
///
/// A trigger rather than a policy: the harness role is `BYPASSRLS` and owns the
/// table, so no policy can refuse it, and an arm that depended on one would be
/// asserting nothing. The trigger reproduces the *shape* of the production
/// failure — the trace INSERT is refused, the claim INSERT ahead of it is not —
/// which is the only property the atomicity claim turns on. Never cleaned up:
/// `#[sqlx::test]` throws the database away.
async fn refuse_every_trace_insert(pool: &PgPool) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION refuse_trace_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             RAISE EXCEPTION 'refused reasoning_traces insert (test trigger)'
                 USING ERRCODE = '42501';
         END $$",
    )
    .execute(pool)
    .await
    .expect("create the refusing trigger function");
    sqlx::query(
        "CREATE TRIGGER refuse_trace_for_test BEFORE INSERT ON reasoning_traces
         FOR EACH ROW EXECUTE FUNCTION refuse_trace_for_test()",
    )
    .execute(pool)
    .await
    .expect("install the refusing trigger");
}

// ───────────────────────────────────────────────────────────────────────────
// FAIL CLOSED: no ScopedPool => no write, and say so
// ───────────────────────────────────────────────────────────────────────────

/// A process that cannot stamp a connection must REFUSE, never fall back to the
/// unstamped pool.
///
/// The fallback is not hypothetical — it is the deployed behaviour this change
/// replaces, and its outcome is a committed claim whose trace was then refused.
/// So the assertion has two halves and both matter: an error, AND nothing
/// written.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_without_a_scoped_pool_refuses_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server_without_scoped(&pool, 0xB1);
    let content = format!("no-scoped submit {}", Uuid::new_v4());

    let err = tools::claims::submit_claim(&server, &viewer, submit_params(&content))
        .await
        .expect_err(
            "a server with no ScopedPool cannot stamp the author's tenancy context, so it must \
             refuse. Succeeding here means the write ran on the unstamped pool — which commits \
             the claim and then loses its trace to a 42501, the exact defect this closes.",
        );
    assert!(
        err.message.contains("not built from a ScopedPool"),
        "the refusal must name the missing ScopedPool so an operator can act on it; got: {}",
        err.message
    );
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "the refusal must leave NOTHING behind. A claim row here is the orphan the whole \
         change exists to stop producing."
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_without_a_scoped_pool_refuses_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server_without_scoped(&pool, 0xB2);
    let content = format!("no-scoped memorize {}", Uuid::new_v4());

    let err = tools::memory::memorize(&server, &viewer, memorize_params(&content))
        .await
        .expect_err("memorize must refuse without a ScopedPool, for submit_claim's reasons");
    assert!(
        err.message.contains("not built from a ScopedPool"),
        "got: {}",
        err.message
    );
    assert_eq!(claims_with_content(&pool, &content).await, 0);
}

// ───────────────────────────────────────────────────────────────────────────
// ATOMICITY: a refused trace takes the claim with it
// ───────────────────────────────────────────────────────────────────────────

/// THE SECOND DEFECT, pinned. `claim_helper.rs` used to log the outcome in as
/// many words: *"claim row persisted as orphan"*.
///
/// Non-vacuous under the superuser harness because it asserts TRANSACTION
/// semantics, not row visibility: before the change the claim was committed by
/// `create_claim_idempotent` before the trace was attempted, so this arm found a
/// row; after it, claim and trace share one transaction and the row is gone.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_trace_rolls_the_claim_back_in_submit_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB3).await;
    refuse_every_trace_insert(&pool).await;
    let content = format!("rollback submit {}", Uuid::new_v4());

    let err = tools::claims::submit_claim(&server, &viewer, submit_params(&content))
        .await
        .expect_err("the refused trace must surface as an error");
    assert!(
        err.message.contains("refused reasoning_traces insert"),
        "the underlying cause must reach the caller rather than being replaced by a \
         commit-time `current transaction is aborted`; got: {}",
        err.message
    );

    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "the claim must have rolled back with its trace. A count of 1 is the orphan: a \
         committed claim with no trace, no evidence and no AUTHORED edge, returned to the \
         caller as an error with no id."
    );
    let orphan_edges =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM edges WHERE relationship = 'AUTHORED'")
            .fetch_one(&pool)
            .await
            .expect("count AUTHORED edges");
    assert_eq!(
        orphan_edges, 0,
        "the AUTHORED edge was emitted inside the same transaction and must be gone too"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_trace_rolls_the_claim_back_in_memorize(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB4).await;
    refuse_every_trace_insert(&pool).await;
    let content = format!("rollback memorize {}", Uuid::new_v4());

    tools::memory::memorize(&server, &viewer, memorize_params(&content))
        .await
        .expect_err("the refused trace must surface as an error");

    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "memorize's claim must roll back with its trace"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// THE HAPPY PATH, as a calibration for the two arms above
// ───────────────────────────────────────────────────────────────────────────

/// Without this, the two rollback arms are satisfied by a write path that
/// refuses everyone — which would prove nothing about atomicity.
///
/// It does NOT prove anything about RLS (see the module doc); it proves the
/// transaction commits and carries all four rows.
#[sqlx::test(migrations = "../../migrations")]
async fn the_committed_submission_carries_claim_trace_evidence_and_link(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB5).await;
    let content = format!("happy submit {}", Uuid::new_v4());

    tools::claims::submit_claim(&server, &viewer, submit_params(&content))
        .await
        .expect("CALIBRATION: a submission on a stamped connection must succeed");

    let claim = claim_id_for(&pool, &content).await;
    let (traces, evidence) = counts_for(&pool, claim).await;
    assert_eq!(traces, 1, "exactly one reasoning_traces row");
    assert_eq!(evidence, 1, "exactly one evidence row");
    assert!(
        trace_id_of(&pool, claim).await.is_some(),
        "claims.trace_id must be linked in the same transaction"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// THE RETRY-OVER-AN-ORPHAN REGRESSION
// ───────────────────────────────────────────────────────────────────────────

/// Simulate the residue a production 42501 left behind: a claim row whose
/// provenance was never written.
///
/// Built by writing a real submission and then stripping its provenance, rather
/// than hand-rolling a `claims` INSERT — the point is that the row is
/// byte-identical to one the write path produced, so the dedup path really does
/// recognise it on the retry.
async fn strip_provenance(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET trace_id = NULL WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("null the trace link");
    sqlx::query("DELETE FROM reasoning_traces WHERE claim_id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("delete the trace");
    sqlx::query("DELETE FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("delete the evidence");
}

/// A retry over an existing ORPHAN must repair it, not report bare success.
///
/// `memory.rs` used to record that the content-hash dedup path skips "Evidence +
/// Trace + update_trace_id + DS + embed". For a claim that is already an orphan
/// that is exactly the wrong branch: the retry a caller performs in order to
/// repair the row returned `{"embedded": false}` and HTTP success, forever, for a
/// row with no provenance at all. Gated on `trace_id IS NULL` and not widened to
/// every resubmit — relinking a claim that already has a canonical trace would
/// rewrite settled provenance.
#[sqlx::test(migrations = "../../migrations")]
async fn a_memorize_retry_over_an_existing_orphan_repairs_its_provenance(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB6).await;
    let content = format!("orphan memorize {}", Uuid::new_v4());

    tools::memory::memorize(&server, &viewer, memorize_params(&content))
        .await
        .expect("the first memorize establishes the row");
    let claim = claim_id_for(&pool, &content).await;
    strip_provenance(&pool, claim).await;

    // Calibration: the fixture really did produce an orphan.
    assert!(trace_id_of(&pool, claim).await.is_none());
    assert_eq!(counts_for(&pool, claim).await, (0, 0));

    tools::memory::memorize(&server, &viewer, memorize_params(&content))
        .await
        .expect("the retry must succeed");

    assert_eq!(
        claims_with_content(&pool, &content).await,
        1,
        "the retry must repair the existing row, never insert a second one"
    );
    assert!(
        trace_id_of(&pool, claim).await.is_some(),
        "the retry must LINK a trace. A `None` here is the regression: bare HTTP success for \
         a row the caller retried precisely because it had no provenance."
    );
    let (traces, evidence) = counts_for(&pool, claim).await;
    assert_eq!(traces, 1, "the repair writes exactly one trace");
    assert_eq!(evidence, 1, "and exactly one evidence row");
}

/// The same repair on `submit_claim`, whose orphan shape differs in one way
/// worth pinning separately: it already wrote a fresh Trace and Evidence on
/// every resubmit, and skipped only `update_trace_id` — so the row accumulated
/// unreferenced traces while `claims.trace_id` stayed NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn a_submit_claim_retry_over_an_existing_orphan_links_its_trace(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB7).await;
    let content = format!("orphan submit {}", Uuid::new_v4());

    tools::claims::submit_claim(&server, &viewer, submit_params(&content))
        .await
        .expect("the first submission establishes the row");
    let claim = claim_id_for(&pool, &content).await;
    strip_provenance(&pool, claim).await;
    assert!(trace_id_of(&pool, claim).await.is_none());

    tools::claims::submit_claim(&server, &viewer, submit_params(&content))
        .await
        .expect("the retry must succeed");

    assert_eq!(claims_with_content(&pool, &content).await, 1);
    assert!(
        trace_id_of(&pool, claim).await.is_some(),
        "the retry must link the trace it just wrote; leaving trace_id NULL while inserting \
         another unreferenced reasoning_traces row is the pre-fix behaviour"
    );
}

/// The guard on the repair: a resubmit over a HEALTHY claim must not relink it.
///
/// Without this, `needs_trace_link` could be widened to every resubmit and every
/// arm above would still pass, while each resubmit silently rewrote the claim's
/// canonical provenance pointer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_resubmit_over_a_healthy_claim_keeps_its_canonical_trace(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (server, _scoped) = server_with_scoped(&pool, 0xB8).await;
    let content = format!("healthy resubmit {}", Uuid::new_v4());

    tools::claims::submit_claim(
        &server,
        &viewer,
        submit_params_with_evidence(&content, "healthy resubmit, first evidence"),
    )
    .await
    .expect("first submission");
    let claim = claim_id_for(&pool, &content).await;
    let first_trace = trace_id_of(&pool, claim)
        .await
        .expect("the first submission links a trace");

    // Distinct evidence text: see `submit_params_with_evidence` for why identical
    // evidence would hit migration 001's UNIQUE(content_hash, claim_id) instead
    // of reaching the branch under test.
    tools::claims::submit_claim(
        &server,
        &viewer,
        submit_params_with_evidence(&content, "healthy resubmit, second evidence"),
    )
    .await
    .expect("resubmit");

    assert_eq!(
        trace_id_of(&pool, claim).await,
        Some(first_trace),
        "a resubmit over a claim that ALREADY has a trace must leave the canonical pointer \
         alone; the repair arm is scoped to trace_id IS NULL for this reason"
    );
}

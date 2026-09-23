//! `claim_text_if_embedding_missing`: the predicate the MCP write path's
//! orphan-repair arm asks before it re-embeds a claim.
//!
//! # The defect these arms pin
//!
//! `submit_claim` and `memorize` gated their post-commit embed on `was_created`
//! alone, on the reasoning that a content-hash dedup hit means the canonical row
//! already carries its vector. For the row the orphan-repair arms exist for that
//! is false, and the code said so out loud: *"skip embed (canonical embedding
//! already exists)"*.
//!
//! A production orphan is a claim whose submission committed the claim and was
//! then refused on `reasoning_traces` with `42501` — and in the pre-transaction
//! code that refusal returned BEFORE the post-commit embed. So the orphan carries
//! `is_current = true` AND `embedding IS NULL`, which is CLAUDE.md's
//! `live_missing` invariant violation. A retry that repaired its trace and
//! evidence but left that NULL in place returned `{"embedded": false}` with HTTP
//! success for a claim that stays invisible to `recall()` forever.
//!
//! # Why the decision is asserted HERE and not in the MCP arms
//!
//! `McpEmbedder::new(pool, None)` has no API key and `embed.rs` posts to a
//! hardcoded `https://api.openai.com/v1/embeddings`, so no offline arm can make a
//! real embedding succeed and no MCP arm can observe a restored vector. What the
//! fix actually changes is one SQL predicate — *should this resubmit embed?* —
//! and that is fully assertable. `mcp_write_path_atomicity.rs::strip_provenance`
//! is what makes the fixture there production-shaped (it nulls the vector too);
//! this file is what says the answer is right.
//!
//! # The telemetry arm is the one that would be missed
//!
//! Host-provenance claims are `is_current = true` with `embedding IS NULL` BY
//! DESIGN — CLAUDE.md's telemetry exception, and they DOMINATE the gap. A naive
//! `embedding IS NULL` gate would make every telemetry resubmit pay an embedding
//! call and pollute semantic recall, turning a repair into a new invariant
//! violation on the highest-volume claim population. The shared
//! `EMBEDDABLE_POPULATION` predicate is what stops that, and the two arms below
//! are what stop the predicate being quietly dropped from this read.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// A 1536-dimension pgvector literal — the shape `claims.embedding` takes.
fn some_vector() -> String {
    let mut s = String::from("[");
    for i in 0..1536 {
        if i > 0 {
            s.push(',');
        }
        s.push_str("0.001");
    }
    s.push(']');
    s
}

async fn label_claim(pool: &PgPool, claim: Uuid, label: &str) {
    sqlx::query("UPDATE claims SET labels = ARRAY[$2::text] WHERE id = $1")
        .bind(claim)
        .bind(label)
        .execute(pool)
        .await
        .expect("label the claim");
}

/// THE REPAIR CASE: a claim in the embedded population whose vector is missing
/// returns its text, so the caller embeds it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_missing_its_vector_returns_its_text(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "embedrepair").await;
    let claim = fixture::seed_public_claim(&pool, agent, "orphan with no vector").await;

    let text = ClaimRepository::claim_text_if_embedding_missing(&pool, &viewer, claim)
        .await
        .expect("read the repair predicate");
    assert_eq!(
        text.as_deref(),
        Some("orphan with no vector"),
        "a live, unsealed, non-telemetry claim with `embedding IS NULL` is exactly the row the \
         repair arm must embed. `None` here is the regression: the resubmit reports success and \
         the claim stays unrecallable."
    );
}

/// THE GUARD: a claim that already carries a vector must NOT be re-embedded.
///
/// Without this the gate could be widened to every resubmit and the arm above
/// would still pass, while each resubmit paid an embedding call for a row that
/// did not need one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_that_already_has_a_vector_returns_none(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "embedrepair2").await;
    let claim = fixture::seed_public_claim(&pool, agent, "healthy claim with a vector").await;
    fixture::set_claim_embedding(&pool, claim, &some_vector()).await;

    let text = ClaimRepository::claim_text_if_embedding_missing(&pool, &viewer, claim)
        .await
        .expect("read the repair predicate");
    assert_eq!(
        text, None,
        "a claim that already has its vector must not be re-embedded"
    );
}

/// THE TELEMETRY EXCEPTION, both markers.
///
/// `telemetry`-labelled and `properties->>'event'`-marked claims are
/// `embedding IS NULL` on purpose. If either clause is dropped from the shared
/// predicate, this arm fails and the arm above does not — which is the whole
/// reason it is separate.
#[sqlx::test(migrations = "../../migrations")]
async fn telemetry_claims_are_never_offered_for_repair(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "embedrepair3").await;

    let labelled = fixture::seed_public_claim(&pool, agent, "telemetry by label").await;
    label_claim(&pool, labelled, "telemetry").await;

    let marked = fixture::seed_public_claim(&pool, agent, "telemetry by properties marker").await;
    sqlx::query(
        "UPDATE claims SET properties = '{\"event\": \"container.started\"}'::jsonb \
                 WHERE id = $1",
    )
    .bind(marked)
    .execute(&pool)
    .await
    .expect("mark the claim as a host-provenance event");

    for (claim, why) in [
        (labelled, "the `telemetry` label"),
        (marked, "the `properties->>'event'` marker"),
    ] {
        let text = ClaimRepository::claim_text_if_embedding_missing(&pool, &viewer, claim)
            .await
            .expect("read the repair predicate");
        assert_eq!(
            text, None,
            "a host-provenance claim carrying {why} is `embedding IS NULL` BY DESIGN and \
             dominates the is_current gap. Offering it for repair would make every telemetry \
             resubmit pay an OpenAI call and pollute semantic recall — a new invariant \
             violation, produced by the fix for a different one."
        );
    }
}

/// A superseded claim is not an embedding gap: the invariant says
/// `is_current = false` rows carry `embedding = NULL` deliberately.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_claim_is_not_offered_for_repair(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "embedrepair4").await;
    let claim =
        fixture::seed_public_claim(&pool, agent, "superseded, vector nulled on purpose").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("supersede the claim");

    let text = ClaimRepository::claim_text_if_embedding_missing(&pool, &viewer, claim)
        .await
        .expect("read the repair predicate");
    assert_eq!(
        text, None,
        "`is_current = false` with `embedding = NULL` is the invariant holding, not a gap"
    );
}

/// The read has to work as the DEPLOYED ROLE, not only as the test harness's
/// superuser.
///
/// `#[sqlx::test]` connects as `epigraph`, which is superuser and `BYPASSRLS`, so
/// every arm above observes the in-query predicate alone and never migration
/// 077's policies. The MCP write path runs this read on `server.pool` as
/// `epigraph_app` with no tenancy GUCs stamped — the same shape whose absence of
/// a stamp is the defect this branch exists to fix — so an arm that never
/// downgrades cannot tell "the predicate is right" from "the read would be
/// refused in production and the repair silently skipped".
#[sqlx::test(migrations = "../../migrations")]
async fn the_repair_read_works_on_an_unstamped_app_connection(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "embedrepair5").await;
    let claim = fixture::seed_public_claim(&pool, agent, "repairable as epigraph_app").await;

    // Resolve BEFORE downgrading: `Viewer::resolve` on a downgraded unstamped
    // session reads no memberships (see `downgraded_pool`'s doc).
    let viewer = fixture::public_viewer(&pool).await;

    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(&pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so this arm is vacuous. Fix the role, not this test."
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let text = ClaimRepository::claim_text_if_embedding_missing(&app, &viewer, claim)
        .await
        .expect("the repair read must not be refused as epigraph_app");
    assert_eq!(
        text.as_deref(),
        Some("repairable as epigraph_app"),
        "a public claim missing its vector must be visible to the unstamped app connection the \
         write path performs this read on; `None` here means every production repair silently \
         decides not to embed"
    );
}

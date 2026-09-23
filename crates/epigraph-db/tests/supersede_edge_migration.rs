//! `ClaimRepository::supersede` — which edges follow the replacement (issue #398).
//!
//! Before this, both migration statements filtered only on
//! `relationship != 'supersedes'`, so `refutes`/`contradicts` were re-pointed
//! along with everything else. Two consequences were observed in production:
//!
//! * incoming — refuting a false claim and then correcting it moved the
//!   refutation onto the correction, so the fix arrived pre-refuted and
//!   `recall(exclude_contested: true)` dropped it;
//! * outgoing — superseding a claim that held two `contradicts` edges moved
//!   them onto a replacement whose entire content was a *retraction* of those
//!   objections, recording it as contesting the claims it declared correct.
//!
//! These tests assert on the EDGE ROW's endpoints, deliberately, and not on a
//! downstream `dispute_count`: `dispute_batch` joins `src.is_current`, so a
//! dispute-count assertion would come out clean over the unmodified code for
//! the outgoing case and prove nothing.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, sha256($2::text::bytea))")
        .bind(id)
        .bind(id.to_string())
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, sha256($3::text::bytea), $4, 0.8, true)",
    )
    .bind(id)
    .bind(content)
    .bind(id.to_string())
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// `(source_id, target_id)` of one edge, by id.
async fn endpoints(pool: &PgPool, edge_id: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as::<_, (Uuid, Uuid)>("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(edge_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The production incident, incoming side: a refutation filed against the
/// original must not be re-pointed at the correction.
#[sqlx::test(migrations = "../../migrations")]
async fn refutes_edge_filed_against_the_original_stays_on_the_original(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let refuter = seed_claim(&pool, agent, "the geometric objection is withdrawn").await;
    let original = seed_claim(&pool, agent, "geometric confound invalidates the series").await;
    let edge = seed_edge(&pool, refuter, original, "refutes").await;

    let (replacement, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(original),
        "corrected series; the geometric objection is withdrawn",
        TruthValue::clamped(0.9),
        "correcting the confound inference",
    )
    .await
    .unwrap();

    let (src, tgt) = endpoints(&pool, edge).await;
    assert_eq!(
        src, refuter,
        "the refuting claim must remain the edge's source"
    );
    assert_eq!(
        tgt, original,
        "the refutation was filed against {original}; re-pointing it at the \
         correction {replacement} makes the fix arrive pre-refuted"
    );
}

/// The production incident, outgoing side: a `contradicts` asserted BY the
/// original must not follow a replacement that retracts it.
#[sqlx::test(migrations = "../../migrations")]
async fn contradicts_edge_asserted_by_the_original_stays_on_the_original(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let objected_to = seed_claim(&pool, agent, "the measurement stands").await;
    let original = seed_claim(&pool, agent, "the measurement is confounded").await;
    let edge = seed_edge(&pool, original, objected_to, "contradicts").await;

    let (replacement, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(original),
        "withdrawing the confound objection; the measurement is sound",
        TruthValue::clamped(0.9),
        "retracting the objection",
    )
    .await
    .unwrap();

    let (src, tgt) = endpoints(&pool, edge).await;
    assert_eq!(
        src, original,
        "the objection was asserted by {original}; re-sourcing it at {replacement} \
         records a retraction as contesting the claim it declared correct"
    );
    assert_eq!(tgt, objected_to, "the target must not move");
}

/// The exclusion is scoped to the weakening set. Negative control: this
/// direction of the behaviour is UNCHANGED by the fix and passes both before
/// and after — it is here so an over-broad predicate (e.g. excluding every
/// epistemic relationship, or every incoming edge) fails loudly.
#[sqlx::test(migrations = "../../migrations")]
async fn strengthening_edges_still_migrate_in_both_directions(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let supporter = seed_claim(&pool, agent, "independent replication").await;
    let downstream = seed_claim(&pool, agent, "the downstream inference").await;
    let original = seed_claim(&pool, agent, "the original finding").await;
    let incoming = seed_edge(&pool, supporter, original, "supports").await;
    let outgoing = seed_edge(&pool, original, downstream, "generalizes").await;

    let (replacement, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(original),
        "the original finding, restated with tighter bounds",
        TruthValue::clamped(0.9),
        "tightening bounds",
    )
    .await
    .unwrap();

    let (_, in_tgt) = endpoints(&pool, incoming).await;
    assert_eq!(
        in_tgt, replacement,
        "incoming `supports` must still follow the replacement"
    );
    let (out_src, _) = endpoints(&pool, outgoing).await;
    assert_eq!(
        out_src, replacement,
        "outgoing `generalizes` must still follow the replacement"
    );
}

// NOTE on the self-loop guards this change also adds to both statements:
// there is deliberately no test, because the precondition cannot be built.
// `edges_no_self_loop` (`CHECK (source_id <> target_id OR source_type <>
// target_type)`, migration 001) refuses to store a claim→claim self-edge —
// attempting to seed one here fails with SQLSTATE 23514 — and `supersede` mints
// its replacement inside the transaction, so no pre-existing edge can name it
// either. The guards are defence in depth against a future relaxation of that
// CHECK; see `ClaimRepository::supersede`'s doc comment.

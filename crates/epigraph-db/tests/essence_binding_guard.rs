//! The write-side guard of essence binding: migration 074's
//! `edges_paper_asserts_requires_essence` trigger (backlog 7c909c49).
//!
//! Every test here is written against the PRE-CHANGE public API on purpose —
//! `create_if_not_exists`, `mark_duplicate`, raw SQL — so the file compiles on
//! the tree before the fix and can be run red there. With migration 074 moved
//! aside, `new_unbound_paper_asserts_edge_is_refused`,
//! `an_update_may_not_strip_a_digest_that_was_present` and
//! `an_update_may_not_launder_another_edge_into_an_unbound_asserts_edge` all
//! fail; with it in place all four pass.
//!
//! The fourth test is the one that decided the MECHANISM. The obvious guard is
//! `ALTER TABLE edges ADD CONSTRAINT ... CHECK (...) NOT VALID`, on the theory
//! that NOT VALID grandfathers the pre-essence corpus. It does not: PostgreSQL
//! skips only the initial table scan and still enforces on every later UPDATE,
//! so `mark_duplicate`'s edge retarget (claim.rs:3211) dies with SQLSTATE 23514
//! on any legacy `asserts` row. A BEFORE INSERT OR UPDATE trigger sees OLD and
//! can tell "was already unbound" (allow) from "is being unbound" (reject),
//! which no CHECK can.

mod helpers;

use epigraph_core::ClaimId;
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};
use uuid::Uuid;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent = make_agent(Some("essence-guard"));
    AgentRepository::create(pool, &agent)
        .await
        .unwrap()
        .id
        .into()
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let claim = make_claim(epigraph_core::AgentId::from_uuid(agent_id), content, 0.5);
    ClaimRepository::create(pool, &claim)
        .await
        .unwrap()
        .id
        .into()
}

/// Write an `asserts` edge the way ingestion did BEFORE this change, bypassing
/// the trigger so a legacy row can be staged. `session_replication_role` is the
/// supported way to insert a row a trigger would now refuse.
async fn insert_legacy_unbound_asserts(pool: &PgPool, paper_id: Uuid, claim_id: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .unwrap();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts', '{}'::jsonb) RETURNING id",
    )
    .bind(paper_id)
    .bind(claim_id)
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    sqlx::query("SET session_replication_role = origin")
        .execute(&mut *conn)
        .await
        .unwrap();
    id
}

/// The defect, stated as a requirement: a DOCUMENT may not assert a claim
/// without naming the bytes the claim was extracted from.
#[sqlx::test(migrations = "../../migrations")]
async fn new_unbound_paper_asserts_edge_is_refused(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let paper = PaperRepository::get_or_create(&pool, "10.9999/essence-refuse", Some("T"), None)
        .await
        .unwrap();
    let claim = seed_claim(&pool, agent, "a paragraph lifted from the artifact").await;

    // Exactly what the four ingestion call sites did before this change.
    let unbound = EdgeRepository::create_if_not_exists(
        &pool, paper, "paper", claim, "claim", "asserts", None, None, None,
    )
    .await;
    assert!(
        unbound.is_err(),
        "an asserts edge with no essence_digest was accepted — the claim is \
         bound to no artifact bytes at all"
    );

    // A malformed digest is not a digest. Uppercase hex, a truncation and a
    // non-hex string must all be refused, or the column is decorative.
    for bad in [
        "not-a-digest",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &DIGEST_A[..63],
    ] {
        let res = EdgeRepository::create_if_not_exists(
            &pool,
            paper,
            "paper",
            claim,
            "claim",
            "asserts",
            Some(serde_json::json!({ "essence_digest": bad })),
            None,
            None,
        )
        .await;
        assert!(res.is_err(), "malformed digest {bad:?} was accepted");
    }

    // ...and a well-formed one is accepted.
    let (row, created) = EdgeRepository::create_if_not_exists(
        &pool,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        Some(serde_json::json!({ "level": 2, "essence_digest": DIGEST_A })),
        None,
        None,
    )
    .await
    .expect("a bound asserts edge must be accepted");
    assert!(created);
    assert_eq!(row.properties["essence_digest"], DIGEST_A);
}

/// D7: only `source_type = 'paper'` is constrained. `do_ingest_document`
/// rewrites the builder's `author_placeholder -asserts-> claim` plan edges into
/// `agent -asserts-> claim`, and an AUTHOR asserting a claim is a different
/// relation from a DOCUMENT asserting one. Pins the guard so it can never
/// become collateral damage on the author path.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_asserts_claim_stays_unconstrained(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent, "an author's own assertion").await;

    let (_row, created) = EdgeRepository::create_if_not_exists(
        &pool, agent, "agent", claim, "claim", "asserts", None, None, None,
    )
    .await
    .expect("agent -asserts-> claim must remain writable without a digest");
    assert!(created);
}

/// The measured refutation of `CHECK ... NOT VALID`. `mark_duplicate` retargets
/// every non-`supersedes` edge pointing at the duplicate, which includes
/// grandfathered `asserts` rows. Under a NOT VALID CHECK this UPDATE dies with
/// SQLSTATE 23514; under the trigger it must still succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn dedup_can_still_retarget_a_legacy_unbound_asserts_edge(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let paper = PaperRepository::get_or_create(&pool, "10.9999/essence-dedup", Some("T"), None)
        .await
        .unwrap();
    let dup = seed_claim(&pool, agent, "duplicate paragraph text").await;
    let canonical = seed_claim(&pool, agent, "canonical paragraph text").await;

    let legacy = insert_legacy_unbound_asserts(&pool, paper, dup).await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup must still be able to retarget a pre-essence asserts edge");

    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(legacy)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        target, canonical,
        "the legacy edge must have been retargeted"
    );
}

/// The property a `CHECK ... NOT VALID` provably cannot hold: a digest that IS
/// present may not be removed or corrupted by a later UPDATE. Only a trigger
/// sees OLD, and only OLD separates "was already unbound" from "is being
/// unbound".
#[sqlx::test(migrations = "../../migrations")]
async fn an_update_may_not_strip_a_digest_that_was_present(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let paper = PaperRepository::get_or_create(&pool, "10.9999/essence-strip", Some("T"), None)
        .await
        .unwrap();
    let claim = seed_claim(&pool, agent, "a bound paragraph").await;

    let (bound_edge, _) = EdgeRepository::create_if_not_exists(
        &pool,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        Some(serde_json::json!({ "essence_digest": DIGEST_A })),
        None,
        None,
    )
    .await
    .unwrap();

    for stripping in [
        serde_json::json!({}),
        serde_json::json!({ "essence_digest": null }),
        serde_json::json!({ "essence_digest": "" }),
        serde_json::json!({ "essence_digest": 7 }),
    ] {
        let res = sqlx::query("UPDATE edges SET properties = $2 WHERE id = $1")
            .bind(bound_edge.id)
            .bind(&stripping)
            .execute(&pool)
            .await;
        assert!(res.is_err(), "digest was strippable via {stripping}");
    }

    // Re-binding to a DIFFERENT well-formed digest is not stripping and stays
    // legal — a re-source or a repair may legitimately do it.
    sqlx::query("UPDATE edges SET properties = jsonb_build_object('essence_digest', $2::text) WHERE id = $1")
        .bind(bound_edge.id)
        .bind(DIGEST_B)
        .execute(&pool)
        .await
        .expect("re-binding to another well-formed digest must stay legal");
}

/// Grandfathering must not become a laundering route: an UPDATE that turns some
/// OTHER edge into a `paper -asserts-> claim` row is a NEW assertion and is held
/// to the insert standard, even though `TG_OP = 'UPDATE'`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_update_may_not_launder_another_edge_into_an_unbound_asserts_edge(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let paper = PaperRepository::get_or_create(&pool, "10.9999/essence-launder", Some("T"), None)
        .await
        .unwrap();
    let claim = seed_claim(&pool, agent, "a laundered paragraph").await;

    // A perfectly ordinary, unconstrained edge.
    let (other, _) = EdgeRepository::create_if_not_exists(
        &pool, paper, "paper", claim, "claim", "mentions", None, None, None,
    )
    .await
    .unwrap();

    let res = sqlx::query("UPDATE edges SET relationship = 'asserts' WHERE id = $1")
        .bind(other.id)
        .execute(&pool)
        .await;
    assert!(
        res.is_err(),
        "an unbound edge was laundered into an asserts edge by an UPDATE"
    );
}

#![cfg(feature = "db")]
//! Acceptance item 21 (`docs/tenancy/FINAL-PLAN.md` §8, §8.5): the
//! unique-constraint / dedup-probe existence oracle, over HTTP.
//!
//! # The rule these tests hold the write paths to
//!
//! §8.5: *any operation on a resource the `Viewer` cannot read returns
//! byte-identical status and body to a nonexistent resource.* Item 21 is the
//! write-side residual of that rule: a unique constraint or a dedup probe
//! answers "this row already exists" whether or not the caller may read the
//! row, so an insert that collides with an invisible row can leak the row's
//! existence (or, for a dedup probe that RETURNS the row, the row itself).
//!
//! # What the plan named, and what is actually on the tree
//!
//! The plan named `idx_edges_unique_triple`. Migrations 017/018 dropped it (and
//! 053 its drifted copy), so there is no edge triple constraint to collide
//! with. The surface this file covers is:
//!
//! * **claims** — `uq_claims_content_hash_agent UNIQUE (content_hash,
//!   agent_id)` (migration 013), reachable by a stranger because the body's
//!   `agent_id` is not a credential (`D-PR16-claim-authorship-is-not-a-credential`).
//!   Fixed to the WEAKER form item 21 states: a collision with an invisible row
//!   answers with exactly the generic conflict a collision with a visible row
//!   answers with, and never a distinctive error. It still differs from the
//!   ABSENT case (409 vs 201). Closing that needs the constraint keyed on
//!   `owner_group_id`, which is a migration and is recorded as
//!   `D-N21-unique-keys-omit-owner-group` in `docs/tenancy/progress.json`.
//!   Nothing here asserts the residual, so the day that migration lands these
//!   tests stay green and the register entry is what has to move.
//!
//! # Why every claims test first proves the constraint is there
//!
//! Test fixtures in `epigraph-db/tests/claim_repo_helpers.rs` and
//! `epigraph-mcp/tests/common/mod.rs` DROP `uq_claims_content_hash_agent`, and
//! the long-lived production database has lost it to exactly that (see
//! `migrations/README.md`). On a schema without it there is no collision, the
//! stranger's write simply lands, and every "invisible answers like visible"
//! assertion below would pass for the wrong reason. `#[sqlx::test]` builds a
//! fresh database from `migrations/`, so it is present — and asserted.

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

/// Fail loudly if the schema under test has no `(content_hash, agent_id)`
/// constraint: without it the claims arms below are vacuous.
async fn assert_content_hash_constraint_present(pool: &PgPool) {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint \
         WHERE conname = 'uq_claims_content_hash_agent' AND conrelid = 'claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        present, 1,
        "uq_claims_content_hash_agent is absent from `claims`. Without it a \
         stranger's write never collides and every assertion in this file \
         passes vacuously; this database has drifted (migrations/README.md)."
    );
}

/// A claim whose `content_hash` is the REAL BLAKE3 of its content.
///
/// `fixture::seed_*_claim` writes a stand-in hash, which is fine for reads and
/// useless here: the collision under test is on `content_hash`, and the write
/// path computes it with `ContentHasher`. A stand-in would never collide.
async fn seed_claim_hashed(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, 0.5, $3, true, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(visibility)
    .bind(owner_group_id)
    .fetch_one(pool)
    .await
    .expect("seed hashed claim")
}

async fn post_json(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("response body");
    (status, text)
}

async fn visible_to(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> bool {
    ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(claim))
        .await
        .expect("get_by_id")
        .is_some()
}

// ─────────────────────────────────────────────────────────────────────────
// claims — uq_claims_content_hash_agent
// ─────────────────────────────────────────────────────────────────────────

/// A stranger who aims `POST /api/v1/claims` at a victim's `(content, agent_id)`
/// gets, for a row it cannot read, EXACTLY the answer it gets for a row it can:
/// the same status and the same bytes, on both `if_not_exists` settings.
///
/// Before this change the `if_not_exists = true` arm answered an invisible
/// collision with a distinctive error (the re-find after the `23505` found
/// nothing), which is a three-way oracle: 200 visible / 201 absent / that error
/// invisible.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_collision_on_an_invisible_row_answers_exactly_like_a_visible_one(pool: PgPool) {
    assert_content_hash_constraint_present(&pool).await;

    let (victim, victim_group) = fixture::seed_agent_with_group(&pool, "n21-victim").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "n21-stranger").await;

    let private_content = format!("n21 private claim {}", Uuid::new_v4());
    let public_content = format!("n21 public claim {}", Uuid::new_v4());
    let private = seed_claim_hashed(&pool, victim, &private_content, "group", victim_group).await;
    let public = seed_claim_hashed(&pool, victim, &public_content, "public", victim_group).await;

    // PREMISE, both directions: the stranger reads the public row and not the
    // private one, and the victim reads both. Without it "identical" below
    // could mean "both visible" or "both invisible".
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let victim_viewer = Viewer::resolve(&pool, victim).await.expect("resolve");
    assert!(visible_to(&pool, &stranger_viewer, public).await);
    assert!(!visible_to(&pool, &stranger_viewer, private).await);
    assert!(visible_to(&pool, &victim_viewer, private).await);

    let url = fixture::database_url_for(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (stranger_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], stranger)
            .await;
    let (victim_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], victim)
            .await;

    let body = |content: &str, if_not_exists: bool| {
        serde_json::json!({
            "content": content,
            "agent_id": victim,
            "if_not_exists": if_not_exists,
        })
    };

    // The reference answer: a collision with a row the stranger CAN read.
    let (visible_status, visible_body) = post_json(
        addr,
        "/api/v1/claims",
        &stranger_token,
        &body(&public_content, false),
    )
    .await;
    assert_eq!(
        visible_status, 409,
        "calibration: a collision with a readable row is a 409; got {visible_status}: \
         {visible_body}"
    );

    for if_not_exists in [false, true] {
        let (status, text) = post_json(
            addr,
            "/api/v1/claims",
            &stranger_token,
            &body(&private_content, if_not_exists),
        )
        .await;
        assert_eq!(
            (status, text.as_str()),
            (visible_status, visible_body.as_str()),
            "if_not_exists={if_not_exists}: a collision with a row the caller \
             CANNOT read must answer byte-for-byte as a collision with one it \
             can. Any difference tells a stranger that the victim holds a \
             private claim with exactly this text."
        );
        for secret in [
            private.to_string(),
            private_content.clone(),
            victim_group.to_string(),
        ] {
            assert!(
                !text.contains(&secret),
                "if_not_exists={if_not_exists}: the refusal names the invisible \
                 row ({secret}): {text}"
            );
        }
    }

    // Nothing the stranger sent was written, on either arm.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(&private_content)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1, "the stranger's colliding writes must not land");

    // CLASS P: the idempotent path still RETURNS the row to a caller who can
    // read it. A fix that answered every collision with the conflict would pass
    // everything above and break `if_not_exists` for its owner.
    let (owner_status, owner_body) = post_json(
        addr,
        "/api/v1/claims",
        &victim_token,
        &body(&private_content, true),
    )
    .await;
    assert_eq!(
        owner_status, 200,
        "the owner's if_not_exists re-assertion must return its own row; got \
         {owner_status}: {owner_body}"
    );
    let owner_json: serde_json::Value = serde_json::from_str(&owner_body).expect("json");
    assert_eq!(
        owner_json["id"].as_str(),
        Some(private.to_string().as_str())
    );

    let _ = shutdown.send(());
}

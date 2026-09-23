#![cfg(feature = "db")]

//! `learn_convention` and `share_skill` must act on the claim the repository
//! actually persisted.
//!
//! Both handlers called the legacy `ClaimRepository::create`, which deduped on
//! `content_hash` ALONE (any agent, any tenant) and returned the matching row,
//! and both then discarded that return value and kept using the id they had
//! minted locally. So whenever the text already existed anywhere:
//!
//! * `POST /api/v1/conventions` inserted nothing, and its evidence write named a
//!   claim id that did not exist, tripping `evidence_claim_id_fkey`. Re-learning
//!   the SAME convention hit it every time.
//! * `POST /api/v1/skills/share` builds its copy from the original's content,
//!   so the dedup found the ORIGINAL on essentially every call. It inserted
//!   nothing, its labels `UPDATE` matched zero rows, and its `SHARED_BY` edge
//!   named a source claim that did not exist, which
//!   `trigger_validate_edge_refs` (migration 001) refuses.
//!
//! Measured on the pre-fix handlers: all four arms below fail, each with a 400
//! "request references a row that does not exist" (the 23503 mapping in
//! `errors.rs`) where the arm expects 2xx.
//!
//! Both now dedup on the noun-claim key `(content_hash, agent_id)` through
//! `ClaimRepository::create_or_get` and use the returned id. Every arm seeds the
//! colliding row with its REAL BLAKE3 content hash: the fixture seeders write a
//! stand-in hash, and a collision the legacy dedup could not see would make
//! these arms pass on the broken tree.
//!
//! Deferred-commitment screen key `legacy-claim-create-callers`
//! (s3a-followup #7).

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

fn admin_token() -> String {
    common::test_bearer_token_with_scopes(&["claims:admin"])
}

/// Overwrite a fixture-seeded claim's stand-in hash with the real one, so the
/// row collides with a later write of the same text exactly as a production
/// row would.
async fn stamp_real_content_hash(pool: &PgPool, claim: Uuid, content: &str) {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let n = sqlx::query("UPDATE claims SET content_hash = $1 WHERE id = $2")
        .bind(hash.as_slice())
        .bind(claim)
        .execute(pool)
        .await
        .expect("stamp content hash")
        .rows_affected();
    assert_eq!(n, 1, "CALIBRATION: the seeded claim {claim} must exist");
}

/// `(agent_id, labels)` for a claim, or `None` when no such row exists.
async fn claim_row(pool: &PgPool, id: Uuid) -> Option<(Uuid, Vec<String>)> {
    sqlx::query_as("SELECT agent_id, labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("claim lookup")
}

async fn learn(addr: std::net::SocketAddr, content: &str, evidence: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conventions"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({ "content": content, "evidence": evidence }))
        .send()
        .await
        .expect("POST /api/v1/conventions");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn share(addr: std::net::SocketAddr, token: &str, workflow_id: Uuid) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/skills/share"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "workflow_id": workflow_id }))
        .send()
        .await
        .expect("POST /api/v1/skills/share");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

fn uuid_field(body: &Value, field: &str) -> Uuid {
    body[field]
        .as_str()
        .unwrap_or_else(|| panic!("`{field}` missing from {body}"))
        .parse()
        .expect("uuid")
}

/// Re-learning a convention is idempotent: 2xx both times, the same id, one row.
#[sqlx::test(migrations = "../../migrations")]
async fn learning_the_same_convention_twice_returns_the_same_claim(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let content = "Always run the lane's tests one crate at a time.";

    let (s1, b1) = learn(addr, content, "first observation").await;
    assert_eq!(s1, 201, "first learn must create: {b1}");
    let id = uuid_field(&b1, "claim_id");

    // Pre-fix this failed (400, 23503): the legacy dedup returned the first
    // row, and the evidence write named the second request's never-inserted id.
    let (s2, b2) = learn(addr, content, "second observation").await;
    assert_eq!(
        s2, 200,
        "re-learning must resolve to the existing convention: {b2}"
    );
    assert_eq!(uuid_field(&b2, "claim_id"), id, "same convention, same id");

    // Repeating the SAME evidence text is the idempotent case
    // (`evidence_content_hash_claim_unique`), not an error.
    let (s3, b3) = learn(addr, content, "second observation").await;
    assert_eq!(
        s3, 200,
        "a repeated evidence text must not fail the re-learn: {b3}"
    );
    assert_eq!(uuid_field(&b3, "claim_id"), id);

    let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_all(&pool)
        .await
        .expect("rows");
    assert_eq!(rows, vec![id], "exactly one convention row for one text");

    let (_agent, labels) = claim_row(&pool, id).await.expect("the convention row");
    assert!(
        labels.contains(&"convention".to_string()) && labels.contains(&"learned".to_string()),
        "labels must land on the persisted row, got {labels:?}"
    );

    let evidence: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("evidence count");
    assert_eq!(
        evidence, 2,
        "two distinct evidence texts support the convention; the repeat adds none"
    );
}

/// A convention whose text ANOTHER agent already holds (here group-private)
/// becomes the system agent's own claim. It neither reuses nor touches the
/// other agent's row.
#[sqlx::test(migrations = "../../migrations")]
async fn learning_a_convention_another_agent_already_holds_creates_the_systems_own(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let content = "Prefer explicit tenancy declarations on every write.";

    let (other_agent, other_group) = fixture::seed_agent_with_group(&pool, "conv-other").await;
    let theirs = fixture::seed_group_claim(&pool, other_agent, other_group, content).await;
    stamp_real_content_hash(&pool, theirs, content).await;

    let (status, body) = learn(addr, content, "seen in review").await;
    assert_eq!(
        status, 201,
        "a different author's text must not block the write: {body}"
    );
    let id = uuid_field(&body, "claim_id");
    assert_ne!(
        id, theirs,
        "the convention must not resolve onto another agent's (group-private) claim"
    );

    let (agent, labels) = claim_row(&pool, id)
        .await
        .expect("the returned claim_id must name a persisted row");
    assert_ne!(agent, other_agent, "the convention is the system agent's");
    assert!(labels.contains(&"convention".to_string()), "got {labels:?}");

    let (_, their_labels) = claim_row(&pool, theirs).await.expect("their row");
    assert!(
        their_labels.is_empty(),
        "the other agent's claim must be untouched, got labels {their_labels:?}"
    );
}

/// Sharing a workflow returns a `shared_claim_id` that names a real,
/// system-authored copy carrying the sharing labels, linked by the edge the
/// response names. A re-share answers with the same copy and the same edge.
#[sqlx::test(migrations = "../../migrations")]
async fn sharing_a_workflow_returns_a_real_labelled_copy(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let content = "Workflow: bisect, reproduce, then fix.";

    let (owner, group) = fixture::seed_agent_with_group(&pool, "share-owner").await;
    let workflow = fixture::seed_group_claim(&pool, owner, group, content).await;
    stamp_real_content_hash(&pool, workflow, content).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], owner);

    let (status, body) = share(addr, &token, workflow).await;
    assert_eq!(status, 201, "first share must create the copy: {body}");
    let shared = uuid_field(&body, "shared_claim_id");
    let edge = uuid_field(&body, "edge_id");
    assert_ne!(shared, workflow, "the copy is a distinct claim");

    // The id the response names must be a persisted row. Pre-fix the handler
    // only ever had the id it minted locally, which the legacy dedup never
    // inserted.
    let (agent, labels) = claim_row(&pool, shared)
        .await
        .expect("shared_claim_id must name a persisted claim");
    assert_ne!(agent, owner, "the copy is authored by the system agent");
    for want in ["workflow", "global", "shared"] {
        assert!(
            labels.contains(&want.to_string()),
            "the copy must carry `{want}`, got {labels:?}"
        );
    }

    let (src, tgt, rel): (Uuid, Uuid, String) =
        sqlx::query_as("SELECT source_id, target_id, relationship FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("the edge the response names");
    assert_eq!((src, tgt, rel.as_str()), (shared, workflow, "SHARED_BY"));

    let (_, original_labels) = claim_row(&pool, workflow).await.expect("original");
    assert!(
        original_labels.is_empty(),
        "sharing must not relabel the ORIGINAL, got {original_labels:?}"
    );

    let (status2, body2) = share(addr, &token, workflow).await;
    assert_eq!(status2, 200, "a re-share reuses the copy: {body2}");
    assert_eq!(uuid_field(&body2, "shared_claim_id"), shared);
    assert_eq!(uuid_field(&body2, "edge_id"), edge, "and the edge");
}

/// The one input for which `(content_hash, system agent)` resolves to the
/// original itself: the original is ALREADY a system-authored shared copy.
/// That is refused, rather than answered with a self-referencing edge.
#[sqlx::test(migrations = "../../migrations")]
async fn sharing_a_shared_copy_is_refused(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let content = "Workflow: write the failing test first.";

    let (owner, group) = fixture::seed_agent_with_group(&pool, "share-twice").await;
    let workflow = fixture::seed_group_claim(&pool, owner, group, content).await;
    stamp_real_content_hash(&pool, workflow, content).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], owner);

    let (status, body) = share(addr, &token, workflow).await;
    assert_eq!(status, 201, "{body}");
    let shared = uuid_field(&body, "shared_claim_id");

    let (status, body) = share(addr, &token, shared).await;
    assert_eq!(
        status, 409,
        "re-sharing a shared copy must be refused: {body}"
    );

    let loops: i64 =
        sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $1")
            .bind(shared)
            .fetch_one(&pool)
            .await
            .expect("self-loop count");
    assert_eq!(loops, 0, "no self-referencing SHARED_BY edge");
}

#![cfg(feature = "db")]
//! `PUT /api/v1/evidence/:id` must keep `content_hash` equal to
//! BLAKE3(`raw_content`) (backlog 9e7a9a96).
//!
//! `POST /api/v1/evidence` refuses a stored digest that disagrees with the
//! body it is stored beside (`evidence_content_hash_override_test.rs`). The
//! PUT path rewrote `raw_content` and left `content_hash` as it was, so an
//! edited row carried the digest of a body it no longer holds, and the POST
//! check could never see it. The repo function that owns the UPDATE now
//! writes both columns together.
//!
//! The pair below discriminates:
//!
//! * **Positive:** a row seeded consistent (`content_hash = BLAKE3(old)`) is
//!   PUT with a new body; afterwards the stored digest is BLAKE3(new) and no
//!   longer BLAKE3(old).
//! * **Negative the fix creates:** `evidence` is `UNIQUE (content_hash,
//!   claim_id)`. A PUT whose new body equals a sibling row's body on the same
//!   claim would now produce a duplicate digest; it must be refused as the
//!   caller's error and leave the row byte-unchanged (body AND digest).

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

fn digest(s: &str) -> Vec<u8> {
    blake3::hash(s.as_bytes()).as_bytes().to_vec()
}

async fn seed_claim(pool: &PgPool, author: Uuid, group: Uuid) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, 'group')",
    )
    .bind(claim_id)
    .bind(format!("evidence put hash claim {claim_id}"))
    .bind(digest(&claim_id.to_string()))
    .bind(author)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

/// Evidence whose stored digest IS the digest of its body, so the only way the
/// row can become inconsistent is through the PUT under test.
async fn seed_consistent_evidence(pool: &PgPool, claim_id: Uuid, group: Uuid, body: &str) -> Uuid {
    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence \
             (id, content_hash, evidence_type, raw_content, claim_id, owner_group_id, visibility) \
         VALUES ($1, $2, 'document', $3, $4, $5, 'group')",
    )
    .bind(evidence_id)
    .bind(digest(body))
    .bind(body)
    .bind(claim_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed evidence");
    evidence_id
}

async fn stored(pool: &PgPool, id: Uuid) -> (Option<String>, Vec<u8>) {
    sqlx::query_as("SELECT raw_content, content_hash FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back evidence")
}

struct World {
    pool: PgPool,
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    token: String,
    principal: Uuid,
    group: Uuid,
}

async fn setup() -> World {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    // `admin` in its own personal group: the write gate passes, so the only
    // variable left is what the UPDATE writes.
    let (principal, group) = fixture::seed_agent_with_group(&pool, "ev-put-hash").await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        token: common::mint_token_with_agent(&["evidence:write", "claims:read"], principal),
        principal,
        group,
    }
}

async fn put_raw_content(w: &World, id: Uuid, body: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/v1/evidence/{id}", w.addr))
        .bearer_auth(&w.token)
        .json(&serde_json::json!({ "raw_content": body }))
        .send()
        .await
        .expect("PUT /api/v1/evidence/:id");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_recomputes_content_hash_from_the_new_raw_content() {
    let w = setup().await;
    let claim = seed_claim(&w.pool, w.principal, w.group).await;
    let old = format!("original body {}", Uuid::new_v4());
    let new = format!("edited body {}", Uuid::new_v4());
    let ev = seed_consistent_evidence(&w.pool, claim, w.group, &old).await;

    let (status, body) = put_raw_content(&w, ev, &new).await;
    assert_eq!(status, 200, "the PUT must succeed; body={body}");

    let (raw, hash) = stored(&w.pool, ev).await;
    assert_eq!(raw.as_deref(), Some(new.as_str()), "the body must change");
    assert_ne!(
        hash,
        digest(&old),
        "content_hash still equals BLAKE3(old raw_content) after the body was \
         replaced: the stored digest no longer describes the stored body"
    );
    assert_eq!(
        hash,
        digest(&new),
        "after a PUT, content_hash must equal BLAKE3(new raw_content)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn put_onto_a_sibling_body_on_the_same_claim_is_refused_and_writes_nothing() {
    let w = setup().await;
    let claim = seed_claim(&w.pool, w.principal, w.group).await;
    let sibling_body = format!("sibling body {}", Uuid::new_v4());
    let own_body = format!("own body {}", Uuid::new_v4());
    let _sibling = seed_consistent_evidence(&w.pool, claim, w.group, &sibling_body).await;
    let ev = seed_consistent_evidence(&w.pool, claim, w.group, &own_body).await;

    let (status, body) = put_raw_content(&w, ev, &sibling_body).await;

    let (raw, hash) = stored(&w.pool, ev).await;
    assert_eq!(
        raw.as_deref(),
        Some(own_body.as_str()),
        "a PUT that would duplicate a sibling's (content_hash, claim_id) must \
         not change the body (status {status}, body {body})"
    );
    assert_eq!(hash, digest(&own_body), "nor the digest");
    assert_eq!(
        status, 400,
        "the duplicate is the caller's error, not a server fault; body={body}"
    );
}

/// The route's main job: backfilling `raw_content` on evidence created without
/// a body. `POST /api/v1/evidence` stores a caller-supplied `content_hash`
/// unchecked when `raw_content` is absent (external evidence). Once the body
/// is backfilled, the stored digest describes that body: the caller-supplied
/// external digest is replaced, deliberately, so the row is checkable.
#[tokio::test(flavor = "multi_thread")]
async fn backfilling_raw_content_replaces_a_caller_supplied_external_digest() {
    let w = setup().await;
    let claim = seed_claim(&w.pool, w.principal, w.group).await;
    let external = digest(&format!("external artefact {}", Uuid::new_v4()));
    let ev = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence \
             (id, content_hash, evidence_type, raw_content, claim_id, owner_group_id, visibility) \
         VALUES ($1, $2, 'document', NULL, $3, $4, 'group')",
    )
    .bind(ev)
    .bind(&external)
    .bind(claim)
    .bind(w.group)
    .execute(&w.pool)
    .await
    .expect("seed body-less evidence");

    let body_text = format!("backfilled body {}", Uuid::new_v4());
    let (status, body) = put_raw_content(&w, ev, &body_text).await;
    assert_eq!(status, 200, "the backfill must succeed; body={body}");

    let (raw, hash) = stored(&w.pool, ev).await;
    assert_eq!(raw.as_deref(), Some(body_text.as_str()));
    assert_ne!(
        hash, external,
        "the external digest no longer describes the row once it has a body"
    );
    assert_eq!(
        hash,
        digest(&body_text),
        "content_hash = BLAKE3(backfilled body)"
    );
}

/// A sealed claim's evidence holds the seal sentinel in `raw_content`; its real
/// body lives in the seal manifest and unseal writes it back. A PUT onto that
/// row would store plaintext into a sealed row and, now that the digest moves
/// with the body, leave the digest of the PUT body behind after unseal restores
/// the original. Refused as not-found (the same answer as "not writable"), and
/// nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn put_onto_a_sealed_evidence_row_is_refused_and_writes_nothing() {
    let w = setup().await;
    let claim = seed_claim(&w.pool, w.principal, w.group).await;
    let sentinel = "[sealed]";
    let ev = seed_consistent_evidence(&w.pool, claim, w.group, sentinel).await;

    let (status, body) = put_raw_content(&w, ev, "plaintext written over a seal").await;

    let (raw, hash) = stored(&w.pool, ev).await;
    assert_eq!(
        raw.as_deref(),
        Some(sentinel),
        "a sealed row's body must not be rewritten (status {status}, body {body})"
    );
    assert_eq!(hash, digest(sentinel), "nor its digest");
    assert_eq!(status, 404, "refused as not-found; body={body}");
}

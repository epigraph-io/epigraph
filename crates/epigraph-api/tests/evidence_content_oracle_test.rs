#![cfg(feature = "db")]
//! An evidence write must not confirm another group's hidden evidence
//! (backlog 12b68201).
//!
//! `evidence` was `UNIQUE (content_hash, claim_id)` across every owner. A
//! writer in group A who wrote evidence onto a shared claim got a conflict
//! whenever its body collided with evidence another group B holds, unreadable
//! to A, on the same claim. The refusal confirmed that the hidden row exists
//! and holds exactly the guessed body. Both write routes reached it:
//! `POST /api/v1/evidence` and the `raw_content` rewrite of
//! `PUT /api/v1/evidence/:id`.
//!
//! The discriminating set:
//!
//! * **POST and PUT, cross-owner:** a body B already holds and a body nobody
//!   holds get the SAME answer (success), so A cannot tell them apart.
//! * **Same owner, still refused:** evidence is still de-duplicated within one
//!   owner. A second identical POST by A is refused. Without this, dropping the
//!   key and its de-duplication outright would pass the two tests above.
//!
//! The POST route writes on the server's raw pool, which this harness runs as
//! the superuser, so A's POSTed row inherits the claim's owner (A); the
//! premise that A cannot read B's row is asserted through A's own viewer.
//!
//! The PUT twin of the same-owner case is
//! `evidence_update_content_hash_test.rs::put_onto_a_sibling_body_on_the_same_claim_is_refused_and_writes_nothing`.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

fn digest(s: &str) -> Vec<u8> {
    blake3::hash(s.as_bytes()).as_bytes().to_vec()
}

struct World {
    pool: PgPool,
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    token: String,
    /// The writer probing for B's evidence: `admin` of its own group A.
    writer: Uuid,
    group_a: Uuid,
    /// Another group, holding evidence A cannot read.
    group_b: Uuid,
    /// A PUBLIC claim A owns, so A may write evidence onto it on every route.
    claim: Uuid,
}

async fn setup(label: &str) -> World {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    let (writer, group_a) = fixture::seed_agent_with_group(&pool, &format!("{label}-a")).await;
    let (_other, group_b) = fixture::seed_agent_with_group(&pool, &format!("{label}-b")).await;

    let claim = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, 'public')",
    )
    .bind(claim)
    .bind(format!("shared claim {claim}"))
    .bind(digest(&claim.to_string()))
    .bind(writer)
    .bind(group_a)
    .execute(&pool)
    .await
    .expect("seed the shared claim");

    let (addr, shutdown) = common::spawn_app(&url).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        token: common::mint_token_with_agent(&["evidence:write", "claims:read"], writer),
        writer,
        group_a,
        group_b,
        claim,
    }
}

/// Evidence on `claim` written by its owner, A.
async fn seed_own_evidence(pool: &PgPool, claim: Uuid, body: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id) \
         VALUES ($1, 'document', $2, $3) RETURNING id",
    )
    .bind(digest(body))
    .bind(body)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed A's evidence")
}

/// Evidence on `claim` owned by `group` and readable only inside it, made so
/// the way the operator `hide` does it (`epigraph-cli operator hide`): a
/// visibility pin, then the owner and visibility. The pin is what keeps the
/// row's tenancy from being re-synced to the claim's on the next evidence
/// insert (migration 110), so the row really stays B's.
async fn seed_hidden_evidence(pool: &PgPool, claim: Uuid, group: Uuid, body: &str) -> Uuid {
    let id = seed_own_evidence(pool, claim, body).await;
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden from A')",
    )
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("pin the hidden row");
    sqlx::query("UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE id = $1")
        .bind(id)
        .bind(group)
        .execute(pool)
        .await
        .expect("hide the row in B");
    assert_eq!(
        tenancy(pool, id).await,
        (group, "group".to_string()),
        "fixture: the hidden row is B's"
    );
    id
}

/// The premise: the writer's own viewer cannot read B's row, so a refusal
/// that names it would disclose something the writer could not otherwise see.
async fn assert_hidden_from_writer(w: &World, id: Uuid) {
    let viewer = epigraph_db::visibility::Viewer::resolve(&w.pool, w.writer)
        .await
        .expect("resolve the writer's viewer");
    let seen = epigraph_db::EvidenceRepository::get_by_id(
        &w.pool,
        &viewer,
        epigraph_core::EvidenceId::from_uuid(id),
    )
    .await
    .expect("read through the writer's viewer");
    assert!(
        seen.is_none(),
        "fixture: the writer can read B's row, so the test proves nothing"
    );
}

async fn tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read evidence tenancy")
}

async fn post_evidence(w: &World, body: &str) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/evidence", w.addr))
        .bearer_auth(&w.token)
        .json(&serde_json::json!({
            "agent_id": w.writer,
            "claim_id": w.claim,
            "raw_content": body,
            "evidence_type": {
                "type": "document",
                "source_url": null,
                "mime_type": "text/plain",
                "checksum": null,
            },
        }))
        .send()
        .await
        .expect("POST /api/v1/evidence");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
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

/// The owner of every row on `claim` whose digest is BLAKE3(`body`), sorted.
async fn rows_with_body(pool: &PgPool, claim: Uuid, body: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT owner_group_id FROM evidence \
          WHERE claim_id = $1 AND content_hash = $2 ORDER BY owner_group_id",
    )
    .bind(claim)
    .bind(digest(body))
    .fetch_all(pool)
    .await
    .expect("read rows by digest")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_cannot_tell_another_groups_hidden_body_from_a_fresh_one() {
    let w = setup("ev-oracle-post").await;
    let hidden = format!("B's hidden finding {}", Uuid::new_v4());
    let fresh = format!("a body nobody holds {}", Uuid::new_v4());
    let b_row = seed_hidden_evidence(&w.pool, w.claim, w.group_b, &hidden).await;
    assert_hidden_from_writer(&w, b_row).await;

    let (hidden_status, hidden_body) = post_evidence(&w, &hidden).await;
    let (fresh_status, fresh_body) = post_evidence(&w, &fresh).await;

    assert_eq!(
        fresh_status, 201,
        "control: a body nobody holds is accepted; body={fresh_body}"
    );
    assert_eq!(
        hidden_status, fresh_status,
        "POSTing a body group B holds on this claim answered {hidden_status} where a fresh \
         body answers {fresh_status}: the refusal confirms B's unreadable evidence and its \
         exact content; body={hidden_body}"
    );
    let mut expected = vec![w.group_a, w.group_b];
    expected.sort();
    assert_eq!(
        rows_with_body(&w.pool, w.claim, &hidden).await,
        expected,
        "A's row is stored beside B's, each under its own owner"
    );
    assert_eq!(
        tenancy(&w.pool, b_row).await,
        (w.group_b, "group".to_string()),
        "B's row is untouched and still hidden"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_put_cannot_tell_another_groups_hidden_body_from_a_fresh_one() {
    let w = setup("ev-oracle-put").await;
    let hidden = format!("B's hidden finding {}", Uuid::new_v4());
    let fresh = format!("a body nobody holds {}", Uuid::new_v4());
    let probe = seed_own_evidence(&w.pool, w.claim, "A's first draft").await;
    let control = seed_own_evidence(&w.pool, w.claim, "A's second draft").await;
    let b_row = seed_hidden_evidence(&w.pool, w.claim, w.group_b, &hidden).await;
    assert_hidden_from_writer(&w, b_row).await;
    assert_eq!(
        tenancy(&w.pool, probe).await.0,
        w.group_a,
        "fixture: A's rows are A's"
    );

    let (hidden_status, hidden_body) = put_raw_content(&w, probe, &hidden).await;
    let (fresh_status, fresh_body) = put_raw_content(&w, control, &fresh).await;

    assert_eq!(
        fresh_status, 200,
        "control: rewriting to a body nobody holds succeeds; body={fresh_body}"
    );
    assert_eq!(
        hidden_status, fresh_status,
        "PUTting a body group B holds on this claim answered {hidden_status} where a fresh \
         body answers {fresh_status}: the refusal confirms B's unreadable evidence and its \
         exact content; body={hidden_body}"
    );
    let stored: Vec<u8> = sqlx::query_scalar("SELECT content_hash FROM evidence WHERE id = $1")
        .bind(probe)
        .fetch_one(&w.pool)
        .await
        .expect("read the rewritten row");
    assert_eq!(stored, digest(&hidden), "the rewrite landed on A's row");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_identical_post_by_the_same_owner_is_still_refused() {
    let w = setup("ev-oracle-same").await;
    let body = format!("A's own finding {}", Uuid::new_v4());

    let (first, first_body) = post_evidence(&w, &body).await;
    assert_eq!(first, 201, "the first submission lands; body={first_body}");
    let (second, second_body) = post_evidence(&w, &body).await;
    assert_eq!(
        second, 400,
        "the same owner's identical evidence on the same claim is still a duplicate; \
         body={second_body}"
    );
    assert_eq!(
        rows_with_body(&w.pool, w.claim, &body).await,
        vec![w.group_a],
        "exactly one row, A's"
    );
}

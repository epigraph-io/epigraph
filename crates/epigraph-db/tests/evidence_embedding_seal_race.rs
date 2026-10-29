//! `EvidenceRepository::store_embedding_as` must not put a vector on an
//! evidence row whose seal commits while the store is waiting for it.
//!
//! # The race
//!
//! The seal (`privatization.rs`, the evidence step of the seal commit) runs, in
//! ONE transaction, `INSERT INTO evidence_encryption …` and then
//! `UPDATE evidence SET raw_content = <sentinel>, embedding = NULL, …`. That
//! UPDATE holds the evidence row's lock until the seal commits.
//!
//! A store written as one statement,
//! `UPDATE evidence … WHERE id = $1 AND NOT EXISTS (evidence_encryption …)`,
//! blocks on that row lock. When the seal commits, READ COMMITTED re-checks the
//! qual on the NEW row version, but against the statement's ORIGINAL snapshot
//! for every other table, `evidence_encryption` included. The seal's ciphertext
//! row is invisible to that snapshot, so the store writes a plaintext-derived
//! vector onto the row the seal just blanked.
//!
//! `ClaimRepository::store_embedding_if_unsealed` closes the same race on
//! `claims` by taking the row lock in a SEPARATE statement first; the guarded
//! UPDATE then takes a fresh snapshot that includes the committed seal. The
//! evidence store must do the same.
//!
//! # How the interleaving is forced
//!
//! Connection A replays the seal's two evidence statements in the seal's order
//! and stays open. Connection B runs the store. A spawned task waits until
//! `pg_stat_activity` shows B blocked on a lock (bounded), then commits A. No
//! sleep decides the order: B is observed waiting before A commits.
//!
//! # Verified to fail
//!
//! With the single-statement store (this branch before the fix), the store
//! returns `true` and the sealed row carries a vector.

mod viewer_fixture;

use epigraph_core::EvidenceId;
use epigraph_db::EvidenceRepository;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn vector_literal(dims: usize, value: f32) -> String {
    format!("[{}]", vec![value.to_string(); dims].join(","))
}

/// A team group with an active key epoch, an author writing in it, and one
/// group-owned claim: `(group, claim)`.
async fn seal_target(pool: &PgPool) -> (Uuid, Uuid) {
    let (author, _) = viewer_fixture::seed_agent_with_group(pool, "race-author").await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id) \
         VALUES ('seal race target', 'did:epigraph:team:' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', 'active', $1) \
         RETURNING id",
    )
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(pool)
        .await
        .expect("seed key epoch");
    let claim = viewer_fixture::seed_group_claim(pool, author, group, "a claim to seal").await;
    (group, claim)
}

/// An evidence row with a plaintext body on `claim`.
async fn plaintext_evidence(pool: &PgPool, claim: Uuid, body: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, $3) RETURNING id",
    )
    .bind(claim)
    .bind(blake3::hash(body.as_bytes()).as_bytes().as_slice())
    .bind(body)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

async fn has_vector(pool: &PgPool, evidence: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM evidence WHERE id = $1")
        .bind(evidence)
        .fetch_one(pool)
        .await
        .expect("read the vector column")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_committing_while_the_store_waits_leaves_no_vector(pool: PgPool) {
    let (group, claim) = seal_target(&pool).await;
    let control = plaintext_evidence(&pool, claim, "an open body").await;
    let target = plaintext_evidence(&pool, claim, "a confidential body").await;
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let vector = vector_literal(1536, 0.25);

    // Control: an unsealed row is embeddable, so the refusal below is not a
    // store that refuses everything.
    let mut b = pool.acquire().await.expect("acquire B");
    assert!(
        EvidenceRepository::store_embedding_as(
            &mut b,
            &viewer,
            EvidenceId::from_uuid(control),
            &vector
        )
        .await
        .expect("store on the unsealed control"),
        "the unsealed control row must take a vector"
    );
    assert!(has_vector(&pool, control).await);

    // A: the seal's evidence statements, in the seal's order, left open.
    let mut a = pool.begin().await.expect("begin A");
    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(target)
    .bind(group)
    .execute(&mut *a)
    .await
    .expect("A: the ciphertext row");
    sqlx::query(
        "UPDATE evidence SET raw_content = '[sealed]', embedding = NULL, \
                             embedding_3072 = NULL WHERE id = $1",
    )
    .bind(target)
    .execute(&mut *a)
    .await
    .expect("A: blank the evidence row (takes its lock)");

    // Commit A only once B is observed waiting on a lock.
    let b_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *b)
        .await
        .expect("B's pid");
    let watcher = pool.clone();
    let committer = tokio::spawn(async move {
        let mut waited = false;
        for _ in 0..500 {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                                 WHERE pid = $1 AND wait_event_type = 'Lock')",
            )
            .bind(b_pid)
            .fetch_one(&watcher)
            .await
            .expect("read pg_stat_activity");
            if blocked {
                waited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        a.commit().await.expect("commit A (the seal)");
        waited
    });

    // B: the store, which must wait for A and then write nothing.
    let wrote = EvidenceRepository::store_embedding_as(
        &mut b,
        &viewer,
        EvidenceId::from_uuid(target),
        &vector,
    )
    .await
    .expect("B: the store runs");
    let waited = committer.await.expect("the committer task");

    assert!(
        waited,
        "B never waited on the evidence row's lock, so the race was not exercised"
    );
    assert!(
        !wrote,
        "the store reported a vector written onto a row sealed while it waited"
    );
    assert!(
        !has_vector(&pool, target).await,
        "a sealed evidence row carries a plaintext-derived vector"
    );
}

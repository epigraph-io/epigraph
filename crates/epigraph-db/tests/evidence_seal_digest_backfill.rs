//! Migration 171 section 3: evidence rows sealed BEFORE the seal wrote a
//! digest sentinel (backlog 12b68201).
//!
//! Such a row kept `content_hash` = BLAKE3(plaintext), so it still confirms a
//! guessed body. 171 gives it the sentinel the seal now writes. Its seal
//! manifest never carried the digest, so unseal has to rebuild it: BLAKE3 of
//! the restored body, recognised by the sentinel in the column. That only
//! works while the migration's expression and the seal's
//! `SEAL_EVIDENCE_DIGEST_SENTINEL` are the same expression, which the round
//! trip below is the check on.
//!
//! The negative halves: an evidence row that is NOT sealed keeps its digest,
//! and a legacy sealed row whose body was NULL (external evidence) keeps the
//! sentinel after unseal, because its writer-supplied digest exists nowhere
//! else. That loss is the stated cost of the backfill, pinned so it is not
//! silently "fixed" by inventing a digest.

mod viewer_fixture;

use epigraph_db::repos::privatization::{
    PrivatizationRepository, UnsealCommitEvidence, UnsealCommitItem,
};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn digest(s: &str) -> Vec<u8> {
    blake3::hash(s.as_bytes()).as_bytes().to_vec()
}

/// A database at migration 170 (the head before 171), seeded by `seed`, then
/// migrated to the tree's head. One connection, reset afterwards, for the
/// reason `viewer_fixture::db_at_122_then_head` gives.
async fn at_170_then_head<F, Fut>(pool: &PgPool, seed: F)
where
    F: FnOnce(PgPool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= 170)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    before.run(&mut *conn).await.expect("migrate 001 -> 170");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);
    seed(pool.clone()).await;
    let mut conn = pool.acquire().await.expect("acquire");
    MIGRATOR.run(&mut *conn).await.expect("migrate 170 -> head");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// What the seed wrote, for the assertions after the migration.
#[derive(Default, Clone)]
struct Seeded {
    group: Uuid,
    claim: Uuid,
    body: String,
    sealed_with_body: Uuid,
    sealed_bodiless: Uuid,
    bodiless_digest: Vec<u8>,
    plain: Uuid,
    plain_digest: Vec<u8>,
}

/// A claim sealed the way `seal_claims_conn` sealed one before 171: ciphertext
/// rows present, the evidence body replaced by the sentinel, and the digest
/// left as the plaintext's.
async fn seed_pre_171_seal(pool: PgPool) -> Seeded {
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "pre171-author").await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id) \
         VALUES ('pre-171 seal target', 'did:epigraph:team:' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', 'active', $1) \
         RETURNING id",
    )
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("seed team group");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(&pool)
        .await
        .expect("seed key epoch");

    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a sealed claim").await;
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(claim)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seal the claim");

    let body = format!("a confidential evidence body {}", Uuid::new_v4());
    let bodiless_digest = digest(&format!("external artefact {}", Uuid::new_v4()));
    let mut sealed = Vec::new();
    for hash in [digest(&body), bodiless_digest.clone()] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
             VALUES ($1, 'document', $2, '[sealed]') RETURNING id",
        )
        .bind(claim)
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .expect("seed sealed evidence");
        sqlx::query(
            "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                              encrypted_content) \
             VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
        )
        .bind(id)
        .bind(group)
        .execute(&pool)
        .await
        .expect("seed evidence ciphertext");
        sealed.push(id);
    }

    let other = viewer_fixture::seed_group_claim(&pool, author, group, "an open claim").await;
    let plain_body = format!("an open evidence body {}", Uuid::new_v4());
    let plain: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, $3) RETURNING id",
    )
    .bind(other)
    .bind(digest(&plain_body))
    .bind(&plain_body)
    .fetch_one(&pool)
    .await
    .expect("seed open evidence");

    Seeded {
        group,
        claim,
        body,
        sealed_with_body: sealed[0],
        sealed_bodiless: sealed[1],
        bodiless_digest,
        plain,
        plain_digest: digest(&plain_body),
    }
}

async fn digest_of(pool: &PgPool, id: Uuid) -> Vec<u8> {
    sqlx::query_scalar("SELECT content_hash FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read digest")
}

#[sqlx::test(migrations = false)]
async fn migration_171_replaces_a_pre_existing_sealed_digest_and_unseal_rebuilds_it(pool: PgPool) {
    let seeded = Arc::new(Mutex::new(Seeded::default()));
    let slot = seeded.clone();
    at_170_then_head(&pool, |pool| async move {
        let s = seed_pre_171_seal(pool).await;
        *slot.lock().unwrap() = s;
    })
    .await;
    let s = seeded.lock().unwrap().clone();

    let sealed = digest_of(&pool, s.sealed_with_body).await;
    assert_eq!(sealed.len(), 32, "evidence_content_hash_length");
    assert_ne!(
        sealed,
        digest(&s.body),
        "a row sealed before 171 still carries BLAKE3 of its plaintext after 171"
    );
    let bodiless = digest_of(&pool, s.sealed_bodiless).await;
    assert_ne!(
        bodiless, s.bodiless_digest,
        "a sealed body-less row still carries its external digest after 171"
    );
    assert_ne!(sealed, bodiless, "the sentinel differs per row");
    assert_eq!(
        digest_of(&pool, s.plain).await,
        s.plain_digest,
        "171 must not touch a row that is not sealed"
    );

    // Unseal as the client would for a pre-171 seal: its manifest carried no
    // digest, so the restored properties have no carrier key.
    let mut conn = pool.acquire().await.expect("acquire");
    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .expect("begin unseal tx");
    let restored = PrivatizationRepository::unseal_claims_conn(
        &mut tx,
        s.group,
        &[UnsealCommitItem {
            claim_id: s.claim,
            content: "a sealed claim".to_string(),
            content_hash: digest("a sealed claim"),
            labels: vec![],
            properties: serde_json::json!({}),
            versions: vec![],
            evidence: vec![
                UnsealCommitEvidence {
                    id: s.sealed_with_body,
                    raw_content: Some(s.body.clone()),
                    properties: serde_json::json!({ "restored": true }),
                },
                UnsealCommitEvidence {
                    id: s.sealed_bodiless,
                    raw_content: None,
                    properties: serde_json::json!({ "restored": true }),
                },
            ],
        }],
    )
    .await
    .expect("unseal");
    tx.commit().await.expect("commit unseal");
    drop(conn);
    assert_eq!(restored, vec![s.claim]);

    assert_eq!(
        digest_of(&pool, s.sealed_with_body).await,
        digest(&s.body),
        "unseal rebuilds a backfilled row's digest from its restored body; if this \
         fails, 171's expression and SEAL_EVIDENCE_DIGEST_SENTINEL have drifted apart"
    );
    assert_eq!(
        digest_of(&pool, s.sealed_bodiless).await,
        bodiless,
        "a backfilled body-less row keeps the sentinel: its external digest is gone"
    );
}

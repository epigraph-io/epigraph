//! The storage-side tamper guards of migration 072.
//!
//! `anchors` needs UPDATE for `pending -> submitted -> confirmed`, so a blanket
//! append-only trigger would break the feature. It instead guards exactly the
//! commitment-bearing columns: an operator must not be able to repoint an
//! existing anchor at a different root while keeping its transaction id and its
//! ledger row. `anchor_mock_chain`, which needs no updates at all, gets the
//! blanket guard.
//!
//! These tests exercise SQL directly rather than the repository, because what
//! is being pinned is what the DATABASE refuses — a repository that simply
//! never issues the statement would prove nothing about an operator at a psql
//! prompt.

use epigraph_crypto::ContentHasher;
use epigraph_db::{AnchorRepository, NewAnchor, ROOT_TYPE_MANIFEST};
use epigraph_interfaces::anchor::AnchorCommitment;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_anchor(pool: &PgPool) -> Uuid {
    let root_id = Uuid::new_v4();
    let sealed_at = chrono::Utc::now();
    let commitment = AnchorCommitment::new(
        ROOT_TYPE_MANIFEST,
        *root_id.as_bytes(),
        [0x9e; 32],
        4,
        u64::try_from(sealed_at.timestamp()).unwrap(),
    );
    let bytes = commitment.to_cbor().expect("encode");
    let row = AnchorRepository::insert_pending(
        pool,
        &NewAnchor {
            root_type: ROOT_TYPE_MANIFEST.to_string(),
            root_id,
            root_hash: [0x9e; 32].to_vec(),
            commitment_version: 1,
            commitment_hash: ContentHasher::hash(&bytes).to_vec(),
            commitment_bytes: bytes,
            backend: "mock".to_string(),
            network: "mock".to_string(),
            sealed_at,
        },
    )
    .await
    .expect("insert anchor");
    row.id
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchors_commitment_columns_cannot_be_updated(pool: PgPool) {
    let id = seed_anchor(&pool).await;

    // Every guarded column, one at a time. Repointing a root is the attack:
    // keep the ledger transaction, swap what it attests to.
    for (column, value) in [
        ("root_hash", "decode(repeat('dd', 32), 'hex')"),
        ("root_type", "'checkpoint'"),
        ("root_id", "gen_random_uuid()"),
        ("commitment_version", "2"),
        ("commitment_hash", "decode(repeat('ee', 32), 'hex')"),
        ("commitment_bytes", "decode('a701', 'hex')"),
        ("backend", "'cardano'"),
        ("network", "'mainnet'"),
        ("sealed_at", "NOW() - INTERVAL '10 years'"),
        ("created_at", "NOW() - INTERVAL '10 years'"),
    ] {
        let err = sqlx::query(&format!(
            "UPDATE anchors SET {column} = {value} WHERE id = $1"
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("commitment columns are immutable"),
            "updating {column} must raise the guard, got: {err}"
        );
    }

    // The lifecycle transition the feature actually needs still works on the
    // very same row — the guard is surgical, not a blanket ban.
    sqlx::query(
        "UPDATE anchors
         SET status = 'confirmed', tx_id = 'abc123', block_height = 42,
             block_time = NOW(), confirmed_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("the legitimate pending -> confirmed transition must succeed");

    let (status, tx_id): (String, Option<String>) =
        sqlx::query_as("SELECT status, tx_id FROM anchors WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(status, "confirmed");
    assert_eq!(tx_id.as_deref(), Some("abc123"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchors_rows_cannot_be_deleted(pool: PgPool) {
    let id = seed_anchor(&pool).await;

    let err = sqlx::query("DELETE FROM anchors WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("anchors is append-only"),
        "the message must name the table via TG_TABLE_NAME, got: {err}"
    );

    let survivors: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM anchors WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(survivors, 1, "the row must still be there");
}

#[sqlx::test(migrations = "../../migrations")]
async fn mock_chain_is_append_only(pool: PgPool) {
    sqlx::query(
        "INSERT INTO anchor_mock_chain (tx_id, metadata_label, metadata_cbor, block_height)
         VALUES ('tx-immutable', 40961, decode('a701', 'hex'), 1)",
    )
    .execute(&pool)
    .await
    .expect("publish");

    let err = sqlx::query(
        "UPDATE anchor_mock_chain SET metadata_cbor = decode('ff', 'hex') WHERE tx_id = 'tx-immutable'",
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("anchor_mock_chain is append-only"),
        "UPDATE must raise and the message must name the table, got: {err}"
    );

    let err = sqlx::query("DELETE FROM anchor_mock_chain WHERE tx_id = 'tx-immutable'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("anchor_mock_chain is append-only"),
        "DELETE must raise, got: {err}"
    );

    // The published bytes are untouched, which is the property verification
    // leans on when it compares the ledger's copy against ours.
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT metadata_cbor FROM anchor_mock_chain WHERE tx_id = $1")
            .bind("tx-immutable")
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(bytes, vec![0xa7, 0x01]);
}

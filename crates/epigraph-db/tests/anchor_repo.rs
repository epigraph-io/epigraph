//! `AnchorRepository` against a real database (migration 072).
//!
//! Every test carries REAL commitment bytes — the same deterministic CBOR the
//! backends publish — rather than a placeholder blob, because the whole point
//! of `commitment_bytes` is that what is stored is byte-identical to what was
//! published. A fixture that stored `b"x"` would pass while proving nothing.

use epigraph_crypto::ContentHasher;
use epigraph_db::{AnchorRepository, NewAnchor, ROOT_TYPE_MANIFEST};
use epigraph_interfaces::anchor::AnchorCommitment;
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────

/// A real commitment plus the row that would carry it.
fn new_anchor(root_id: Uuid, root_hash: [u8; 32], leaf_count: u64) -> (NewAnchor, Vec<u8>) {
    let sealed_at = chrono::Utc::now();
    let commitment = AnchorCommitment::new(
        ROOT_TYPE_MANIFEST,
        *root_id.as_bytes(),
        root_hash,
        leaf_count,
        u64::try_from(sealed_at.timestamp()).unwrap(),
    );
    let bytes = commitment.to_cbor().expect("encode commitment");
    let hash = ContentHasher::hash(&bytes);
    (
        NewAnchor {
            root_type: ROOT_TYPE_MANIFEST.to_string(),
            root_id,
            root_hash: root_hash.to_vec(),
            commitment_version: 1,
            commitment_hash: hash.to_vec(),
            commitment_bytes: bytes.clone(),
            backend: "mock".to_string(),
            network: "mock".to_string(),
            sealed_at,
        },
        bytes,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn insert_anchor_roundtrips_commitment_bytes(pool: PgPool) {
    let root_id = Uuid::new_v4();
    let (anchor, published) = new_anchor(root_id, [0x3c; 32], 5);

    let row = AnchorRepository::insert_pending(&pool, &anchor)
        .await
        .expect("insert");

    assert_eq!(row.root_type, ROOT_TYPE_MANIFEST);
    assert_eq!(row.root_id, root_id);
    assert_eq!(row.status, "pending");
    assert_eq!(row.commitment_version, 1);
    assert!(row.tx_id.is_none());

    // The bytes must survive the round trip EXACTLY. Anything else and the
    // ledger's copy would stop matching ours for reasons that have nothing to
    // do with tampering.
    assert_eq!(
        row.commitment_bytes, published,
        "commitment_bytes must be byte-identical to what was published"
    );
    assert_eq!(
        ContentHasher::hash(&row.commitment_bytes).to_vec(),
        row.commitment_hash,
        "commitment_hash must be blake3 of the stored payload"
    );

    // And they must still decode to the root we anchored.
    let decoded = AnchorCommitment::from_cbor(&row.commitment_bytes).expect("decode");
    assert_eq!(decoded.root_hash.to_vec(), row.root_hash);
    assert_eq!(decoded.root_id, *root_id.as_bytes());
    assert_eq!(decoded.leaf_count, 5);
    assert_eq!(decoded.kind, ROOT_TYPE_MANIFEST);

    let fetched = AnchorRepository::get_by_id(&pool, row.id)
        .await
        .expect("get")
        .expect("row exists");
    assert_eq!(fetched.commitment_bytes, published);
}

/// A SUCCESSFUL anchor can never be duplicated — two live commitments over one
/// root would let an operator present whichever suited them at verify time.
/// A FAILED one must not block a retry.
#[sqlx::test(migrations = "../../migrations")]
async fn live_anchor_is_unique_per_root_backend_network(pool: PgPool) {
    let root_id = Uuid::new_v4();
    let (anchor, _) = new_anchor(root_id, [0x11; 32], 3);

    let first = AnchorRepository::insert_pending(&pool, &anchor)
        .await
        .expect("first insert");
    let second = AnchorRepository::insert_pending(&pool, &anchor)
        .await
        .expect("second insert is a no-op, not an error");
    assert_eq!(
        first.id, second.id,
        "a second insert must return the row already there"
    );
    assert_eq!(count_anchors(&pool, root_id).await, 1);

    // A different backend is a different anchor, not a conflict.
    let mut other_backend = anchor.clone();
    other_backend.backend = "cardano".to_string();
    other_backend.network = "preprod".to_string();
    let third = AnchorRepository::insert_pending(&pool, &other_backend)
        .await
        .expect("different backend");
    assert_ne!(third.id, first.id);
    assert_eq!(count_anchors(&pool, root_id).await, 2);

    // Once the first attempt has failed it leaves the partial index, so a
    // retry is allowed and gets a NEW row.
    AnchorRepository::mark_failed(&pool, first.id, "transport blew up")
        .await
        .expect("mark failed");
    assert!(
        AnchorRepository::get_live(&pool, ROOT_TYPE_MANIFEST, root_id, "mock", "mock")
            .await
            .expect("get_live")
            .is_none(),
        "a failed anchor is not live"
    );

    let retry = AnchorRepository::insert_pending(&pool, &anchor)
        .await
        .expect("retry after failure");
    assert_ne!(retry.id, first.id, "a retry must be a fresh row");
    assert_eq!(retry.status, "pending");
    assert_eq!(count_anchors(&pool, root_id).await, 3);

    let failed = AnchorRepository::get_by_id(&pool, first.id)
        .await
        .expect("get")
        .expect("the failed row is kept as the outage signal");
    assert_eq!(failed.status, "failed");
    assert_eq!(failed.failure_reason.as_deref(), Some("transport blew up"));
}

/// `anchors_confirmed_has_tx`: a confirmation with nothing to point at is not a
/// confirmation.
#[sqlx::test(migrations = "../../migrations")]
async fn confirmed_status_requires_tx_and_block(pool: PgPool) {
    let root_id = Uuid::new_v4();
    let (anchor, _) = new_anchor(root_id, [0x22; 32], 2);
    let row = AnchorRepository::insert_pending(&pool, &anchor)
        .await
        .expect("insert");

    let err = sqlx::query("UPDATE anchors SET status = 'confirmed' WHERE id = $1")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect_err("confirming with a NULL tx_id must be refused");
    assert!(
        err.to_string().contains("anchors_confirmed_has_tx"),
        "expected the CHECK by name, got: {err}"
    );

    // A block height with no tx_id is equally refused.
    let err =
        sqlx::query("UPDATE anchors SET status = 'confirmed', block_height = 7 WHERE id = $1")
            .bind(row.id)
            .execute(&pool)
            .await
            .expect_err("still no tx_id");
    assert!(err.to_string().contains("anchors_confirmed_has_tx"));

    // The complete transition succeeds.
    AnchorRepository::mark_submitted(&pool, row.id, "deadbeef")
        .await
        .expect("submit");
    AnchorRepository::mark_confirmed(&pool, row.id, "deadbeef", 7, chrono::Utc::now())
        .await
        .expect("confirm");

    let confirmed = AnchorRepository::get_by_id(&pool, row.id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(confirmed.status, "confirmed");
    assert_eq!(confirmed.tx_id.as_deref(), Some("deadbeef"));
    assert_eq!(confirmed.block_height, Some(7));
    assert!(confirmed.block_time.is_some());
    assert!(confirmed.submitted_at.is_some());
    assert!(confirmed.confirmed_at.is_some());
}

/// `list_open` is the read path `idx_anchors_open` exists for, and the input to
/// `poll_pending`.
#[sqlx::test(migrations = "../../migrations")]
async fn list_open_returns_only_unconfirmed_anchors(pool: PgPool) {
    let pending = Uuid::new_v4();
    let submitted = Uuid::new_v4();
    let confirmed = Uuid::new_v4();
    let failed = Uuid::new_v4();

    for (root_id, hash) in [
        (pending, 0x01u8),
        (submitted, 0x02),
        (confirmed, 0x03),
        (failed, 0x04),
    ] {
        let (anchor, _) = new_anchor(root_id, [hash; 32], 1);
        let row = AnchorRepository::insert_pending(&pool, &anchor)
            .await
            .expect("insert");
        if root_id == submitted {
            AnchorRepository::mark_submitted(&pool, row.id, "tx-submitted")
                .await
                .expect("submit");
        } else if root_id == confirmed {
            AnchorRepository::mark_submitted(&pool, row.id, "tx-confirmed")
                .await
                .expect("submit");
            AnchorRepository::mark_confirmed(&pool, row.id, "tx-confirmed", 3, chrono::Utc::now())
                .await
                .expect("confirm");
        } else if root_id == failed {
            AnchorRepository::mark_failed(&pool, row.id, "nope")
                .await
                .expect("fail");
        }
    }

    let open: Vec<Uuid> = AnchorRepository::list_open(&pool, 50)
        .await
        .expect("list_open")
        .into_iter()
        .map(|r| r.root_id)
        .collect();
    assert!(open.contains(&pending), "pending must be open");
    assert!(open.contains(&submitted), "submitted must be open");
    assert!(!open.contains(&confirmed), "confirmed is done");
    assert!(!open.contains(&failed), "failed is not awaiting anything");

    assert_eq!(
        AnchorRepository::list_all(&pool, 50)
            .await
            .expect("all")
            .len(),
        4,
        "list_all sees every row including the failed one"
    );
}

async fn count_anchors(pool: &PgPool, root_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM anchors WHERE root_id = $1")
        .bind(root_id)
        .fetch_one(pool)
        .await
        .expect("count anchors")
}

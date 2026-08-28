//! `ManifestRepository` against a real database (migration 071).
//!
//! These tests pin the schema decisions that the rest of the feature relies on
//! and that a future "tidy-up" would otherwise quietly undo:
//!
//! * `manifest_entries.row_id` is NOT a foreign key, so deleting a committed
//!   claim leaves the entry row behind as evidence of the omission;
//! * `manifests.signer_id` is `ON DELETE SET NULL`, so a manifest outlives its
//!   signer's `agents` row and the snapshotted public key still verifies;
//! * the manifest and its leaves land in ONE transaction.

use epigraph_db::{
    ClaimLeafInput, ManifestRepository, NewManifest, NewManifestEntry, MANIFEST_ALGO,
};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&pk)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value)
         VALUES ($1, $2, sha256($1::text::bytea), $3, 0.6)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    id
}

/// A syntactically valid manifest over `rows`, with fabricated (but
/// correctly-shaped) crypto material. These tests exercise persistence, not
/// hashing — the real leaves are built in the engine's tests.
fn make_manifest(signer_id: Option<Uuid>, rows: &[(&str, Uuid)]) -> NewManifest {
    let entries: Vec<NewManifestEntry> = rows
        .iter()
        .enumerate()
        .map(|(i, (kind, row_id))| NewManifestEntry {
            position: i32::try_from(i).unwrap(),
            row_kind: (*kind).to_string(),
            row_id: *row_id,
            leaf_hash: vec![u8::try_from(i).unwrap_or(0); 32],
        })
        .collect();
    NewManifest {
        id: Uuid::new_v4(),
        root: vec![0xAB; 32],
        entry_count: i32::try_from(entries.len()).unwrap(),
        subject: serde_json::json!({"kind": "test_export"}),
        signed_header: br#"{"algo":"blake3-merkle-v1"}"#.to_vec(),
        signature: vec![0xCD; 64],
        signer_id,
        signer_public_key: vec![0xEF; 32],
        created_at: chrono::DateTime::from_timestamp_micros(1_756_000_000_123_456).unwrap(),
        entries,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn insert_then_get_roundtrips_all_columns(pool: PgPool) {
    let agent = seed_agent(&pool, "manifest-signer").await;
    let claim = seed_claim(&pool, agent, "committed claim").await;
    let new = make_manifest(Some(agent), &[("claim", claim)]);

    let id = ManifestRepository::insert(&pool, &new)
        .await
        .expect("insert manifest");
    assert_eq!(id, new.id, "insert returns the caller-supplied id");

    let got = ManifestRepository::get(&pool, id)
        .await
        .expect("get")
        .expect("manifest exists");

    assert_eq!(got.algo, MANIFEST_ALGO);
    assert_eq!(got.root, new.root);
    assert_eq!(got.entry_count, 1);
    assert_eq!(got.subject, new.subject);
    assert_eq!(got.signed_header, new.signed_header);
    assert_eq!(got.signature, new.signature);
    assert_eq!(got.signer_id, Some(agent));
    assert_eq!(got.signer_public_key, new.signer_public_key);
    assert_eq!(
        got.created_at, new.created_at,
        "created_at must round-trip EXACTLY — the signed header carries it, so a \
         sub-microsecond drift would fail header_consistent on every manifest"
    );

    let entries = ManifestRepository::entries(&pool, id)
        .await
        .expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].position, 0);
    assert_eq!(entries[0].row_kind, "claim");
    assert_eq!(entries[0].row_id, claim);
    assert_eq!(entries[0].leaf_hash.len(), 32);
    assert_eq!(
        ManifestRepository::count_entries(&pool, id).await.unwrap(),
        1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn insert_writes_manifest_and_entries_atomically(pool: PgPool) {
    let agent = seed_agent(&pool, "atomic-signer").await;
    let claim = seed_claim(&pool, agent, "atomic claim").await;

    // Two entries at the same position violate the (manifest_id, position)
    // primary key. The manifests row is inserted FIRST in the same tx, so a
    // non-transactional implementation would leave it behind — a signed root
    // over a leaf list that cannot reproduce it.
    let mut new = make_manifest(Some(agent), &[("claim", claim)]);
    new.entries.push(NewManifestEntry {
        position: 0,
        row_kind: "edge".to_string(),
        row_id: Uuid::new_v4(),
        leaf_hash: vec![0x11; 32],
    });
    new.entry_count = 2;

    let err = ManifestRepository::insert(&pool, &new).await.unwrap_err();
    assert!(
        err.to_string().contains("duplicate")
            || err.to_string().contains("Duplicate")
            || err.to_string().contains("unique"),
        "expected a duplicate-key failure, got: {err}"
    );

    assert!(
        ManifestRepository::get(&pool, new.id)
            .await
            .unwrap()
            .is_none(),
        "the manifests row must NOT survive a failed entry insert"
    );
    let orphans: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM manifest_entries WHERE manifest_id = $1")
            .bind(new.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(orphans, 0, "no entry rows may survive either");
}

#[sqlx::test(migrations = "../../migrations")]
async fn load_claim_leaf_inputs_returns_only_the_immutable_columns_for_the_requested_ids(
    pool: PgPool,
) {
    let agent = seed_agent(&pool, "leaf-agent").await;
    let a = seed_claim(&pool, agent, "claim A").await;
    let b = seed_claim(&pool, agent, "claim B").await;
    let unrelated = seed_claim(&pool, agent, "claim C, not requested").await;

    let rows = ManifestRepository::load_claim_leaf_inputs(&pool, &[a, b])
        .await
        .expect("load claim leaf inputs");

    let ids: Vec<Uuid> = rows.iter().map(|r: &ClaimLeafInput| r.id).collect();
    assert_eq!(rows.len(), 2);
    assert!(ids.contains(&a) && ids.contains(&b));
    assert!(!ids.contains(&unrelated));

    for row in &rows {
        assert_eq!(
            row.content_hash.len(),
            32,
            "content_hash is the fixed-width column the leaf commits to"
        );
        assert_eq!(row.agent_id, agent);
    }

    // A missing id is simply absent — the CALLER fails closed on the length
    // mismatch rather than the repo inventing a placeholder.
    let with_ghost = ManifestRepository::load_claim_leaf_inputs(&pool, &[a, Uuid::new_v4()])
        .await
        .unwrap();
    assert_eq!(with_ghost.len(), 1);

    assert!(ManifestRepository::load_claim_leaf_inputs(&pool, &[])
        .await
        .unwrap()
        .is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn load_edge_leaf_inputs_returns_relationship_and_created_at(pool: PgPool) {
    let agent = seed_agent(&pool, "edge-agent").await;
    let src = seed_claim(&pool, agent, "edge source").await;
    let dst = seed_claim(&pool, agent, "edge target").await;
    let edge = seed_edge(&pool, src, dst, "derived_from").await;

    let rows = ManifestRepository::load_edge_leaf_inputs(&pool, &[edge])
        .await
        .expect("load edge leaf inputs");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, edge);
    assert_eq!(rows[0].relationship, "derived_from");
    assert!(rows[0].created_at.timestamp_micros() > 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_the_manifest_cascades_its_entries(pool: PgPool) {
    let agent = seed_agent(&pool, "cascade-signer").await;
    let claim = seed_claim(&pool, agent, "cascade claim").await;
    let new = make_manifest(Some(agent), &[("claim", claim)]);
    ManifestRepository::insert(&pool, &new).await.unwrap();

    sqlx::query("DELETE FROM manifests WHERE id = $1")
        .bind(new.id)
        .execute(&pool)
        .await
        .expect("delete manifest");

    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM manifest_entries WHERE manifest_id = $1")
            .bind(new.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(left, 0, "entries cascade with their manifest");
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_a_committed_claim_leaves_the_entry_row_intact(pool: PgPool) {
    // THE no-FK decision. An ON DELETE CASCADE from `claims` would erase this
    // entry when the claim is deleted — silently destroying the evidence of the
    // very omission the manifest exists to detect.
    let agent = seed_agent(&pool, "no-fk-signer").await;
    let claim = seed_claim(&pool, agent, "about to be deleted").await;
    let new = make_manifest(Some(agent), &[("claim", claim)]);
    ManifestRepository::insert(&pool, &new).await.unwrap();

    sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("delete the committed claim");

    let entries = ManifestRepository::entries(&pool, new.id).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "the dangling entry MUST survive so verification can report it missing"
    );
    assert_eq!(entries[0].row_id, claim);
    assert_eq!(
        ManifestRepository::count_entries(&pool, new.id)
            .await
            .unwrap(),
        1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_the_signer_agent_nulls_signer_id_but_keeps_signer_public_key(pool: PgPool) {
    // ON DELETE SET NULL, not RESTRICT: `AgentRepository::delete` is exercised
    // by existing teardown paths and RESTRICT would start failing them. The
    // snapshotted key means verification survives the loss of the FK.
    let signer = seed_agent(&pool, "doomed-signer").await;
    let author = seed_agent(&pool, "claim-author").await;
    let claim = seed_claim(&pool, author, "outlives its signer").await;
    let new = make_manifest(Some(signer), &[("claim", claim)]);
    ManifestRepository::insert(&pool, &new).await.unwrap();

    let deleted = epigraph_db::AgentRepository::delete(&pool, signer.into())
        .await
        .expect("AgentRepository::delete must not be blocked by a manifest");
    assert!(deleted);

    let got = ManifestRepository::get(&pool, new.id)
        .await
        .unwrap()
        .expect("the manifest itself survives");
    assert_eq!(got.signer_id, None, "lineage FK is nulled");
    assert_eq!(
        got.signer_public_key, new.signer_public_key,
        "the verification authority is the snapshot, and it must survive"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn entry_count_zero_is_rejected_by_the_check_constraint(pool: PgPool) {
    // Belt and braces with `MerkleError::Empty` in the crypto layer: a manifest
    // over zero rows proves nothing and must not be storable by any path.
    let agent = seed_agent(&pool, "empty-signer").await;
    let mut new = make_manifest(Some(agent), &[]);
    new.entry_count = 0;

    let err = ManifestRepository::insert(&pool, &new).await.unwrap_err();
    assert!(
        err.to_string().contains("manifests_entry_count_positive"),
        "expected the entry_count CHECK to fire, got: {err}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_object_subject_is_rejected(pool: PgPool) {
    let agent = seed_agent(&pool, "subject-signer").await;
    let claim = seed_claim(&pool, agent, "subject claim").await;
    let mut new = make_manifest(Some(agent), &[("claim", claim)]);
    new.subject = serde_json::json!("a bare string is not a subject");

    let err = ManifestRepository::insert(&pool, &new).await.unwrap_err();
    assert!(
        err.to_string().contains("manifests_subject_is_object"),
        "expected the subject CHECK to fire, got: {err}"
    );
}

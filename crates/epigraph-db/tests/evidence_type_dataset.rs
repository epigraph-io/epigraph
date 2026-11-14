//! `dataset` evidence (backlog c8beb101): migration 229 and its undo, and the
//! repository write and read-back.
//!
//! Before 229, `evidence_type_valid` (migration 001) admitted seven names and
//! not `dataset`, so every dataset row was refused with 23514. Each test here
//! measures the stored row or the catalog, not a fixture's echo.

mod viewer_fixture;

use epigraph_core::{
    AgentId, ClaimId, DatasetManifestInput, Evidence, EvidenceType, STORED_EVIDENCE_TYPES,
};
use epigraph_db::EvidenceRepository;
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const UNDO_229: &str = include_str!("../../../docs/runbooks/229-undo.sql");

const B3_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

fn dataset(root: &str) -> EvidenceType {
    EvidenceType::dataset(DatasetManifestInput {
        root_uri: root.to_string(),
        manifest_uri: Some(format!("{root}/MANIFEST.b3")),
        manifest_blob_id: None,
        manifest_hash: format!("blake3:{B3_HEX}"),
        hash_algorithm: None,
        file_count: 12,
        total_bytes: 9_876_543_210,
        sample_id: Some("sample-3".to_string()),
        blob_ids: vec!["blob-a".to_string()],
    })
    .expect("a valid dataset")
}

async fn write_dataset_evidence(pool: &PgPool, claim: Uuid, body: &str, root: &str) -> Evidence {
    let evidence = Evidence::new(
        AgentId::new(),
        [0u8; 32],
        epigraph_crypto::ContentHasher::hash(body.as_bytes()),
        dataset(root),
        Some(body.to_string()),
        ClaimId::from_uuid(claim),
    );
    EvidenceRepository::create(pool, &evidence)
        .await
        .expect("a dataset evidence row must be admitted")
}

/// The quoted names in `evidence_type_valid`'s current definition.
async fn constraint_vocabulary(pool: &PgPool) -> BTreeSet<String> {
    let def = constraint_def(pool)
        .await
        .expect("evidence_type_valid exists");
    def.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

async fn constraint_def(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = 'public.evidence'::regclass AND conname = 'evidence_type_valid'",
    )
    .fetch_optional(pool)
    .await
    .expect("read pg_constraint")
}

/// A dataset row written through the repository lands with the stored type
/// `dataset`, its root in `evidence.source_url`, and every structured field
/// back intact on read.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dataset_row_round_trips_through_the_repository(pool: PgPool) {
    let agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101")
        .await
        .0;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: run 42 passed").await;
    let root = "s3://lab-runs/c8beb101/run-42";
    let written = write_dataset_evidence(&pool, claim, "run 42 output", root).await;

    let (stored_type, source_url): (String, Option<String>) =
        sqlx::query_as("SELECT evidence_type, source_url FROM evidence WHERE id = $1")
            .bind(Uuid::from(written.id))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_type, "dataset");
    assert_eq!(source_url.as_deref(), Some(root));

    let viewer = viewer_fixture::public_viewer(&pool).await;
    let read = EvidenceRepository::get_by_id(&pool, &viewer, written.id)
        .await
        .unwrap()
        .expect("the public row is visible");
    assert_eq!(read.evidence_type, dataset(root));
}

/// The CHECK's vocabulary and its one Rust copy are the same set, so a later
/// widening that forgets either side fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_check_admits_exactly_the_stored_vocabulary(pool: PgPool) {
    let expected: BTreeSet<String> = STORED_EVIDENCE_TYPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(constraint_vocabulary(&pool).await, expected);

    // And it still refuses a name outside it.
    let claim_agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-neg")
        .await
        .0;
    let claim = viewer_fixture::seed_public_claim(&pool, claim_agent, "c8beb101: neg").await;
    let err = sqlx::query(
        "INSERT INTO evidence (content_hash, evidence_type, claim_id) VALUES ($1, 'manifest', $2)",
    )
    .bind(vec![7u8; 32])
    .bind(claim)
    .execute(&pool)
    .await
    .expect_err("an unknown evidence_type must be refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
}

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

async fn run_undo(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = sqlx::raw_sql(UNDO_229)
        .execute(&mut *conn)
        .await
        .map(|_| ());
    if out.is_err() {
        // The script's own BEGIN is left open by the refusal, as psql would
        // leave it before exiting; end it so the pooled connection is usable.
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("ROLLBACK");
    }
    out
}

/// `docs/runbooks/229-undo.sql`: on a database migrated through 229 it returns
/// `evidence_type_valid` to its definition below 229, a second run changes
/// nothing, and while a dataset row exists it refuses and changes nothing.
#[sqlx::test(migrations = false)]
async fn the_229_undo_restores_the_constraint_below_229(pool: PgPool) {
    migrate(&pool, &up_to(228)).await;
    let below = constraint_def(&pool).await.expect("001's constraint");
    assert!(!below.contains("dataset"), "{below}");

    migrate(&pool, &MIGRATOR).await;
    let at_229 = constraint_def(&pool).await.unwrap();
    assert!(at_229.contains("'dataset'"), "{at_229}");

    // A dataset row blocks the undo, which then changes nothing.
    let agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-undo")
        .await
        .0;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: undo").await;
    let row = write_dataset_evidence(&pool, claim, "run u", "s3://b/run-u").await;
    let err = run_undo(&pool).await.expect_err("the undo must refuse");
    assert!(err.to_string().contains("229-undo"), "{err}");
    assert_eq!(constraint_def(&pool).await.unwrap(), at_229);

    sqlx::query("DELETE FROM evidence WHERE id = $1")
        .bind(Uuid::from(row.id))
        .execute(&pool)
        .await
        .unwrap();
    run_undo(&pool).await.expect("undo");
    assert_eq!(constraint_def(&pool).await.unwrap(), below);
    run_undo(&pool).await.expect("undo, second run");
    assert_eq!(constraint_def(&pool).await.unwrap(), below);
}

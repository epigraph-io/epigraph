//! `dataset` evidence (backlog c8beb101): migration 229 and its undo, the
//! repository write and read-back, and the per-row-filtered read behind
//! `get_claim`'s `datasets`.
//!
//! Before 229, `evidence_type_valid` (migration 001) admitted seven names and
//! not `dataset`, so every dataset row was refused with 23514. Each test here
//! measures the stored row or the catalog, not a fixture's echo.

mod viewer_fixture;

use epigraph_core::{
    AgentId, ClaimId, DatasetManifestInput, Evidence, EvidenceType, STORED_EVIDENCE_TYPES,
};
use epigraph_db::{EvidenceRepository, LineageRepository};
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

/// `get_claim`'s read: dataset rows only, per claim, oldest first, filtered
/// PER ROW so a group-private dataset row on a public claim stays hidden from
/// a viewer outside the group.
#[sqlx::test(migrations = "../../migrations")]
async fn datasets_by_claim_ids_returns_visible_dataset_rows_only(pool: PgPool) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-read").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: two runs").await;
    let other = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: no datasets").await;
    let first = write_dataset_evidence(&pool, claim, "run 1", "s3://b/run-1").await;
    let second = write_dataset_evidence(&pool, claim, "run 2", "s3://b/run-2").await;
    // A non-dataset row on the same claim is not a dataset.
    viewer_fixture::seed_evidence(&pool, claim, "document").await;
    // A dataset row pinned to the group: a public reader must not see it.
    let hidden = write_dataset_evidence(&pool, claim, "run 3", "s3://b/run-3").await;
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(Uuid::from(hidden.id))
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();

    let public = viewer_fixture::public_viewer(&pool).await;
    let got = EvidenceRepository::datasets_by_claim_ids(&pool, &public, &[claim, other], 32)
        .await
        .unwrap();
    let ids: Vec<Uuid> = got[&claim].iter().map(|d| d.evidence_id).collect();
    assert_eq!(ids, vec![Uuid::from(first.id), Uuid::from(second.id)]);
    assert_eq!(got[&claim][0].dataset, dataset("s3://b/run-1"));
    assert!(!got.contains_key(&other), "{got:?}");

    // Serialised flat, with the variant's tag: the shape get_claim returns.
    let json = serde_json::to_value(&got[&claim][0]).unwrap();
    assert_eq!(json["evidence_id"], Uuid::from(first.id).to_string());
    assert_eq!(json["type"], "dataset");
    assert_eq!(json["manifest_hash"], format!("blake3:{B3_HEX}"));
    assert_eq!(json["file_count"], 12);

    let member = epigraph_db::Viewer::resolve(&pool, agent).await.unwrap();
    let got = EvidenceRepository::datasets_by_claim_ids(&pool, &member, &[claim], 32)
        .await
        .unwrap();
    assert_eq!(got[&claim].len(), 3, "the group member sees its own row");
}

/// The lineage read behind `get_provenance` carries a dataset row's fields,
/// and nothing for any other evidence type.
#[sqlx::test(migrations = "../../migrations")]
async fn the_lineage_carries_dataset_properties(pool: PgPool) {
    let agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-lin")
        .await
        .0;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: lineage").await;
    let ds = write_dataset_evidence(&pool, claim, "run 9", "s3://b/run-9").await;
    let doc = viewer_fixture::seed_evidence(&pool, claim, "document").await;

    let viewer = viewer_fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let lineage = LineageRepository::get_lineage_conn(&mut conn, &viewer, claim, Some(1), Some(10))
        .await
        .unwrap();
    let ds_row = &lineage.evidence[&Uuid::from(ds.id)];
    let parsed: EvidenceType =
        serde_json::from_value(ds_row.dataset.clone().expect("dataset properties")).unwrap();
    assert_eq!(parsed, dataset("s3://b/run-9"));
    assert_eq!(lineage.evidence[&doc].dataset, None);
}

/// A sealed dataset row has its `properties` blanked to `{}`. The lineage
/// must then report no dataset rather than a `{}` with no root or digest
/// (review finding 5), agreeing with `datasets_by_claim_ids`, which skips it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dataset_row_with_blanked_properties_reports_no_dataset(pool: PgPool) {
    let agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-seal")
        .await
        .0;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: sealed").await;
    let ds = write_dataset_evidence(&pool, claim, "run 10", "s3://b/run-10").await;
    // The seal's own blanking (`privatization`: `properties = '{}'::jsonb`).
    sqlx::query("UPDATE evidence SET properties = '{}'::jsonb WHERE id = $1")
        .bind(Uuid::from(ds.id))
        .execute(&pool)
        .await
        .unwrap();

    let viewer = viewer_fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let lineage = LineageRepository::get_lineage_conn(&mut conn, &viewer, claim, Some(1), Some(10))
        .await
        .unwrap();
    let row = &lineage.evidence[&Uuid::from(ds.id)];
    assert_eq!(row.evidence_type, "dataset");
    assert_eq!(row.dataset, None, "a blanked row is not a dataset: {row:?}");
    let datasets = EvidenceRepository::datasets_by_claim_ids(&pool, &viewer, &[claim], 32)
        .await
        .unwrap();
    assert!(!datasets.contains_key(&claim), "{datasets:?}");
}

/// `get_claim` always includes a claim's datasets, so the read is capped per
/// claim (review finding 6): the oldest `limit` rows, per claim, never more.
#[sqlx::test(migrations = "../../migrations")]
async fn datasets_by_claim_ids_caps_rows_per_claim(pool: PgPool) {
    let agent = viewer_fixture::seed_agent_with_group(&pool, "c8beb101-cap")
        .await
        .0;
    let a = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: cap a").await;
    let b = viewer_fixture::seed_public_claim(&pool, agent, "c8beb101: cap b").await;
    let mut a_ids = Vec::new();
    for i in 0..3 {
        let e =
            write_dataset_evidence(&pool, a, &format!("a run {i}"), &format!("s3://b/a-{i}")).await;
        a_ids.push(Uuid::from(e.id));
    }
    let b_only = write_dataset_evidence(&pool, b, "b run", "s3://b/b-0").await;

    let viewer = viewer_fixture::public_viewer(&pool).await;
    let got = EvidenceRepository::datasets_by_claim_ids(&pool, &viewer, &[a, b], 2)
        .await
        .unwrap();
    let ids: Vec<Uuid> = got[&a].iter().map(|d| d.evidence_id).collect();
    assert_eq!(ids, a_ids[..2].to_vec(), "the oldest two of claim a");
    // The cap is per claim: claim b's row is not crowded out by claim a's.
    assert_eq!(
        got[&b].iter().map(|d| d.evidence_id).collect::<Vec<_>>(),
        vec![Uuid::from(b_only.id)]
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

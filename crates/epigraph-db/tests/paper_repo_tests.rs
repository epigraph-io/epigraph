//! `PaperRepository` integration tests.

#[path = "viewer_fixture.rs"]
mod fixture;

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_inserts_then_returns_existing(pool: PgPool) {
    let doi = "10.1234/test-paper-1";
    let id1 = PaperRepository::get_or_create(&pool, doi, Some("Title 1"), Some("Journal X"))
        .await
        .expect("first insert");

    // Second call with the same DOI should return the same id (UNIQUE on doi).
    let id2 = PaperRepository::get_or_create(&pool, doi, Some("Title 1 updated"), None)
        .await
        .expect("second insert");
    assert_eq!(id1, id2, "same DOI must return same paper id");

    // The conflict path updated the title.
    let row = PaperRepository::find_by_doi(&pool, doi)
        .await
        .expect("find_by_doi")
        .expect("paper row");
    assert_eq!(row.id, id1);
    assert_eq!(row.title.as_deref(), Some("Title 1 updated"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_doi_returns_none_for_unknown(pool: PgPool) {
    let result = PaperRepository::find_by_doi(&pool, "10.0000/does-not-exist")
        .await
        .expect("find_by_doi");
    assert!(result.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn has_processed_by_edge_reflects_pipeline_property(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let paper_id =
        PaperRepository::get_or_create(&pool, "10.1234/has-pbe", Some("Has-PBE Paper"), None)
            .await
            .expect("create paper");

    // No edge yet → false.
    assert!(!PaperRepository::has_processed_by_edge(
        &pool,
        &viewer,
        paper_id,
        "hierarchical_extraction_v1"
    )
    .await
    .expect("query has_processed_by_edge"));

    // Edges enforce target existence via trigger_validate_edge_refs, so we
    // create a real agent + claim to use as the edge target.
    let agent = make_agent(Some("test-agent"));
    let agent_row = AgentRepository::create(&pool, &agent)
        .await
        .expect("create agent");
    let claim = make_claim(agent_row.id, "test claim", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create claim");

    EdgeRepository::create(
        &pool,
        paper_id,
        "paper",
        claim_row.id.into(),
        "claim",
        "processed_by",
        Some(serde_json::json!({"pipeline": "hierarchical_extraction_v1"})),
        None,
        None,
    )
    .await
    .expect("create edge");

    assert!(PaperRepository::has_processed_by_edge(
        &pool,
        &viewer,
        paper_id,
        "hierarchical_extraction_v1"
    )
    .await
    .expect("query has_processed_by_edge"));

    // Different pipeline string → still false.
    assert!(
        !PaperRepository::has_processed_by_edge(&pool, &viewer, paper_id, "other_pipeline_v1")
            .await
            .expect("query has_processed_by_edge")
    );
}

/// `count_claims_by_doi_label` counts claims labelled `doi:<doi>` regardless
/// of whether a `paper -asserts-> claim` edge exists for them — this is the
/// signal `query_paper` unions with `count_asserted_claims` so a partial
/// ingestion (claim labelled, edge not yet written) still reads as non-zero.
#[sqlx::test(migrations = "../../migrations")]
async fn count_claims_by_doi_label_ignores_asserts_edges(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let doi = "10.1234/label-count-test";

    assert_eq!(
        PaperRepository::count_claims_by_doi_label(&pool, &viewer, doi)
            .await
            .expect("count with no claims"),
        0
    );

    let agent = make_agent(Some("label-count-agent"));
    let agent_row = AgentRepository::create(&pool, &agent)
        .await
        .expect("create agent");
    let claim = make_claim(agent_row.id, "orphan-labeled claim", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create claim");

    // Label the claim but deliberately create no `asserts` edge.
    ClaimRepository::update_labels(&pool, claim_row.id.into(), &[format!("doi:{doi}")], &[])
        .await
        .expect("label claim");

    assert_eq!(
        PaperRepository::count_claims_by_doi_label(&pool, &viewer, doi)
            .await
            .expect("count after labeling"),
        1,
        "labeled claim must count even without an asserts edge"
    );
}

// =============================================================================
// One document key per paper on the MCP writer too (backlog 90756d26)
// =============================================================================
//
// `get_or_create` is the writer every MCP ingest path uses
// (`ensure_paper_node`, `do_ingest_document`, `do_ingest_document_spine`). Its
// old `INSERT ... ON CONFLICT (doi)` only matched the exact spelling, so a DOI
// whose only row was keyed on a resolver URL (written before keys were
// canonicalized) got a bare-keyed twin beside it on the next ingest.

/// Every `papers` row whose key ends in `suffix`, whatever its prefix.
async fn rows_ending_in(pool: &PgPool, suffix: &str) -> Vec<(uuid::Uuid, String)> {
    sqlx::query_as("SELECT id, doi FROM papers WHERE doi LIKE '%' || $1 ORDER BY doi")
        .bind(suffix)
        .fetch_all(pool)
        .await
        .expect("read papers rows")
}

/// A row keyed VERBATIM, the way a pre-canonicalization writer stored it.
async fn seed_raw_paper(pool: &PgPool, key: &str, title: &str) -> uuid::Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(key)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("seed raw paper row")
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_reuses_a_legacy_url_keyed_row_instead_of_twinning(pool: PgPool) {
    let bare = "10.5555/repo-legacy-reuse";
    let legacy_key = format!("https://doi.org/{bare}");
    let legacy_id = seed_raw_paper(&pool, &legacy_key, "legacy").await;

    let id = PaperRepository::get_or_create(&pool, bare, Some("re-ingested"), None)
        .await
        .expect("get_or_create");

    assert_eq!(
        rows_ending_in(&pool, "repo-legacy-reuse").await,
        vec![(legacy_id, legacy_key)],
        "an ingest under the bare DOI must reuse the URL-keyed row, not mint a bare twin"
    );
    assert_eq!(id, legacy_id);
    let title: Option<String> = sqlx::query_scalar("SELECT title FROM papers WHERE id = $1")
        .bind(legacy_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        title.as_deref(),
        Some("re-ingested"),
        "the row found is upserted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_prefers_the_canonical_row_over_a_legacy_twin(pool: PgPool) {
    let bare = "10.5555/repo-twin-order";
    // Legacy row FIRST, so heap order alone would hand it back.
    let _legacy = seed_raw_paper(&pool, &format!("https://doi.org/{bare}"), "legacy").await;
    let canonical = seed_raw_paper(&pool, bare, "canonical").await;

    let id = PaperRepository::get_or_create(&pool, &format!("https://doi.org/{bare}"), None, None)
        .await
        .expect("get_or_create");
    assert_eq!(
        id, canonical,
        "with both spellings stored, the canonical (bare) row is the one returned"
    );
    assert_eq!(rows_ending_in(&pool, "repo-twin-order").await.len(), 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_stores_a_new_paper_under_the_canonical_key(pool: PgPool) {
    let bare = "10.5555/repo-canonical-insert";
    for spelling in [format!("doi:{bare}"), format!("https://dx.doi.org/{bare}")] {
        PaperRepository::get_or_create(&pool, &spelling, None, None)
            .await
            .expect("get_or_create");
    }
    let rows = rows_ending_in(&pool, "repo-canonical-insert").await;
    assert_eq!(rows.len(), 1, "two spellings, one paper: {rows:?}");
    assert_eq!(rows[0].1, bare, "stored under the bare DOI: {rows:?}");
}

/// Two writers racing on one NEW DOI under different spellings must converge
/// on one row. Made deterministic by holding the canonical row's INSERT open
/// on another connection until the writer under test is seen waiting on it.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_writers_under_two_spellings_of_a_new_doi_converge(pool: PgPool) {
    let bare = "10.5555/repo-race";
    let mut held = pool.begin().await.expect("begin held tx");
    let held_id: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'held') RETURNING id")
            .bind(bare)
            .fetch_one(&mut *held)
            .await
            .expect("held insert");

    let p = pool.clone();
    let writer = tokio::spawn(async move {
        PaperRepository::get_or_create(&p, &format!("https://doi.org/{bare}"), None, None).await
    });

    // Wait (bounded) until the writer blocks on the held row's unique-index
    // entry, or finishes without blocking.
    for _ in 0..200 {
        if writer.is_finished() {
            break;
        }
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE '%INSERT INTO papers%'",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    held.commit().await.expect("commit held row");

    let id = writer.await.expect("join").expect("get_or_create");
    assert_eq!(
        rows_ending_in(&pool, "repo-race").await,
        vec![(held_id, bare.to_string())],
        "one paper, under the canonical key"
    );
    assert_eq!(id, held_id);
}

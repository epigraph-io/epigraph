//! `PaperRepository` integration tests.

#[path = "viewer_fixture.rs"]
mod fixture;

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_inserts_then_returns_existing(pool: PgPool) {
    let doi = "10.1234/test-paper-1";
    let id1 = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        Some("Title 1"),
        Some("Journal X"),
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("first insert");

    // Second call with the same DOI should return the same id (UNIQUE on doi).
    let id2 = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        Some("Title 1 updated"),
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("second insert");
    assert_eq!(id1, id2, "same DOI must return same paper id");

    // A hit fills only what is missing (backlog 62ce37ca): the first
    // writer's title stands.
    let row = PaperRepository::find_by_doi(&pool, doi)
        .await
        .expect("find_by_doi")
        .expect("paper row");
    assert_eq!(row.id, id1);
    assert_eq!(row.title.as_deref(), Some("Title 1"));
    assert_eq!(row.journal.as_deref(), Some("Journal X"));
}

/// Backlog 62ce37ca: `papers` is a global table with no row security, so a
/// get-or-create HIT must not rewrite another ingester's bibliographic fields.
/// It may only fill a field that is still NULL. Both halves are asserted: a
/// pure insert-only writer would pass the first and fail the second.
#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_on_a_hit_fills_only_null_fields(pool: PgPool) {
    let doi = "10.5555/repo-fill-only";
    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        Some("Original title"),
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("first writer");

    let again = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        Some("Rewritten by a second ingester"),
        Some("Second journal"),
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("second writer");
    assert_eq!(again, id);

    let row = PaperRepository::find_by_doi(&pool, doi)
        .await
        .expect("find_by_doi")
        .expect("paper row");
    assert_eq!(
        row.title.as_deref(),
        Some("Original title"),
        "a hit must not overwrite a title another writer set"
    );
    assert_eq!(
        row.journal.as_deref(),
        Some("Second journal"),
        "a hit still fills a field the first writer left NULL"
    );

    // And once filled, the journal is not rewritten either.
    PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        doi,
        None,
        Some("Third journal"),
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("third writer");
    let row = PaperRepository::find_by_doi(&pool, doi)
        .await
        .expect("find_by_doi")
        .expect("paper row");
    assert_eq!(row.title.as_deref(), Some("Original title"));
    assert_eq!(row.journal.as_deref(), Some("Second journal"));
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
    let paper_id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        "10.1234/has-pbe",
        Some("Has-PBE Paper"),
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
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
// (`do_ingest_document`, `do_ingest_document_spine`, on the walk's own
// transaction since backlog b995f117). Its
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

    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        bare,
        Some("re-ingested"),
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
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
        Some("legacy"),
        "the row found keeps its title: a hit fills only NULL fields (backlog 62ce37ca)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_prefers_the_canonical_row_over_a_legacy_twin(pool: PgPool) {
    let bare = "10.5555/repo-twin-order";
    // Legacy row FIRST, so heap order alone would hand it back.
    let _legacy = seed_raw_paper(&pool, &format!("https://doi.org/{bare}"), "legacy").await;
    let canonical = seed_raw_paper(&pool, bare, "canonical").await;

    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        &format!("https://doi.org/{bare}"),
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
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
        PaperRepository::get_or_create(
            &mut pool.acquire().await.expect("acquire"),
            &spelling,
            None,
            None,
            epigraph_core::TenancyDecl::instance_wide(),
        )
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
        PaperRepository::get_or_create(
            &mut p.acquire().await.expect("acquire"),
            &format!("https://doi.org/{bare}"),
            None,
            None,
            epigraph_core::TenancyDecl::instance_wide(),
        )
        .await
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

/// The `ON CONFLICT (doi)` arm of `get_or_create` (reached only when another
/// writer inserts the same new key concurrently) must fill only NULL fields
/// too, or the race loser rewrites the winner's title (backlog 62ce37ca).
/// Same deterministic hold as the test above.
#[sqlx::test(migrations = "../../migrations")]
async fn the_race_loser_does_not_overwrite_the_winners_title(pool: PgPool) {
    let bare = "10.5555/repo-race-fill-only";
    let mut held = pool.begin().await.expect("begin held tx");
    let held_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title, journal) VALUES ($1, 'winner', NULL) RETURNING id",
    )
    .bind(bare)
    .fetch_one(&mut *held)
    .await
    .expect("held insert");

    let p = pool.clone();
    let writer = tokio::spawn(async move {
        PaperRepository::get_or_create(
            &mut p.acquire().await.expect("acquire"),
            bare,
            Some("loser"),
            Some("loser journal"),
            epigraph_core::TenancyDecl::instance_wide(),
        )
        .await
    });

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
    assert_eq!(id, held_id);
    let (title, journal): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT title, journal FROM papers WHERE id = $1")
            .bind(held_id)
            .fetch_one(&pool)
            .await
            .expect("read the row");
    assert_eq!(
        title.as_deref(),
        Some("winner"),
        "the winner's title stands"
    );
    assert_eq!(
        journal.as_deref(),
        Some("loser journal"),
        "the loser fills only what the winner left NULL"
    );
}

/// A paper's asserted claims are listed and counted once each, however many
/// edges state the same fact, and its authors are listed once PER INGEST
/// PRINCIPAL. Each principal whose ingest of a paper names an author (or
/// asserts a claim) keeps an ingest-written edge of its own, so a paper
/// ingested by two principals carries two `authored` edges for one author and
/// two `asserts` edges for one claim: the claim is one claim, and the
/// authorship is listed with each principal's `written_by`, never merged.
#[sqlx::test(migrations = "../../migrations")]
async fn parallel_edges_list_each_claim_once_and_each_author_once_per_principal(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let paper_id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        "10.1234/parallel-edges",
        Some("Parallel"),
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("create paper");
    let author = AgentRepository::create(&pool, &make_agent(Some("Ysolde Pemberton")))
        .await
        .expect("create author")
        .id;
    let claim = ClaimRepository::create(
        &pool,
        &make_claim(author, "a twice-asserted finding", 0.5),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create claim")
    .id;
    let author: uuid::Uuid = author.into();
    let mut principals = Vec::new();
    for name in ["Ingester One", "Ingester Two"] {
        let by: uuid::Uuid = AgentRepository::create(&pool, &make_agent(Some(name)))
            .await
            .expect("create ingester")
            .id
            .into();
        principals.push(by);
        let mut conn = pool.acquire().await.expect("conn");
        for (src, st, tgt, tt, rel, props) in [
            (
                author,
                "agent",
                paper_id,
                "paper",
                "authored",
                Some(serde_json::json!({"position": 0})),
            ),
            (paper_id, "paper", claim.into(), "claim", "asserts", None),
        ] {
            let (_, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
                &mut conn,
                None,
                "ingest_document",
                by,
                src,
                st,
                tgt,
                tt,
                rel,
                props,
            )
            .await
            .expect("ingest-written edge");
            assert!(
                created,
                "CALIBRATION: each principal writes its own {rel} edge"
            );
        }
    }

    let authors = PaperRepository::list_authors(&pool, &viewer, paper_id)
        .await
        .expect("list_authors");
    let mut written_by: Vec<_> = authors.iter().map(|a| a.written_by).collect();
    written_by.sort();
    let mut expected: Vec<_> = principals.iter().copied().map(Some).collect();
    expected.sort();
    assert_eq!(
        written_by, expected,
        "the author is listed once per principal, each with its own writer: {authors:?}"
    );
    assert!(authors.iter().all(|a| a.agent_id == author));
    assert_eq!(
        PaperRepository::count_asserted_claims(&pool, &viewer, paper_id)
            .await
            .expect("count_asserted_claims"),
        1,
        "a claim counted twice"
    );
    let claims = PaperRepository::list_asserted_claims(&pool, &viewer, paper_id, 10, 0)
        .await
        .expect("list_asserted_claims");
    assert_eq!(claims.len(), 1, "a claim listed twice");
}

// --- Case-variant resolver prefixes (backlog f3a3ca54) ----------------------
//
// A legacy row keyed on a resolver URL whose PREFIX differs from the listed
// spellings only in letter case (`HTTPS://DOI.ORG/10.x/y`, `Doi:10.x/y`) is the
// same document as the bare DOI: `canonical_document_key` already folds the
// prefix's case. The lookup matched the legacy spellings byte-for-byte, so a
// re-ingest under the bare DOI missed such a row and minted a bare twin. The
// DOI suffix keeps its case: only the prefix is compared case-insensitively.

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_reuses_a_case_variant_prefix_row_instead_of_twinning(pool: PgPool) {
    for (n, prefix) in [
        "HTTPS://DOI.ORG/",
        "Http://Dx.Doi.Org/",
        "WWW.DOI.ORG/",
        "DOI:",
    ]
    .into_iter()
    .enumerate()
    {
        let suffix = format!("repo-case-variant-{n}");
        let bare = format!("10.5555/{suffix}");
        let legacy_key = format!("{prefix}{bare}");
        let legacy_id = seed_raw_paper(&pool, &legacy_key, "legacy").await;

        let id = PaperRepository::get_or_create(
            &mut pool.acquire().await.expect("acquire"),
            &bare,
            Some("re-ingested"),
            None,
            epigraph_core::TenancyDecl::instance_wide(),
        )
        .await
        .expect("get_or_create");
        assert_eq!(
            rows_ending_in(&pool, &suffix).await,
            vec![(legacy_id, legacy_key.clone())],
            "an ingest under the bare DOI must reuse the {prefix:?}-keyed row, not mint a twin"
        );
        assert_eq!(id, legacy_id, "{legacy_key}");

        // The read path the MCP paper tools use agrees with the writer, under
        // the bare DOI and under another spelling of it.
        for spelling in [bare.clone(), format!("https://doi.org/{bare}")] {
            let row = PaperRepository::find_by_document_key(&pool, &spelling)
                .await
                .expect("find_by_document_key")
                .unwrap_or_else(|| panic!("{spelling} must find the {legacy_key} row"));
            assert_eq!(row.id, legacy_id, "{spelling} -> {legacy_key}");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_case_variant_prefix_match_keeps_the_suffix_exact_and_prefers_the_exact_row(
    pool: PgPool,
) {
    // The suffix is not folded: a stored `HTTPS://DOI.ORG/10.5555/REPO-SUFFIX`
    // is not the paper a lookup for `10.5555/repo-suffix` names.
    let upper = seed_raw_paper(&pool, "HTTPS://DOI.ORG/10.5555/REPO-SUFFIX", "upper").await;
    let found = PaperRepository::find_by_document_key(&pool, "10.5555/repo-suffix")
        .await
        .expect("find_by_document_key");
    assert!(
        found.is_none(),
        "the DOI suffix is compared exactly: {found:?}"
    );
    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        "10.5555/repo-suffix",
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("get_or_create");
    assert_ne!(id, upper, "a different suffix case is a different key");

    // A non-DOI key is not matched case-insensitively at all.
    seed_raw_paper(&pool, "URN:EPIGRAPH:DOC:repo-case", "urn").await;
    assert!(
        PaperRepository::find_by_document_key(&pool, "urn:epigraph:doc:repo-case")
            .await
            .expect("find_by_document_key")
            .is_none()
    );

    // With both an exact spelling and a case-variant one stored, the exact
    // (canonical) row wins, whatever the heap order.
    let bare = "10.5555/repo-case-order";
    let _variant = seed_raw_paper(&pool, &format!("HTTPS://DOI.ORG/{bare}"), "variant").await;
    let canonical = seed_raw_paper(&pool, bare, "canonical").await;
    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        bare,
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("get_or_create");
    assert_eq!(id, canonical);
    let row = PaperRepository::find_by_document_key(&pool, bare)
        .await
        .expect("find_by_document_key")
        .expect("row");
    assert_eq!(row.id, canonical);
}

// --- The case-variant fallback must not cost an exact hit its index ---------
//
// No index serves the case-variant arm. Written as `exact OR case-variant` in
// one WHERE, it made every lookup scan the whole `papers` table, exact hits
// included: every re-ingest's `get_or_create`, every `query_paper` probe,
// every `GET /api/v1/papers?doi=`. The lookup runs the case-variant scan only
// when no exact spelling is stored, and never for a key that is not a DOI.

/// Sequential scans of `papers` counted so far in the cluster's statistics,
/// after flushing the calling backend's pending counts (PG 15+).
async fn papers_seq_scans(pool: &PgPool) -> i64 {
    sqlx::query("SELECT pg_stat_force_next_flush()")
        .execute(pool)
        .await
        .expect("force stats flush");
    sqlx::query("SELECT pg_stat_clear_snapshot()")
        .execute(pool)
        .await
        .expect("clear stats snapshot");
    sqlx::query_scalar(
        "SELECT seq_scan FROM pg_stat_user_tables \
         WHERE relid = 'public.papers'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("read papers seq_scan")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_exact_key_hit_never_scans_papers(pool: PgPool) {
    use sqlx::postgres::PgPoolOptions;

    let bare = "10.5555/repo-index-hit";
    let canonical = seed_raw_paper(&pool, bare, "canonical").await;
    seed_raw_paper(&pool, "10.5555/repo-index-other", "other").await;
    seed_raw_paper(&pool, "urn:epigraph:doc:repo-index-urn", "urn").await;

    // One connection, so every statement below runs on the backend whose
    // counts `papers_seq_scans` flushes; sequential scans priced out, so a
    // scan that still appears is one the statement had no index path for.
    let one = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET enable_seqscan = off")
                    .execute(conn)
                    .await
                    .map(|_| ())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("single-connection pool");

    let before = papers_seq_scans(&one).await;

    // Exact hits, through every lookup shape: the writer's get-or-create, the
    // read the MCP paper tools use (bare and URL spelling of the key), and
    // the row set the REST list and count read.
    let id = PaperRepository::get_or_create(
        &mut one.acquire().await.expect("acquire"),
        bare,
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("get_or_create");
    assert_eq!(id, canonical);
    for spelling in [bare.to_string(), format!("https://doi.org/{bare}")] {
        let row = PaperRepository::find_by_document_key(&one, &spelling)
            .await
            .expect("find_by_document_key")
            .expect("hit");
        assert_eq!(row.id, canonical, "{spelling}");
    }
    let listed: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM ({}) AS m",
        epigraph_db::repos::paper::document_key_rows_sql("id, doi", 1)
    ))
    .bind(epigraph_db::repos::paper::document_key_spellings(bare))
    .fetch_one(&one)
    .await
    .expect("rows count");
    assert_eq!(listed, 1);
    // A miss on a key that is not a DOI has no prefix to fold: no scan.
    assert!(
        PaperRepository::find_by_document_key(&one, "urn:epigraph:doc:repo-index-miss")
            .await
            .expect("find_by_document_key")
            .is_none()
    );

    assert_eq!(
        papers_seq_scans(&one).await,
        before,
        "an exact hit (or a non-DOI miss) must stay on the papers.doi index"
    );

    // Control: the instrument sees a scan. A miss on a bare DOI is the one
    // lookup that must look for a case-variant prefix, which only a scan can.
    assert!(
        PaperRepository::find_by_document_key(&one, "10.5555/repo-index-miss")
            .await
            .expect("find_by_document_key")
            .is_none()
    );
    assert!(
        papers_seq_scans(&one).await > before,
        "a bare-DOI miss scans papers for a case-variant prefix"
    );
}

// --- The case-variant fallback inside a declared scope (246 + f3a3ca54) -----
//
// Since migration 246 a `papers` row carries the tenancy of the ingest that
// wrote it, and `get_or_create` reuses only a row of the declared scope. The
// case-variant fallback must stay inside that scope too, gate included: a
// group's case-variant row is not a public ingest's to reuse, and a group's
// exact-spelling row must not switch off the fallback for the public scope.

async fn seed_scoped_paper(
    pool: &PgPool,
    key: &str,
    visibility: &str,
    owner: uuid::Uuid,
) -> uuid::Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title, visibility, owner_group_id) \
         VALUES ($1, 'scoped', $2, $3) RETURNING id",
    )
    .bind(key)
    .bind(visibility)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed scoped paper row")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_case_variant_fallback_stays_inside_the_declared_scope(pool: PgPool) {
    let (_, g) = fixture::seed_agent_with_group(&pool, "case-variant-scope").await;
    let world = epigraph_core::TenancyDecl::instance_wide()
        .owner_group_bind()
        .expect("the instance-wide declaration names its owner");

    // A GROUP row keyed on a case-variant prefix belongs to that group.
    let bare = "10.5555/repo-case-scope";
    let group_variant =
        seed_scoped_paper(&pool, &format!("HTTPS://DOI.ORG/{bare}"), "group", g).await;
    let public_id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        bare,
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("public get_or_create");
    assert_ne!(
        public_id, group_variant,
        "a public ingest must not reuse a group's case-variant row"
    );
    let group_id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        bare,
        None,
        None,
        epigraph_core::TenancyDecl::group(g),
    )
    .await
    .expect("group get_or_create");
    assert_eq!(
        group_id, group_variant,
        "the group's own ingest reuses its case-variant row instead of twinning it"
    );
    assert_eq!(
        PaperRepository::find_in_scope(&pool, bare, epigraph_core::TenancyDecl::group(g))
            .await
            .expect("find_in_scope"),
        Some(group_variant),
        "find_in_scope agrees with the writer"
    );

    // The gate is scoped as well: a group row stored under the EXACT bare key
    // does not hide the public scope's case-variant row from a public ingest.
    let bare2 = "10.5555/repo-case-gate";
    let public_variant = seed_scoped_paper(&pool, &format!("Doi:{bare2}"), "public", world).await;
    let _group_exact = seed_scoped_paper(&pool, bare2, "group", g).await;
    let id = PaperRepository::get_or_create(
        &mut pool.acquire().await.expect("acquire"),
        bare2,
        None,
        None,
        epigraph_core::TenancyDecl::instance_wide(),
    )
    .await
    .expect("public get_or_create");
    assert_eq!(
        id, public_variant,
        "another scope's exact row must not switch off this scope's case-variant match"
    );
}

// =============================================================================
// The id of a new row, and the race on it (backlog b995f117)
// =============================================================================

/// A creator whose insert collides with a concurrent writer's row on the
/// PRIMARY KEY, not on the document-key-per-scope index, converges on that
/// row instead of failing. A new public row's id is derived from the document
/// key, so two concurrent public creators insert the same id, and Postgres may
/// check the primary key before the key index: an `ON CONFLICT` naming only
/// the key index then raised 23505 on `papers_pkey`. Here the held row has
/// the derived id under a resolver-URL spelling of the key, so only the
/// primary key collides (deterministically), and the writer's second run must
/// find the held row under that spelling.
#[sqlx::test(migrations = "../../migrations")]
async fn a_creator_colliding_on_the_primary_key_converges_instead_of_failing(pool: PgPool) {
    use epigraph_db::repos::paper::public_paper_id;

    let bare = "10.5555/repo-pk-race";
    let spelled = format!("https://doi.org/{bare}");
    let mut held = pool.begin().await.expect("begin held tx");
    let held_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'held') RETURNING id",
    )
    .bind(public_paper_id(bare))
    .bind(&spelled)
    .fetch_one(&mut *held)
    .await
    .expect("held insert");

    let p = pool.clone();
    let writer = tokio::spawn(async move {
        PaperRepository::get_or_create(
            &mut p.acquire().await.expect("acquire"),
            bare,
            Some("writer"),
            Some("writer journal"),
            epigraph_core::TenancyDecl::instance_wide(),
        )
        .await
    });

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
    assert!(
        !writer.is_finished(),
        "fixture: the writer must be waiting on the held row's primary-key entry"
    );
    held.commit().await.expect("commit held row");

    let id = writer
        .await
        .expect("join")
        .expect("a primary-key collision must converge, not fail with 23505");
    assert_eq!(id, held_id);
    assert_eq!(
        rows_ending_in(&pool, "repo-pk-race").await,
        vec![(held_id, spelled.clone())],
        "one paper"
    );
    let (title, journal): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT title, journal FROM papers WHERE id = $1")
            .bind(held_id)
            .fetch_one(&pool)
            .await
            .expect("read the row");
    assert_eq!(title.as_deref(), Some("held"), "the winner's title stands");
    assert_eq!(
        journal.as_deref(),
        Some("writer journal"),
        "the loser fills only what the winner left NULL"
    );
}

/// `planned` predicts exactly what `get_or_create_stored` then stores, in the
/// three cases a detached ingest meets: no row yet (the derived public id and
/// the caller's title), a row with a title (its id and its title, not the
/// caller's), and a row with a NULL title (its id, filled with the caller's).
/// A drift here is a detached handler announcing an id or a title the walk
/// does not write.
#[sqlx::test(migrations = "../../migrations")]
async fn planned_predicts_what_get_or_create_stored_stores(pool: PgPool) {
    use epigraph_db::repos::paper::public_paper_id;

    let public = epigraph_core::TenancyDecl::instance_wide();
    let titled = "10.1234/planned-titled";
    let untitled = "10.1234/planned-untitled";
    let absent = "https://doi.org/10.1234/planned-absent";
    seed_raw_paper(&pool, titled, "Kept").await;
    sqlx::query("INSERT INTO papers (doi, title) VALUES ($1, NULL)")
        .bind(untitled)
        .execute(&pool)
        .await
        .expect("seed an untitled row");

    for (doi, exists) in [(titled, true), (untitled, true), (absent, false)] {
        let planned = PaperRepository::planned(&pool, doi, Some("Caller"), public)
            .await
            .expect("planned");
        assert_eq!(planned.exists, exists, "{doi}");
        let stored = PaperRepository::get_or_create_stored(
            &mut pool.acquire().await.expect("acquire"),
            doi,
            Some("Caller"),
            None,
            public,
            Some(uuid::Uuid::new_v4()),
        )
        .await
        .expect("get_or_create_stored");
        assert_eq!(
            planned.id, stored.id,
            "{doi}: the announced id is the stored id"
        );
        assert_eq!(
            planned.title, stored.title,
            "{doi}: the announced title is stored"
        );
    }
    let kept = PaperRepository::planned(&pool, titled, Some("Caller"), public)
        .await
        .expect("planned");
    assert_eq!(
        kept.title.as_deref(),
        Some("Kept"),
        "fill-only keeps a title"
    );
    // The new public row is stored under the canonical key, with the id derived
    // from it whichever spelling the caller used, and not the group-copy id the
    // call above passed.
    let created = PaperRepository::find_by_doi(&pool, "10.1234/planned-absent")
        .await
        .expect("find_by_doi")
        .expect("the new row is stored under the canonical key");
    assert_eq!(created.id, public_paper_id(absent));
    assert_eq!(created.id, public_paper_id("10.1234/planned-absent"));
}

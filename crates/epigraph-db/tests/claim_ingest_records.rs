//! The read contract of a claim's ingest records
//! (`ClaimIngestRepository::for_claims`): which document ingest CREATED the
//! claim, and every ingest that asserted it.
//!
//! The record is written by the document walk
//! (`epigraph-mcp/tests/ingest_author_resolution.rs` pins that, through the
//! real ingest). Pinned here, with records written by the same writer
//! (`ClaimIngestRepository::record_conn`):
//! * a record counts only while the SAME paper's `asserts` edge onto the claim
//!   is in force AND readable: a record whose assertion was retracted, or
//!   whose paper never asserted the claim, is not listed;
//! * an `asserts` edge with no record makes no ingest (never inferred from
//!   the edge);
//! * a group-private assertion's record is invisible to an outsider, visible
//!   to a member (the edges' own tenancy, set by the insert trigger);
//! * the creator is the `created_claim` record; a re-run writes no second
//!   record and never turns a convergence into a creation.
//!
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimIngestRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $1) RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("paper")
}

/// The ingest's `paper -asserts-> claim` edge, written as the walk writes it.
async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut conn, None, paper, "paper", claim, "claim", "asserts", None, None, None,
    )
    .await
    .expect("asserts")
    .0
    .id
}

async fn record(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid, created: bool) -> bool {
    let mut conn = pool.acquire().await.expect("conn");
    ClaimIngestRepository::record_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        created,
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("record")
}

/// `(paper, ingested_by, created_claim)` of each listed record, and the
/// creator's paper.
async fn read(
    pool: &PgPool,
    viewer: &Viewer,
    claim: Uuid,
) -> (Vec<(Uuid, Uuid, bool)>, Option<Uuid>) {
    let mut conn = pool.acquire().await.expect("conn");
    let got = ClaimIngestRepository::for_claim(&mut conn, viewer, claim)
        .await
        .expect("for_claim");
    (
        got.records
            .iter()
            .map(|r| (r.paper_id, r.ingested_by, r.created_claim))
            .collect(),
        got.creator.map(|c| c.paper_id),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_record_counts_only_with_its_papers_readable_in_force_assertion(pool: PgPool) {
    let (filer, _) = fixture::seed_agent_with_group(&pool, "ingest-record-filer").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "ingest-record-other").await;
    let claim = fixture::seed_public_claim(&pool, filer, "a recorded claim").await;
    let (p1, p2, p3) = (
        paper(&pool, "10.9999/record-read-1").await,
        paper(&pool, "10.9999/record-read-2").await,
        paper(&pool, "10.9999/record-read-3").await,
    );
    let public = fixture::public_viewer(&pool).await;

    asserts(&pool, p1, claim).await;
    assert!(record(&pool, p1, claim, filer, true).await);
    asserts(&pool, p2, claim).await;
    assert!(record(&pool, p2, claim, other, false).await);
    // A paper that asserts the claim with NO record (an edge written outside
    // the ingest), and a record whose paper never asserted the claim.
    asserts(&pool, p3, claim).await;
    let stray = paper(&pool, "10.9999/record-read-stray").await;
    assert!(record(&pool, stray, claim, other, false).await);

    let (records, creator) = read(&pool, &public, claim).await;
    assert_eq!(
        records,
        vec![(p1, filer, true), (p2, other, false)],
        "only records backed by their own paper's assertion; an assertion alone is no ingest"
    );
    assert_eq!(creator, Some(p1));

    // A re-run writes nothing, and a later "creation" claim for the same
    // (paper, claim, ingester) is not recorded over the convergence.
    assert!(!record(&pool, p2, claim, other, true).await, "dedup");
    assert_eq!(read(&pool, &public, claim).await.0.len(), 2);

    // The creating paper's assertion retracted: its record goes with it.
    sqlx::query(
        "UPDATE edges SET valid_to = now() - interval '1 second' \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'asserts'",
    )
    .bind(p1)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("retract");
    let (records, creator) = read(&pool, &public, claim).await;
    assert_eq!(
        records,
        vec![(p2, other, false)],
        "retracted assertion, no record"
    );
    assert_eq!(creator, None, "no readable creator");
}

/// A document ingested into a group: the claim, its assertion and its record
/// are the group's (the edge insert trigger takes the endpoints' meet). An
/// outsider reads no record; a member reads it, creator included.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_private_ingest_record_is_the_groups(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "ingest-record-member").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ingest-record-outsider").await;
    let claim = fixture::seed_group_claim(&pool, member, group, "a group's claim").await;
    let p = paper(&pool, "10.9999/record-group").await;
    asserts(&pool, p, claim).await;
    assert!(record(&pool, p, claim, member, true).await);
    let vis: Vec<String> = sqlx::query_scalar(
        "SELECT visibility FROM edges WHERE source_id = $1 AND target_id = $2 ORDER BY 1",
    )
    .bind(p)
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("visibility");
    assert_eq!(
        vis,
        vec!["group".to_string(), "group".to_string()],
        "CALIBRATION: assertion and record took the group claim's tenancy"
    );

    let as_outsider = Viewer::resolve(&pool, outsider).await.expect("viewer");
    assert_eq!(read(&pool, &as_outsider, claim).await, (vec![], None));
    let as_member = Viewer::resolve(&pool, member).await.expect("viewer");
    assert_eq!(
        read(&pool, &as_member, claim).await,
        (vec![(p, member, true)], Some(p))
    );
}

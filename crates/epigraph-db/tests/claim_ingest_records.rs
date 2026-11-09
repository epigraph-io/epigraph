//! The read contract of a claim's ingest records
//! (`ClaimIngestRepository::for_claims`): which document ingest CREATED the
//! claim, and every ingest that asserted it.
//!
//! The record is written by the document walk
//! (`epigraph-mcp/tests/ingest_author_resolution.rs` pins that, through the
//! real ingest). Pinned here, with records written by the same writer
//! (`ClaimIngestRepository::record_signed_conn`):
//! * a record counts only while the SAME paper's `asserts` edge onto the claim,
//!   written by the SAME ingest principal, is in force AND readable: a record
//!   whose assertion was retracted, whose paper never asserted the claim, or
//!   that rests on another principal's assertion of it, is not listed;
//! * an unmarked record of (paper, claim, ingester) never stops the
//!   ingester's own marked one from being written;
//! * an `asserts` edge with no record makes no ingest (never inferred from
//!   the edge), and only an ingest-written record on an ingest-written
//!   assertion counts (a hand-written copy of either is no ingest);
//! * a group-private assertion's record is invisible to an outsider, visible
//!   to a member (the edges' own tenancy, set by the insert trigger);
//! * the creator is the `created_claim` record whose ingester is the claim's
//!   filer (a "creation" by anyone else reads as a convergence); a re-run
//!   writes no second record and never turns a convergence into a creation.
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

/// `by`'s ingest's `paper -asserts-> claim` edge, written as the walk writes
/// it (ingest-written, marked by `by`: every ingest principal keeps its own).
async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("asserts")
    .0
    .id
}

/// A `paper -asserts-> claim` edge written outside the ingest (unmarked).
async fn hand_asserts(pool: &PgPool, paper: Uuid, claim: Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut conn, None, paper, "paper", claim, "claim", "asserts", None, None, None,
    )
    .await
    .expect("unmarked asserts");
}

async fn record(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid, created: bool) -> bool {
    let mut conn = pool.acquire().await.expect("conn");
    ClaimIngestRepository::record_signed_conn(
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

    asserts(&pool, p1, claim, filer).await;
    assert!(record(&pool, p1, claim, filer, true).await);
    asserts(&pool, p2, claim, other).await;
    assert!(record(&pool, p2, claim, other, false).await);
    // A paper that asserts the claim with NO record (an edge written outside
    // the ingest), and a record whose paper never asserted the claim.
    asserts(&pool, p3, claim, filer).await;
    let stray = paper(&pool, "10.9999/record-read-stray").await;
    assert!(record(&pool, stray, claim, other, false).await);
    // A record claiming creation for an ingester that is not the claim's
    // filer: the walk files every claim it creates, so it is a convergence.
    let p4 = paper(&pool, "10.9999/record-read-4").await;
    asserts(&pool, p4, claim, other).await;
    assert!(record(&pool, p4, claim, other, true).await);

    let (records, creator) = read(&pool, &public, claim).await;
    assert_eq!(
        records,
        vec![(p1, filer, true), (p2, other, false), (p4, other, false)],
        "only records backed by their own paper's assertion; an assertion alone is no ingest; \
         a creation by someone other than the filer is no creation"
    );
    assert_eq!(creator, Some(p1));

    // A re-run writes nothing, and a later "creation" claim for the same
    // (paper, claim, ingester) is not recorded over the convergence.
    assert!(!record(&pool, p2, claim, other, true).await, "dedup");
    assert_eq!(read(&pool, &public, claim).await.0.len(), 3);

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
        vec![(p2, other, false), (p4, other, false)],
        "retracted assertion, no record"
    );
    assert_eq!(creator, None, "no readable creator, and no stand-in");
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
    asserts(&pool, p, claim, member).await;
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

/// The read takes only what the ingest wrote: a record carrying the
/// ingest-written marker for its own ingester, resting on an ingest-written
/// assertion. A record written by hand (no marker, as any writer that
/// bypasses the walk would leave it), or a marked record on a paper whose
/// assertion was written by hand, is no ingest. CONTROL: the walk's record
/// on the walk's assertion is read, creator included.
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_ingest_written_record_on_an_ingest_written_assertion_is_read(pool: PgPool) {
    let (filer, _) = fixture::seed_agent_with_group(&pool, "ingest-record-mark").await;
    let claim = fixture::seed_public_claim(&pool, filer, "a marked claim").await;
    let public = fixture::public_viewer(&pool).await;

    // A hand-written record (the walk's properties, no marker) on the walk's
    // assertion.
    let p1 = paper(&pool, "10.9999/record-mark-1").await;
    asserts(&pool, p1, claim, filer).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'paper', $2, 'claim', 'ingested_claim', $3)",
    )
    .bind(p1)
    .bind(claim)
    .bind(serde_json::json!({
        "ingested_by": filer.to_string(),
        "created_claim": true,
        "tool": "ingest_document",
    }))
    .execute(&pool)
    .await
    .expect("a hand-written record");
    // The walk's record on a hand-written assertion.
    let p2 = paper(&pool, "10.9999/record-mark-2").await;
    hand_asserts(&pool, p2, claim).await;
    assert!(record(&pool, p2, claim, filer, true).await);
    assert_eq!(
        read(&pool, &public, claim).await,
        (vec![], None),
        "neither half is the ingest's own: no record, no creator"
    );

    // CONTROL: the walk's record on the walk's assertion.
    let p3 = paper(&pool, "10.9999/record-mark-3").await;
    asserts(&pool, p3, claim, filer).await;
    assert!(record(&pool, p3, claim, filer, true).await);
    assert_eq!(
        read(&pool, &public, claim).await,
        (vec![(p3, filer, true)], Some(p3))
    );
    let marker: serde_json::Value = sqlx::query_scalar(
        "SELECT properties -> 'ingest_written' FROM edges \
          WHERE source_id = $1 AND relationship = 'ingested_claim'",
    )
    .bind(p3)
    .fetch_one(&pool)
    .await
    .expect("the record's marker");
    assert_eq!(
        marker,
        serde_json::json!({"tool": "ingest_document", "by": filer.to_string()}),
        "the record names its ingester in the marker"
    );
}

/// The record writer declares the ingest for its own INSERT only: once it
/// returns, a later write on the same (stamped, application-role)
/// transaction cannot carry the ingest-written marker.
#[sqlx::test(migrations = "../../migrations")]
async fn the_record_writer_declares_only_its_own_insert(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingest-record-declare").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "ingest-record-author").await;
    let claim = fixture::seed_public_claim(&pool, ingester, "a declared claim").await;
    let p = paper(&pool, "10.9999/record-declare").await;
    let v = Viewer::resolve(&pool, ingester).await.expect("viewer");

    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        ingester,
        p,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("the walk's assertion");
    assert!(ClaimIngestRepository::record_signed_conn(
        &mut tx,
        None,
        p,
        claim,
        ingester,
        true,
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("the record on the application role"));
    let r = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) VALUES ($1, 'agent', $2, 'claim', 'asserts', $3)",
    )
    .bind(author)
    .bind(claim)
    .bind(serde_json::json!({ "ingest_written": {"tool": "ingest_document"} }))
    .execute(&mut *tx)
    .await;
    let refused = matches!(&r, Err(sqlx::Error::Database(e)) if e.message().contains("IWE01"));
    assert!(
        refused,
        "a write after the record kept the ingest declaration: {r:?}"
    );
}

/// A record counts only on its OWN ingester's assertion. Every ingest
/// principal keeps a `paper -asserts-> claim` edge of its own, so ingester B's
/// record of a claim that only A's ingest asserted (B wrote no assertion of
/// it) rests on another principal's word and is not B's ingest of the claim.
/// Once B's own assertion exists, B's record is read.
#[sqlx::test(migrations = "../../migrations")]
async fn a_record_counts_only_on_its_own_ingesters_assertion(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "ingest-record-a").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "ingest-record-b").await;
    let claim = fixture::seed_public_claim(&pool, a, "a claim two principals record").await;
    let p = paper(&pool, "10.9999/record-own-assertion").await;
    let public = fixture::public_viewer(&pool).await;

    asserts(&pool, p, claim, a).await;
    assert!(record(&pool, p, claim, a, true).await);
    assert!(record(&pool, p, claim, b, false).await);
    assert_eq!(
        read(&pool, &public, claim).await,
        (vec![(p, a, true)], Some(p)),
        "b's record rests on a's assertion alone: not b's ingest of the claim"
    );

    asserts(&pool, p, claim, b).await;
    assert_eq!(
        read(&pool, &public, claim).await,
        (vec![(p, a, true), (p, b, false)], Some(p)),
        "with b's own assertion, b's record is read"
    );
}

/// An UNMARKED record of (paper, claim, ingester), as a hand write or a
/// cascade's re-point would leave it, never stops that ingester's own marked
/// record: the walk's dedup probe matches only a marked record naming the
/// same ingester, so a real later ingest is recorded and read.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmarked_record_never_stops_the_ingesters_own(pool: PgPool) {
    let (filer, _) = fixture::seed_agent_with_group(&pool, "ingest-record-unmarked").await;
    let claim = fixture::seed_public_claim(&pool, filer, "a claim with a stray record").await;
    let p = paper(&pool, "10.9999/record-unmarked").await;
    let public = fixture::public_viewer(&pool).await;
    asserts(&pool, p, claim, filer).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'paper', $2, 'claim', 'ingested_claim', $3)",
    )
    .bind(p)
    .bind(claim)
    .bind(serde_json::json!({
        "ingested_by": filer.to_string(),
        "created_claim": true,
        "tool": "ingest_document",
    }))
    .execute(&pool)
    .await
    .expect("an unmarked record");
    assert_eq!(read(&pool, &public, claim).await, (vec![], None), "CALIBRATION");

    assert!(
        record(&pool, p, claim, filer, true).await,
        "the ingest's own marked record is written beside the unmarked one"
    );
    assert_eq!(
        read(&pool, &public, claim).await,
        (vec![(p, filer, true)], Some(p))
    );
    assert!(!record(&pool, p, claim, filer, true).await, "a re-run dedups on it");
}

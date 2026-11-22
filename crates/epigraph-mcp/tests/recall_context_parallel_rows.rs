//! `recall_with_context`'s corroborates statement (7) lists a corroborating
//! neighbour ONCE when two ingest principals each hold a marked
//! `paper -asserts-> neighbour` row of one fact (backlog 11402482).
//!
//! The document ingest keeps one marked row of a fact per ingest principal
//! (`epigraph_db::ingest_written`), so a paper two principals ingested asserts
//! each of its claims twice. Statement 7 joined the paper attribution onto the
//! neighbour row by row, so such a neighbour appeared once per asserting row,
//! took a second slot of the per-paragraph limit, and counted twice in `total`.
//!
//! Both rows are written through the walk's own writer as two principals; a
//! CALIBRATION pins that there are two. A second test pins that the one
//! attribution kept prefers an in-force row over a retracted one. All names
//! are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use epigraph_mcp::tools;
use sqlx::PgPool;
use uuid::Uuid;

async fn walk_write(pool: &PgPool, scoped: &ScopedPool, by: Uuid, paper: Uuid, claim: Uuid) {
    let v = Viewer::resolve(pool, by).await.expect("resolve");
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let (_, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
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
    .expect("the walk's asserts write");
    tx.commit().await.expect("commit");
    assert!(created, "CALIBRATION: {by}'s ingest wrote its own row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_doubly_ingested_neighbour_is_one_corroborator(pool: PgPool) {
    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let (first, _) = fixture::seed_agent_with_group(&pool, "rcp-one").await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "rcp-two").await;
    let world = fixture::world_group(&pool).await;

    let p = fixture::seed_public_claim(&pool, first, "rcp: paragraph").await;
    let cor = fixture::seed_public_claim(&pool, first, "rcp: corroborator").await;
    fixture::seed_edge_owned_by(&pool, cor, p, "public", world).await;
    sqlx::query(
        "UPDATE edges SET relationship = 'corroborates' WHERE source_id = $1 AND target_id = $2",
    )
    .bind(cor)
    .bind(p)
    .execute(&pool)
    .await
    .expect("corroborates");

    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.9999/rcp-shared', 'p') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    walk_write(&pool, &scoped, first, paper, cor).await;
    walk_write(&pool, &scoped, second, paper, cor).await;
    let rows = sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $3, co_owner_group_id = NULL \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'asserts'",
    )
    .bind(paper)
    .bind(cor)
    .bind(world)
    .execute(&pool)
    .await
    .expect("force public")
    .rows_affected();
    assert_eq!(rows, 2, "CALIBRATION: two principals' rows of one fact");

    let viewer = fixture::public_viewer(&pool).await;
    let ctx = tools::recall::__test_only::fetch_batched_context(&pool, &viewer, &[p], 8, 8, 8)
        .await
        .expect("batched context");
    let cors = ctx
        .corroborates_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let ids: Vec<Uuid> = cors.iter().map(|e| e.claim_id).collect();
    assert_eq!(ids, vec![cor], "the neighbour is listed once");
    assert_eq!(
        cors[0].paper_doi.as_deref(),
        Some("10.9999/rcp-shared"),
        "and keeps its paper attribution"
    );
    assert_eq!(
        ctx.corroborates_total_by_paragraph.get(&p),
        Some(&1),
        "the window total counts the neighbour once"
    );
}

/// The one attribution kept is an IN-FORCE one: when the older asserting row
/// is retracted (`valid_to` reached) and a newer paper still asserts the
/// neighbour, the newer paper's DOI is shown, not the retracted one's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_attribution_yields_to_an_in_force_one(pool: PgPool) {
    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let (first, _) = fixture::seed_agent_with_group(&pool, "rcp-retract").await;
    let world = fixture::world_group(&pool).await;

    let p = fixture::seed_public_claim(&pool, first, "rcp-r: paragraph").await;
    let cor = fixture::seed_public_claim(&pool, first, "rcp-r: corroborator").await;
    fixture::seed_edge_owned_by(&pool, cor, p, "public", world).await;
    sqlx::query(
        "UPDATE edges SET relationship = 'corroborates' WHERE source_id = $1 AND target_id = $2",
    )
    .bind(cor)
    .bind(p)
    .execute(&pool)
    .await
    .expect("corroborates");

    let mut papers = Vec::new();
    for doi in ["10.9999/rcp-retracted", "10.9999/rcp-in-force"] {
        let paper: Uuid =
            sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'p') RETURNING id")
                .bind(doi)
                .fetch_one(&pool)
                .await
                .expect("paper");
        // Sequential transactions: the first paper's row is the older one.
        walk_write(&pool, &scoped, first, paper, cor).await;
        papers.push(paper);
    }
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE target_id = $1 AND relationship = 'asserts'",
    )
    .bind(cor)
    .bind(world)
    .execute(&pool)
    .await
    .expect("force public");
    let retracted = sqlx::query(
        "UPDATE edges SET valid_to = now() \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'asserts'",
    )
    .bind(papers[0])
    .bind(cor)
    .execute(&pool)
    .await
    .expect("retract the older attribution")
    .rows_affected();
    assert_eq!(retracted, 1, "CALIBRATION: one older row retracted");

    let viewer = fixture::public_viewer(&pool).await;
    let ctx = tools::recall::__test_only::fetch_batched_context(&pool, &viewer, &[p], 8, 8, 8)
        .await
        .expect("batched context");
    let cors = ctx
        .corroborates_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    assert_eq!(cors.len(), 1, "the neighbour is listed once");
    assert_eq!(
        cors[0].paper_doi.as_deref(),
        Some("10.9999/rcp-in-force"),
        "the in-force attribution represents the neighbour"
    );
}

//! Readers that must count or render one fact once when two ingest principals
//! each hold a marked row of it (backlog 11402482).
//!
//! # Why a fact can carry two rows
//!
//! The document ingest keeps ONE marked row of a fact PER INGEST PRINCIPAL
//! (`epigraph_db::ingest_written`, "One marked row per ingest principal"): a
//! paper is shared by DOI, so when two principals ingest the same document,
//! each writes its own `paper -asserts-> claim` and `agent -asserts-> claim`
//! row. Readers that render or count every row show such a fact twice.
//!
//! The fixture writes both rows through the walk's own writer
//! (`create_ingest_written_edge_if_absent_conn`) as two different principals,
//! so the parallel rows are exactly the ones production holds, not rows a test
//! inserted by hand. Each test first pins (CALIBRATION) that the triple really
//! has two rows, so a green run cannot come from the fixture writing one.
//!
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use epigraph_db::{GraphViewRepository, MethodRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ($1, 'A Fixture Paper') RETURNING id",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("paper")
}

/// One write through the ingest walk's writer, as principal `by`, on an
/// `epigraph_app` transaction stamped for `by`. Returns whether it inserted.
async fn walk_write(
    pool: &PgPool,
    scoped: &ScopedPool,
    by: Uuid,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
) -> bool {
    let v = Viewer::resolve(pool, by).await.expect("resolve");
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let (_, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        by,
        src.0,
        src.1,
        tgt.0,
        tgt.1,
        rel,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("the walk's {rel} write as {by}: {e}"));
    tx.commit().await.expect("commit");
    created
}

/// Force every row of the triple public, so the reader's visibility predicate
/// keeps both and only its own deduplication can collapse them.
async fn rows_of_fact_public(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> i64 {
    let world = fixture::world_group(pool).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $4, co_owner_group_id = NULL \
          WHERE source_id = $1 AND target_id = $2 AND relationship = $3",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .bind(world)
    .execute(pool)
    .await
    .expect("force public");
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = $3",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("count rows")
}

/// Two principals ingest one document naming one author who asserts claim
/// `x`; the agent card counts it once, so must the graph view.
#[sqlx::test(migrations = "../../migrations")]
async fn subgraph_edges_render_a_doubly_ingested_fact_once(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (first, _) = fixture::seed_agent_with_group(&pool, "pr-reader-one").await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "pr-reader-two").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "Ysolde Penhallow").await;
    let x = fixture::seed_public_claim(&pool, first, "a twice-ingested finding").await;

    assert!(
        walk_write(
            &pool,
            &scoped,
            first,
            (author, "agent"),
            (x, "claim"),
            "asserts"
        )
        .await
    );
    assert!(
        walk_write(
            &pool,
            &scoped,
            second,
            (author, "agent"),
            (x, "claim"),
            "asserts"
        )
        .await
    );
    assert_eq!(
        rows_of_fact_public(&pool, author, x, "asserts").await,
        2,
        "CALIBRATION: each ingest principal holds its own row of the fact"
    );

    let viewer = fixture::public_viewer(&pool).await;
    let rows = GraphViewRepository::subgraph_edges(&pool, &viewer, &[author, x])
        .await
        .expect("subgraph edges");
    let asserts: Vec<_> = rows
        .iter()
        .filter(|r| r.source_id == author && r.target_id == x && r.relationship == "asserts")
        .collect();
    assert_eq!(
        asserts.len(),
        1,
        "one fact renders as one edge, whatever the number of ingest principals: {rows:?}"
    );

    // Retract the row picked: the in-force row now represents the fact.
    let picked = asserts[0].id;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(picked)
        .execute(&pool)
        .await
        .expect("retract the picked row");
    let rows = GraphViewRepository::subgraph_edges(&pool, &viewer, &[author, x])
        .await
        .expect("subgraph edges after the retraction");
    let asserts: Vec<_> = rows
        .iter()
        .filter(|r| r.source_id == author && r.target_id == x && r.relationship == "asserts")
        .collect();
    assert_eq!(asserts.len(), 1, "{rows:?}");
    assert_ne!(
        asserts[0].id, picked,
        "a retracted row does not represent a fact that has an in-force row: {rows:?}"
    );
}

/// `get_evidence_strength` over a method citing two claims, one of which two
/// principals' ingests of one paper assert (and a second paper too): the
/// claim count and the mean belief are per CLAIM, the source count per paper.
#[sqlx::test(migrations = "../../migrations")]
async fn method_evidence_strength_counts_each_claim_once(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (first, _) = fixture::seed_agent_with_group(&pool, "pr-method-one").await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "pr-method-two").await;
    let x = fixture::seed_public_claim(&pool, first, "a twice-asserted method claim").await;
    let y = fixture::seed_public_claim(&pool, first, "an unasserted method claim").await;
    for (id, betp) in [(x, 0.9_f64), (y, 0.3_f64)] {
        sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
            .bind(id)
            .bind(betp)
            .execute(&pool)
            .await
            .expect("set betp");
    }
    let p = paper(&pool, "10.9999/parallel-rows.method.1").await;
    let p2 = paper(&pool, "10.9999/parallel-rows.method.2").await;
    assert!(walk_write(&pool, &scoped, first, (p, "paper"), (x, "claim"), "asserts").await);
    assert!(
        walk_write(
            &pool,
            &scoped,
            second,
            (p, "paper"),
            (x, "claim"),
            "asserts"
        )
        .await
    );
    assert!(
        walk_write(
            &pool,
            &scoped,
            first,
            (p2, "paper"),
            (x, "claim"),
            "asserts"
        )
        .await
    );
    assert_eq!(
        rows_of_fact_public(&pool, p, x, "asserts").await,
        2,
        "CALIBRATION: each ingest principal holds its own row of the fact"
    );
    rows_of_fact_public(&pool, p2, x, "asserts").await;

    let method = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO methods (id, name, canonical_name, technique_type, source_claim_ids) \
         VALUES ($1, 'parallel-rows method', 'parallel-rows-method', 'measurement', $2)",
    )
    .bind(method)
    .bind(vec![x, y])
    .execute(&pool)
    .await
    .expect("insert method");

    let viewer = fixture::public_viewer(&pool).await;
    let s = MethodRepository::get_evidence_strength(&pool, &viewer, method)
        .await
        .expect("evidence strength");
    assert_eq!(s.claim_count, 2, "two claims, each counted once: {s:?}");
    assert!(
        (s.avg_belief - 0.6).abs() < 1e-9,
        "the mean belief weighs each claim once, not once per asserting row: {s:?}"
    );
    assert_eq!(s.source_count, 2, "two distinct asserting papers: {s:?}");
}

/// A clustering run with one cluster holding `members` (the metadata tables
/// carry no tenancy columns; seeded as `graph_view_edge_scope.rs` seeds them).
async fn cluster_of(pool: &PgPool, members: &[Uuid]) -> (Uuid, Uuid) {
    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed run");
    sqlx::query(
        "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, degraded) \
         VALUES ($1, $2, 'cluster-0', 3, 0.5, 'claim', FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed cluster");
    for m in members {
        sqlx::query(
            "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(m)
        .bind(cluster_id)
        .bind(run_id)
        .execute(pool)
        .await
        .expect("seed cluster membership");
    }
    (cluster_id, run_id)
}

/// The cluster expansion's degree ordering counts a fact once, whatever the
/// number of ingest principals holding a row of it.
///
/// `twice` has ONE fact (`author -asserts-> twice`) stored as two rows, one per
/// ingest principal; `once` has one fact in one row and a higher pignistic
/// probability; `bare` has no edge at all and the highest. Ordered by degree,
/// then pignistic probability:
///
/// - a row count gives `twice` degree 2 and puts it first;
/// - a fact count that also counts the LEFT JOIN's all-NULL row gives `bare`
///   degree 1, so it ties and wins on pignistic probability;
/// - only a fact count of readable edges gives `[once, twice, bare]`.
#[sqlx::test(migrations = "../../migrations")]
async fn cluster_expansion_degree_counts_a_doubly_ingested_fact_once(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (first, _) = fixture::seed_agent_with_group(&pool, "pr-cluster-one").await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "pr-cluster-two").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "Ottoline Brack").await;
    let (other_author, _) = fixture::seed_agent_with_group(&pool, "Caspar Wendle").await;
    let twice = fixture::seed_public_claim(&pool, first, "a twice-ingested cluster claim").await;
    let once = fixture::seed_public_claim(&pool, first, "a once-ingested cluster claim").await;
    let bare = fixture::seed_public_claim(&pool, first, "an unasserted cluster claim").await;
    for (id, betp) in [(twice, 0.3_f64), (once, 0.6), (bare, 0.9)] {
        sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
            .bind(id)
            .bind(betp)
            .execute(&pool)
            .await
            .expect("set betp");
    }

    for by in [first, second] {
        assert!(
            walk_write(
                &pool,
                &scoped,
                by,
                (author, "agent"),
                (twice, "claim"),
                "asserts"
            )
            .await
        );
    }
    assert!(
        walk_write(
            &pool,
            &scoped,
            first,
            (other_author, "agent"),
            (once, "claim"),
            "asserts"
        )
        .await
    );
    assert_eq!(
        rows_of_fact_public(&pool, author, twice, "asserts").await,
        2,
        "CALIBRATION: each ingest principal holds its own row of the fact"
    );
    assert_eq!(
        rows_of_fact_public(&pool, other_author, once, "asserts").await,
        1
    );

    let (cluster_id, run_id) = cluster_of(&pool, &[twice, once, bare]).await;
    let viewer = fixture::public_viewer(&pool).await;
    let rows = GraphViewRepository::expand_cluster_nodes(
        &pool,
        &viewer,
        cluster_id,
        run_id,
        &["asserts".to_string()],
        10,
    )
    .await
    .expect("expand_cluster_nodes");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![once, twice, bare],
        "degree = facts, not rows, and an edgeless member stays at 0 \
         (twice = {twice}, once = {once}, bare = {bare})"
    );
}

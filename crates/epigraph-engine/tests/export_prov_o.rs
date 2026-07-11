//! Regression test: PROV-O export maps internal edge relationship names to
//! PROV-O predicates and leaves `edges.relationship` in the database
//! completely unchanged (export-time-only serialization, never a live
//! rename).
//!
//! Fixture graph:
//!
//!   root_claim  -- derived_from --> child_claim   (child derives from root)
//!   prior_claim -- supersedes   --> child_claim   (child supersedes prior)
//!
//! Both edges are `source_id = <ancestor>`, `target_id = child_claim`:
//! `LineageRepository`'s recursive CTEs (`get_lineage`, `get_ancestor_ids`)
//! walk `edges e ON e.source_id = c.id ... JOIN lineage l ON e.target_id =
//! l.id`, i.e. an ancestor is reached by an edge whose `source_id` is the
//! ancestor and whose `target_id` is the already-known (descendant) claim.
//! This fixture matches that existing, production convention rather than
//! inventing a new one.

use epigraph_engine::export::prov::export_provenance_prov_o;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set");
                return;
            }
        }
    };
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), 'export-test-agent', NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($1::text::bytea), 0.7, $3)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn insert_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
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
    .expect("insert edge");
    id
}

#[tokio::test]
async fn export_maps_predicates_and_leaves_edges_relationship_column_unchanged() {
    let pool = test_pool_or_skip!();

    let agent = insert_agent(&pool).await;
    let root_claim = insert_claim(&pool, agent, "Root: computational model baseline").await;
    let prior_claim = insert_claim(&pool, agent, "Prior version of the derived claim").await;
    let child_claim = insert_claim(&pool, agent, "Derived claim under test").await;

    let derives_edge_id = insert_edge(&pool, root_claim, child_claim, "derived_from").await;
    let supersedes_edge_id = insert_edge(&pool, prior_claim, child_claim, "supersedes").await;

    let document = export_provenance_prov_o(&pool, child_claim, Some(5))
        .await
        .expect("export should succeed");

    // The exported JSON-LD must carry the PROV-O predicates, not the
    // internal relationship strings.
    let serialized = serde_json::to_string(&document).unwrap();
    assert!(
        serialized.contains("prov:wasDerivedFrom"),
        "expected prov:wasDerivedFrom in export, got: {serialized}"
    );
    assert!(
        serialized.contains("prov:wasRevisionOf"),
        "expected prov:wasRevisionOf in export, got: {serialized}"
    );

    // Re-query the edges table directly: the raw `relationship` column must
    // be untouched by the export call. This is the entire point of the
    // "export-time-only" claim — a live rename would show PROV-O strings
    // here instead.
    let derives_row: (String,) = sqlx::query_as("SELECT relationship FROM edges WHERE id = $1")
        .bind(derives_edge_id)
        .fetch_one(&pool)
        .await
        .expect("fetch derives edge");
    assert_eq!(derives_row.0, "derived_from");

    let supersedes_row: (String,) = sqlx::query_as("SELECT relationship FROM edges WHERE id = $1")
        .bind(supersedes_edge_id)
        .fetch_one(&pool)
        .await
        .expect("fetch supersedes edge");
    assert_eq!(supersedes_row.0, "supersedes");
}

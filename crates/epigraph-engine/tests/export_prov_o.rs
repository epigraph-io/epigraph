//! Regression test: PROV-O export maps internal edge relationship names to
//! PROV-O predicates and leaves `edges.relationship` in the database
//! completely unchanged (export-time-only serialization, never a live
//! rename).
//!
//! Fixture graph:
//!
//!   root_claim  -- derived_from --> child_claim   (child derives from root)
//!   child_claim -- supersedes   --> prior_claim    (child supersedes prior)
//!
//! `derived_from`: `source_id = <ancestor>`, `target_id = <descendant>` —
//! matches `LineageRepository`'s recursive CTEs (`get_lineage`,
//! `get_ancestor_ids`), which walk `edges e ON e.source_id = c.id ... JOIN
//! lineage l ON e.target_id = l.id`, i.e. an ancestor is reached by an edge
//! whose `source_id` is the ancestor and whose `target_id` is the
//! already-known (descendant) claim.
//!
//! `supersedes`: the OPPOSITE direction — `source_id = <new/current claim>`,
//! `target_id = <old/superseded claim>`. This is not a choice made for this
//! module; it is how the two production write paths
//! (`ClaimRepository::supersede` and `ClaimRepository::evolve_step`) both
//! actually insert the edge (`source_id` bound to the newly-inserted claim,
//! `target_id` bound to the claim being superseded). The fixture mirrors
//! real data rather than the more "natural"-looking old-to-new direction.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_engine::export::prov::{export_provenance_prov_o, ProvExportLimits};
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
    let viewer = fixture::public_viewer(&pool).await;

    let agent = insert_agent(&pool).await;
    let root_claim = insert_claim(&pool, agent, "Root: computational model baseline").await;
    let prior_claim = insert_claim(&pool, agent, "Prior version of the derived claim").await;
    let child_claim = insert_claim(&pool, agent, "Derived claim under test").await;

    let derives_edge_id = insert_edge(&pool, root_claim, child_claim, "derived_from").await;
    // Real direction (see module doc comment above): source = new claim,
    // target = superseded claim.
    let supersedes_edge_id = insert_edge(&pool, child_claim, prior_claim, "supersedes").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let document = export_provenance_prov_o(
        &mut conn,
        &viewer,
        child_claim,
        Some(5),
        ProvExportLimits::default(),
    )
    .await
    .expect("export should succeed");

    // All three claims — root (ancestor), child (root of the export), and
    // prior (reached only via the one-hop supersedes expansion) — must be
    // present as entities. `prior_claim` is the case that proves the
    // one-hop supersedes expansion works: `get_ancestor_ids` alone would
    // never surface it (see module doc comment).
    let entities = document["entities"].as_array().expect("entities array");
    let entity_ids: Vec<&str> = entities
        .iter()
        .map(|e| e["@id"].as_str().unwrap())
        .collect();
    assert!(entity_ids.contains(&format!("claim:{root_claim}").as_str()));
    assert!(entity_ids.contains(&format!("claim:{child_claim}").as_str()));
    assert!(
        entity_ids.contains(&format!("claim:{prior_claim}").as_str()),
        "prior_claim must be reachable via the one-hop supersedes expansion, got entities: {entity_ids:?}"
    );

    // The exported JSON-LD must carry the PROV-O predicates, not the
    // internal relationship strings, and — critically — with the correct
    // subject/object direction per relationship type (derived_from and
    // supersedes are inverted in the underlying edges table).
    let relations = document["relations"].as_array().expect("relations array");

    let derived_from_relation = relations
        .iter()
        .find(|r| r["predicate"] == "prov:wasDerivedFrom")
        .unwrap_or_else(|| panic!("expected a prov:wasDerivedFrom relation, got: {relations:?}"));
    assert_eq!(
        derived_from_relation["prov:generatedEntity"],
        format!("claim:{child_claim}"),
        "child_claim (the newer claim) must be the generated entity for wasDerivedFrom"
    );
    assert_eq!(
        derived_from_relation["prov:usedEntity"],
        format!("claim:{root_claim}"),
        "root_claim (the ancestor) must be the used entity for wasDerivedFrom"
    );

    let supersedes_relation = relations
        .iter()
        .find(|r| r["predicate"] == "prov:wasRevisionOf")
        .unwrap_or_else(|| panic!("expected a prov:wasRevisionOf relation, got: {relations:?}"));
    assert_eq!(
        supersedes_relation["prov:generatedEntity"],
        format!("claim:{child_claim}"),
        "child_claim (the new claim) must be the generated entity for wasRevisionOf"
    );
    assert_eq!(
        supersedes_relation["prov:usedEntity"],
        format!("claim:{prior_claim}"),
        "prior_claim (the superseded claim) must be the used entity for wasRevisionOf"
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

// ---------------------------------------------------------------------------
// Bounds and walk set (backlog 4caad789, 19d325d5) and parallel rows (11402482)
// ---------------------------------------------------------------------------

/// A public claim-to-claim `relationship` edge `source -> target`, forced to
/// `('public', world)` so only the CLAIM predicate can hide an endpoint.
async fn public_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let world = fixture::world_group(pool).await;
    let id = fixture::seed_edge_owned_by(pool, source, target, "public", world).await;
    sqlx::query("UPDATE edges SET relationship = $2 WHERE id = $1")
        .bind(id)
        .bind(relationship)
        .execute(pool)
        .await
        .expect("set relationship");
    id
}

async fn export_as(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    root: Uuid,
    max_depth: i32,
    max_nodes: Option<usize>,
) -> serde_json::Value {
    let mut conn = pool.acquire().await.expect("acquire");
    export_provenance_prov_o(
        &mut conn,
        viewer,
        root,
        Some(max_depth),
        ProvExportLimits {
            max_nodes,
            max_content_chars: None,
        },
    )
    .await
    .expect("export")
}

fn entity_set(doc: &serde_json::Value) -> std::collections::BTreeSet<String> {
    doc["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .map(|e| e["@id"].as_str().unwrap().to_string())
        .collect()
}

fn claim_set(ids: &[Uuid]) -> std::collections::BTreeSet<String> {
    ids.iter().map(|id| format!("claim:{id}")).collect()
}

/// Two parallel rows of one `derived_from` fact (the edges table has no triple
/// uniqueness since migrations 017/018/053) are ONE `prov:Relation`.
#[sqlx::test(migrations = "../../migrations")]
async fn parallel_rows_of_one_fact_are_one_relation(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "prov-parallel").await;
    let root = fixture::seed_public_claim(&pool, agent, "parallel root").await;
    let anc = fixture::seed_public_claim(&pool, agent, "parallel ancestor").await;
    public_edge(&pool, anc, root, "derived_from").await;
    public_edge(&pool, anc, root, "derived_from").await;

    let viewer = fixture::public_viewer(&pool).await;
    let doc = export_as(&pool, &viewer, root, 5, None).await;
    let derived: Vec<_> = doc["relations"]
        .as_array()
        .expect("relations")
        .iter()
        .filter(|r| r["predicate"] == "prov:wasDerivedFrom")
        .collect();
    assert_eq!(
        derived.len(),
        1,
        "one derivation fact is one relation, whatever its row count: {doc}"
    );
    assert_eq!(entity_set(&doc), claim_set(&[root, anc]));
}

/// The walk follows DERIVATION edges only. Disputing neighbours (`refutes`,
/// `contradicts`) and a successor that `supersedes` the root (written
/// new -> old, so it is an incoming edge but not an ancestor) are not
/// ancestors; a `supports` ancestor still is. Under a node cap, the depth-2
/// derivation ancestor is kept instead of the depth-1 disputers.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_follows_derivation_edges_only(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "prov-walkset").await;
    let root = fixture::seed_public_claim(&pool, agent, "walkset root").await;
    let a = fixture::seed_public_claim(&pool, agent, "walkset parent").await;
    let b = fixture::seed_public_claim(&pool, agent, "walkset grandparent").await;
    let refuter = fixture::seed_public_claim(&pool, agent, "walkset refuter").await;
    let contra = fixture::seed_public_claim(&pool, agent, "walkset contradicter").await;
    let successor = fixture::seed_public_claim(&pool, agent, "walkset successor").await;
    public_edge(&pool, a, root, "derived_from").await;
    public_edge(&pool, b, a, "derived_from").await;
    public_edge(&pool, refuter, root, "refutes").await;
    public_edge(&pool, contra, root, "contradicts").await;
    public_edge(&pool, successor, root, "supersedes").await;

    let viewer = fixture::public_viewer(&pool).await;
    let whole = export_as(&pool, &viewer, root, 5, None).await;
    assert_eq!(
        entity_set(&whole),
        claim_set(&[root, a, b]),
        "only derivation ancestors are in the export: {whole}"
    );

    let capped = export_as(&pool, &viewer, root, 5, Some(3)).await;
    assert_eq!(
        entity_set(&capped),
        claim_set(&[root, a, b]),
        "a capped export keeps the derivation ancestors, not disputing neighbours: {capped}"
    );
    assert_eq!(capped["truncated"], false, "nothing derivational was cut");

    // A `supports` ancestor is still lineage (as in `get_lineage`).
    let support = fixture::seed_public_claim(&pool, agent, "walkset support").await;
    public_edge(&pool, support, root, "supports").await;
    let with_support = export_as(&pool, &viewer, root, 5, None).await;
    assert!(
        entity_set(&with_support).contains(&format!("claim:{support}")),
        "a supports ancestor is still walked: {with_support}"
    );
}

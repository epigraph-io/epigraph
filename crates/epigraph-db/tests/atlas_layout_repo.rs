//! The Atlas layout (migration 197) and `AtlasLayoutRepository`: the build
//! reads public rows only, the narrowing epoch turns a run off, and every
//! per-viewer read keeps another group's themes, members and links out of
//! the counts, ids and existence signals a viewer receives.
//!
//! Every test runs on its own fresh database. Fixtures seed claims and edges
//! FIRST and write the layout run after, at the current epoch: forcing a
//! row's tenancy from public is itself a narrowing, which would invalidate a
//! run written before it. The `narrowing_*` tests narrow after on purpose.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};

use epigraph_db::repos::atlas_layout::{
    DetailPart, LayoutBuild, LayoutLinkOut, LayoutRegionOut, LayoutThemeOut, LinkSideKind,
    ThemePlacement,
};
use epigraph_db::{AtlasLayoutRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// The pgvector literal of the `axis`-th basis vector.
fn basis(axis: usize) -> String {
    let mut v = vec!["0"; DIM];
    v[axis] = "1";
    format!("[{}]", v.join(","))
}

fn basis_f32(axis: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[axis] = 1.0;
    v
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// A current claim in `theme`: public when `group` is `None`, else private to
/// that group; with the `axis`-th basis embedding when given.
async fn claim_in(
    pool: &PgPool,
    agent: Uuid,
    group: Option<Uuid>,
    theme: Uuid,
    axis: Option<usize>,
) -> Uuid {
    let content = format!("atlas claim {}", Uuid::new_v4());
    let id = match group {
        None => fixture::seed_public_claim(pool, agent, &content).await,
        Some(g) => fixture::seed_group_claim(pool, agent, g, &content).await,
    };
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(id)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
    if let Some(a) = axis {
        fixture::set_claim_embedding(pool, id, &basis(a)).await;
    }
    id
}

/// One edge with an explicit relationship spelling and properties (the shape
/// of `relationship_spelling_readers.rs::edge`). Tenancy is left to migration
/// 070's trigger.
async fn edge_with(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4, $5)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(properties)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
    id
}

/// Force an edge's tenancy (`seed_edge_owned_by`'s UPDATE).
async fn force_edge(pool: &PgPool, edge: Uuid, visibility: &str, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

async fn narrow_claim(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow claim");
}

async fn epoch(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT n FROM atlas_layout_epoch WHERE singleton")
        .fetch_one(pool)
        .await
        .expect("epoch")
}

async fn viewer_of(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve viewer")
}

/// A layout run written through `write_run` at the CURRENT epoch. `regions`
/// are `(id, centroid axis)`, placed 300 apart on x; `themes` are `(theme,
/// region)`, ranked in the order given per region.
async fn write_layout(
    pool: &PgPool,
    regions: &[(Uuid, usize)],
    themes: &[(Uuid, Uuid)],
    links: &[(Uuid, Uuid, &str, i64)],
) -> Uuid {
    let mut rank: BTreeMap<Uuid, i32> = BTreeMap::new();
    let region_out: Vec<LayoutRegionOut> = regions
        .iter()
        .enumerate()
        .map(|(i, (id, axis))| LayoutRegionOut {
            id: *id,
            ordinal: i32::try_from(i).unwrap(),
            label: format!("Region {i}"),
            x: 300.0 * i as f64,
            y: 0.0,
            r: 100.0,
            centroid: basis_f32(*axis),
        })
        .collect();
    let theme_out: Vec<LayoutThemeOut> = themes
        .iter()
        .map(|(t, r)| {
            let k = rank.entry(*r).or_insert(0);
            let out = LayoutThemeOut {
                theme_id: *t,
                region_id: *r,
                rank_in_region: *k,
                x: f64::from(*k),
                y: 1.0,
                public_member_count: 1,
            };
            *k += 1;
            out
        })
        .collect();
    let links: Vec<LayoutLinkOut> = links
        .iter()
        .map(|(a, b, rel, n)| LayoutLinkOut {
            theme_a: *a.min(b),
            theme_b: *a.max(b),
            relationship: (*rel).to_string(),
            link_count: *n,
        })
        .collect();
    let build = LayoutBuild {
        algo: "pca2-ward-v1".into(),
        params: serde_json::json!({}),
        cluster_run_id: None,
        visibility_epoch: epoch(pool).await,
        public_claim_count: 0,
        public_link_count: 0,
        theme_set_digest: "0".repeat(64),
        regions: region_out,
        themes: theme_out,
        theme_links: links,
    };
    let mut conn = pool.acquire().await.unwrap();
    AtlasLayoutRepository::write_run(&mut conn, &build)
        .await
        .expect("write run")
}

async fn current(pool: &PgPool) -> bool {
    AtlasLayoutRepository::run(pool, None)
        .await
        .unwrap()
        .expect("a run")
        .current
}

fn first_two(centroid: &str) -> (f64, f64) {
    let inner = centroid.trim_start_matches('[').trim_end_matches(']');
    let mut it = inner.split(',').map(|s| s.trim().parse::<f64>().unwrap());
    (it.next().unwrap(), it.next().unwrap())
}

// ── build side ───────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn read_public_inputs_averages_public_members_only(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-avg").await;
    let t = seed_theme(&pool, "T").await;
    claim_in(&pool, agent, None, t, Some(0)).await;
    claim_in(&pool, agent, None, t, Some(0)).await;
    claim_in(&pool, agent, Some(group), t, Some(1)).await;

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut tx, &bypass)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(inputs.themes.len(), 1);
    let row = &inputs.themes[0];
    assert_eq!(row.theme_id, t);
    assert_eq!(row.public_member_count, 2);
    assert_eq!(row.embedded_count, 2);
    let (x, y) = first_two(row.centroid.as_deref().expect("centroid"));
    // A leak of the group member would give (2/3, 1/3).
    assert!((x - 1.0).abs() < 1e-6 && y.abs() < 1e-6, "({x}, {y})");
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_public_inputs_omits_a_theme_whose_members_are_all_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-priv").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t3 = seed_theme(&pool, "T3 private").await;
    claim_in(&pool, agent, None, t1, Some(0)).await;
    claim_in(&pool, agent, Some(group), t3, Some(1)).await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut tx, &bypass)
        .await
        .unwrap();
    let ids: Vec<Uuid> = inputs.themes.iter().map(|t| t.theme_id).collect();
    assert_eq!(ids, vec![t1]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_public_inputs_counts_only_public_edges_between_public_current_claims(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-edges").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let a1 = claim_in(&pool, agent, None, t1, None).await;
    let a2 = claim_in(&pool, agent, None, t1, None).await;
    let b1 = claim_in(&pool, agent, None, t2, None).await;
    let x = claim_in(&pool, agent, Some(group), t1, None).await;
    let old = claim_in(&pool, agent, None, t1, None).await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();

    // Counted: both spellings fold into one `supports` row.
    edge_with(&pool, a1, b1, "supports", serde_json::json!({})).await;
    edge_with(&pool, a2, b1, "SUPPORTS", serde_json::json!({})).await;
    // Not counted: a private endpoint.
    edge_with(&pool, x, b1, "contradicts", serde_json::json!({})).await;
    // Not counted: public endpoints, the edge itself forced private.
    let e = edge_with(&pool, a1, b1, "refutes", serde_json::json!({})).await;
    force_edge(&pool, e, "group", group).await;
    // Not counted: a superseded endpoint.
    edge_with(&pool, old, b1, "elaborates", serde_json::json!({})).await;
    // Not counted: a retracted edge.
    let r = edge_with(&pool, a1, b1, "cites", serde_json::json!({})).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    // Not counted: both endpoints in one theme.
    edge_with(&pool, a1, a2, "supports", serde_json::json!({})).await;
    // Not counted: a claim -> evidence edge.
    let ev = fixture::seed_evidence(&pool, b1, "observation").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'evidence', 'supports')",
    )
    .bind(a1)
    .bind(ev)
    .execute(&pool)
    .await
    .expect("seed claim -> evidence edge");

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut tx, &bypass)
        .await
        .unwrap();
    let got: Vec<(Uuid, Uuid, String, i64)> = inputs
        .links
        .iter()
        .map(|l| (l.theme_a, l.theme_b, l.relationship.clone(), l.link_count))
        .collect();
    assert_eq!(
        got,
        vec![(t1.min(t2), t1.max(t2), "supports".to_string(), 2)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_public_inputs_returns_the_snapshot_epoch(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-epoch").await;
    let t = seed_theme(&pool, "T").await;
    let p1 = claim_in(&pool, agent, None, t, None).await;
    let p2 = claim_in(&pool, agent, None, t, None).await;
    let before = epoch(&pool).await;
    narrow_claim(&pool, p1, group).await;
    narrow_claim(&pool, p2, group).await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut tx, &bypass)
        .await
        .unwrap();
    assert_eq!(inputs.visibility_epoch, before + 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_public_inputs_is_one_snapshot(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
    let err = AtlasLayoutRepository::read_public_inputs(&mut tx, &bypass).await;
    assert!(
        err.is_err(),
        "a transaction that already ran a statement cannot become REPEATABLE READ"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn write_run_round_trips(pool: PgPool) {
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let t3 = seed_theme(&pool, "T3").await;
    let ra = Uuid::new_v4();
    let rb = Uuid::new_v4();
    let run = write_layout(
        &pool,
        &[(ra, 0), (rb, 1)],
        &[(t1, ra), (t2, ra), (t3, rb)],
        &[(t3, t1, "supports", 4), (t2, t3, "cites", 1)],
    )
    .await;
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM atlas_layout_regions WHERE run_id = $1), \
                (SELECT COUNT(*) FROM atlas_layout_themes WHERE run_id = $1), \
                (SELECT COUNT(*) FROM atlas_layout_theme_links WHERE run_id = $1)",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts, (2, 3, 2));
    let (dims, centroid): (i32, String) = sqlx::query_as(
        "SELECT vector_dims(centroid), centroid::text FROM atlas_layout_regions WHERE id = $1",
    )
    .bind(rb)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dims, 1536);
    assert_eq!(first_two(&centroid), (0.0, 1.0));
    let ranks: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT theme_id, rank_in_region FROM atlas_layout_themes WHERE run_id = $1 \
         ORDER BY region_id = $2 DESC, rank_in_region",
    )
    .bind(run)
    .bind(ra)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ranks, vec![(t1, 0), (t2, 1), (t3, 0)]);
    let row = AtlasLayoutRepository::run(&pool, Some(run))
        .await
        .unwrap()
        .unwrap();
    assert!(row.current && !row.stale);
    assert_eq!(row.theme_count, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn prune_runs_keeps_the_newest_n_and_cascades(pool: PgPool) {
    let t1 = seed_theme(&pool, "T1").await;
    let mut runs = Vec::new();
    for _ in 0..3 {
        let r = Uuid::new_v4();
        runs.push(write_layout(&pool, &[(r, 0)], &[(t1, r)], &[]).await);
    }
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        AtlasLayoutRepository::prune_runs(&mut conn, 1)
            .await
            .unwrap(),
        2
    );
    let left: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM atlas_layout_runs")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![runs[2]]);
    let orphans: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM atlas_layout_regions WHERE run_id <> $1) + \
                (SELECT COUNT(*) FROM atlas_layout_themes WHERE run_id <> $1)",
    )
    .bind(runs[2])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphans, 0);
    let r = Uuid::new_v4();
    write_layout(&pool, &[(r, 0)], &[(t1, r)], &[]).await;
    assert_eq!(
        AtlasLayoutRepository::prune_runs(&mut conn, 0)
            .await
            .unwrap(),
        1
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM atlas_layout_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "keep = 0 acts as 1");
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_a_theme_cascades_its_layout_rows_and_links(pool: PgPool) {
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let r = Uuid::new_v4();
    let run = write_layout(
        &pool,
        &[(r, 0)],
        &[(t1, r), (t2, r)],
        &[(t1, t2, "supports", 1)],
    )
    .await;
    sqlx::query("DELETE FROM claim_themes WHERE id = $1")
        .bind(t2)
        .execute(&pool)
        .await
        .unwrap();
    let (themes, links): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM atlas_layout_themes WHERE run_id = $1), \
                (SELECT COUNT(*) FROM atlas_layout_theme_links WHERE run_id = $1)",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((themes, links), (1, 0));
    let row = AtlasLayoutRepository::run(&pool, None)
        .await
        .unwrap()
        .unwrap();
    assert!(row.stale, "a deleted placed theme makes the run stale");
}

// ── the narrowing epoch ──────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn narrowing_a_public_claim_invalidates_the_run(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-narrow").await;
    let t1 = seed_theme(&pool, "T1").await;
    let p = claim_in(&pool, agent, None, t1, Some(0)).await;
    let r = Uuid::new_v4();
    write_layout(&pool, &[(r, 0)], &[(t1, r)], &[]).await;
    assert!(current(&pool).await);
    narrow_claim(&pool, p, group).await;
    assert!(!current(&pool).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn narrowing_a_public_edge_invalidates_the_run(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-narrow-e").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let p1 = claim_in(&pool, agent, None, t1, None).await;
    let p2 = claim_in(&pool, agent, None, t2, None).await;
    let e = edge_with(&pool, p1, p2, "supports", serde_json::json!({})).await;
    let r = Uuid::new_v4();
    write_layout(
        &pool,
        &[(r, 0)],
        &[(t1, r), (t2, r)],
        &[(t1, t2, "supports", 1)],
    )
    .await;
    assert!(current(&pool).await);
    force_edge(&pool, e, "group", group).await;
    assert!(!current(&pool).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn repointing_an_edge_to_a_private_claim_invalidates_the_run(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-repoint").await;
    let t1 = seed_theme(&pool, "T1").await;
    let p1 = claim_in(&pool, agent, None, t1, None).await;
    let p2 = claim_in(&pool, agent, None, t1, None).await;
    let x = claim_in(&pool, agent, Some(group), t1, None).await;
    let e = edge_with(&pool, p1, p2, "supports", serde_json::json!({})).await;
    let r = Uuid::new_v4();
    write_layout(&pool, &[(r, 0)], &[(t1, r)], &[]).await;
    assert!(current(&pool).await);
    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(e)
        .bind(x)
        .execute(&pool)
        .await
        .unwrap();
    let vis: String = sqlx::query_scalar("SELECT visibility FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(vis, "group", "070's trigger re-derives the edge's tenancy");
    assert!(!current(&pool).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn widening_and_unrelated_updates_do_not_invalidate(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-widen").await;
    let t1 = seed_theme(&pool, "T1").await;
    let p = claim_in(&pool, agent, None, t1, None).await;
    let q = claim_in(&pool, agent, None, t1, None).await;
    let g = claim_in(&pool, agent, Some(group), t1, None).await;
    let r = Uuid::new_v4();
    write_layout(&pool, &[(r, 0)], &[(t1, r)], &[]).await;
    assert!(current(&pool).await);

    let world = fixture::world_group(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL epigraph.allow_declassify = 'yes'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(g)
        .bind(world)
        .execute(&mut *tx)
        .await
        .expect("declassify");
    tx.commit().await.unwrap();
    sqlx::query("UPDATE claims SET truth_value = 0.31 WHERE id = $1")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(q)
        .execute(&pool)
        .await
        .unwrap();
    assert!(current(&pool).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_built_while_a_narrowing_is_uncommitted_is_invalid_on_arrival(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-race").await;
    let t1 = seed_theme(&pool, "T1").await;
    let p = claim_in(&pool, agent, None, t1, Some(0)).await;
    claim_in(&pool, agent, None, t1, Some(0)).await;

    // A narrows and does not commit yet.
    let mut a = pool.begin().await.unwrap();
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(p)
        .bind(group)
        .execute(&mut *a)
        .await
        .unwrap();

    // B builds from its own snapshot (A's change invisible to it) and commits.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut b = pool.begin().await.unwrap();
    let inputs = AtlasLayoutRepository::read_public_inputs(&mut b, &bypass)
        .await
        .unwrap();
    assert_eq!(
        inputs.themes[0].public_member_count, 2,
        "B sees the old row"
    );
    let r = Uuid::new_v4();
    let build = LayoutBuild {
        algo: "pca2-ward-v1".into(),
        params: serde_json::json!({}),
        cluster_run_id: None,
        visibility_epoch: inputs.visibility_epoch,
        public_claim_count: 2,
        public_link_count: 0,
        theme_set_digest: "0".repeat(64),
        regions: vec![LayoutRegionOut {
            id: r,
            ordinal: 0,
            label: "R".into(),
            x: 0.0,
            y: 0.0,
            r: 800.0,
            centroid: basis_f32(0),
        }],
        themes: vec![LayoutThemeOut {
            theme_id: t1,
            region_id: r,
            rank_in_region: 0,
            x: 0.0,
            y: 0.0,
            public_member_count: 2,
        }],
        theme_links: vec![],
    };
    AtlasLayoutRepository::write_run(&mut b, &build)
        .await
        .unwrap();
    b.commit().await.unwrap();
    assert!(
        current(&pool).await,
        "nothing has committed a narrowing yet"
    );

    a.commit().await.unwrap();
    assert!(
        !current(&pool).await,
        "the run is invalid once the narrowing commits"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn narrowing_bump_is_a_pinned_definer(pool: PgPool) {
    let (definer, owner, config, public_exec): (bool, String, String, bool) = sqlx::query_as(
        "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                coalesce(array_to_string(p.proconfig, ';'), ''), \
                has_function_privilege('public', p.oid, 'EXECUTE') \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_atlas_layout_narrowed()'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert!(definer, "SECURITY DEFINER");
    let maint: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    if maint {
        assert_eq!(owner, "epigraph_maintenance");
    }
    assert_eq!(config, "search_path=pg_catalog, pg_temp");
    assert!(!public_exec, "PUBLIC must not execute the bump");
    let triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger \
          WHERE tgfoid = 'public.epigraph_atlas_layout_narrowed()'::regprocedure ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        triggers,
        vec![
            "claims_atlas_layout_narrowed",
            "edges_atlas_layout_narrowed"
        ]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn layout_tables_are_read_only_to_the_app_role(pool: PgPool) {
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT rolname::text FROM pg_roles \
          WHERE rolname IN ('epigraph_app', 'epigraph_maintenance')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let r = Uuid::new_v4();
    let run = write_layout(&pool, &[(r, 0)], &[(t1, r), (t2, r)], &[]).await;
    let centroid = basis(0);

    if roles.iter().any(|r| r == "epigraph_app") {
        let attempts: Vec<String> = vec![
            "INSERT INTO atlas_layout_epoch (singleton, n) VALUES (true, 5)".into(),
            "UPDATE atlas_layout_epoch SET n = n + 1".into(),
            "INSERT INTO atlas_layout_runs (algo, visibility_epoch, theme_count, region_count, \
             public_claim_count, public_link_count, theme_set_digest) \
             VALUES ('x', 0, 0, 0, 0, 0, repeat('0', 64))"
                .into(),
            format!(
                "INSERT INTO atlas_layout_regions (id, run_id, ordinal, label, x, y, r, centroid) \
                 VALUES (gen_random_uuid(), '{run}', 9, 'x', 0, 0, 1, '{centroid}')"
            ),
            format!(
                "INSERT INTO atlas_layout_themes (run_id, theme_id, region_id, rank_in_region, \
                 x, y, public_member_count) VALUES ('{run}', '{t1}', '{r}', 7, 0, 0, 1)"
            ),
            format!(
                "INSERT INTO atlas_layout_theme_links (run_id, theme_a, theme_b, relationship, \
                 link_count) VALUES ('{run}', '{}', '{}', 'supports', 1)",
                t1.min(t2),
                t1.max(t2)
            ),
            format!("DELETE FROM atlas_layout_runs WHERE id = '{run}'"),
        ];
        let codes = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let mut codes = Vec::new();
            for sql in &attempts {
                let err = sqlx::query(sql).execute(&mut *conn).await.unwrap_err();
                codes.push(
                    err.as_database_error()
                        .and_then(|d| d.code().map(|c| c.to_string()))
                        .unwrap_or_default(),
                );
            }
            let n: i64 = sqlx::query_scalar(
                "SELECT (SELECT COUNT(*) FROM atlas_layout_runs) + \
                        (SELECT COUNT(*) FROM atlas_layout_regions) + \
                        (SELECT COUNT(*) FROM atlas_layout_themes) + \
                        (SELECT COUNT(*) FROM atlas_layout_theme_links) + \
                        (SELECT COUNT(*) FROM atlas_layout_epoch)",
            )
            .fetch_one(&mut *conn)
            .await
            .expect("the app role reads every layout table");
            assert!(n > 0);
            (conn, codes)
        })
        .await;
        assert!(codes.iter().all(|c| c == "42501"), "{codes:?}");
    }

    if roles.iter().any(|r| r == "epigraph_maintenance") {
        let sqls = vec![
            "INSERT INTO atlas_layout_runs (id, algo, visibility_epoch, theme_count, \
             region_count, public_claim_count, public_link_count, theme_set_digest) \
             VALUES ('00000000-0000-0000-0000-0000000000aa', 'x', 0, 0, 0, 0, 0, repeat('0', 64))"
                .to_string(),
            format!(
                "INSERT INTO atlas_layout_regions (id, run_id, ordinal, label, x, y, r, centroid) \
                 VALUES ('00000000-0000-0000-0000-0000000000ab', \
                         '00000000-0000-0000-0000-0000000000aa', 0, 'x', 0, 0, 1, '{centroid}')"
            ),
            format!(
                "INSERT INTO atlas_layout_themes (run_id, theme_id, region_id, rank_in_region, \
                 x, y, public_member_count) VALUES ('00000000-0000-0000-0000-0000000000aa', \
                 '{t1}', '00000000-0000-0000-0000-0000000000ab', 0, 0, 0, 1)"
            ),
            "DELETE FROM atlas_layout_runs WHERE id = '00000000-0000-0000-0000-0000000000aa'"
                .to_string(),
        ];
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            for sql in &sqls {
                sqlx::query(sql)
                    .execute(&mut *conn)
                    .await
                    .unwrap_or_else(|e| panic!("maintenance: {sql}: {e}"));
            }
            (conn, ())
        })
        .await;
    }
}

// ── serve side ───────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn overview_positions_are_shared_and_counts_are_per_viewer(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "atlas-member").await;
    let t1 = seed_theme(&pool, "T1").await;
    claim_in(&pool, member, None, t1, Some(0)).await;
    claim_in(&pool, member, None, t1, Some(0)).await;
    claim_in(&pool, member, Some(group), t1, Some(0)).await;
    let ra = Uuid::new_v4();
    let run = write_layout(&pool, &[(ra, 0)], &[(t1, ra)], &[]).await;

    let mut conn = pool.acquire().await.unwrap();
    let mv = viewer_of(&pool, member).await;
    let pv = fixture::public_viewer(&pool).await;
    let m = AtlasLayoutRepository::overview(&mut conn, &mv, run, None, None, 200)
        .await
        .unwrap();
    let p = AtlasLayoutRepository::overview(&mut conn, &pv, run, None, None, 200)
        .await
        .unwrap();
    assert_eq!(m.regions.len(), 1);
    assert_eq!(p.regions.len(), 1);
    let (mr, pr) = (&m.regions[0], &p.regions[0]);
    assert_eq!((mr.x, mr.y, mr.r, &mr.label), (pr.x, pr.y, pr.r, &pr.label));
    assert_eq!(mr.member_count, 3);
    assert_eq!(pr.member_count, 2);
}

/// Regions RA = {T1} and RB = {T2, T4}; layout links T1-T2 `supports: 1` and
/// T1-T4 `contradicts: 1`. T2's only public member is superseded, so the
/// public viewer cannot see T2; a member of G reads T2's group claim.
#[sqlx::test(migrations = "../../migrations")]
async fn overview_region_bundle_excludes_themes_the_viewer_cannot_see(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "atlas-bundle").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let t4 = seed_theme(&pool, "T4").await;
    let c1 = claim_in(&pool, member, None, t1, Some(0)).await;
    let c2 = claim_in(&pool, member, None, t2, Some(1)).await;
    claim_in(&pool, member, Some(group), t2, Some(1)).await;
    let c4 = claim_in(&pool, member, None, t4, Some(1)).await;
    edge_with(&pool, c1, c2, "supports", serde_json::json!({})).await;
    edge_with(&pool, c1, c4, "contradicts", serde_json::json!({})).await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(c2)
        .execute(&pool)
        .await
        .unwrap();
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(
        &pool,
        &[(ra, 0), (rb, 1)],
        &[(t1, ra), (t2, rb), (t4, rb)],
        &[(t1, t2, "supports", 1), (t1, t4, "contradicts", 1)],
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let p = AtlasLayoutRepository::overview(&mut conn, &pv, run, None, None, 200)
        .await
        .unwrap();
    let counts: BTreeMap<String, i64> = p
        .links
        .iter()
        .map(|l| (l.relationship.clone(), l.link_count))
        .collect();
    assert_eq!(counts, BTreeMap::from([("contradicts".to_string(), 1)]));
    assert!(p.links.iter().all(|l| l.total == 1 && l.kind == "region"));
    let drill =
        AtlasLayoutRepository::links_between(&mut conn, &pv, &[t1], &[t2, t4], None, None, 50)
            .await
            .unwrap();
    assert_eq!(drill.counts, vec![("contradicts".to_string(), 1)]);
    let rb_row = p
        .regions
        .iter()
        .find(|r| r.id == rb)
        .expect("RB visible via T4");
    assert_eq!(rb_row.theme_ids, vec![t4]);

    let mv = viewer_of(&pool, member).await;
    let m = AtlasLayoutRepository::overview(&mut conn, &mv, run, None, None, 200)
        .await
        .unwrap();
    let counts: BTreeMap<String, i64> = m
        .links
        .iter()
        .map(|l| (l.relationship.clone(), l.link_count))
        .collect();
    assert_eq!(
        counts,
        BTreeMap::from([("contradicts".to_string(), 1), ("supports".to_string(), 1)])
    );
    assert!(m.links.iter().all(|l| l.total == 2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_drops_a_theme_and_region_the_viewer_cannot_read(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "atlas-drop").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    claim_in(&pool, member, None, t1, Some(0)).await;
    claim_in(&pool, member, Some(group), t2, Some(1)).await;
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(
        &pool,
        &[(ra, 0), (rb, 1)],
        &[(t1, ra), (t2, rb)],
        &[(t1, t2, "supports", 1)],
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let p = AtlasLayoutRepository::overview(&mut conn, &pv, run, None, None, 200)
        .await
        .unwrap();
    let rendered = format!("{p:?}");
    assert_eq!(p.regions.len(), 1);
    assert_eq!(p.regions[0].id, ra);
    assert!(p.links.is_empty());
    assert!(!rendered.contains(&t2.to_string()));
    assert!(!rendered.contains(&rb.to_string()));
    let mv = viewer_of(&pool, member).await;
    let m = AtlasLayoutRepository::overview(&mut conn, &mv, run, None, None, 200)
        .await
        .unwrap();
    assert_eq!(m.regions.len(), 2);
    assert_eq!(m.links.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn viewer_placement_assigns_the_nearest_region_from_readable_members_only(pool: PgPool) {
    let (v1, g1) = fixture::seed_agent_with_group(&pool, "atlas-g1").await;
    let (v2, g2) = fixture::seed_agent_with_group(&pool, "atlas-g2").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let tp = seed_theme(&pool, "TP private").await;
    claim_in(&pool, v1, None, t1, Some(0)).await;
    claim_in(&pool, v1, None, t2, Some(1)).await;
    claim_in(&pool, v1, Some(g1), tp, Some(0)).await;
    claim_in(&pool, v2, Some(g2), tp, Some(1)).await;
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(&pool, &[(ra, 0), (rb, 1)], &[(t1, ra), (t2, rb)], &[]).await;

    let mut conn = pool.acquire().await.unwrap();
    let viewer1 = viewer_of(&pool, v1).await;
    let viewer2 = viewer_of(&pool, v2).await;
    let pv = fixture::public_viewer(&pool).await;

    let d1 = AtlasLayoutRepository::region_detail(
        &mut conn,
        &viewer1,
        run,
        ra,
        None,
        DetailPart::Both,
        200,
    )
    .await
    .unwrap()
    .unwrap();
    let tp_row = d1
        .themes
        .iter()
        .find(|t| t.theme_id == tp)
        .expect("TP in RA for G1");
    assert_eq!(tp_row.placement, ThemePlacement::Viewer);
    assert_eq!((tp_row.x, tp_row.y), (None, None));
    assert_eq!(tp_row.member_count, 1);

    let d2 = AtlasLayoutRepository::region_detail(
        &mut conn,
        &viewer2,
        run,
        rb,
        None,
        DetailPart::Both,
        200,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(d2
        .themes
        .iter()
        .any(|t| t.theme_id == tp && t.placement == ThemePlacement::Viewer));
    let d2a = AtlasLayoutRepository::region_detail(
        &mut conn,
        &viewer2,
        run,
        ra,
        None,
        DetailPart::Both,
        200,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!d2a.themes.iter().any(|t| t.theme_id == tp));

    let p = AtlasLayoutRepository::overview(&mut conn, &pv, run, None, None, 200)
        .await
        .unwrap();
    assert!(!format!("{p:?}").contains(&tp.to_string()));
    for r in &p.regions {
        assert_eq!((r.theme_count, r.member_count), (1, 1), "{r:?}");
    }
    assert_eq!(p.unplaced_theme_count, 0);
    let o1 = AtlasLayoutRepository::overview(&mut conn, &viewer1, run, None, None, 200)
        .await
        .unwrap();
    let ra1 = o1.regions.iter().find(|r| r.id == ra).unwrap();
    assert_eq!((ra1.theme_count, ra1.member_count), (2, 2));
    assert_eq!(ra1.theme_ids, vec![t1, tp]);

    let placed = AtlasLayoutRepository::placement_layout(&mut conn, &viewer1, tp)
        .await
        .unwrap()
        .expect("placed for G1");
    assert_eq!(
        (placed.region_id, placed.placement),
        (ra, ThemePlacement::Viewer)
    );
    assert!(AtlasLayoutRepository::placement_layout(&mut conn, &pv, tp)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_theme_with_readable_members_but_no_embeddings_is_unplaced(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "atlas-unplaced").await;
    let t1 = seed_theme(&pool, "T1").await;
    let tu = seed_theme(&pool, "TU no vectors").await;
    claim_in(&pool, agent, None, t1, Some(0)).await;
    claim_in(&pool, agent, None, tu, None).await;
    let ra = Uuid::new_v4();
    let run = write_layout(&pool, &[(ra, 0)], &[(t1, ra)], &[]).await;
    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let o = AtlasLayoutRepository::overview(&mut conn, &pv, run, None, None, 200)
        .await
        .unwrap();
    assert_eq!(o.unplaced_theme_count, 1);
    assert_eq!(o.regions[0].theme_ids, vec![t1]);
    let page = AtlasLayoutRepository::unplaced_themes(&mut conn, &pv, run, None, 200)
        .await
        .unwrap();
    assert_eq!(page.themes.len(), 1);
    let row = &page.themes[0];
    assert_eq!(row.theme_id, tu);
    assert_eq!(row.placement, ThemePlacement::Unplaced);
    assert_eq!((row.region_id, row.x, row.y), (None, None, None));
    assert_eq!(row.label, "TU no vectors");
}

#[sqlx::test(migrations = "../../migrations")]
async fn region_detail_returns_none_for_unknown_and_invisible_regions_alike(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "atlas-none").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    claim_in(&pool, agent, None, t1, Some(0)).await;
    claim_in(&pool, agent, Some(group), t2, Some(1)).await;
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(&pool, &[(ra, 0), (rb, 1)], &[(t1, ra), (t2, rb)], &[]).await;
    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    for region in [rb, Uuid::new_v4()] {
        let d = AtlasLayoutRepository::region_detail(
            &mut conn,
            &pv,
            run,
            region,
            None,
            DetailPart::Both,
            200,
        )
        .await
        .unwrap();
        assert!(d.is_none(), "{region}");
    }
    let mv = viewer_of(&pool, agent).await;
    assert!(AtlasLayoutRepository::region_detail(
        &mut conn,
        &mv,
        run,
        rb,
        None,
        DetailPart::Both,
        200
    )
    .await
    .unwrap()
    .is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn region_detail_pages_themes_and_links_without_gaps(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "atlas-pages").await;
    let ra = Uuid::new_v4();
    let mut themes = Vec::new();
    for i in 0..205 {
        let t = seed_theme(&pool, &format!("Theme {i:03}")).await;
        claim_in(&pool, agent, None, t, None).await;
        themes.push((t, ra));
    }
    let ids: Vec<Uuid> = themes.iter().map(|(t, _)| *t).collect();
    let mut links: Vec<(Uuid, Uuid, &str, i64)> = Vec::new();
    for w in ids.windows(2) {
        links.push((w[0], w[1], "supports", 1));
    }
    links.push((ids[0], ids[2], "supports", 2));
    let run = write_layout(&pool, &[(ra, 0)], &themes, &links).await;

    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let first =
        AtlasLayoutRepository::region_detail(&mut conn, &pv, run, ra, None, DetailPart::Both, 200)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(first.region.theme_count, 205);
    assert_eq!(first.region.theme_ids.len(), 200);
    assert_eq!(first.themes.len(), 200);
    let cursor = first.next_themes.expect("a themes cursor");
    let second = AtlasLayoutRepository::region_detail(
        &mut conn,
        &pv,
        run,
        ra,
        None,
        DetailPart::ThemesAfter(cursor),
        200,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(second.themes.len(), 5);
    assert!(second.next_themes.is_none() && second.links.is_empty());
    let all: BTreeSet<Uuid> = first
        .themes
        .iter()
        .chain(&second.themes)
        .map(|t| t.theme_id)
        .collect();
    assert_eq!(all.len(), 205);
    assert_eq!(all, ids.iter().copied().collect());

    // Links: 205 theme pairs, in two pages.
    let mut seen: BTreeSet<(Uuid, Uuid)> = first.links.iter().map(|l| (l.a, l.b)).collect();
    assert_eq!(seen.len(), 200);
    assert_eq!(first.links[0].total, 2, "the heaviest bundle first");
    let lc = first.next_links.expect("a links cursor");
    let rest = AtlasLayoutRepository::region_detail(
        &mut conn,
        &pv,
        run,
        ra,
        None,
        DetailPart::LinksAfter(lc),
        200,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(rest.themes.is_empty() && rest.next_links.is_none());
    assert_eq!(rest.links.len(), 5);
    for l in &rest.links {
        assert!(seen.insert((l.a, l.b)), "duplicate bundle across pages");
    }
    assert_eq!(seen.len(), 205);
}

/// RA = {T0, T1}, RB = {T4, T5}; links T1-T4 `supports: 2`, T1-T5
/// `supports: 3`. From RA, T1's links to RB fold into one stub.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_region_stubs_sum_cross_region_theme_links(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "atlas-stubs").await;
    let t0 = seed_theme(&pool, "T0").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t4 = seed_theme(&pool, "T4").await;
    let t5 = seed_theme(&pool, "T5").await;
    claim_in(&pool, member, None, t0, Some(0)).await;
    claim_in(&pool, member, None, t1, Some(0)).await;
    claim_in(&pool, member, None, t4, Some(1)).await;
    // T5's only member is private to G.
    claim_in(&pool, member, Some(group), t5, Some(1)).await;
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(
        &pool,
        &[(ra, 0), (rb, 1)],
        &[(t0, ra), (t1, ra), (t4, rb), (t5, rb)],
        &[(t1, t4, "supports", 2), (t1, t5, "supports", 3)],
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    let mv = viewer_of(&pool, member).await;
    let d =
        AtlasLayoutRepository::region_detail(&mut conn, &mv, run, ra, None, DetailPart::Both, 200)
            .await
            .unwrap()
            .unwrap();
    let stubs: Vec<(Uuid, Uuid, i64)> = d
        .links
        .iter()
        .filter(|l| l.kind == "theme_region")
        .map(|l| (l.a, l.b, l.link_count))
        .collect();
    assert_eq!(stubs, vec![(t1, rb, 5)]);

    // Hidden other side: the public viewer cannot see T5, so the stub counts
    // only T4.
    let pv = fixture::public_viewer(&pool).await;
    let d =
        AtlasLayoutRepository::region_detail(&mut conn, &pv, run, ra, None, DetailPart::Both, 200)
            .await
            .unwrap()
            .unwrap();
    let stubs: Vec<(Uuid, Uuid, i64)> = d.links.iter().map(|l| (l.a, l.b, l.link_count)).collect();
    assert_eq!(stubs, vec![(t1, rb, 2)]);

    // Hidden R side: from RB, the public viewer sees T4's stub to RA but
    // nothing that names T5.
    let d =
        AtlasLayoutRepository::region_detail(&mut conn, &pv, run, rb, None, DetailPart::Both, 200)
            .await
            .unwrap()
            .unwrap();
    let rendered = format!("{d:?}");
    assert!(!rendered.contains(&t5.to_string()), "{rendered}");
    let stubs: Vec<(Uuid, Uuid, i64)> = d.links.iter().map(|l| (l.a, l.b, l.link_count)).collect();
    assert_eq!(stubs, vec![(t4, ra, 2)]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_between_orders_by_strength_nulls_last_and_walks_by_cursor(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "atlas-strength").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let mut ids = BTreeMap::new();
    let cases = [
        ("s09", serde_json::json!({"strength": 0.9})),
        ("s05", serde_json::json!({"strength": 0.5})),
        ("s17", serde_json::json!({"strength": 1.7})),
        ("c07", serde_json::json!({"confidence": 0.7})),
        ("none", serde_json::json!({})),
        ("high", serde_json::json!({"strength": "high"})),
    ];
    for (i, (name, props)) in cases.iter().enumerate() {
        let a = claim_in(&pool, agent, None, t1, None).await;
        let b = claim_in(&pool, agent, None, t2, None).await;
        let e = edge_with(&pool, a, b, "supports", props.clone()).await;
        sqlx::query(
            "UPDATE edges SET created_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(e)
        .bind(f64::from(u32::try_from(i).unwrap() * 10))
        .execute(&pool)
        .await
        .unwrap();
        ids.insert(*name, e);
    }
    let want = vec![
        ids["s17"],
        ids["s09"],
        ids["c07"],
        ids["s05"],
        ids["none"],
        ids["high"],
    ];
    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let all = AtlasLayoutRepository::links_between(&mut conn, &pv, &[t1], &[t2], None, None, 50)
        .await
        .unwrap();
    let got: Vec<Uuid> = all.items.iter().map(|i| i.edge_id).collect();
    assert_eq!(got, want);
    assert_eq!(all.items[2].strength, Some(0.7));
    assert_eq!(all.items[5].strength, None);

    let mut walked = Vec::new();
    let mut after = None;
    loop {
        let page =
            AtlasLayoutRepository::links_between(&mut conn, &pv, &[t1], &[t2], None, after, 2)
                .await
                .unwrap();
        walked.extend(page.items.iter().map(|i| i.edge_id));
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    assert_eq!(walked, want);
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_between_hides_private_endpoints_and_their_counts(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "atlas-hide").await;
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let p1 = claim_in(&pool, member, None, t1, None).await;
    let p2 = claim_in(&pool, member, None, t2, None).await;
    let x = claim_in(&pool, member, Some(group), t1, None).await;
    edge_with(&pool, p1, p2, "supports", serde_json::json!({})).await;
    edge_with(&pool, x, p2, "contradicts", serde_json::json!({})).await;
    let mut conn = pool.acquire().await.unwrap();
    let pv = fixture::public_viewer(&pool).await;
    let p = AtlasLayoutRepository::links_between(&mut conn, &pv, &[t1], &[t2], None, None, 50)
        .await
        .unwrap();
    assert_eq!(p.counts, vec![("supports".to_string(), 1)]);
    assert!(!format!("{p:?}").contains(&x.to_string()));
    let mv = viewer_of(&pool, member).await;
    let m = AtlasLayoutRepository::links_between(&mut conn, &mv, &[t1], &[t2], None, None, 50)
        .await
        .unwrap();
    assert_eq!(
        m.counts,
        vec![("contradicts".to_string(), 1), ("supports".to_string(), 1)]
    );
    assert!(m.items.iter().any(|i| i.source_id == x && i.from_is_source));
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_sides_is_one_statement_and_types_each_side(pool: PgPool) {
    let t1 = seed_theme(&pool, "T1").await;
    let t2 = seed_theme(&pool, "T2").await;
    let t3 = seed_theme(&pool, "T3").await;
    let (ra, rb) = (Uuid::new_v4(), Uuid::new_v4());
    let run = write_layout(
        &pool,
        &[(ra, 0), (rb, 1)],
        &[(t1, ra), (t2, ra), (t3, rb)],
        &[],
    )
    .await;

    let (from, to) = AtlasLayoutRepository::resolve_sides(&pool, Some(run), ra, t3)
        .await
        .unwrap();
    let from = from.expect("a region");
    assert_eq!(from.kind, LinkSideKind::Region);
    let mut want = vec![t1, t2];
    want.sort_unstable();
    assert_eq!(from.theme_ids, want);
    let to = to.expect("a theme");
    assert_eq!(
        (to.kind, to.theme_ids.clone()),
        (LinkSideKind::Theme, vec![t3])
    );

    let (from, to) = AtlasLayoutRepository::resolve_sides(&pool, Some(run), Uuid::new_v4(), t1)
        .await
        .unwrap();
    assert!(from.is_none());
    assert_eq!(to.map(|s| s.kind), Some(LinkSideKind::Theme));

    // Without a run a region id resolves to nothing; a theme still resolves.
    let (from, to) = AtlasLayoutRepository::resolve_sides(&pool, None, ra, t2)
        .await
        .unwrap();
    assert!(from.is_none());
    assert_eq!(to.map(|s| s.theme_ids), Some(vec![t2]));
}

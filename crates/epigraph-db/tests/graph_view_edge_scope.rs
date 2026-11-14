//! The `edges` rows a graph projection walks are filtered by the viewer, and
//! not only the `claims` rows it returns (`F-edges-unfiltered`,
//! `F-atom-count-cardinality`).
//!
//! # The instrument
//!
//! `#[sqlx::test]` hands out a SUPERUSER pool, which bypasses row security. So
//! the in-query predicate `Viewer::splice` renders is the ONLY control on every
//! statement here, and deleting a marker is directly observable. That is the
//! property these tests need: on a stamped application-role session the edge
//! policies would hide the same rows, and a test run there could not tell a
//! filtered statement from an unfiltered one.
//!
//! # Hidden edges join two PUBLIC claims
//!
//! Every hidden edge below is built with [`hidden`], which forces the edge's
//! own tenancy to a stranger's group AFTER the insert. Migration 070's trigger
//! would otherwise stamp the edge with the meet of its endpoints, so an edge to
//! a private claim would be private, and the `claims` predicate (which these
//! statements already carried) would hide the row for a reason unrelated to the
//! one under test. Between two public claims only the edge predicate can act.
//!
//! # Every negative arm has a calibration partner
//!
//! A statement that drops every edge satisfies "the hidden edge is absent" too.
//! So each arm also seeds an edge private to the VIEWER's own group between
//! public claims, and asserts it IS walked. Only a predicate that admits the
//! viewer's groups passes both.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::GraphViewRepository;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_group_claim, seed_public_claim, world_group};

// ── fixtures ──

struct Cast {
    viewer: Viewer,
    viewer_agent: Uuid,
    viewer_group: Uuid,
    stranger: Uuid,
    stranger_group: Uuid,
}

async fn cast(pool: &PgPool, label: &str) -> Cast {
    let (viewer_agent, viewer_group) = seed_agent_with_group(pool, &format!("{label}-mine")).await;
    let (stranger, stranger_group) = seed_agent_with_group(pool, &format!("{label}-theirs")).await;
    let viewer = Viewer::resolve(pool, viewer_agent).await.expect("resolve");
    assert!(
        viewer
            .group_bind()
            .is_some_and(|g| g.contains(&viewer_group)),
        "CALIBRATION: the viewer must be scoped to its own group, or every \
         calibration arm below is vacuous"
    );
    Cast {
        viewer,
        viewer_agent,
        viewer_group,
        stranger,
        stranger_group,
    }
}

/// An edge `source -> target` of `relationship`, with its tenancy FORCED to
/// `(visibility, owner)` after the insert (the trigger only fires on an update
/// of the endpoints, so the forced columns stick).
async fn edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    visibility: &str,
    owner: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("force edge tenancy");
    let (v, o): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM edges WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read back edge tenancy");
    assert_eq!(
        (v.as_str(), o),
        (visibility, owner),
        "CALIBRATION: the forced edge tenancy must stick"
    );
    id
}

/// An edge only the STRANGER's group may read, between whatever endpoints.
async fn hidden(pool: &PgPool, c: &Cast, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    edge(pool, source, target, rel, "group", c.stranger_group).await
}

/// An edge private to the VIEWER's own group: the calibration partner.
async fn mine(pool: &PgPool, c: &Cast, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    edge(pool, source, target, rel, "group", c.viewer_group).await
}

async fn public_edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    let world = world_group(pool).await;
    edge(pool, source, target, rel, "public", world).await
}

async fn claim(pool: &PgPool, c: &Cast, content: &str) -> Uuid {
    seed_public_claim(pool, c.viewer_agent, content).await
}

struct Run {
    run_id: Uuid,
    cluster_id: Uuid,
    neighborhood_id: Uuid,
}

/// A clustering run with one cluster and one neighborhood. None of the three
/// metadata tables carries tenancy columns.
async fn seed_run(pool: &PgPool) -> Run {
    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    let neighborhood_id = Uuid::new_v4();
    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label) VALUES ($1, 'edge-scope-theme')")
        .bind(theme_id)
        .execute(pool)
        .await
        .expect("seed theme");
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed run");
    sqlx::query(
        "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, degraded) \
         VALUES ($1, $2, 'cluster-0', 2, 0.5, 'claim', FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed cluster");
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp) \
         VALUES ($1, $2, $3, 'neighborhood-0', 2, 0.5)",
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .execute(pool)
    .await
    .expect("seed neighborhood");
    Run {
        run_id,
        cluster_id,
        neighborhood_id,
    }
}

async fn join_neighborhood(pool: &PgPool, run: &Run, claim: Uuid) {
    sqlx::query(
        "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(run.run_id)
    .bind(claim)
    .bind(run.neighborhood_id)
    .execute(pool)
    .await
    .expect("seed neighborhood membership");
}

async fn join_cluster(pool: &PgPool, run: &Run, claim: Uuid) {
    sqlx::query(
        "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
    )
    .bind(claim)
    .bind(run.cluster_id)
    .bind(run.run_id)
    .execute(pool)
    .await
    .expect("seed cluster membership");
}

async fn set_pignistic(pool: &PgPool, claim: Uuid, p: f64) {
    sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
        .bind(claim)
        .bind(p)
        .execute(pool)
        .await
        .expect("set pignistic_prob");
}

// ── expand_cluster_nodes ──

/// The degree ordering counts only the edges the viewer may read.
///
/// `busy` has three hidden edges and the higher pignistic probability; `quiet`
/// has two edges private to the viewer's own group. With `budget = 1` the one
/// node returned is the higher-degree one, so:
///
/// - an unfiltered degree returns `busy` (3 > 2);
/// - a predicate that drops every edge ties both at 0 and the pignistic
///   tie-break returns `busy`;
/// - only a degree that counts exactly the viewer's edges returns `quiet`.
#[sqlx::test(migrations = "../../migrations")]
async fn expand_cluster_degree_counts_only_edges_the_viewer_can_read(pool: PgPool) {
    let c = cast(&pool, "ev-expand").await;
    let busy = claim(&pool, &c, "ev expand: busy member").await;
    let quiet = claim(&pool, &c, "ev expand: quiet member").await;
    set_pignistic(&pool, busy, 0.9).await;
    set_pignistic(&pool, quiet, 0.1).await;
    for i in 0..3 {
        let far = claim(&pool, &c, &format!("ev expand: far {i}")).await;
        hidden(&pool, &c, busy, far, "supports").await;
    }
    for i in 0..2 {
        let far = claim(&pool, &c, &format!("ev expand: near {i}")).await;
        mine(&pool, &c, far, quiet, "supports").await;
    }
    let run = seed_run(&pool).await;
    join_cluster(&pool, &run, busy).await;
    join_cluster(&pool, &run, quiet).await;

    let rows = GraphViewRepository::expand_cluster_nodes(
        &pool,
        &c.viewer,
        run.cluster_id,
        run.run_id,
        &["supports".to_string()],
        1,
    )
    .await
    .expect("expand_cluster_nodes");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![quiet],
        "the top node by degree must be the one whose edges the viewer can read \
         (busy = {busy}, quiet = {quiet})"
    );

    // Zero visible edges must not drop a member: the filter belongs in the LEFT
    // JOIN's ON, not in WHERE.
    let all = GraphViewRepository::expand_cluster_nodes(
        &pool,
        &c.viewer,
        run.cluster_id,
        run.run_id,
        &["supports".to_string()],
        10,
    )
    .await
    .expect("expand_cluster_nodes");
    assert_eq!(
        all.len(),
        2,
        "both members are readable claims and must both be served"
    );
}

// ── neighborhood_compound_nodes ──

/// A compound whose only `decomposes_to` edge is hidden is not a compound to
/// this viewer, and its atom is served as standalone.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_nodes_follow_only_edges_the_viewer_can_read(pool: PgPool) {
    let c = cast(&pool, "ev-cnodes").await;
    let their_parent = claim(&pool, &c, "ev cnodes: compound by a hidden edge").await;
    let orphan = claim(&pool, &c, "ev cnodes: atom whose parent edge is hidden").await;
    let my_parent = claim(&pool, &c, "ev cnodes: compound by my edge").await;
    let child = claim(&pool, &c, "ev cnodes: atom of my compound").await;
    hidden(&pool, &c, their_parent, orphan, "decomposes_to").await;
    mine(&pool, &c, my_parent, child, "decomposes_to").await;
    // A member whose only CHILD edge is hidden (the child is outside the
    // neighborhood): the source-side `NOT EXISTS` probe.
    let barren = claim(&pool, &c, "ev cnodes: member whose child edge is hidden").await;
    let outside = claim(&pool, &c, "ev cnodes: child outside the neighborhood").await;
    hidden(&pool, &c, barren, outside, "decomposes_to").await;
    let run = seed_run(&pool).await;
    join_neighborhood(&pool, &run, orphan).await;
    join_neighborhood(&pool, &run, child).await;
    join_neighborhood(&pool, &run, barren).await;

    let rows =
        GraphViewRepository::neighborhood_compound_nodes(&pool, &c.viewer, run.neighborhood_id)
            .await
            .expect("neighborhood_compound_nodes");
    let kind_of = |id: Uuid| {
        rows.iter()
            .find(|r| r.id == id)
            .map(|r| (r.kind.clone(), r.atom_count))
    };

    assert_eq!(
        kind_of(my_parent),
        Some(("compound".to_string(), 1)),
        "CALIBRATION: a compound reached by an edge private to the viewer's own group \
         must be served with its atom counted; got {rows:?}"
    );
    assert_eq!(
        kind_of(child),
        None,
        "CALIBRATION: an atom with a visible parent is not standalone; got {rows:?}"
    );
    assert_eq!(
        kind_of(their_parent),
        None,
        "a compound reached only through a hidden decomposes_to edge must be ABSENT; \
         got {rows:?}"
    );
    assert_eq!(
        kind_of(orphan),
        Some(("standalone".to_string(), 0)),
        "an atom whose only parent edge is hidden must be served as standalone, the \
         same as if the edge did not exist; got {rows:?}"
    );
    assert_eq!(
        kind_of(barren),
        Some(("standalone".to_string(), 0)),
        "a member whose only child edge is hidden must be served as standalone; \
         got {rows:?}"
    );
}

/// `atom_count` counts only atoms whose `claims` row the viewer can read.
///
/// The stranger's atom has its MEMBERSHIP row forced public and its edge
/// forced public, so neither the membership predicate nor the edge predicate
/// can drop it. Only a claims predicate on the atoms can.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atom_count_excludes_an_atom_the_viewer_cannot_read(pool: PgPool) {
    let c = cast(&pool, "ev-acount").await;
    let world = world_group(&pool).await;
    let compound = claim(&pool, &c, "ev acount: the compound").await;
    let open_atom = claim(&pool, &c, "ev acount: public atom").await;
    let my_atom = seed_group_claim(
        &pool,
        c.viewer_agent,
        c.viewer_group,
        "ev acount: my private atom",
    )
    .await;
    let their_atom = seed_group_claim(
        &pool,
        c.stranger,
        c.stranger_group,
        "ev acount: their private atom",
    )
    .await;
    let run = seed_run(&pool).await;
    for atom in [open_atom, my_atom, their_atom] {
        public_edge(&pool, compound, atom, "decomposes_to").await;
        join_neighborhood(&pool, &run, atom).await;
    }
    sqlx::query(
        "UPDATE claim_neighborhood_membership SET visibility = 'public', owner_group_id = $2 \
         WHERE claim_id = $1",
    )
    .bind(their_atom)
    .bind(world)
    .execute(&pool)
    .await
    .expect("force the stranger atom's membership public");
    let m: String = sqlx::query_scalar(
        "SELECT visibility::text FROM claim_neighborhood_membership WHERE claim_id = $1",
    )
    .bind(their_atom)
    .fetch_one(&pool)
    .await
    .expect("read back membership");
    assert_eq!(m, "public", "CALIBRATION: the forced membership must stick");

    let rows =
        GraphViewRepository::neighborhood_compound_nodes(&pool, &c.viewer, run.neighborhood_id)
            .await
            .expect("neighborhood_compound_nodes");
    let count = rows.iter().find(|r| r.id == compound).map(|r| r.atom_count);
    assert_eq!(
        count,
        Some(2),
        "atom_count must be 2 (the public atom and the viewer's own private one); a 3 \
         counts an atom the viewer cannot read and a 1 drops the viewer's own; got {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.id == their_atom),
        "the unreadable atom must not appear as a node either; got {rows:?}"
    );
}

// ── neighborhood_atomic_nodes / neighborhood_compound_groups ──

/// `compound_id` names only a parent reached through an edge the viewer can
/// read, and the compound groups list only such parents.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_parents_follow_only_edges_the_viewer_can_read(pool: PgPool) {
    let c = cast(&pool, "ev-atomic").await;
    let their_parent = claim(&pool, &c, "ev atomic: parent by a hidden edge").await;
    let orphan = claim(&pool, &c, "ev atomic: atom whose parent edge is hidden").await;
    let my_parent = claim(&pool, &c, "ev atomic: parent by my edge").await;
    let child = claim(&pool, &c, "ev atomic: atom of my parent").await;
    hidden(&pool, &c, their_parent, orphan, "decomposes_to").await;
    mine(&pool, &c, my_parent, child, "decomposes_to").await;
    let run = seed_run(&pool).await;
    join_neighborhood(&pool, &run, orphan).await;
    join_neighborhood(&pool, &run, child).await;

    let nodes =
        GraphViewRepository::neighborhood_atomic_nodes(&pool, &c.viewer, run.neighborhood_id)
            .await
            .expect("neighborhood_atomic_nodes");
    let parent_of = |id: Uuid| nodes.iter().find(|n| n.id == id).map(|n| n.compound_id);
    assert_eq!(
        parent_of(child),
        Some(Some(my_parent)),
        "CALIBRATION: a parent reached by the viewer's own edge must be named; got {nodes:?}"
    );
    assert_eq!(
        parent_of(orphan),
        Some(None),
        "an atom whose only parent edge is hidden must be served with NO compound_id; \
         got {nodes:?}"
    );

    let groups =
        GraphViewRepository::neighborhood_compound_groups(&pool, &c.viewer, run.neighborhood_id)
            .await
            .expect("neighborhood_compound_groups");
    let group_ids: Vec<Uuid> = groups.iter().map(|g| g.compound_id).collect();
    assert!(
        group_ids.contains(&my_parent),
        "CALIBRATION: the viewer's own compound group must be served; got {group_ids:?}"
    );
    assert!(
        !group_ids.contains(&their_parent),
        "a compound group reached only through a hidden edge must be ABSENT; got {group_ids:?}"
    );
}

// ── compound_neighbors ──

/// The epistemic edges, and the `decomposes_to` edge that projects a neighbour
/// onto its parent compound, are both filtered.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_walk_only_edges_the_viewer_can_read(pool: PgPool) {
    let c = cast(&pool, "ev-cn").await;
    let center = claim(&pool, &c, "ev cn: centre").await;

    // Epistemic edges.
    let behind_hidden = claim(&pool, &c, "ev cn: neighbour by a hidden edge").await;
    let behind_mine = claim(&pool, &c, "ev cn: neighbour by my edge").await;
    hidden(&pool, &c, behind_hidden, center, "supports").await;
    mine(&pool, &c, behind_mine, center, "supports").await;

    // Projection onto a parent compound.
    let atom_a = claim(&pool, &c, "ev cn: atom with a hidden parent").await;
    let hidden_parent = claim(&pool, &c, "ev cn: parent by a hidden edge").await;
    public_edge(&pool, center, atom_a, "supports").await;
    hidden(&pool, &c, hidden_parent, atom_a, "decomposes_to").await;
    let atom_b = claim(&pool, &c, "ev cn: atom with my parent").await;
    let my_parent = claim(&pool, &c, "ev cn: parent by my edge").await;
    public_edge(&pool, center, atom_b, "supports").await;
    mine(&pool, &c, my_parent, atom_b, "decomposes_to").await;

    let rows = GraphViewRepository::compound_neighbors(&pool, &c.viewer, center, 50)
        .await
        .expect("compound_neighbors");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();

    assert!(
        ids.contains(&behind_mine),
        "CALIBRATION: a neighbour reached by the viewer's own edge must be served; got {ids:?}"
    );
    assert!(
        !ids.contains(&behind_hidden),
        "a neighbour reached only through a hidden epistemic edge must be ABSENT; got {ids:?}"
    );
    assert!(
        ids.contains(&my_parent) && !ids.contains(&atom_b),
        "CALIBRATION: an atom whose parent edge the viewer can read projects onto that \
         parent; got {ids:?}"
    );
    assert!(
        ids.contains(&atom_a) && !ids.contains(&hidden_parent),
        "an atom whose only parent edge is hidden must stand as itself, not project onto \
         the hidden parent; got {ids:?}"
    );
}

/// A centre whose only `decomposes_to` child edge is hidden is walked as a
/// standalone claim: its own edges are followed, and the hidden child's are not.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_treat_a_centre_with_only_hidden_children_as_standalone(pool: PgPool) {
    let c = cast(&pool, "ev-cnc").await;
    let center = claim(&pool, &c, "ev cnc: centre").await;
    let child = claim(&pool, &c, "ev cnc: child by a hidden edge").await;
    hidden(&pool, &c, center, child, "decomposes_to").await;
    let via_child = claim(&pool, &c, "ev cnc: neighbour of the hidden child").await;
    let via_center = claim(&pool, &c, "ev cnc: neighbour of the centre").await;
    public_edge(&pool, child, via_child, "supports").await;
    public_edge(&pool, center, via_center, "supports").await;

    let rows = GraphViewRepository::compound_neighbors(&pool, &c.viewer, center, 50)
        .await
        .expect("compound_neighbors");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert!(
        ids.contains(&via_center),
        "the centre has no child the viewer can see, so its own edges are walked; got {ids:?}"
    );
    assert!(
        !ids.contains(&via_child),
        "the hidden child's neighbours must not be reachable; got {ids:?}"
    );

    // CALIBRATION: the same shape with the child edge private to the viewer's
    // own group walks the child and not the centre.
    let c2 = claim(&pool, &c, "ev cnc: second centre").await;
    let child2 = claim(&pool, &c, "ev cnc: child by my edge").await;
    mine(&pool, &c, c2, child2, "decomposes_to").await;
    let via_child2 = claim(&pool, &c, "ev cnc: neighbour of my child").await;
    let via_c2 = claim(&pool, &c, "ev cnc: neighbour of the second centre").await;
    public_edge(&pool, child2, via_child2, "supports").await;
    public_edge(&pool, c2, via_c2, "supports").await;
    let rows = GraphViewRepository::compound_neighbors(&pool, &c.viewer, c2, 50)
        .await
        .expect("compound_neighbors");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert!(
        ids.contains(&via_child2) && !ids.contains(&via_c2),
        "CALIBRATION: a centre with a child the viewer can see is walked through that \
         child; got {ids:?}"
    );
}

//! `F-edges-unfiltered`: the `edges` traversals that never carried a viewer
//! predicate of their own.
//!
//! # The fixture shape every test here uses, and why
//!
//! Endpoint filtering is not edge filtering. Migration 070 arm (b) KEEPS an edge
//! explicitly declared `('group', G)` between two PUBLIC endpoints, so the
//! interesting edge in each fixture joins claims the stranger CAN read and is
//! itself private. Every claims-side predicate therefore passes it, and the only
//! thing that can stop it reaching a stranger is a predicate on the edge.
//!
//! The private edges are forced with an `UPDATE` after the INSERT, exactly as
//! `viewer_fixture::seed_edge_owned_by` does and for the reason its doc gives:
//! 070's trigger fires on `INSERT OR UPDATE OF source_id, target_id` only, so an
//! `UPDATE` touching the tenancy columns alone is left as written.
//!
//! # Every negative assertion has a positive counterpart
//!
//! "A stranger does not see X" is satisfied by a statement that returns nothing
//! to anybody. Each test asserts the OWNER (a live member of the edge's group)
//! does see it on the same fixture, and the bypass viewer where the statement's
//! behaviour under `Bypass` is not obvious from the fragment (`" "`).

#![allow(clippy::too_many_lines)]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::GraphViewRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// An owner (member of `group`), a stranger (member of its own, unrelated
/// personal group), and the owner's agent id for seeding claims.
struct Tenants {
    agent: Uuid,
    group: Uuid,
    owner: Viewer,
    stranger: Viewer,
}

async fn tenants(pool: &PgPool) -> Tenants {
    let (agent, group) = fixture::seed_agent_with_group(pool, "edge-owner").await;
    let (stranger_agent, _g) = fixture::seed_agent_with_group(pool, "edge-stranger").await;
    Tenants {
        agent,
        group,
        owner: Viewer::resolve(pool, agent).await.expect("owner viewer"),
        stranger: Viewer::resolve(pool, stranger_agent)
            .await
            .expect("stranger viewer"),
    }
}

/// A claim→claim edge, left as 070's trigger stamps it (the meet of its
/// endpoints — public between two public claims).
async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
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
    id
}

/// [`edge`], then force it `('group', group)` with no co-owner.
async fn private_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    group: Uuid,
) -> Uuid {
    let id = edge(pool, source, target, relationship).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(group)
    .execute(pool)
    .await
    .expect("privatise edge");
    id
}

async fn public_claims(pool: &PgPool, agent: Uuid, labels: &[&str]) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(labels.len());
    for l in labels {
        out.push(fixture::seed_public_claim(pool, agent, l).await);
    }
    out
}

/// A completed cluster run with one cluster whose (public) members are
/// `members`. Returns `(cluster_id, run_id)`.
async fn cluster(pool: &PgPool, members: &[Uuid]) -> (Uuid, Uuid) {
    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES ($1, 1)")
        .bind(run_id)
        .execute(pool)
        .await
        .expect("seed cluster run");
    sqlx::query("INSERT INTO graph_clusters (id, run_id, label, size) VALUES ($1, $2, 'c', $3)")
        .bind(cluster_id)
        .bind(run_id)
        .bind(i32::try_from(members.len()).expect("small"))
        .execute(pool)
        .await
        .expect("seed cluster");
    for m in members {
        sqlx::query(
            "INSERT INTO claim_cluster_membership \
               (claim_id, cluster_id, run_id, owner_group_id, visibility) \
             VALUES ($1, $2, $3, '00000000-0000-0000-0000-000000000000'::uuid, 'public')",
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

/// A neighborhood in a fresh run whose (public) members are `members`.
async fn neighborhood(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let run_id = Uuid::new_v4();
    let neighborhood_id = Uuid::new_v4();
    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description) VALUES ($1, 'ev', 'fixture')")
        .bind(theme_id)
        .execute(pool)
        .await
        .expect("seed theme");
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES ($1, 1)")
        .bind(run_id)
        .execute(pool)
        .await
        .expect("seed cluster run");
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size) \
         VALUES ($1, $2, $3, 'ev', $4)",
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .bind(i32::try_from(members.len()).expect("small"))
    .execute(pool)
    .await
    .expect("seed neighborhood");
    for m in members {
        sqlx::query(
            "INSERT INTO claim_neighborhood_membership \
               (run_id, claim_id, neighborhood_id, owner_group_id, visibility) \
             VALUES ($1, $2, $3, '00000000-0000-0000-0000-000000000000'::uuid, 'public')",
        )
        .bind(run_id)
        .bind(m)
        .bind(neighborhood_id)
        .execute(pool)
        .await
        .expect("seed neighborhood membership");
    }
    neighborhood_id
}

// ── expand_cluster_nodes ────────────────────────────────────────────────────

/// The degree ORDER BY decides which members a small `budget` returns, so an
/// unfiltered degree lets private edges choose what a stranger is shown.
#[sqlx::test(migrations = "../../migrations")]
async fn expand_cluster_nodes_orders_by_the_degree_the_viewer_can_see(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["X", "Y", "O1", "O2", "O3"]).await;
    let (x, y) = (ids[0], ids[1]);
    edge(&pool, x, ids[2], "supports").await;
    for o in &ids[2..] {
        private_edge(&pool, y, *o, "supports", t.group).await;
    }
    let (cluster_id, run_id) = cluster(&pool, &[x, y]).await;
    let rels = vec!["supports".to_string()];

    let first = |rows: Vec<epigraph_db::GraphNodeRow>| rows.first().map(|r| r.id);

    let owner =
        GraphViewRepository::expand_cluster_nodes(&pool, &t.owner, cluster_id, run_id, &rels, 1)
            .await
            .expect("owner expand");
    assert_eq!(
        first(owner),
        Some(y),
        "the owner reads Y's three private edges, so Y (degree 3) outranks X (degree 1)"
    );

    let stranger =
        GraphViewRepository::expand_cluster_nodes(&pool, &t.stranger, cluster_id, run_id, &rels, 1)
            .await
            .expect("stranger expand");
    assert_eq!(
        first(stranger),
        Some(x),
        "for a stranger Y's degree is 0 — its three edges are group-private even \
         though every endpoint is public — so X must win the single budget slot"
    );

    // Both members still come back with a larger budget: the predicate lives in
    // the LEFT JOIN's ON, so a degree-0 member is kept, not dropped.
    let stranger_all = GraphViewRepository::expand_cluster_nodes(
        &pool,
        &t.stranger,
        cluster_id,
        run_id,
        &rels,
        10,
    )
    .await
    .expect("stranger expand, full budget");
    let mut got: Vec<Uuid> = stranger_all.iter().map(|r| r.id).collect();
    got.sort();
    let mut want = vec![x, y];
    want.sort();
    assert_eq!(
        got, want,
        "a member whose every edge is hidden must still be listed (degree 0); \
         a WHERE-placed predicate would have dropped it"
    );

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let sys =
        GraphViewRepository::expand_cluster_nodes(&pool, &bypass, cluster_id, run_id, &rels, 1)
            .await
            .expect("bypass expand");
    assert_eq!(first(sys), Some(y), "the bypass viewer counts every edge");
}

// ── neighborhood_compound_nodes ─────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_nodes_counts_and_classifies_over_visible_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["compound P", "atom a1", "atom a2"]).await;
    let (p, a1, a2) = (ids[0], ids[1], ids[2]);
    private_edge(&pool, p, a1, "decomposes_to", t.group).await;
    edge(&pool, p, a2, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[a1, a2]).await;

    let summarise = |rows: Vec<epigraph_db::CompoundNodeRow>| {
        let mut v: Vec<(Uuid, String, i32)> = rows
            .into_iter()
            .map(|r| (r.id, r.kind, r.atom_count))
            .collect();
        v.sort();
        v
    };

    let owner = summarise(
        GraphViewRepository::neighborhood_compound_nodes(&pool, &t.owner, nbhd)
            .await
            .expect("owner compound nodes"),
    );
    assert_eq!(
        owner,
        vec![(p, "compound".to_string(), 2)],
        "the owner reads both decomposes_to edges: P owns two atoms and neither \
         atom is standalone"
    );

    let stranger = summarise(
        GraphViewRepository::neighborhood_compound_nodes(&pool, &t.stranger, nbhd)
            .await
            .expect("stranger compound nodes"),
    );
    let mut want = vec![
        (p, "compound".to_string(), 1),
        (a1, "standalone".to_string(), 0),
    ];
    want.sort();
    assert_eq!(
        stranger, want,
        "a stranger must count only the public decomposes_to edge (atom_count 1, \
         not 2), and a1 — whose only parent edge is private — must render as a \
         standalone rather than vanish; vanishing from the compound view while \
         present in the atomic view would betray the hidden edge"
    );
}

// ── neighborhood_atomic_nodes ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_nodes_resolves_compound_id_over_visible_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["compound P", "atom a1", "atom a2"]).await;
    let (p, a1, a2) = (ids[0], ids[1], ids[2]);
    private_edge(&pool, p, a1, "decomposes_to", t.group).await;
    edge(&pool, p, a2, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[a1, a2]).await;

    let parent_of = |rows: &[epigraph_db::AtomicNodeRow], id: Uuid| {
        rows.iter()
            .find(|r| r.id == id)
            .map(|r| r.compound_id)
            .expect("member present")
    };

    let owner = GraphViewRepository::neighborhood_atomic_nodes(&pool, &t.owner, nbhd)
        .await
        .expect("owner atomic nodes");
    assert_eq!(parent_of(&owner, a1), Some(p), "the owner sees a1's parent");
    assert_eq!(parent_of(&owner, a2), Some(p));

    let stranger = GraphViewRepository::neighborhood_atomic_nodes(&pool, &t.stranger, nbhd)
        .await
        .expect("stranger atomic nodes");
    assert_eq!(
        parent_of(&stranger, a1),
        None,
        "a1's only parent edge is group-private: its compound_id must not name P"
    );
    assert_eq!(
        parent_of(&stranger, a2),
        Some(p),
        "a2's parent edge is public and must still resolve"
    );
}

// ── neighborhood_compound_groups ────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_groups_aggregates_only_visible_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(
        &pool,
        t.agent,
        &["compound P", "atom a1", "atom a2", "compound Q", "atom q1"],
    )
    .await;
    let (p, a1, a2, q, q1) = (ids[0], ids[1], ids[2], ids[3], ids[4]);
    private_edge(&pool, p, a1, "decomposes_to", t.group).await;
    edge(&pool, p, a2, "decomposes_to").await;
    private_edge(&pool, q, q1, "decomposes_to", t.group).await;
    let nbhd = neighborhood(&pool, &[a1, a2, q1]).await;

    let groups = |rows: Vec<epigraph_db::CompoundGroupRow>| {
        let mut v: Vec<(Uuid, Vec<Uuid>)> = rows
            .into_iter()
            .map(|r| {
                let mut m = r.member_atom_ids;
                m.sort();
                (r.compound_id, m)
            })
            .collect();
        v.sort();
        v
    };

    let owner = groups(
        GraphViewRepository::neighborhood_compound_groups(&pool, &t.owner, nbhd)
            .await
            .expect("owner groups"),
    );
    let mut pa = vec![a1, a2];
    pa.sort();
    let mut want_owner = vec![(p, pa), (q, vec![q1])];
    want_owner.sort();
    assert_eq!(owner, want_owner, "the owner sees every grouping");

    let stranger = groups(
        GraphViewRepository::neighborhood_compound_groups(&pool, &t.stranger, nbhd)
            .await
            .expect("stranger groups"),
    );
    assert_eq!(
        stranger,
        vec![(p, vec![a2])],
        "a stranger must see P with only its publicly-linked atom, and Q — whose \
         only child edge is private — not at all"
    );
}

// ── compound_neighbors ──────────────────────────────────────────────────────

/// Centre C decomposes (publicly) to atom ca. From ca:
///   * a PRIVATE `supports` edge to oa1, whose parent OC1 is public-linked;
///   * a public `supports` edge to oa2, whose parent edge from OC2 is PRIVATE.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_walks_and_projects_only_visible_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(
        &pool,
        t.agent,
        &[
            "centre C",
            "atom ca",
            "atom oa1",
            "compound OC1",
            "atom oa2",
            "compound OC2",
        ],
    )
    .await;
    let (c, ca, oa1, oc1, oa2, oc2) = (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    edge(&pool, c, ca, "decomposes_to").await;
    private_edge(&pool, ca, oa1, "supports", t.group).await;
    edge(&pool, oc1, oa1, "decomposes_to").await;
    edge(&pool, ca, oa2, "supports").await;
    private_edge(&pool, oc2, oa2, "decomposes_to", t.group).await;

    let neighbours = |rows: Vec<epigraph_db::CompoundNeighborRow>| {
        let mut v: Vec<(Uuid, String, i64)> = rows
            .into_iter()
            .map(|r| (r.id, r.relationship, r.atom_edge_count))
            .collect();
        v.sort();
        v
    };

    let owner = neighbours(
        GraphViewRepository::compound_neighbors(&pool, &t.owner, c, 10)
            .await
            .expect("owner neighbours"),
    );
    let mut want_owner = vec![
        (oc1, "supports".to_string(), 1),
        (oc2, "supports".to_string(), 1),
    ];
    want_owner.sort();
    assert_eq!(
        owner, want_owner,
        "the owner walks both edges to both compounds"
    );

    let stranger = neighbours(
        GraphViewRepository::compound_neighbors(&pool, &t.stranger, c, 10)
            .await
            .expect("stranger neighbours"),
    );
    assert_eq!(
        stranger,
        vec![(oa2, "supports".to_string(), 1)],
        "a stranger must not walk the private ca→oa1 edge (so OC1 is absent), and \
         must not resolve oa2 through its private parent edge — the LEFT JOIN falls \
         back to oa2 itself, a claim the stranger can already read"
    );

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let sys = neighbours(
        GraphViewRepository::compound_neighbors(&pool, &bypass, c, 10)
            .await
            .expect("bypass neighbours"),
    );
    assert_eq!(
        sys, want_owner,
        "the bypass viewer sees exactly what the owner does"
    );
}

/// `center_atoms`' `NOT EXISTS` is filtered: a centre whose only child edge is
/// private is walked as a standalone by a stranger. The owner walks the child,
/// which has no epistemic edges, and so sees nothing — the two views differ in
/// SHAPE, and neither discloses anything the viewer may not read.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_treats_a_centre_with_only_private_children_as_standalone(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["centre C", "child ca", "neighbour n"]).await;
    let (c, ca, n) = (ids[0], ids[1], ids[2]);
    private_edge(&pool, c, ca, "decomposes_to", t.group).await;
    edge(&pool, c, n, "supports").await;

    let owner = GraphViewRepository::compound_neighbors(&pool, &t.owner, c, 10)
        .await
        .expect("owner neighbours");
    assert!(
        owner.is_empty(),
        "the owner sees C's child and walks from it; the child has no epistemic \
         edges. Got {owner:?}"
    );

    let stranger = GraphViewRepository::compound_neighbors(&pool, &t.stranger, c, 10)
        .await
        .expect("stranger neighbours");
    let got: Vec<Uuid> = stranger.iter().map(|r| r.id).collect();
    assert_eq!(
        got,
        vec![n],
        "for a stranger C has no visible children, so C is walked as its own atom \
         and its public supports edge to n is found"
    );
}

// ── F-atom-count-cardinality ────────────────────────────────────────────────

/// `atom_count` must not count an atom whose own claims row the viewer cannot
/// read, EVEN WHEN the edge to it is readable.
///
/// This pins why `F-atom-count-cardinality` is closed WITHOUT a claims join on
/// the `atoms` CTE. The register entry reasoned that `{VISIBILITY:m}` is inert
/// because `claim_neighborhood_membership.visibility` "defaults to 'public'".
/// That premise predates migration 070: the table is in arm (c)'s
/// `inheritors` array, whose stamp is UNCONDITIONAL, so a membership row takes
/// its claim's `(visibility, owner_group_id)` whatever the writer declared —
/// and arm (d) re-stamps it when the claim's tenancy changes. `{VISIBILITY:m}`
/// is therefore a predicate on the atom's claims row by construction.
///
/// The fixture breaks the OTHER layer to prove it: the edge to the private atom
/// is forced `('public', world)` — a state 070/072 never produce — so the edge
/// predicate cannot be what hides the atom, and the membership row is declared
/// `'public'` on INSERT, which arm (c) overwrites. Measured while writing this:
/// additionally forcing the MEMBERSHIP row public by a bare `UPDATE` (which no
/// trigger re-stamps) makes the stranger's count 2 — so the assertion below is
/// reading the inheritance, not an empty corpus.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_nodes_atom_count_excludes_unreadable_atoms(pool: PgPool) {
    let t = tenants(&pool).await;
    let p = fixture::seed_public_claim(&pool, t.agent, "compound P").await;
    let a_pub = fixture::seed_public_claim(&pool, t.agent, "public atom").await;
    let a_priv = fixture::seed_group_claim(&pool, t.agent, t.group, "private atom").await;
    edge(&pool, p, a_pub, "decomposes_to").await;
    let world = fixture::world_group(&pool).await;
    let forced = edge(&pool, p, a_priv, "decomposes_to").await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(forced)
    .bind(world)
    .execute(&pool)
    .await
    .expect("force the edge public");
    // Both memberships are DECLARED public; arm (c) re-stamps a_priv's.
    let nbhd = neighborhood(&pool, &[a_pub, a_priv]).await;

    let count_for = |rows: &[epigraph_db::CompoundNodeRow]| {
        rows.iter()
            .find(|r| r.id == p)
            .map(|r| r.atom_count)
            .expect("P is a compound")
    };

    let owner = GraphViewRepository::neighborhood_compound_nodes(&pool, &t.owner, nbhd)
        .await
        .expect("owner compound nodes");
    assert_eq!(count_for(&owner), 2, "the owner reads both atoms");

    let stranger = GraphViewRepository::neighborhood_compound_nodes(&pool, &t.stranger, nbhd)
        .await
        .expect("stranger compound nodes");
    assert_eq!(
        count_for(&stranger),
        1,
        "a stranger must not learn that P decomposes into an atom it cannot read"
    );
}

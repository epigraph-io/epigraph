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

// ── ClaimRepository::semantic_graph_neighbors / rag_hybrid_context ─────────

/// A 1536-d pgvector literal with every component `v` (the `embedding` column's
/// dimension; `embedding_3072` is not touched by these reads' default path).
fn unit_ish(v: f32) -> String {
    let body: Vec<String> = (0..1536).map(|_| v.to_string()).collect();
    format!("[{}]", body.join(","))
}

/// The strongest member of the finding: this projects `e.source_id`,
/// `e.target_id` and `e.relationship`, so a private `contradicts` between two
/// public claims reached a stranger as a fully-labelled, directed edge.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_graph_neighbors_hides_a_private_edge_between_public_claims(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(
        &pool,
        t.agent,
        &["seed S", "private-out N1", "public-out N2", "private-in N3"],
    )
    .await;
    let (s, n1, n2, n3) = (ids[0], ids[1], ids[2], ids[3]);
    let v = unit_ish(0.5);
    for c in &ids {
        fixture::set_claim_embedding(&pool, *c, &v).await;
    }
    private_edge(&pool, s, n1, "contradicts", t.group).await;
    edge(&pool, s, n2, "supports").await;
    private_edge(&pool, n3, s, "refines", t.group).await;

    let seen = |rows: Vec<epigraph_db::repos::claim::SemanticNeighborHit>| {
        let mut v: Vec<(Uuid, String, String)> = rows
            .into_iter()
            .map(|r| (r.neighbor_id, r.relationship, r.direction))
            .collect();
        v.sort();
        v
    };

    let owner = seen(
        epigraph_db::ClaimRepository::semantic_graph_neighbors(
            &pool,
            &t.owner,
            "embedding",
            &v,
            &[s],
        )
        .await
        .expect("owner neighbours"),
    );
    let mut want_owner = vec![
        (n1, "contradicts".to_string(), "outbound".to_string()),
        (n2, "supports".to_string(), "outbound".to_string()),
        (n3, "refines".to_string(), "inbound".to_string()),
    ];
    want_owner.sort();
    assert_eq!(owner, want_owner, "the owner reads all three edges");

    let stranger = seen(
        epigraph_db::ClaimRepository::semantic_graph_neighbors(
            &pool,
            &t.stranger,
            "embedding",
            &v,
            &[s],
        )
        .await
        .expect("stranger neighbours"),
    );
    assert_eq!(
        stranger,
        vec![(n2, "supports".to_string(), "outbound".to_string())],
        "every endpoint is public; only the edge predicate can withhold the private \
         `contradicts` (outbound) and `refines` (inbound) edges"
    );
}

/// `edge_count` is a returned scalar AND a ranking input. The fixture puts
/// private edges on BOTH sides of the claim, because the statement's
/// `source_id = c.id OR target_id = c.id` needs parenthesising for the spliced
/// `AND (...)` to govern both arms — `AND` binds tighter than `OR`, and a
/// one-sided fixture would pass the unparenthesised fail-open.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_hybrid_context_edge_count_counts_only_readable_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["R", "A", "B", "C"]).await;
    let (r, a, b, c) = (ids[0], ids[1], ids[2], ids[3]);
    let private_claim = fixture::seed_group_claim(&pool, t.agent, t.group, "P").await;
    let v = unit_ish(0.5);
    fixture::set_claim_embedding(&pool, r, &v).await;
    sqlx::query("UPDATE claims SET truth_value = 0.9 WHERE id = $1")
        .bind(r)
        .execute(&pool)
        .await
        .expect("truth");

    edge(&pool, r, a, "supports").await; // public
    private_edge(&pool, r, b, "contradicts", t.group).await; // declared private, source side
    private_edge(&pool, c, r, "refines", t.group).await; // declared private, target side
    edge(&pool, r, private_claim, "supports").await; // private by the meet (070 arm (b))

    let count_for = |hits: Vec<epigraph_db::repos::claim::RagContextHit>| {
        hits.into_iter()
            .find(|h| h.claim_id == r)
            .map(|h| h.edge_count)
            .expect("R is retrieved")
    };

    let owner = count_for(
        epigraph_db::ClaimRepository::rag_hybrid_context(&pool, &t.owner, &v, 0.0, None, 10)
            .await
            .expect("owner rag"),
    );
    assert_eq!(owner, 4, "the owner reads all four edges");

    let stranger = count_for(
        epigraph_db::ClaimRepository::rag_hybrid_context(&pool, &t.stranger, &v, 0.0, None, 10)
            .await
            .expect("stranger rag"),
    );
    assert_eq!(
        stranger, 1,
        "a stranger's degree for R must count only the one public edge — not the \
         two declared-private ones (one per side) nor the one to a claim it \
         cannot read"
    );

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let sys = count_for(
        epigraph_db::ClaimRepository::rag_hybrid_context(&pool, &bypass, &v, 0.0, None, 10)
            .await
            .expect("bypass rag"),
    );
    assert_eq!(sys, 4, "the bypass viewer counts every edge");
}

// ── cluster_subgraph_edges (was routes/graph.rs::fetch_subgraph_edges) ─────

/// The route's module doc argued this read "needs no predicate of its own"
/// because both endpoints come from the viewer-filtered node set. The fixture
/// is the counterexample: every node is public, and the `contradicts` edge
/// between two of them is not.
#[sqlx::test(migrations = "../../migrations")]
async fn cluster_subgraph_edges_withholds_a_private_edge_between_visible_nodes(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["A", "B", "C"]).await;
    let (a, b, c) = (ids[0], ids[1], ids[2]);
    edge(&pool, a, b, "supports").await;
    private_edge(&pool, a, c, "contradicts", t.group).await;
    edge(&pool, b, c, "same_source").await; // outside the allowlist
    let allow = vec!["supports".to_string(), "contradicts".to_string()];

    let shape = |rows: Vec<epigraph_db::ClusterSubgraphEdgeRow>| {
        let mut v: Vec<(Uuid, Uuid, String, bool)> = rows
            .into_iter()
            .map(|r| (r.source_id, r.target_id, r.relationship, r.is_allowed))
            .collect();
        v.sort();
        v
    };

    let owner = shape(
        GraphViewRepository::cluster_subgraph_edges(&pool, &t.owner, &ids, Some(&allow))
            .await
            .expect("owner edges"),
    );
    let mut want_owner = vec![
        (a, b, "supports".to_string(), true),
        (a, c, "contradicts".to_string(), true),
        (b, c, "same_source".to_string(), false),
    ];
    want_owner.sort();
    assert_eq!(owner, want_owner, "the owner reads all three edges");

    let stranger = shape(
        GraphViewRepository::cluster_subgraph_edges(&pool, &t.stranger, &ids, Some(&allow))
            .await
            .expect("stranger edges"),
    );
    let mut want_stranger = vec![
        (a, b, "supports".to_string(), true),
        (b, c, "same_source".to_string(), false),
    ];
    want_stranger.sort();
    assert_eq!(
        stranger, want_stranger,
        "all three endpoints are visible to the stranger, and the private \
         `contradicts` edge between two of them must still be withheld — from \
         edges[] AND from filtered_edge_count"
    );

    // `None` = no allowlist: every readable edge is allowed, the private one
    // still absent.
    let stranger_all = shape(
        GraphViewRepository::cluster_subgraph_edges(&pool, &t.stranger, &ids, None)
            .await
            .expect("stranger edges, no allowlist"),
    );
    assert!(
        stranger_all.iter().all(|r| r.3) && stranger_all.len() == 2,
        "with no allowlist every returned edge is allowed and the private one is \
         still withheld: {stranger_all:?}"
    );
}

// ── neighborhood edge projections (were inline in routes/graph_neighborhood.rs) ─

/// Compounds P and Q (public), each decomposing (publicly) into two
/// neighborhood atoms: P→{a1,a2}, Q→{b1,b2}. Between the atoms: a1→b1 public
/// `supports`, a2→b2 PRIVATE `supports`. Between the compounds: P→Q public
/// `refines` and P→Q PRIVATE `contradicts`.
struct Nbhd {
    id: Uuid,
    p: Uuid,
    q: Uuid,
    a1: Uuid,
    b1: Uuid,
}

async fn two_compound_neighborhood(pool: &PgPool, t: &Tenants) -> Nbhd {
    let ids = public_claims(pool, t.agent, &["P", "Q", "a1", "a2", "b1", "b2"]).await;
    let (p, q, a1, a2, b1, b2) = (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    for (parent, atom) in [(p, a1), (p, a2), (q, b1), (q, b2)] {
        edge(pool, parent, atom, "decomposes_to").await;
    }
    edge(pool, a1, b1, "supports").await;
    private_edge(pool, a2, b2, "supports", t.group).await;
    edge(pool, p, q, "refines").await;
    private_edge(pool, p, q, "contradicts", t.group).await;
    let id = neighborhood(pool, &[a1, a2, b1, b2]).await;
    Nbhd { id, p, q, a1, b1 }
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_induced_edges_aggregate_only_readable_atom_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let n = two_compound_neighborhood(&pool, &t).await;

    let shape = |rows: Vec<epigraph_db::InducedEdgeRow>| {
        rows.into_iter()
            .map(|r| (r.source, r.target, r.relationship, r.atom_edge_count))
            .collect::<Vec<_>>()
    };

    let owner = shape(
        GraphViewRepository::neighborhood_induced_edges(&pool, &t.owner, n.id)
            .await
            .expect("owner induced"),
    );
    assert_eq!(
        owner,
        vec![(n.p, n.q, "supports".to_string(), 2)],
        "the owner's P→Q induced edge aggregates both atom edges"
    );

    let stranger = shape(
        GraphViewRepository::neighborhood_induced_edges(&pool, &t.stranger, n.id)
            .await
            .expect("stranger induced"),
    );
    assert_eq!(
        stranger,
        vec![(n.p, n.q, "supports".to_string(), 1)],
        "the private a2→b2 edge must not add to the stranger's atom_edge_count \
         (or its strength) — the filter must run before the GROUP BY"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_direct_edges_withhold_a_private_edge_between_displayed_compounds(
    pool: PgPool,
) {
    let t = tenants(&pool).await;
    let n = two_compound_neighborhood(&pool, &t).await;

    let rels = |rows: Vec<epigraph_db::NeighborhoodEdgeRow>| {
        let mut v: Vec<(Uuid, Uuid, String)> = rows
            .into_iter()
            .map(|r| (r.source_id, r.target_id, r.relationship))
            .collect();
        v.sort();
        v
    };

    let owner = rels(
        GraphViewRepository::neighborhood_direct_edges(&pool, &t.owner, n.id)
            .await
            .expect("owner direct"),
    );
    let mut want_owner = vec![
        (n.p, n.q, "contradicts".to_string()),
        (n.p, n.q, "refines".to_string()),
    ];
    want_owner.sort();
    assert_eq!(
        owner, want_owner,
        "the owner sees both compound→compound edges"
    );

    let stranger = rels(
        GraphViewRepository::neighborhood_direct_edges(&pool, &t.stranger, n.id)
            .await
            .expect("stranger direct"),
    );
    assert_eq!(
        stranger,
        vec![(n.p, n.q, "refines".to_string())],
        "P and Q are both displayed to the stranger; the private `contradicts` \
         between them must still be withheld"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_edges_withhold_a_private_edge_between_visible_members(pool: PgPool) {
    let t = tenants(&pool).await;
    let n = two_compound_neighborhood(&pool, &t).await;

    let count = |rows: &[epigraph_db::NeighborhoodEdgeRow]| rows.len();
    let owner = GraphViewRepository::neighborhood_atomic_edges(&pool, &t.owner, n.id)
        .await
        .expect("owner atomic edges");
    assert_eq!(count(&owner), 2, "the owner sees both atom edges");

    let stranger = GraphViewRepository::neighborhood_atomic_edges(&pool, &t.stranger, n.id)
        .await
        .expect("stranger atomic edges");
    let got: Vec<(Uuid, Uuid)> = stranger
        .iter()
        .map(|r| (r.source_id, r.target_id))
        .collect();
    assert_eq!(
        got,
        vec![(n.a1, n.b1)],
        "only the public a1→b1 edge reaches the stranger"
    );
}

/// Structural links are DERIVED from `decomposes_to` edges; a private one must
/// not manufacture a link the stranger can read.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_structural_edges_are_derived_only_from_readable_edges(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(
        &pool,
        t.agent,
        &["P", "Q", "shared atom s", "p-atom", "q-atom", "R"],
    )
    .await;
    let (p, q, s, pa, qa, r) = (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    // Both compounds are in the neighborhood through a public child each.
    edge(&pool, p, pa, "decomposes_to").await;
    edge(&pool, q, qa, "decomposes_to").await;
    // shared_atom: P publicly, Q privately, parent s.
    edge(&pool, p, s, "decomposes_to").await;
    private_edge(&pool, q, s, "decomposes_to", t.group).await;
    // shared_ancestor: R publicly parents P, privately parents Q.
    edge(&pool, r, p, "decomposes_to").await;
    private_edge(&pool, r, q, "decomposes_to", t.group).await;
    let nbhd = neighborhood(&pool, &[s, pa, qa]).await;

    let kinds = |rows: Vec<epigraph_db::StructuralEdgeRow>| {
        let mut v: Vec<(String, i64)> = rows.into_iter().map(|r| (r.kind, r.atom_count)).collect();
        v.sort();
        v
    };

    let owner = kinds(
        GraphViewRepository::neighborhood_structural_edges(&pool, &t.owner, nbhd)
            .await
            .expect("owner structural"),
    );
    assert_eq!(
        owner,
        vec![
            ("shared_ancestor".to_string(), 1),
            ("shared_atom".to_string(), 1)
        ],
        "the owner reads both private decomposes_to edges, so both links exist"
    );

    let stranger = GraphViewRepository::neighborhood_structural_edges(&pool, &t.stranger, nbhd)
        .await
        .expect("stranger structural");
    assert!(
        stranger.is_empty(),
        "each link rests on one private decomposes_to edge; a stranger must get \
         neither. Got {stranger:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn decomposition_flags_ignore_edges_the_viewer_cannot_read(pool: PgPool) {
    let t = tenants(&pool).await;
    let ids = public_claims(&pool, t.agent, &["centre", "child", "parent"]).await;
    let (c, child, parent) = (ids[0], ids[1], ids[2]);
    private_edge(&pool, c, child, "decomposes_to", t.group).await;
    private_edge(&pool, parent, c, "decomposes_to", t.group).await;

    assert_eq!(
        GraphViewRepository::decomposition_flags(&pool, &t.owner, c)
            .await
            .expect("owner flags"),
        (true, true),
        "the owner reads both edges"
    );
    assert_eq!(
        GraphViewRepository::decomposition_flags(&pool, &t.stranger, c)
            .await
            .expect("stranger flags"),
        (false, false),
        "a stranger must see a standalone: reporting `compound`/`atom` would \
         confirm a decomposition edge it cannot read"
    );
}

// ── ClaimRepository::search_by_embedding_since's DOI filter ────────────────

/// The `paper_doi_filter` shape keeps a paragraph only if an `asserts` edge
/// ties it to that paper. A match through a PRIVATE attribution edge confirms
/// the hidden edge to whoever asked — the paragraph and the paper are public.
#[sqlx::test(migrations = "../../migrations")]
async fn search_by_embedding_doi_filter_ignores_a_private_attribution_edge(pool: PgPool) {
    let t = tenants(&pool).await;
    let para = fixture::seed_public_claim(&pool, t.agent, "attributed paragraph").await;
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || '{\"level\": 2}' \
         WHERE id = $1",
    )
    .bind(para)
    .execute(&pool)
    .await
    .expect("level 2");
    let v = unit_ish(0.5);
    fixture::set_claim_embedding(&pool, para, &v).await;
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0/doi-x', 't') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    let e: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts') RETURNING id",
    )
    .bind(paper)
    .bind(para)
    .fetch_one(&pool)
    .await
    .expect("asserts edge");
    sqlx::query("UPDATE edges SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(e)
        .bind(t.group)
        .execute(&pool)
        .await
        .expect("privatise asserts edge");

    let hits = |rows: Vec<epigraph_db::repos::claim::ClaimEmbeddingHit>| {
        rows.into_iter().map(|h| h.claim_id).collect::<Vec<_>>()
    };

    let owner = hits(
        epigraph_db::ClaimRepository::search_by_embedding_since(
            &pool,
            &t.owner,
            &v,
            1536,
            10,
            Some("10.0/doi-x"),
            None,
        )
        .await
        .expect("owner search"),
    );
    assert_eq!(owner, vec![para], "the owner reads the attribution edge");

    let stranger = hits(
        epigraph_db::ClaimRepository::search_by_embedding_since(
            &pool,
            &t.stranger,
            &v,
            1536,
            10,
            Some("10.0/doi-x"),
            None,
        )
        .await
        .expect("stranger search"),
    );
    assert!(
        stranger.is_empty(),
        "the only attribution to 10.0/doi-x is a private edge: the stranger's DOI \
         filter must not match through it. Got {stranger:?}"
    );

    // Without the DOI filter the paragraph itself is public and is returned.
    let unfiltered = hits(
        epigraph_db::ClaimRepository::search_by_embedding_since(
            &pool,
            &t.stranger,
            &v,
            1536,
            10,
            None,
            None,
        )
        .await
        .expect("stranger search, no DOI"),
    );
    assert_eq!(unfiltered, vec![para], "the paragraph itself is public");
}

// ── ClaimThemeRepository::claims_in_themes_at_dim_since's DOI filter ────────

/// A public level-2 paragraph in `theme`, embedded at `vec`, that a new paper
/// with `doi` `asserts`. Returns `(paragraph, asserts_edge)`.
async fn themed_attributed_paragraph(
    pool: &PgPool,
    agent: Uuid,
    theme: Uuid,
    vec: &str,
    doi: &str,
) -> (Uuid, Uuid) {
    let para = fixture::seed_public_claim(pool, agent, &format!("themed paragraph of {doi}")).await;
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || '{\"level\": 2}', \
         theme_id = $2 WHERE id = $1",
    )
    .bind(para)
    .bind(theme)
    .execute(pool)
    .await
    .expect("level 2 + theme");
    fixture::set_claim_embedding(pool, para, vec).await;
    let paper: Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 't') RETURNING id")
            .bind(doi)
            .fetch_one(pool)
            .await
            .expect("paper");
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts') RETURNING id",
    )
    .bind(paper)
    .bind(para)
    .fetch_one(pool)
    .await
    .expect("asserts edge");
    (para, edge)
}

/// `claims_in_themes_at_dim_since` over one theme, as sorted ids.
async fn theme_candidates(
    pool: &PgPool,
    viewer: &Viewer,
    theme: Uuid,
    vec: &str,
    doi: Option<&str>,
) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = epigraph_db::ClaimThemeRepository::claims_in_themes_at_dim_since(
        pool,
        viewer,
        &[theme],
        vec,
        10,
        1536,
        /*paragraph_only=*/ true,
        /*since=*/ None,
        doi,
    )
    .await
    .expect("theme candidates")
    .into_iter()
    .map(|(id, _, _)| id)
    .collect();
    ids.sort();
    ids
}

/// The diverse-retrieval candidate pull's `paper_doi` filter (deferred
/// commitment `paper-doi-filter-diverse`) mirrors the flat path's above: a
/// candidate survives only if an `asserts` edge the VIEWER can read ties it to
/// that paper.
///
/// Two public level-2 paragraphs share one theme. X is attributed to its paper
/// through a PRIVATE edge, Y through a public one. The owner's X-scoped pull
/// returns X and not Y (the filter narrows); the stranger's X-scoped pull
/// returns nothing (the hidden attribution does not match); the stranger's
/// Y-scoped pull returns Y (so the empty result above is the edge predicate,
/// not a filter that matches nothing); and the unscoped pull returns both.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_in_themes_doi_filter_narrows_and_ignores_a_private_attribution_edge(pool: PgPool) {
    let t = tenants(&pool).await;
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ('doi-theme', 't') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("theme");
    let v = unit_ish(0.5);

    let (para_x, private_attribution) =
        themed_attributed_paragraph(&pool, t.agent, theme, &v, "10.0/doi-tx").await;
    let (para_y, _) = themed_attributed_paragraph(&pool, t.agent, theme, &v, "10.0/doi-ty").await;
    sqlx::query("UPDATE edges SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(private_attribution)
        .bind(t.group)
        .execute(&pool)
        .await
        .expect("privatise asserts edge");

    assert_eq!(
        theme_candidates(&pool, &t.owner, theme, &v, Some("10.0/doi-tx")).await,
        vec![para_x],
        "the owner reads the private attribution edge, and the DOI filter drops the \
         other paper's paragraph from the same theme"
    );
    let stranger_x = theme_candidates(&pool, &t.stranger, theme, &v, Some("10.0/doi-tx")).await;
    assert!(
        stranger_x.is_empty(),
        "the only attribution to 10.0/doi-tx is a private edge: the stranger's DOI \
         filter must not match through it. Got {stranger_x:?}"
    );
    assert_eq!(
        theme_candidates(&pool, &t.stranger, theme, &v, Some("10.0/doi-ty")).await,
        vec![para_y],
        "a publicly attributed paragraph matches its DOI for the stranger too"
    );
    let mut both = vec![para_x, para_y];
    both.sort();
    assert_eq!(
        theme_candidates(&pool, &t.stranger, theme, &v, None).await,
        both,
        "unscoped, both public paragraphs are candidates"
    );
}

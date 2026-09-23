//! Display-tier reads hide RETRACTED edges.
//!
//! Edge removal is a retraction: MCP `delete_edge`, `DELETE /api/v1/edges/:id`,
//! the `mark_duplicate` collapse and match retire all set `valid_to` and keep
//! the row. `edge_retraction_enforcement.rs` pins that the belief-bearing reads
//! ignore such an edge; this file pins the display tier — the graph
//! visualisation projections in `GraphViewRepository` — which kept rendering a
//! deleted edge as live until the in-force predicate was added to every
//! `edges` alias there.
//!
//! # Fixture shape
//!
//! Every test builds a graph whose endpoints are all public claims, retracts
//! some edges through the production primitive (`EdgeRepository::retract`,
//! the same `UPDATE ... SET valid_to = now()` `retract_by_id` issues), and
//! leaves a sibling edge in force. Each negative assertion ("the retracted edge
//! is gone") therefore has a positive counterpart on the same fixture ("the
//! in-force sibling is still there"), so no assertion can pass on an empty
//! result.

#![allow(clippy::too_many_lines)]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::edge::EdgeRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::GraphViewRepository;
use sqlx::PgPool;
use uuid::Uuid;

struct World {
    agent: Uuid,
    viewer: Viewer,
}

async fn world(pool: &PgPool) -> World {
    let (agent, _group) = fixture::seed_agent_with_group(pool, "retraction-display").await;
    World {
        agent,
        viewer: fixture::public_viewer(pool).await,
    }
}

async fn claims(pool: &PgPool, agent: Uuid, labels: &[&str]) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(labels.len());
    for l in labels {
        out.push(fixture::seed_public_claim(pool, agent, l).await);
    }
    out
}

/// An in-force claim→claim edge.
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

/// [`edge`], then retract it through the production primitive.
async fn retracted(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = edge(pool, source, target, relationship).await;
    let closed = EdgeRepository::retract(pool, &[id]).await.expect("retract");
    assert_eq!(
        closed,
        vec![id],
        "fixture: the edge must actually be retracted"
    );
    id
}

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

// ── cluster expansion ───────────────────────────────────────────────────────

/// Y's three edges were deleted; X keeps one. The degree ORDER BY decides which
/// member a budget of 1 returns, so a retracted edge still counting would let
/// deleted structure choose what the explorer shows.
#[sqlx::test(migrations = "../../migrations")]
async fn expand_cluster_nodes_ranks_by_in_force_degree(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["X", "Y", "O1", "O2", "O3"]).await;
    let (x, y) = (ids[0], ids[1]);
    edge(&pool, x, ids[2], "supports").await;
    for o in &ids[2..] {
        retracted(&pool, y, *o, "supports").await;
    }
    let (cluster_id, run_id) = cluster(&pool, &[x, y]).await;
    let rels = vec!["supports".to_string()];

    let top =
        GraphViewRepository::expand_cluster_nodes(&pool, &w.viewer, cluster_id, run_id, &rels, 1)
            .await
            .expect("expand");
    assert_eq!(
        top.first().map(|r| r.id),
        Some(x),
        "Y's three edges are retracted, so its degree is 0 and X (degree 1) must \
         win the single budget slot"
    );

    let all =
        GraphViewRepository::expand_cluster_nodes(&pool, &w.viewer, cluster_id, run_id, &rels, 10)
            .await
            .expect("expand, full budget");
    assert_eq!(
        all.len(),
        2,
        "a member whose every edge is retracted is still a member (degree 0): the \
         predicate belongs in the LEFT JOIN's ON, not WHERE"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cluster_subgraph_edges_omit_a_retracted_edge(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["A", "B", "C"]).await;
    let (a, b, c) = (ids[0], ids[1], ids[2]);
    edge(&pool, a, b, "supports").await;
    retracted(&pool, a, c, "contradicts").await;

    let rows = GraphViewRepository::cluster_subgraph_edges(&pool, &w.viewer, &ids, None)
        .await
        .expect("cluster edges");
    let got: Vec<(Uuid, Uuid)> = rows.iter().map(|r| (r.source_id, r.target_id)).collect();
    assert_eq!(
        got,
        vec![(a, b)],
        "the in-force a→b edge is returned and the retracted a→c is not"
    );
}

// ── compound / atomic neighborhood views ───────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_nodes_ignore_a_retracted_decomposition(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["compound P", "atom a1", "atom a2"]).await;
    let (p, a1, a2) = (ids[0], ids[1], ids[2]);
    retracted(&pool, p, a1, "decomposes_to").await;
    edge(&pool, p, a2, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[a1, a2]).await;

    let mut got: Vec<(Uuid, String, i32)> =
        GraphViewRepository::neighborhood_compound_nodes(&pool, &w.viewer, nbhd)
            .await
            .expect("compound nodes")
            .into_iter()
            .map(|r| (r.id, r.kind, r.atom_count))
            .collect();
    got.sort();
    let mut want = vec![
        (p, "compound".to_string(), 1),
        (a1, "standalone".to_string(), 0),
    ];
    want.sort();
    assert_eq!(
        got, want,
        "P must count only its in-force child (atom_count 1), and a1 — whose only \
         parent edge was retracted — must render as standalone"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_nodes_do_not_resolve_a_retracted_parent(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["compound P", "atom a1", "atom a2"]).await;
    let (p, a1, a2) = (ids[0], ids[1], ids[2]);
    retracted(&pool, p, a1, "decomposes_to").await;
    edge(&pool, p, a2, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[a1, a2]).await;

    let rows = GraphViewRepository::neighborhood_atomic_nodes(&pool, &w.viewer, nbhd)
        .await
        .expect("atomic nodes");
    let parent = |id: Uuid| rows.iter().find(|r| r.id == id).map(|r| r.compound_id);
    assert_eq!(parent(a1), Some(None), "a1's only parent edge is retracted");
    assert_eq!(
        parent(a2),
        Some(Some(p)),
        "a2's in-force parent still resolves"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_compound_groups_aggregate_only_in_force_children(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(
        &pool,
        w.agent,
        &["compound P", "atom a1", "atom a2", "compound Q", "atom q1"],
    )
    .await;
    let (p, a1, a2, q, q1) = (ids[0], ids[1], ids[2], ids[3], ids[4]);
    retracted(&pool, p, a1, "decomposes_to").await;
    edge(&pool, p, a2, "decomposes_to").await;
    retracted(&pool, q, q1, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[a1, a2, q1]).await;

    let got: Vec<(Uuid, Vec<Uuid>)> =
        GraphViewRepository::neighborhood_compound_groups(&pool, &w.viewer, nbhd)
            .await
            .expect("groups")
            .into_iter()
            .map(|r| (r.compound_id, r.member_atom_ids))
            .collect();
    assert_eq!(
        got,
        vec![(p, vec![a2])],
        "P groups only its in-force child, and Q — whose only child edge is \
         retracted — is not a compound at all"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_do_not_walk_a_retracted_edge(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["centre C", "atom ca", "n live", "n gone"]).await;
    let (c, ca, live, gone) = (ids[0], ids[1], ids[2], ids[3]);
    edge(&pool, c, ca, "decomposes_to").await;
    edge(&pool, ca, live, "supports").await;
    retracted(&pool, ca, gone, "supports").await;

    let got: Vec<Uuid> = GraphViewRepository::compound_neighbors(&pool, &w.viewer, c, 10)
        .await
        .expect("neighbours")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        got,
        vec![live],
        "the in-force supports edge is walked and the retracted one is not"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighbors_walk_a_centre_whose_children_were_retracted_as_standalone(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["centre C", "child ca", "neighbour n"]).await;
    let (c, ca, n) = (ids[0], ids[1], ids[2]);
    retracted(&pool, c, ca, "decomposes_to").await;
    edge(&pool, c, n, "supports").await;

    let got: Vec<Uuid> = GraphViewRepository::compound_neighbors(&pool, &w.viewer, c, 10)
        .await
        .expect("neighbours")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        got,
        vec![n],
        "C's only child edge is retracted, so C is walked as its own atom and its \
         in-force supports edge to n is found"
    );
}

/// Compounds P and Q, each decomposing into two neighborhood atoms: P→{a1,a2},
/// Q→{b1,b2}. Atom edges: a1→b1 in force, a2→b2 RETRACTED. Compound edges:
/// P→Q `refines` in force, P→Q `contradicts` RETRACTED.
struct Nbhd {
    id: Uuid,
    p: Uuid,
    q: Uuid,
    a1: Uuid,
    b1: Uuid,
}

async fn two_compound_neighborhood(pool: &PgPool, w: &World) -> Nbhd {
    let ids = claims(pool, w.agent, &["P", "Q", "a1", "a2", "b1", "b2"]).await;
    let (p, q, a1, a2, b1, b2) = (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    for (parent, atom) in [(p, a1), (p, a2), (q, b1), (q, b2)] {
        edge(pool, parent, atom, "decomposes_to").await;
    }
    edge(pool, a1, b1, "supports").await;
    retracted(pool, a2, b2, "supports").await;
    edge(pool, p, q, "refines").await;
    retracted(pool, p, q, "contradicts").await;
    let id = neighborhood(pool, &[a1, a2, b1, b2]).await;
    Nbhd { id, p, q, a1, b1 }
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_induced_edges_aggregate_only_in_force_atom_edges(pool: PgPool) {
    let w = world(&pool).await;
    let n = two_compound_neighborhood(&pool, &w).await;

    let got: Vec<(Uuid, Uuid, String, i32)> =
        GraphViewRepository::neighborhood_induced_edges(&pool, &w.viewer, n.id)
            .await
            .expect("induced")
            .into_iter()
            .map(|r| (r.source, r.target, r.relationship, r.atom_edge_count))
            .collect();
    assert_eq!(
        got,
        vec![(n.p, n.q, "supports".to_string(), 1)],
        "the retracted a2→b2 edge must not add to the induced P→Q edge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_direct_edges_omit_a_retracted_compound_edge(pool: PgPool) {
    let w = world(&pool).await;
    let n = two_compound_neighborhood(&pool, &w).await;

    let got: Vec<(Uuid, Uuid, String)> =
        GraphViewRepository::neighborhood_direct_edges(&pool, &w.viewer, n.id)
            .await
            .expect("direct")
            .into_iter()
            .map(|r| (r.source_id, r.target_id, r.relationship))
            .collect();
    assert_eq!(
        got,
        vec![(n.p, n.q, "refines".to_string())],
        "P→Q `refines` is in force and shown; P→Q `contradicts` was retracted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_edges_omit_a_retracted_atom_edge(pool: PgPool) {
    let w = world(&pool).await;
    let n = two_compound_neighborhood(&pool, &w).await;

    let got: Vec<(Uuid, Uuid)> =
        GraphViewRepository::neighborhood_atomic_edges(&pool, &w.viewer, n.id)
            .await
            .expect("atomic edges")
            .into_iter()
            .map(|r| (r.source_id, r.target_id))
            .collect();
    assert_eq!(got, vec![(n.a1, n.b1)], "only the in-force a1→b1 edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_structural_edges_are_derived_only_from_in_force_edges(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(
        &pool,
        w.agent,
        &["P", "Q", "shared atom s", "p-atom", "q-atom", "R"],
    )
    .await;
    let (p, q, s, pa, qa, r) = (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    edge(&pool, p, pa, "decomposes_to").await;
    edge(&pool, q, qa, "decomposes_to").await;
    // shared_atom through a RETRACTED Q→s.
    edge(&pool, p, s, "decomposes_to").await;
    retracted(&pool, q, s, "decomposes_to").await;
    // shared_ancestor through a RETRACTED R→Q.
    edge(&pool, r, p, "decomposes_to").await;
    retracted(&pool, r, q, "decomposes_to").await;
    let nbhd = neighborhood(&pool, &[s, pa, qa]).await;

    let derived = GraphViewRepository::neighborhood_structural_edges(&pool, &w.viewer, nbhd)
        .await
        .expect("structural");
    assert!(
        derived.is_empty(),
        "both links rest on a retracted decomposes_to edge; neither may be \
         derived. Got {derived:?}"
    );

    // Positive counterpart: restore Q→s as an in-force edge and the shared_atom
    // link appears, so the empty result above is not an empty fixture.
    edge(&pool, q, s, "decomposes_to").await;
    let kinds: Vec<String> =
        GraphViewRepository::neighborhood_structural_edges(&pool, &w.viewer, nbhd)
            .await
            .expect("structural, restored")
            .into_iter()
            .map(|r| r.kind)
            .collect();
    assert_eq!(kinds, vec!["shared_atom".to_string()]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn decomposition_flags_ignore_retracted_edges(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["centre", "child", "parent", "live child"]).await;
    let (c, child, parent, live) = (ids[0], ids[1], ids[2], ids[3]);
    retracted(&pool, c, child, "decomposes_to").await;
    retracted(&pool, parent, c, "decomposes_to").await;

    assert_eq!(
        GraphViewRepository::decomposition_flags(&pool, &w.viewer, c)
            .await
            .expect("flags"),
        (false, false),
        "both decomposition edges are retracted: the centre is a standalone"
    );

    edge(&pool, c, live, "decomposes_to").await;
    assert_eq!(
        GraphViewRepository::decomposition_flags(&pool, &w.viewer, c)
            .await
            .expect("flags, with a live child"),
        (true, false),
        "an in-force child edge still classifies the centre as a compound"
    );
}

// ── load_subgraph ───────────────────────────────────────────────────────────

/// `subgraph_edges` backs `GET /api/v1/graph/full` and the graph-query routes.
/// A future-dated `valid_to` is "in force until then", not retracted — this
/// also guards the predicate against being simplified to `valid_to IS NULL`.
#[sqlx::test(migrations = "../../migrations")]
async fn subgraph_edges_omit_retracted_and_keep_future_dated_edges(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["A", "B", "C", "D"]).await;
    let (a, b, c, d) = (ids[0], ids[1], ids[2], ids[3]);
    let live = edge(&pool, a, b, "supports").await;
    let gone = retracted(&pool, a, c, "contradicts").await;
    let until_next_year = edge(&pool, a, d, "elaborates").await;
    sqlx::query("UPDATE edges SET valid_to = now() + interval '1 year' WHERE id = $1")
        .bind(until_next_year)
        .execute(&pool)
        .await
        .expect("future-date");

    let mut got: Vec<Uuid> = GraphViewRepository::subgraph_edges(&pool, &w.viewer, &ids)
        .await
        .expect("subgraph edges")
        .into_iter()
        .map(|r| r.id)
        .collect();
    got.sort();
    let mut want = vec![live, until_next_year];
    want.sort();
    assert_eq!(
        got, want,
        "the in-force and future-dated edges are returned; the retracted one ({gone}) is not"
    );
}

// ── EdgeRepository::get_by_{source,target}_in_force ────────────────────────

/// The in-force endpoint reads drop a retracted edge AND keep the PR-13 edge
/// viewer predicate they were copied from. Losing the second while adding the
/// first would be a tenancy leak, so both halves are asserted on one fixture:
/// a private edge between two PUBLIC claims (migration 070 arm (b) keeps that
/// declaration) is visible to its owner and not to a stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn in_force_endpoint_reads_drop_retracted_edges_and_keep_the_viewer_predicate(pool: PgPool) {
    let (owner_agent, group) = fixture::seed_agent_with_group(&pool, "in-force-owner").await;
    let (stranger_agent, _g) = fixture::seed_agent_with_group(&pool, "in-force-stranger").await;
    let owner = Viewer::resolve(&pool, owner_agent).await.expect("owner");
    let stranger = Viewer::resolve(&pool, stranger_agent)
        .await
        .expect("stranger");
    let ids = claims(&pool, owner_agent, &["hub", "live", "gone", "private"]).await;
    let (hub, live, gone, private) = (ids[0], ids[1], ids[2], ids[3]);
    let e_live = edge(&pool, hub, live, "supports").await;
    let e_gone = retracted(&pool, hub, gone, "supports").await;
    let e_private = edge(&pool, hub, private, "supports").await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(e_private)
    .bind(group)
    .execute(&pool)
    .await
    .expect("privatise edge");

    let ids_of = |rows: Vec<epigraph_db::repos::edge::EdgeRow>| {
        let mut v: Vec<Uuid> = rows.into_iter().map(|r| r.id).collect();
        v.sort();
        v
    };
    let sorted = |mut v: Vec<Uuid>| {
        v.sort();
        v
    };

    // The unfiltered structural read still returns the retracted row — the
    // precondition that makes the in-force assertions below meaningful.
    assert_eq!(
        ids_of(
            EdgeRepository::get_by_source(&pool, &owner, hub, "claim")
                .await
                .expect("unfiltered")
        ),
        sorted(vec![e_live, e_gone, e_private]),
    );

    assert_eq!(
        ids_of(
            EdgeRepository::get_by_source_in_force(&pool, &owner, hub, "claim")
                .await
                .expect("owner, outgoing")
        ),
        sorted(vec![e_live, e_private]),
        "the owner sees its private edge and not the retracted one"
    );
    assert_eq!(
        ids_of(
            EdgeRepository::get_by_source_in_force(&pool, &stranger, hub, "claim")
                .await
                .expect("stranger, outgoing")
        ),
        vec![e_live],
        "a stranger sees neither the retracted edge nor the private one"
    );
    assert_eq!(
        ids_of(
            EdgeRepository::get_by_target_in_force(&pool, &owner, gone, "claim")
                .await
                .expect("owner, incoming at gone")
        ),
        Vec::<Uuid>::new(),
        "the retracted edge is gone from the target side too"
    );
    assert_eq!(
        ids_of(
            EdgeRepository::get_by_target_in_force(&pool, &owner, private, "claim")
                .await
                .expect("owner, incoming at private")
        ),
        vec![e_private]
    );
    assert_eq!(
        ids_of(
            EdgeRepository::get_by_target_in_force(&pool, &stranger, private, "claim")
                .await
                .expect("stranger, incoming at private")
        ),
        Vec::<Uuid>::new()
    );
}

// ── recall / search context (ClaimRepository) ───────────────────────────────

/// A 1536-d pgvector literal with every component `v`.
fn unit_ish(v: f32) -> String {
    let body: Vec<String> = (0..1536).map(|_| v.to_string()).collect();
    format!("[{}]", body.join(","))
}

/// recall_with_context's graph expansion. A deleted supports edge must neither
/// emit its target nor bridge the walk to the claim behind it.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_expand_seeds_neither_emits_nor_walks_a_retracted_edge(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["seed", "live", "gone", "behind gone"]).await;
    let (seed, live, gone, behind) = (ids[0], ids[1], ids[2], ids[3]);
    edge(&pool, seed, live, "supports").await;
    let e = edge(&pool, seed, gone, "supports").await;
    edge(&pool, gone, behind, "elaborates").await;

    let reached = |hits: Vec<epigraph_db::GraphExpansionHit>| {
        let mut v: Vec<Uuid> = hits.into_iter().map(|h| h.claim_id).collect();
        v.sort();
        v
    };
    let mut all = vec![live, gone, behind];
    all.sort();
    assert_eq!(
        reached(
            epigraph_db::ClaimRepository::graph_expand_seeds(&pool, &w.viewer, &[seed], 3)
                .await
                .expect("expand before")
        ),
        all,
        "precondition: every claim is reached before the retraction"
    );

    EdgeRepository::retract(&pool, &[e]).await.expect("retract");
    assert_eq!(
        reached(
            epigraph_db::ClaimRepository::graph_expand_seeds(&pool, &w.viewer, &[seed], 3)
                .await
                .expect("expand after")
        ),
        vec![live],
        "`gone` was reached only through the retracted edge and `behind` only through `gone`"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn semantic_graph_neighbors_omit_a_retracted_edge(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(
        &pool,
        w.agent,
        &["seed S", "live N1", "gone N2", "gone-in N3"],
    )
    .await;
    let (s, n1, n2, n3) = (ids[0], ids[1], ids[2], ids[3]);
    let v = unit_ish(0.5);
    for c in &ids {
        fixture::set_claim_embedding(&pool, *c, &v).await;
    }
    edge(&pool, s, n1, "supports").await;
    retracted(&pool, s, n2, "contradicts").await;
    retracted(&pool, n3, s, "refines").await;

    let got: Vec<Uuid> = epigraph_db::ClaimRepository::semantic_graph_neighbors(
        &pool,
        &w.viewer,
        "embedding",
        &v,
        &[s],
    )
    .await
    .expect("neighbours")
    .into_iter()
    .map(|r| r.neighbor_id)
    .collect();
    assert_eq!(
        got,
        vec![n1],
        "only the in-force supports edge yields a neighbour; the retracted outbound \
         `contradicts` and inbound `refines` do not"
    );
}

/// Retracted edges on BOTH sides of the claim, so a predicate that bound to
/// only one arm of `source_id = c.id OR target_id = c.id` would be caught.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_hybrid_context_edge_count_counts_only_in_force_edges(pool: PgPool) {
    let w = world(&pool).await;
    let ids = claims(&pool, w.agent, &["R", "A", "B", "C"]).await;
    let (r, a, b, c) = (ids[0], ids[1], ids[2], ids[3]);
    let v = unit_ish(0.5);
    fixture::set_claim_embedding(&pool, r, &v).await;
    sqlx::query("UPDATE claims SET truth_value = 0.9 WHERE id = $1")
        .bind(r)
        .execute(&pool)
        .await
        .expect("truth");
    edge(&pool, r, a, "supports").await;
    retracted(&pool, r, b, "contradicts").await; // source side
    retracted(&pool, c, r, "refines").await; // target side

    let count =
        epigraph_db::ClaimRepository::rag_hybrid_context(&pool, &w.viewer, &v, 0.0, None, 10)
            .await
            .expect("rag")
            .into_iter()
            .find(|h| h.claim_id == r)
            .map(|h| h.edge_count)
            .expect("R is retrieved");
    assert_eq!(
        count, 1,
        "R's degree counts its one in-force edge, not the two retracted ones"
    );
}

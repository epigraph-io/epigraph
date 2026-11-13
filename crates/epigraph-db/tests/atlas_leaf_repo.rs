//! Atlas leaf node sets (Atlas W3, backlog bd6f0a02): every leaf holds at most
//! 100 nodes (claims, agents and evidence counted together), a leaf that
//! agents or evidence push over the cap asks for a re-split, a high-degree
//! agent is one node, a row outside the map's readable set never appears, and
//! the node set does not depend on input or row order.
//!
//! Every read runs the way the nightly build runs it: a transaction opened by
//! `AtlasMapRepository::begin_build_snapshot` on the `#[sqlx::test]` pool (a
//! BYPASSRLS superuser, the maintenance stand-in) with a BYPASS viewer, where
//! neither the viewer splice nor row security filters anything, so the map
//! predicate is the only thing keeping another team's rows out. The scope test
//! also reads as a scoped viewer in two teams, on the superuser pool and on a
//! stamped `epigraph_app` connection.
//!
//! Rows are seeded by direct inserts on the superuser pool; tenancy that
//! migration 070's triggers would stamp otherwise is forced by UPDATE.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use epigraph_db::repos::atlas_leaf::{
    fallback_split, resolve_with_fallback, AtlasLeafRepository, LeafEdgeOrigin, LeafNode,
    LeafNodeKind, LeafNodeSet, LeafOutcome, LeafRows, SplitReason, ATLAS_LEAF_NODE_CAP,
    DERIVED_EVIDENCE_RELATIONSHIP, DERIVED_FILER_RELATIONSHIP,
};
use epigraph_db::repos::atlas_map::AtlasMap;
use epigraph_db::{AtlasMapRepository, ScopedPool, SessionGucMode, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const CAP: usize = ATLAS_LEAF_NODE_CAP;

/// A keyed TEAM group with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// An agent row with no group: a filer or an author, never a viewer.
async fn agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// `n` claims filed by `filer`, declared `(visibility, owner)`. Ids are random,
/// so insertion order is not id order.
async fn claims(pool: &PgPool, filer: Uuid, visibility: &str, owner: Uuid, n: i32) -> Vec<Uuid> {
    sqlx::query_scalar(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         SELECT gen_random_uuid(), 'leaf claim ' || gen_random_uuid()::text, \
                decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $1, true, $2, $3 \
           FROM generate_series(1, $4) \
         RETURNING id",
    )
    .bind(filer)
    .bind(visibility)
    .bind(owner)
    .bind(n)
    .fetch_all(pool)
    .await
    .expect("seed claims")
}

/// `n` evidence rows on `claim`; 070 stamps the claim's tenancy on them.
async fn evidence(pool: &PgPool, claim: Uuid, n: i32) -> Vec<Uuid> {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
         SELECT $1, 'document', decode(md5(random()::text) || md5(random()::text), 'hex') \
           FROM generate_series(1, $2) \
         RETURNING id",
    )
    .bind(claim)
    .bind(n)
    .fetch_all(pool)
    .await
    .expect("seed evidence")
}

/// A stored edge, tenancy as 070's trigger stamps it from the endpoints.
async fn edge(pool: &PgPool, source: LeafNode, target: LeafNode, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source.id)
    .bind(source.kind.as_str())
    .bind(target.id)
    .bind(target.kind.as_str())
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

/// Force an edge's tenancy columns (the trigger fires on endpoint changes only).
async fn force_edge(pool: &PgPool, id: Uuid, owner: Uuid, co_owner: Option<Uuid>) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .bind(co_owner)
    .execute(pool)
    .await
    .expect("force edge tenancy")
    .rows_affected();
    assert_eq!(n, 1);
}

async fn force_evidence(pool: &PgPool, id: Uuid, owner: Uuid) {
    let n =
        sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
            .bind(id)
            .bind(owner)
            .execute(pool)
            .await
            .expect("force evidence tenancy")
            .rows_affected();
    assert_eq!(n, 1);
}

/// The build path: a snapshot transaction on the superuser pool, read with
/// `viewer` (a bypass viewer unless the test says otherwise).
async fn read(pool: &PgPool, viewer: &Viewer, map: AtlasMap, ids: &[Uuid]) -> LeafRows {
    let mut tx = pool.begin().await.expect("begin the build");
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .expect("begin_build_snapshot");
    let rows = AtlasLeafRepository::read_leaf_rows(&mut tx, viewer, map, ids)
        .await
        .expect("read_leaf_rows");
    tx.commit().await.expect("commit");
    rows
}

async fn build(pool: &PgPool, viewer: &Viewer, map: AtlasMap, ids: &[Uuid]) -> LeafOutcome {
    let mut tx = pool.begin().await.expect("begin the build");
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .expect("begin_build_snapshot");
    let out = AtlasLeafRepository::build_leaf(&mut tx, viewer, map, ids, CAP)
        .await
        .expect("build_leaf");
    tx.commit().await.expect("commit");
    out
}

fn fits(outcome: LeafOutcome) -> LeafNodeSet {
    match outcome {
        LeafOutcome::Fits(set) => set,
        other => panic!("expected Fits, got {other:?}"),
    }
}

fn of_kind(set: &LeafNodeSet, kind: LeafNodeKind) -> BTreeSet<Uuid> {
    set.nodes
        .iter()
        .filter(|n| n.kind == kind)
        .map(|n| n.id)
        .collect()
}

fn stored_ids(set: &LeafNodeSet) -> BTreeSet<Uuid> {
    set.edges
        .iter()
        .filter_map(|e| match &e.origin {
            LeafEdgeOrigin::Stored { edge_ids } => Some(edge_ids.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// The node count measured on the set itself, not on its own counts.
fn assert_within_cap(set: &LeafNodeSet) {
    assert!(
        set.nodes.len() <= CAP,
        "a leaf of {} nodes is over the cap",
        set.nodes.len()
    );
    assert_eq!(set.nodes.len(), set.counts.nodes);
    let distinct: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
    assert_eq!(distinct.len(), set.nodes.len(), "a node appears twice");
}

// ===========================================================================
// The cap
// ===========================================================================

/// A test hierarchy of three candidate leaves under one theme of team T's map:
/// one that fits (30 team claims and 2 public ones, one evidence row each, one
/// filer), one that evidence pushes over the cap (60 claims, one evidence row
/// each: 121 nodes), and one claim carrying 150 evidence rows. Every leaf the
/// builder ends with holds at most 100 nodes, and the leaves cover every
/// drawable claim exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn every_leaf_of_a_test_hierarchy_fits_the_cap(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let world = fixture::world_group(&pool).await;
    let f = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;

    let mut fitting = claims(&pool, f, "group", t, 30).await;
    fitting.extend(claims(&pool, f, "public", world, 2).await);
    let crowded = claims(&pool, f, "group", t, 60).await;
    for &c in fitting.iter().chain(&crowded) {
        evidence(&pool, c, 1).await;
    }
    let flooded = claims(&pool, f, "group", t, 1).await;
    evidence(&pool, flooded[0], 150).await;

    // Calibration: the crowded leaf really is over the cap before any split.
    match build(&pool, &system, AtlasMap::Team(t), &crowded).await {
        LeafOutcome::NeedsSplit(n) => {
            assert_eq!(n.reason, SplitReason::NodeCap);
            assert_eq!(
                (n.counts.claims, n.counts.agents, n.counts.evidence),
                (60, 1, 60)
            );
        }
        other => panic!("the crowded leaf must need a split, got {other:?}"),
    }

    let hierarchy = [&fitting, &crowded, &flooded];
    let mut leaves_per_candidate = Vec::new();
    for candidate in hierarchy {
        let rows = read(&pool, &system, AtlasMap::Team(t), candidate).await;
        let leaves = resolve_with_fallback(&rows, candidate, CAP).expect("resolve");
        let mut covered: Vec<Uuid> = Vec::new();
        for leaf in &leaves {
            assert_within_cap(leaf);
            covered.extend(leaf.claim_ids());
        }
        covered.sort_unstable();
        let mut want = candidate.clone();
        want.sort_unstable();
        assert_eq!(
            covered, want,
            "the leaves cover the candidate's claims once"
        );
        leaves_per_candidate.push(leaves);
    }
    assert_eq!(
        leaves_per_candidate[0].len(),
        1,
        "the fitting leaf stays whole"
    );
    assert!(leaves_per_candidate[1].len() >= 2, "the crowded leaf split");
    let flood = &leaves_per_candidate[2];
    assert_eq!(flood.len(), 1);
    assert_eq!(
        flood[0].capped.len(),
        1,
        "the flooded claim's evidence was cut"
    );
    assert_eq!(flood[0].capped[0].total_evidence, 150);
    assert_eq!(flood[0].nodes.len(), CAP);
}

/// A leaf of 40 claims with one evidence row each and one filer is 81 nodes
/// and fits. Twenty more evidence rows, or twenty authors on authorship edges,
/// take it to 101: the answer turns into a split request with the counts, and
/// the fallback split's parts each fit.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_or_evidence_pushing_a_leaf_over_the_cap_trigger_a_resplit(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let f = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);

    // Evidence.
    let by_evidence = claims(&pool, f, "group", t, 40).await;
    for &c in &by_evidence {
        evidence(&pool, c, 1).await;
    }
    let before = fits(build(&pool, &system, map, &by_evidence).await);
    assert_eq!(
        (
            before.counts.claims,
            before.counts.agents,
            before.counts.evidence,
            before.counts.nodes
        ),
        (40, 1, 40, 81)
    );
    evidence(&pool, by_evidence[0], 20).await;
    match build(&pool, &system, map, &by_evidence).await {
        LeafOutcome::NeedsSplit(n) => {
            assert_eq!(n.reason, SplitReason::NodeCap);
            assert_eq!((n.counts.evidence, n.counts.nodes), (60, 101));
        }
        other => panic!("twenty evidence rows must force a split, got {other:?}"),
    }
    let rows = read(&pool, &system, map, &by_evidence).await;
    let parts = fallback_split(&rows, &by_evidence, CAP).expect("split");
    assert!(parts.len() >= 2);
    for p in &parts {
        assert_within_cap(&fits(
            epigraph_db::repos::atlas_leaf::assemble_leaf(&rows, p, CAP).expect("assemble"),
        ));
    }

    // Agents.
    let by_agents = claims(&pool, f, "group", t, 40).await;
    for &c in &by_agents {
        evidence(&pool, c, 1).await;
    }
    fits(build(&pool, &system, map, &by_agents).await);
    for (i, &c) in by_agents.iter().take(20).enumerate() {
        let a = agent(&pool).await;
        let rel = if i % 2 == 0 { "AUTHORED" } else { "asserts" };
        edge(&pool, LeafNode::agent(a), LeafNode::claim(c), rel).await;
    }
    match build(&pool, &system, map, &by_agents).await {
        LeafOutcome::NeedsSplit(n) => {
            assert_eq!(n.reason, SplitReason::NodeCap);
            assert_eq!((n.counts.agents, n.counts.nodes), (21, 101));
        }
        other => panic!("twenty authors must force a split, got {other:?}"),
    }
    let rows = read(&pool, &system, map, &by_agents).await;
    let leaves = resolve_with_fallback(&rows, &by_agents, CAP).expect("resolve");
    assert!(leaves.len() >= 2);
    leaves.iter().for_each(assert_within_cap);
}

/// One agent files 60 claims and holds an `AUTHORED` edge to every one of
/// them: one agent node, 61 nodes, and each claim keeps its stored authorship
/// edge (no derived filer twin beside it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_high_degree_agent_appears_once(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let h = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let ids = claims(&pool, h, "group", t, 60).await;
    for &c in &ids {
        edge(&pool, LeafNode::agent(h), LeafNode::claim(c), "AUTHORED").await;
    }

    let set = fits(build(&pool, &system, AtlasMap::Team(t), &ids).await);
    assert_within_cap(&set);
    assert_eq!(of_kind(&set, LeafNodeKind::Agent), BTreeSet::from([h]));
    assert_eq!((set.counts.agents, set.counts.nodes), (1, 61));
    let from_h: Vec<_> = set
        .edges
        .iter()
        .filter(|e| e.source == LeafNode::agent(h))
        .collect();
    assert_eq!(from_h.len(), 60);
    assert!(from_h.iter().all(|e| !e.origin.is_derived()));
}

// ===========================================================================
// Scope
// ===========================================================================

/// Team T's map and the public map, built from the same candidate leaf that
/// names a claim of team U. Never drawn: U's claim, its evidence and filer, an
/// evidence row of U on T's claim (reached by `claim_id` and by an edge), a
/// claim-to-claim edge owned by U, an edge co-owned by T and U, and an
/// authorship edge owned by U that is the only path to its agent, and an
/// evidence-to-agent edge owned by U and an evidence-to-evidence edge co-owned
/// by T and U between nodes the map does draw. T's own and public rows are
/// drawn, an evidence-to-evidence edge of T's among them (the calibration that
/// the map is not just empty).
///
/// The same answer for the bypass viewer (the nightly), for a scoped viewer who
/// is a member of BOTH T and U (whose own splice admits U's rows), on the
/// superuser pool and on a stamped `epigraph_app` connection.
#[sqlx::test(migrations = "../../migrations")]
async fn another_teams_private_rows_never_appear(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let u = team(&pool, "team-u").await;
    let world = fixture::world_group(&pool).await;
    let (f_t, f_u, f_p) = (agent(&pool).await, agent(&pool).await, agent(&pool).await);
    let (a_x, a_y) = (agent(&pool).await, agent(&pool).await);

    let tc = claims(&pool, f_t, "group", t, 2).await;
    let (t1, t2) = (tc[0], tc[1]);
    let p1 = claims(&pool, f_p, "public", world, 1).await[0];
    let u1 = claims(&pool, f_u, "group", u, 1).await[0];

    let ev_t1 = evidence(&pool, t1, 1).await[0];
    let ev_p = evidence(&pool, p1, 1).await[0];
    let ev_u1 = evidence(&pool, u1, 1).await[0];
    // U's evidence on T's claim, linked by claim_id AND by an edge stamped T
    // before the evidence moved to U.
    let ev_u = evidence(&pool, t1, 1).await[0];
    let e_evu = edge(
        &pool,
        LeafNode::evidence(ev_u),
        LeafNode::claim(t1),
        "supports",
    )
    .await;
    force_evidence(&pool, ev_u, u).await;

    let e_tt = edge(&pool, LeafNode::claim(t1), LeafNode::claim(t2), "supports").await;
    let e_tp_u = edge(&pool, LeafNode::claim(t1), LeafNode::claim(p1), "supports").await;
    force_edge(&pool, e_tp_u, u, None).await;
    let e_co = edge(&pool, LeafNode::claim(t2), LeafNode::claim(t1), "refutes").await;
    force_edge(&pool, e_co, t, Some(u)).await;
    let e_ax = edge(&pool, LeafNode::agent(a_x), LeafNode::claim(t1), "AUTHORED").await;
    force_edge(&pool, e_ax, u, None).await;
    let e_ay = edge(&pool, LeafNode::agent(a_y), LeafNode::claim(t1), "AUTHORED").await;
    let e_up = edge(&pool, LeafNode::claim(u1), LeafNode::claim(p1), "supports").await;
    // Edges among agent and evidence nodes the team map draws (the read's
    // fifth statement): one of T's is drawn, one owned by U and one co-owned
    // by T and U are not.
    let e_ee_t = edge(
        &pool,
        LeafNode::evidence(ev_p),
        LeafNode::evidence(ev_t1),
        "cites",
    )
    .await;
    force_edge(&pool, e_ee_t, t, None).await;
    let e_ea_u = edge(
        &pool,
        LeafNode::evidence(ev_t1),
        LeafNode::agent(f_t),
        "cites",
    )
    .await;
    force_edge(&pool, e_ea_u, u, None).await;
    let e_ee_co = edge(
        &pool,
        LeafNode::evidence(ev_t1),
        LeafNode::evidence(ev_p),
        "cites",
    )
    .await;
    force_edge(&pool, e_ee_co, t, Some(u)).await;

    // Calibration: the stamps the scope rests on.
    let stamp: Vec<(Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges \
          WHERE id = ANY($1) ORDER BY id",
    )
    .bind(vec![e_tt, e_ay, e_evu, e_up])
    .fetch_all(&pool)
    .await
    .expect("stamps");
    for (id, vis, owner, co) in &stamp {
        let want = if *id == e_up { u } else { t };
        assert_eq!(
            (vis.as_str(), *owner, *co),
            ("group", want, None),
            "edge {id}"
        );
    }

    let input = [u1, p1, t2, t1];
    let team_nodes: BTreeSet<LeafNode> = BTreeSet::from([
        LeafNode::claim(t1),
        LeafNode::claim(t2),
        LeafNode::claim(p1),
        LeafNode::agent(f_t),
        LeafNode::agent(f_p),
        LeafNode::agent(a_y),
        LeafNode::evidence(ev_t1),
        LeafNode::evidence(ev_p),
    ]);
    let public_nodes: BTreeSet<LeafNode> = BTreeSet::from([
        LeafNode::claim(p1),
        LeafNode::agent(f_p),
        LeafNode::evidence(ev_p),
    ]);
    let never_edges = BTreeSet::from([e_tp_u, e_co, e_ax, e_evu, e_up, e_ea_u, e_ee_co]);
    let never_ids = [u1, ev_u, ev_u1, f_u, a_x];

    let check_team = |set: &LeafNodeSet, who: &str| {
        let nodes: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
        assert_eq!(nodes, team_nodes, "{who}: team map nodes");
        assert_eq!(set.counts.unreadable_claims, 1, "{who}");
        let stored = stored_ids(set);
        assert_eq!(
            stored,
            BTreeSet::from([e_tt, e_ay, e_ee_t]),
            "{who}: team map stored edges"
        );
        assert!(stored.is_disjoint(&never_edges), "{who}");
        for n in &set.nodes {
            assert!(!never_ids.contains(&n.id), "{who}: {n:?} must not be drawn");
        }
        // Every non-claim node keeps an edge to a claim (derived where no
        // stored edge links it).
        let derived: BTreeSet<(LeafNode, LeafNode, String)> = set
            .edges
            .iter()
            .filter(|e| e.origin.is_derived())
            .map(|e| (e.source, e.target, e.relationship.clone()))
            .collect();
        let filer = DERIVED_FILER_RELATIONSHIP.to_string();
        let attached = DERIVED_EVIDENCE_RELATIONSHIP.to_string();
        assert_eq!(
            derived,
            BTreeSet::from([
                (LeafNode::agent(f_t), LeafNode::claim(t1), filer.clone()),
                (LeafNode::agent(f_t), LeafNode::claim(t2), filer.clone()),
                (LeafNode::agent(f_p), LeafNode::claim(p1), filer),
                (
                    LeafNode::evidence(ev_t1),
                    LeafNode::claim(t1),
                    attached.clone()
                ),
                (LeafNode::evidence(ev_p), LeafNode::claim(p1), attached),
            ]),
            "{who}"
        );
    };

    // The nightly: bypass viewer.
    let (scoped, system) = fixture::bypass(&pool).await;
    let team_set = fits(build(&pool, &system, AtlasMap::Team(t), &input).await);
    check_team(&team_set, "bypass");

    let public_set = fits(build(&pool, &system, AtlasMap::Public, &input).await);
    let nodes: BTreeSet<LeafNode> = public_set.nodes.iter().copied().collect();
    assert_eq!(nodes, public_nodes, "public map nodes");
    assert_eq!(public_set.counts.unreadable_claims, 3);
    assert!(
        stored_ids(&public_set).is_empty(),
        "no stored edge is public here"
    );

    // A member of both teams.
    let (m, _) = fixture::seed_agent_with_group(&pool, "leaf-both").await;
    add_member(&pool, t, m, "reader").await;
    add_member(&pool, u, m, "reader").await;
    let both = Viewer::resolve(&pool, m).await.expect("viewer");
    let set = fits(build(&pool, &both, AtlasMap::Team(t), &input).await);
    check_team(&set, "scoped, superuser pool");
    assert_eq!(set, team_set);

    // And on a stamped epigraph_app connection, where row security applies.
    let url = fixture::database_url_for(&pool).await;
    let app =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut tx = app.begin_as(&both).await.expect("stamped tx");
    let outcome = AtlasLeafRepository::build_leaf(&mut tx, &both, AtlasMap::Team(t), &input, CAP)
        .await
        .expect("build_leaf as epigraph_app");
    tx.commit().await.expect("commit");
    let set = fits(outcome);
    check_team(&set, "scoped, epigraph_app");
    assert_eq!(set, team_set);
    drop(scoped);
}

// ===========================================================================
// Determinism
// ===========================================================================

/// Two builds over the same rows, the claim ids passed in different orders and
/// with duplicates, give the same node set, edges and counts; and so does a
/// third, whose leaf a split cuts into the same parts.
#[sqlx::test(migrations = "../../migrations")]
async fn the_node_set_is_identical_across_runs(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let world = fixture::world_group(&pool).await;
    let (f1, f2, author) = (agent(&pool).await, agent(&pool).await, agent(&pool).await);
    let (_scoped, system) = fixture::bypass(&pool).await;
    let mut ids = claims(&pool, f1, "group", t, 12).await;
    ids.extend(claims(&pool, f2, "group", t, 10).await);
    ids.extend(claims(&pool, f2, "public", world, 3).await);
    for (i, &c) in ids.iter().enumerate() {
        evidence(&pool, c, 1 + (i % 3) as i32).await;
        if i > 0 {
            let rel = ["supports", "SUPPORTS", "refutes", "cites"][i % 4];
            edge(&pool, LeafNode::claim(c), LeafNode::claim(ids[i / 2]), rel).await;
        }
        if i % 4 == 0 {
            edge(
                &pool,
                LeafNode::agent(author),
                LeafNode::claim(c),
                "authored",
            )
            .await;
        }
    }
    // A resubmitted edge: two stored rows, one leaf edge.
    edge(
        &pool,
        LeafNode::claim(ids[1]),
        LeafNode::claim(ids[0]),
        "SUPPORTS",
    )
    .await;

    let forward = ids.clone();
    let mut backward: Vec<Uuid> = ids.iter().rev().copied().collect();
    backward.extend_from_slice(&ids[..5]);

    let a = fits(build(&pool, &system, AtlasMap::Team(t), &forward).await);
    let b = fits(build(&pool, &system, AtlasMap::Team(t), &backward).await);
    assert_eq!(a, b);
    assert!(a.edges.iter().any(|e| matches!(
        &e.origin,
        LeafEdgeOrigin::Stored { edge_ids } if edge_ids.len() == 2
    )));

    // At a smaller cap the same leaf splits, identically from either order.
    let rows_a = read(&pool, &system, AtlasMap::Team(t), &forward).await;
    let rows_b = read(&pool, &system, AtlasMap::Team(t), &backward).await;
    assert_eq!(rows_a.claims, rows_b.claims);
    let split_a = resolve_with_fallback(&rows_a, &forward, 20).expect("resolve a");
    let split_b = resolve_with_fallback(&rows_b, &backward, 20).expect("resolve b");
    assert!(split_a.len() >= 2);
    assert_eq!(split_a, split_b);
}

//! Atlas leaf node sets (Atlas W3, backlog bd6f0a02): every leaf holds at most
//! 100 nodes (claims, agents and evidence counted together), a leaf that
//! agents or evidence push over the cap asks for a re-split, a high-degree
//! agent is one node, a row outside the map's readable set never appears,
//! evidence is a node only through a stored edge to a claim of the leaf, and
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
    DERIVED_FILER_RELATIONSHIP,
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

/// `n` evidence rows on `claim` by `claim_id` ONLY, with no stored edge to it
/// (most evidence today, until the evidence-edge backfill); 070 stamps the
/// claim's tenancy on them.
async fn bare_evidence(pool: &PgPool, claim: Uuid, n: i32) -> Vec<Uuid> {
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

/// `n` evidence rows on `claim`, each also linked to it by a stored
/// `evidence -> claim` edge, spelled `supports` and `SUPPORTS` in turn (both
/// spellings are stored today); 070 stamps each edge from its endpoints.
/// Returns `(evidence, edge)` pairs.
async fn linked_evidence(pool: &PgPool, claim: Uuid, n: i32) -> Vec<(Uuid, Uuid)> {
    let ev = bare_evidence(pool, claim, n).await;
    let mut pairs: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         SELECT u.ev, 'evidence', $2, 'claim', \
                CASE WHEN u.o % 2 = 0 THEN 'SUPPORTS' ELSE 'supports' END \
           FROM unnest($1::uuid[]) WITH ORDINALITY AS u(ev, o) \
         RETURNING source_id, id",
    )
    .bind(&ev)
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("seed evidence edges");
    pairs.sort_unstable_by_key(|&(e, _)| ev.iter().position(|x| *x == e));
    assert_eq!(pairs.len(), ev.len());
    pairs
}

/// [`linked_evidence`], the evidence ids only.
async fn evidence(pool: &PgPool, claim: Uuid, n: i32) -> Vec<Uuid> {
    linked_evidence(pool, claim, n)
        .await
        .into_iter()
        .map(|(e, _)| e)
        .collect()
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

/// Force an evidence row public (070 re-stamps it only on the next evidence
/// INSERT for its claim, which the test makes before this).
async fn force_evidence_public(pool: &PgPool, id: Uuid, world: Uuid) {
    let n =
        sqlx::query("UPDATE evidence SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
            .bind(id)
            .bind(world)
            .execute(pool)
            .await
            .expect("force evidence public")
            .rows_affected();
    assert_eq!(n, 1);
}

/// Retract an edge: in force from two hours ago until one hour ago.
async fn retract_edge(pool: &PgPool, id: Uuid) {
    let n = sqlx::query(
        "UPDATE edges SET valid_from = now() - interval '2 hours', \
                          valid_to = now() - interval '1 hour' \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("retract edge")
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

/// [`build`] on a stamped `epigraph_app` transaction, where row security
/// applies beneath the viewer's splice.
async fn build_stamped(
    app: &ScopedPool,
    viewer: &Viewer,
    map: AtlasMap,
    ids: &[Uuid],
) -> LeafNodeSet {
    let mut tx = app.begin_as(viewer).await.expect("stamped tx");
    let out = AtlasLeafRepository::build_leaf(&mut tx, viewer, map, ids, CAP)
        .await
        .expect("build_leaf as epigraph_app");
    tx.commit().await.expect("commit");
    fits(out)
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
/// the map is not just empty). A co-owned edge is on no single-team map
/// ([`a_co_owned_edge_is_on_no_single_team_map`] has the co-owner's map, a
/// third team, the public map and the stamped audience).
///
/// Evidence is a node only through a stored edge to a claim of the leaf: an
/// evidence row attached by `claim_id` alone, one of T's and one public, is no
/// node on either map and is counted in `unlinked_evidence`.
///
/// The public map's own arms: rows of T hung on public nodes the public map
/// draws (an edge between two public claims, an evidence row on a public
/// claim, an edge between a public evidence row and a public claim's filer)
/// are on T's map and never on the public one. Without them every private row
/// the public map must drop is already dropped by the claims filter.
///
/// A public evidence row whose `claim_id` is U's claim, reached through a
/// public edge to a public claim, is drawn on both maps, and the read never
/// carries U's claim id for it.
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
    let pc = claims(&pool, f_p, "public", world, 2).await;
    let (p1, p2) = (pc[0], pc[1]);
    let u1 = claims(&pool, f_u, "group", u, 1).await[0];

    let (ev_t1, ed_t1) = linked_evidence(&pool, t1, 1).await[0];
    let (ev_p, ed_p) = linked_evidence(&pool, p1, 1).await[0];
    // T's evidence on a public claim (migration 110's hidden evidence), its
    // edge stamped public before the row was hidden. Forced after the last
    // evidence INSERT on p1, which would re-publish it.
    let (ev_tp, ed_tp) = linked_evidence(&pool, p1, 1).await[0];
    force_evidence(&pool, ev_tp, t).await;
    let (ev_u1, ed_u1) = linked_evidence(&pool, u1, 1).await[0];
    // A public evidence row of U's claim, forced after the last evidence
    // INSERT on u1 and reached on these maps only through a public edge.
    let ev_x = bare_evidence(&pool, u1, 1).await[0];
    force_evidence_public(&pool, ev_x, world).await;
    let e_xp = edge(
        &pool,
        LeafNode::evidence(ev_x),
        LeafNode::claim(p1),
        "supports",
    )
    .await;
    // U's evidence on T's claim, linked by claim_id AND by an edge stamped T
    // before the evidence moved to U.
    let ev_u = bare_evidence(&pool, t1, 1).await[0];
    let e_evu = edge(
        &pool,
        LeafNode::evidence(ev_u),
        LeafNode::claim(t1),
        "supports",
    )
    .await;
    force_evidence(&pool, ev_u, u).await;
    // Evidence attached by claim_id alone: one of T's, one public.
    let ev_bare_t = bare_evidence(&pool, t2, 1).await[0];
    let ev_bare_p = bare_evidence(&pool, p2, 1).await[0];

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
    // T's edges between nodes the PUBLIC map draws: claim to claim (the read's
    // second statement) and evidence to agent (its fifth).
    let e_pp_t = edge(&pool, LeafNode::claim(p1), LeafNode::claim(p2), "supports").await;
    force_edge(&pool, e_pp_t, t, None).await;
    let e_pa_t = edge(
        &pool,
        LeafNode::evidence(ev_p),
        LeafNode::agent(f_p),
        "cites",
    )
    .await;
    force_edge(&pool, e_pa_t, t, None).await;

    // Calibration: the stamps the scope rests on.
    let stamp: Vec<(Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges \
          WHERE id = ANY($1) ORDER BY id",
    )
    .bind(vec![e_tt, e_ay, e_evu, e_up, ed_t1, ed_u1])
    .fetch_all(&pool)
    .await
    .expect("stamps");
    assert_eq!(stamp.len(), 6);
    for (id, vis, owner, co) in &stamp {
        let want = if *id == e_up || *id == ed_u1 { u } else { t };
        assert_eq!(
            (vis.as_str(), *owner, *co),
            ("group", want, None),
            "edge {id}"
        );
    }
    let co_stamps: Vec<(String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = ANY($1)",
    )
    .bind(vec![e_co, e_ee_co])
    .fetch_all(&pool)
    .await
    .expect("stamps of the co-owned edges");
    assert_eq!(co_stamps, vec![("group".to_string(), t, Some(u)); 2]);
    let public_edges: Vec<(String, Option<Uuid>)> =
        sqlx::query_as("SELECT visibility::text, co_owner_group_id FROM edges WHERE id = ANY($1)")
            .bind(vec![e_xp, ed_p, ed_tp])
            .fetch_all(&pool)
            .await
            .expect("stamps of the public edges");
    assert_eq!(public_edges, vec![("public".to_string(), None); 3]);
    let ev_stamps: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id FROM evidence WHERE id = ANY($1) ORDER BY id",
    )
    .bind(vec![ev_tp, ev_x, ev_u, ev_bare_t, ev_bare_p])
    .fetch_all(&pool)
    .await
    .expect("evidence stamps");
    assert_eq!(ev_stamps.len(), 5);
    for (id, vis, owner) in &ev_stamps {
        let want = if *id == ev_tp || *id == ev_bare_t {
            ("group", t)
        } else if *id == ev_x || *id == ev_bare_p {
            ("public", world)
        } else {
            ("group", u)
        };
        assert_eq!((vis.as_str(), *owner), want, "evidence {id}");
    }
    let bare_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1)",
    )
    .bind(vec![ev_bare_t, ev_bare_p])
    .fetch_one(&pool)
    .await
    .expect("edges of the bare evidence");
    assert_eq!(bare_edges, 0, "the bare evidence rows have no stored edge");

    let input = [u1, p2, p1, t2, t1];
    let team_nodes: BTreeSet<LeafNode> = BTreeSet::from([
        LeafNode::claim(t1),
        LeafNode::claim(t2),
        LeafNode::claim(p1),
        LeafNode::claim(p2),
        LeafNode::agent(f_t),
        LeafNode::agent(f_p),
        LeafNode::agent(a_y),
        LeafNode::evidence(ev_t1),
        LeafNode::evidence(ev_p),
        LeafNode::evidence(ev_tp),
        LeafNode::evidence(ev_x),
    ]);
    let public_nodes: BTreeSet<LeafNode> = BTreeSet::from([
        LeafNode::claim(p1),
        LeafNode::claim(p2),
        LeafNode::agent(f_p),
        LeafNode::evidence(ev_p),
        LeafNode::evidence(ev_x),
    ]);
    let never_edges = BTreeSet::from([e_tp_u, e_co, e_ax, e_evu, e_up, e_ea_u, e_ee_co, ed_u1]);
    let never_ids = [u1, ev_u, ev_u1, f_u, a_x, ev_bare_t, ev_bare_p];

    let check_team = |set: &LeafNodeSet, who: &str| {
        let nodes: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
        assert_eq!(nodes, team_nodes, "{who}: team map nodes");
        assert_eq!(set.counts.unreadable_claims, 1, "{who}");
        assert_eq!(
            set.counts.unlinked_evidence, 2,
            "{who}: T's and the public bare evidence rows are counted"
        );
        let stored = stored_ids(set);
        assert_eq!(
            stored,
            BTreeSet::from([e_tt, e_ay, e_ee_t, e_pp_t, e_pa_t, e_xp, ed_t1, ed_p, ed_tp]),
            "{who}: team map stored edges"
        );
        assert!(stored.is_disjoint(&never_edges), "{who}");
        for n in &set.nodes {
            assert!(!never_ids.contains(&n.id), "{who}: {n:?} must not be drawn");
        }
        // The filer is the only derived edge; evidence keeps its stored one.
        let derived: BTreeSet<(LeafNode, LeafNode, String)> = set
            .edges
            .iter()
            .filter(|e| e.origin.is_derived())
            .map(|e| (e.source, e.target, e.relationship.clone()))
            .collect();
        let filer = DERIVED_FILER_RELATIONSHIP.to_string();
        assert_eq!(
            derived,
            BTreeSet::from([
                (LeafNode::agent(f_t), LeafNode::claim(t1), filer.clone()),
                (LeafNode::agent(f_t), LeafNode::claim(t2), filer.clone()),
                (LeafNode::agent(f_p), LeafNode::claim(p1), filer.clone()),
                (LeafNode::agent(f_p), LeafNode::claim(p2), filer),
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
    assert!(
        !nodes.contains(&LeafNode::evidence(ev_tp)),
        "T's evidence on a public claim is not on the public map"
    );
    assert_eq!(nodes, public_nodes, "public map nodes");
    assert_eq!(public_set.counts.unreadable_claims, 3);
    assert_eq!(
        public_set.counts.unlinked_evidence, 1,
        "the public bare evidence row is counted, T's is not read"
    );
    let public_stored = stored_ids(&public_set);
    assert!(
        !public_stored.contains(&e_pp_t),
        "T's edge between two public claims is not on the public map"
    );
    assert!(
        !public_stored.contains(&e_pa_t),
        "T's edge between a public evidence row and a public filer is not on the public map"
    );
    assert_eq!(
        public_stored,
        BTreeSet::from([e_xp, ed_p]),
        "public map stored edges"
    );

    // The read itself never carries U's claim id for the public evidence row
    // it reached through an edge, on either map.
    for (map, who) in [(AtlasMap::Team(t), "team"), (AtlasMap::Public, "public")] {
        let rows = read(&pool, &system, map, &input).await;
        assert_eq!(
            rows.evidence.get(&ev_x),
            Some(&None),
            "{who}: ev_x is read, without its claim id"
        );
        for (ev, claim) in &rows.evidence {
            if let Some(c) = claim {
                assert!(rows.claims.contains_key(c), "{who}: {ev} names claim {c}");
            }
        }
    }

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

/// An edge co-owned by teams A and B is drawn on no single-team map: not on
/// A's (the owner's), not on B's (the co-owner's), not on a third team C's,
/// and not on the public map. A map draws an edge only when its whole audience
/// may read the row, and row security (migration 077's `edges_tenancy`, after
/// 072) lets a session read a co-owned edge only when it is in BOTH teams.
///
/// The co-owned edges hang on public nodes, so every map draws both endpoints
/// and only the edge's own tenancy decides: a claim-to-claim edge (the read's
/// second statement) and an evidence-to-agent edge (its fifth), each owned by A
/// and co-owned by B. A's own edge between the same claims (no co-owner) is the
/// calibration: on A's map only, so A's map is not just empty of group edges.
///
/// Public edges are drawn on every map, one from each edge read: the stored
/// evidence-to-claim edge `ed` (the second statement) and an evidence-to-agent
/// edge `pub_ea` (the fifth), both left as the tenancy trigger stamps them.
///
/// A co-owned edge as the tenancy trigger stamps it, between a claim of A and a
/// claim of B, is on no map either, but only because each map lacks one of its
/// endpoints (A's map has no claim of B, B's none of A, C's and the public map
/// neither). It shows the endpoint filter, not the edge predicate.
///
/// Built the way the nightly builds (bypass viewer), then on a stamped
/// `epigraph_app` connection for a member of A alone, a member of B alone and
/// a member of both: each gets exactly the bypass build of its map. That is
/// the audience rule itself, and it fails if the map draws an edge some member
/// of its team cannot read.
#[sqlx::test(migrations = "../../migrations")]
async fn a_co_owned_edge_is_on_no_single_team_map(pool: PgPool) {
    let a = team(&pool, "team-a").await;
    let b = team(&pool, "team-b").await;
    let c = team(&pool, "team-c").await;
    let world = fixture::world_group(&pool).await;
    let f = agent(&pool).await;
    let pc = claims(&pool, f, "public", world, 2).await;
    let (p1, p2) = (pc[0], pc[1]);
    let a1 = claims(&pool, f, "group", a, 1).await[0];
    let b1 = claims(&pool, f, "group", b, 1).await[0];
    let (ev, ed) = linked_evidence(&pool, p1, 1).await[0];

    let co_cc = edge(&pool, LeafNode::claim(p1), LeafNode::claim(p2), "supports").await;
    force_edge(&pool, co_cc, a, Some(b)).await;
    let co_ea = edge(&pool, LeafNode::evidence(ev), LeafNode::agent(f), "cites").await;
    force_edge(&pool, co_ea, a, Some(b)).await;
    let a_cc = edge(&pool, LeafNode::claim(p2), LeafNode::claim(p1), "refutes").await;
    force_edge(&pool, a_cc, a, None).await;
    let co_ab = edge(&pool, LeafNode::claim(a1), LeafNode::claim(b1), "supports").await;
    // Public: its evidence is on a public claim and an agent has no tenancy.
    let pub_ea = edge(
        &pool,
        LeafNode::evidence(ev),
        LeafNode::agent(f),
        "supports",
    )
    .await;

    // Calibration: the stamps the test rests on.
    let stamps: Vec<(Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges \
          WHERE id = ANY($1)",
    )
    .bind(vec![co_cc, co_ea, a_cc, co_ab, ed, pub_ea])
    .fetch_all(&pool)
    .await
    .expect("stamps");
    assert_eq!(stamps.len(), 6);
    for (id, vis, owner, co) in &stamps {
        let want = if *id == a_cc {
            ("group", a, None)
        } else if *id == ed || *id == pub_ea {
            ("public", world, None)
        } else {
            ("group", a, Some(b))
        };
        assert_eq!((vis.as_str(), *owner, *co), want, "edge {id}");
    }

    let input = [b1, p2, a1, p1];
    let public_nodes = [
        LeafNode::claim(p1),
        LeafNode::claim(p2),
        LeafNode::agent(f),
        LeafNode::evidence(ev),
    ];
    let with = |extra: Option<LeafNode>| -> BTreeSet<LeafNode> {
        public_nodes.iter().copied().chain(extra).collect()
    };
    let (_scoped, system) = fixture::bypass(&pool).await;
    let maps = [
        (
            AtlasMap::Team(a),
            "A",
            with(Some(LeafNode::claim(a1))),
            BTreeSet::from([ed, pub_ea, a_cc]),
        ),
        (
            AtlasMap::Team(b),
            "B",
            with(Some(LeafNode::claim(b1))),
            BTreeSet::from([ed, pub_ea]),
        ),
        (
            AtlasMap::Team(c),
            "C",
            with(None),
            BTreeSet::from([ed, pub_ea]),
        ),
        (
            AtlasMap::Public,
            "public",
            with(None),
            BTreeSet::from([ed, pub_ea]),
        ),
    ];
    let never = BTreeSet::from([co_cc, co_ea, co_ab]);
    let mut built = Vec::new();
    for (map, who, nodes, edges) in &maps {
        let set = fits(build(&pool, &system, *map, &input).await);
        let got: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
        // Both endpoints of co_cc and co_ea are nodes of every map.
        assert_eq!(&got, nodes, "{who}: nodes");
        let stored = stored_ids(&set);
        assert!(
            stored.is_disjoint(&never),
            "{who}: a co-owned edge is drawn"
        );
        assert_eq!(&stored, edges, "{who}: stored edges");
        built.push(set);
    }

    // A stamped epigraph_app connection, where row security applies: every
    // member of the map's team gets the map as the nightly built it.
    let url = fixture::database_url_for(&pool).await;
    let app =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let member = |name: &'static str, teams: Vec<Uuid>| {
        let pool = pool.clone();
        async move {
            let (m, _) = fixture::seed_agent_with_group(&pool, name).await;
            for t in teams {
                add_member(&pool, t, m, "reader").await;
            }
            Viewer::resolve(&pool, m).await.expect("viewer")
        }
    };
    let only_a = member("leaf-a", vec![a]).await;
    let only_b = member("leaf-b", vec![b]).await;
    let both = member("leaf-ab", vec![a, b]).await;
    let cases = [
        (&only_a, AtlasMap::Team(a), 0, "A, member of A alone"),
        (&both, AtlasMap::Team(a), 0, "A, member of both"),
        (&only_b, AtlasMap::Team(b), 1, "B, member of B alone"),
        (&both, AtlasMap::Team(b), 1, "B, member of both"),
    ];
    for (viewer, map, i, who) in cases {
        let set = build_stamped(&app, viewer, map, &input).await;
        assert_eq!(set, built[i], "{who}");
    }
}

/// A retracted edge (its `valid_to` past) is never drawn, and neither is the
/// agent it alone would bring in: a retracted authorship edge, a retracted
/// claim-to-claim edge (the read's second statement) and a retracted
/// evidence-to-agent edge (its fifth). Calibrated by building the same leaf
/// while the three are still in force, where all three and the author are
/// drawn.
#[sqlx::test(migrations = "../../migrations")]
async fn retracted_edges_are_never_drawn(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let (f, a_r) = (agent(&pool).await, agent(&pool).await);
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);
    let cs = claims(&pool, f, "group", t, 2).await;
    let (c1, c2) = (cs[0], cs[1]);
    let (e1, e_e1) = linked_evidence(&pool, c1, 1).await[0];

    let e_cc = edge(&pool, LeafNode::claim(c1), LeafNode::claim(c2), "supports").await;
    let e_ef = edge(&pool, LeafNode::evidence(e1), LeafNode::agent(f), "cites").await;
    let r_cc = edge(&pool, LeafNode::claim(c2), LeafNode::claim(c1), "refutes").await;
    let r_ar = edge(&pool, LeafNode::agent(a_r), LeafNode::claim(c1), "AUTHORED").await;
    let r_ef = edge(
        &pool,
        LeafNode::evidence(e1),
        LeafNode::agent(f),
        "mentions",
    )
    .await;

    let live = fits(build(&pool, &system, map, &cs).await);
    assert_eq!(
        stored_ids(&live),
        BTreeSet::from([e_e1, e_cc, e_ef, r_cc, r_ar, r_ef]),
        "calibration: in force, all six are drawn"
    );
    assert!(of_kind(&live, LeafNodeKind::Agent).contains(&a_r));

    for id in [r_cc, r_ar, r_ef] {
        retract_edge(&pool, id).await;
    }
    let set = fits(build(&pool, &system, map, &cs).await);
    assert_within_cap(&set);
    let stored = stored_ids(&set);
    assert!(!stored.contains(&r_cc), "a retracted claim-to-claim edge");
    assert!(!stored.contains(&r_ar), "a retracted authorship edge");
    assert!(
        !stored.contains(&r_ef),
        "a retracted evidence-to-agent edge"
    );
    assert_eq!(stored, BTreeSet::from([e_e1, e_cc, e_ef]));
    let nodes: BTreeSet<LeafNode> = set.nodes.iter().copied().collect();
    assert_eq!(
        nodes,
        BTreeSet::from([
            LeafNode::claim(c1),
            LeafNode::claim(c2),
            LeafNode::agent(f),
            LeafNode::evidence(e1),
        ]),
        "the retracted author is no node"
    );
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

/// Atlas W9's leaf labels (review finding: the tenancy filter was untested).
/// `node_labels` serves an evidence row's raw text, so it must label only
/// the evidence the map may draw, whatever ids the caller passes: team T's
/// map labels T's and public evidence, never team U's; the public map labels
/// public evidence only. Agents carry no tenancy (077) and are labelled by
/// display name on every map.
#[sqlx::test(migrations = "../../migrations")]
async fn node_labels_label_only_the_evidence_the_map_may_draw(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let u = team(&pool, "team-u").await;
    let world = fixture::world_group(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let filer = agent(&pool).await;
    sqlx::query("UPDATE agents SET display_name = 'The Filer' WHERE id = $1")
        .bind(filer)
        .execute(&pool)
        .await
        .unwrap();
    let tc = claims(&pool, filer, "group", t, 1).await[0];
    let uc = claims(&pool, filer, "group", u, 1).await[0];
    let pc = claims(&pool, filer, "public", world, 1).await[0];
    let ev_t = evidence(&pool, tc, 1).await[0];
    let ev_u = evidence(&pool, uc, 1).await[0];
    let ev_p = evidence(&pool, pc, 1).await[0];
    for (ev, text) in [
        (ev_t, "text of t"),
        (ev_u, "text of u"),
        (ev_p, "public text"),
    ] {
        sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
            .bind(ev)
            .bind(text)
            .execute(&pool)
            .await
            .unwrap();
    }
    let all = [ev_t, ev_u, ev_p];
    let mut conn = pool.acquire().await.unwrap();
    let (agents, ev) =
        AtlasLeafRepository::node_labels(&mut conn, &system, AtlasMap::Team(t), &[filer], &all)
            .await
            .expect("node_labels");
    assert_eq!(agents.get(&filer).map(String::as_str), Some("The Filer"));
    assert_eq!(
        ev.into_iter().collect::<Vec<_>>(),
        {
            let mut want = vec![
                (ev_t, "text of t".to_string()),
                (ev_p, "public text".to_string()),
            ];
            want.sort();
            want
        },
        "team T's map labels T's and public evidence only"
    );
    let (agents, ev) =
        AtlasLeafRepository::node_labels(&mut conn, &system, AtlasMap::Public, &[filer], &all)
            .await
            .expect("node_labels");
    assert_eq!(agents.get(&filer).map(String::as_str), Some("The Filer"));
    assert_eq!(
        ev.into_iter().collect::<Vec<_>>(),
        vec![(ev_p, "public text".to_string())],
        "the public map labels public evidence only"
    );
}

/// Atlas W9's cross-group links read: only claim-to-claim edges in force
/// between two of the claims asked for, under the MAP edge rule. Team T's map
/// gets T's own edges and public ones, never one co-owned with another team
/// (the co-owner's members alone cannot read it), never another team's, and
/// never a retracted one or one that touches evidence; the public map gets
/// public edges only.
#[sqlx::test(migrations = "../../migrations")]
async fn map_claim_links_return_only_claim_edges_the_map_may_draw(pool: PgPool) {
    let t = team(&pool, "team-t").await;
    let u = team(&pool, "team-u").await;
    let world = fixture::world_group(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let filer = agent(&pool).await;
    let tc = claims(&pool, filer, "group", t, 3).await;
    let uc = claims(&pool, filer, "group", u, 1).await[0];
    let pc = claims(&pool, filer, "public", world, 1).await[0];
    let c = LeafNode::claim;
    // In: T's own edge (070 stamps it T's from its endpoints).
    edge(&pool, c(tc[0]), c(tc[1]), "supports").await;
    // In on both maps: a public edge.
    let public = edge(&pool, c(tc[0]), c(pc), "elaborates").await;
    sqlx::query("UPDATE edges SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(public)
        .bind(world)
        .execute(&pool)
        .await
        .unwrap();
    // Out: co-owned by T and U.
    let co = edge(&pool, c(tc[1]), c(tc[2]), "refutes").await;
    force_edge(&pool, co, t, Some(u)).await;
    // Out: owned by U, between two of T's claims.
    let other = edge(&pool, c(tc[2]), c(tc[0]), "supports").await;
    force_edge(&pool, other, u, None).await;
    // Out: retracted.
    let gone = edge(&pool, c(tc[1]), c(tc[0]), "cites").await;
    retract_edge(&pool, gone).await;
    // Out: evidence to a claim, and a claim edge to a claim not asked for.
    evidence(&pool, tc[0], 1).await;
    edge(&pool, c(tc[0]), c(uc), "supports").await;

    let ids = [tc[0], tc[1], tc[2], pc];
    let mut conn = pool.acquire().await.unwrap();
    let mut team_links =
        AtlasLeafRepository::map_claim_links(&mut conn, &system, AtlasMap::Team(t), &ids)
            .await
            .expect("map_claim_links");
    team_links.sort();
    let mut want = vec![
        (tc[0], tc[1], "supports".to_string()),
        (tc[0], pc, "elaborates".to_string()),
    ];
    want.sort();
    assert_eq!(
        team_links, want,
        "team T's map: its own and public edges only"
    );
    let public_links =
        AtlasLeafRepository::map_claim_links(&mut conn, &system, AtlasMap::Public, &ids)
            .await
            .expect("map_claim_links");
    assert_eq!(
        public_links,
        vec![(tc[0], pc, "elaborates".to_string())],
        "the public map: public edges only"
    );
    // Team U's map, asked about T's claims, gets U's edge but never the
    // co-owned one: U's members alone cannot read it either.
    let u_links = AtlasLeafRepository::map_claim_links(&mut conn, &system, AtlasMap::Team(u), &ids)
        .await
        .expect("map_claim_links");
    assert!(
        u_links.iter().all(|(s, tg, _)| (*s, *tg) != (tc[1], tc[2])),
        "a co-owned edge on the co-owner's map: {u_links:?}"
    );
    assert!(u_links.contains(&(tc[2], tc[0], "supports".to_string())));
}

//! Atlas leaf flow weights (Atlas W7, backlog 7a03f5e4), on a fresh database
//! per test.
//!
//! Every leaf is built the way the nightly build builds it: a transaction
//! opened by `AtlasMapRepository::begin_build_snapshot` on the
//! `#[sqlx::test]` pool (a BYPASSRLS superuser, the maintenance stand-in) with
//! a BYPASS viewer, W3's `AtlasLeafRepository::build_leaf`, then W7's
//! `build_leaf_flow_edges` on the same transaction. Rows are seeded by direct
//! inserts on the superuser pool; tenancy that migration 070's triggers would
//! stamp otherwise is forced by UPDATE, and every forced stamp is checked.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_atlas_contract::{
    Edge, FlowBasis, Hierarchy, LeafLevel, LevelDocument, MapScope, Node, PlainNode, Switch,
    SCHEMA_VERSION,
};
use epigraph_db::repos::atlas_leaf::{
    LeafEdge, LeafEdgeOrigin, LeafNode, LeafNodeKind, LeafNodeSet, LeafOutcome,
};
use epigraph_db::repos::atlas_map::AtlasMap;
use epigraph_db::{AtlasFlowRepository, AtlasLeafRepository, AtlasMapRepository, DbError, Viewer};
use epigraph_engine::atlas_flow::build_leaf_flow_edges;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const CAP: usize = 100;

// ===========================================================================
// Seeding
// ===========================================================================

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

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed membership");
}

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

/// One claim filed by `filer`, declared `(visibility, owner)`, with a cached
/// belief so the invariance test has something to move. The values are exact
/// binary fractions, so a mutation probe can scale a weight by a belief
/// factor that is exactly 1 on them (and only the invariance assertion sees
/// it).
async fn claim(pool: &PgPool, filer: Uuid, visibility: &str, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, belief, plausibility, \
                             pignistic_prob, open_world_mass) \
         VALUES (gen_random_uuid(), 'flow claim ' || gen_random_uuid()::text, \
                 decode(md5(random()::text) || md5(random()::text), 'hex'), 0.5, $1, true, \
                 $2, $3, 0.25, 0.75, 0.5, 0.125) \
         RETURNING id",
    )
    .bind(filer)
    .bind(visibility)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// An evidence row on `claim` (by `claim_id`); 070 stamps the claim's
/// tenancy on it.
async fn evidence_row(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
         VALUES ($1, 'document', decode(md5(random()::text) || md5(random()::text), 'hex')) \
         RETURNING id",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

/// A stored edge, tenancy as 070's trigger stamps it from the endpoints.
async fn edge(
    pool: &PgPool,
    (source_kind, source): (&str, Uuid),
    (target_kind, target): (&str, Uuid),
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(source)
    .bind(source_kind)
    .bind(target)
    .bind(target_kind)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn claim_edge(pool: &PgPool, a: Uuid, b: Uuid, rel: &str, props: serde_json::Value) -> Uuid {
    edge(pool, ("claim", a), ("claim", b), rel, props).await
}

async fn evidence_edge(pool: &PgPool, ev: Uuid, c: Uuid, rel: &str) -> Uuid {
    edge(pool, ("evidence", ev), ("claim", c), rel, json!({})).await
}

/// A public frame of `n` hypotheses.
async fn frame(pool: &PgPool, n: usize) -> Uuid {
    let hyps: Vec<String> = (0..n).map(|i| format!("h{i}")).collect();
    sqlx::query_scalar("INSERT INTO frames (name, hypotheses) VALUES ($1, $2) RETURNING id")
        .bind(format!("atlas-flow-{}", Uuid::new_v4()))
        .bind(&hyps)
        .fetch_one(pool)
        .await
        .expect("seed frame")
}

async fn claim_frame(pool: &PgPool, claim: Uuid, frame: Uuid, index: i32) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, $3)",
    )
    .bind(claim)
    .bind(frame)
    .bind(index)
    .execute(pool)
    .await
    .expect("seed claim_frames");
}

/// A perspective row with id `id`, as an edge-keyed or evidence-keyed BBA
/// needs for its `perspective_id`.
async fn perspective(pool: &PgPool, id: Uuid, owner: Uuid, world: Uuid) {
    sqlx::query(
        "INSERT INTO perspectives (id, name, owner_agent_id, perspective_type, visibility, \
                                   owner_group_id) \
         VALUES ($1, 'atlas-flow', $2, 'evidence', 'public', $3)",
    )
    .bind(id)
    .bind(owner)
    .bind(world)
    .execute(pool)
    .await
    .expect("seed perspective");
}

/// A BBA on `claim`; tenancy inherited from the claim.
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    source_agent: Uuid,
    perspective: Option<Uuid>,
    evidence: Option<Uuid>,
    masses: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, evidence_id, source_strength) \
         VALUES ($1, $2, $3, $4, $5, $6, 0.5) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(source_agent)
    .bind(perspective)
    .bind(masses)
    .bind(evidence)
    .fetch_one(pool)
    .await
    .expect("seed bba")
}

/// Force a BBA's owner to `group` (a writer-owned row, migration 114).
async fn force_bba_owner(pool: &PgPool, id: Uuid, group: Uuid) {
    let n = sqlx::query(
        "UPDATE mass_functions SET visibility = 'group', owner_group_id = $2, writer_owned = true \
         WHERE id = $1",
    )
    .bind(id)
    .bind(group)
    .execute(pool)
    .await
    .expect("force bba owner")
    .rows_affected();
    assert_eq!(n, 1);
    let got: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read bba owner");
    assert_eq!(got, ("group".to_string(), group), "the forced stamp held");
}

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

async fn force_edge_owner(pool: &PgPool, id: Uuid, owner: Uuid) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .execute(pool)
    .await
    .expect("force edge owner")
    .rows_affected();
    assert_eq!(n, 1);
}

async fn retract_bba(pool: &PgPool, id: Uuid, by: Uuid) {
    let n = sqlx::query(
        "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                retract_reason = 'atlas flow test' WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .execute(pool)
    .await
    .expect("retract bba")
    .rows_affected();
    assert_eq!(n, 1);
}

// ===========================================================================
// Building
// ===========================================================================

/// The build path: W3's leaf and W7's weights on one snapshot transaction.
async fn build(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    ids: &[Uuid],
) -> (LeafNodeSet, Vec<Edge>) {
    let mut tx = pool.begin().await.expect("begin the build");
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .expect("begin_build_snapshot");
    let set = match AtlasLeafRepository::build_leaf(&mut tx, viewer, map, ids, CAP)
        .await
        .expect("build_leaf")
    {
        LeafOutcome::Fits(set) => set,
        other => panic!("expected Fits, got {other:?}"),
    };
    let edges = build_leaf_flow_edges(&mut tx, viewer, map, &set)
        .await
        .expect("build_leaf_flow_edges");
    tx.commit().await.expect("commit");
    (set, edges)
}

fn find<'e>(edges: &'e [Edge], source: Uuid, target: Uuid, rel: &str) -> &'e Edge {
    edges
        .iter()
        .find(|e| e.source == source && e.target == target && e.relationship == rel)
        .unwrap_or_else(|| panic!("no {rel} edge {source} -> {target} in {edges:#?}"))
}

/// (sign, weight, basis) of one edge.
fn swb(e: &Edge) -> (i8, f64, FlowBasis) {
    (e.sign, e.flow_weight, e.flow_basis)
}

/// The leaf as a v1 level document: W3's nodes, placeholder labels and
/// positions, W7's edges.
fn document(set: &LeafNodeSet, edges: Vec<Edge>, map: AtlasMap) -> LevelDocument {
    let nodes = set
        .nodes
        .iter()
        .map(|n| {
            let plain = PlainNode {
                id: n.id,
                label: "node".into(),
                x: 0.0,
                y: 0.0,
            };
            match n.kind {
                LeafNodeKind::Claim => Node::Claim(epigraph_atlas_contract::ClaimNode {
                    id: n.id,
                    label: "claim".into(),
                    x: 0.0,
                    y: 0.0,
                    truth_value: None,
                }),
                LeafNodeKind::Agent => Node::Agent(plain),
                LeafNodeKind::Evidence => Node::Evidence(plain),
            }
        })
        .collect();
    let (map_scope, map_group_id) = match map {
        AtlasMap::Public => (MapScope::Public, None),
        AtlasMap::Team(t) => (MapScope::Team, Some(t)),
    };
    LevelDocument::Leaf(LeafLevel {
        schema_version: SCHEMA_VERSION,
        map_scope,
        map_group_id,
        hierarchy: Hierarchy::Meaning,
        theme_id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        level_id: Uuid::new_v4(),
        depth: 0,
        name: Some("leaf".into()),
        needs_naming: false,
        breadcrumbs: Vec::new(),
        switch: Switch {
            hierarchy: Hierarchy::Links,
            level_id: Uuid::new_v4(),
        },
        nodes,
        edges,
        outgoing: Vec::new(),
    })
}

// ===========================================================================
// The invariance test
// ===========================================================================

/// THE INVARIANCE TEST. A claim-to-claim weight is the link's strength times
/// its sign and nothing else: moving every belief value on both endpoints of
/// every proxy edge (the cached belief, plausibility, BetP, truth_value and
/// open-world mass; every claim BBA; the edge-keyed BBA on each target and its
/// reliability) leaves every proxy weight bit-identical. Calibrated twice:
/// the proxy weights are non-zero from a stored strength and from the
/// engine's factor, with both signs, so a multiplicative belief factor would
/// show; and one evidence BBA moved too, and its exact weight did move, so
/// the rebuild really re-read the rows.
#[sqlx::test(migrations = "../../migrations")]
async fn proxy_weights_do_not_move_when_any_belief_moves(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let world = fixture::world_group(&pool).await;
    let f = agent(&pool).await;
    let x = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);
    let binary = frame(&pool, 2).await;

    let a = claim(&pool, f, "group", t).await;
    let b = claim(&pool, f, "group", t).await;
    let c = claim(&pool, f, "public", world).await;
    let links = [
        claim_edge(&pool, a, b, "supports", json!({"strength": 0.37})).await,
        claim_edge(&pool, b, c, "supports", json!({})).await,
        claim_edge(&pool, c, a, "contradicts", json!({})).await,
        claim_edge(&pool, a, c, "refutes", json!({"strength": 0.45})).await,
        claim_edge(&pool, b, a, "elaborates", json!({})).await,
    ];
    let ev = evidence_row(&pool, a).await;
    evidence_edge(&pool, ev, a, "supports").await;
    perspective(&pool, ev, x, world).await;
    bba(
        &pool,
        a,
        binary,
        x,
        Some(ev),
        Some(ev),
        json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;

    // Every claim's own BBA, and the edge-keyed BBA each link would wire on
    // its target.
    for &claim in &[a, b, c] {
        bba(
            &pool,
            claim,
            binary,
            f,
            None,
            None,
            json!({"0": 0.3, "0,1": 0.7}),
        )
        .await;
    }
    let targets = [b, c, a, c, a];
    for (&link, &target) in links.iter().zip(&targets) {
        perspective(&pool, link, x, world).await;
        bba(
            &pool,
            target,
            binary,
            x,
            Some(link),
            None,
            json!({"0": 0.2, "0,1": 0.8}),
        )
        .await;
    }

    let (_, before) = build(&pool, &system, map, &[a, b, c]).await;
    let proxy = |edges: &[Edge]| -> Vec<(Uuid, Uuid, String, i8, u64)> {
        edges
            .iter()
            .filter(|e| e.flow_basis == FlowBasis::Proxy)
            .map(|e| {
                (
                    e.source,
                    e.target,
                    e.relationship.clone(),
                    e.sign,
                    e.flow_weight.to_bits(),
                )
            })
            .collect()
    };
    // Calibration: both paths, both signs, non-zero.
    assert_eq!(
        swb(find(&before, a, b, "supports")),
        (1, 0.37, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&before, b, c, "supports")),
        (1, 0.80, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&before, c, a, "contradicts")),
        (-1, 0.90, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&before, a, c, "refutes")),
        (-1, 0.45, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&before, b, a, "elaborates")),
        (1, 0.60, FlowBasis::Proxy)
    );
    assert_eq!(proxy(&before).len(), 5);
    assert_eq!(
        swb(find(&before, ev, a, "supports")),
        (1, 0.6, FlowBasis::Exact)
    );

    // Move every belief value on every endpoint.
    let moved = sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.95, pignistic_prob = 0.92, \
                           truth_value = 0.88, open_world_mass = 0.01 \
         WHERE id = ANY($1)",
    )
    .bind(vec![a, b, c])
    .execute(&pool)
    .await
    .expect("move the cached beliefs")
    .rows_affected();
    assert_eq!(moved, 3);
    let moved = sqlx::query(
        "UPDATE mass_functions SET masses = '{\"0\": 0.97, \"0,1\": 0.03}'::jsonb, \
                                   source_strength = 0.99 \
         WHERE claim_id = ANY($1)",
    )
    .bind(vec![a, b, c])
    .execute(&pool)
    .await
    .expect("move every BBA")
    .rows_affected();
    assert_eq!(moved, 9, "3 claim BBAs, 5 edge-keyed BBAs, 1 evidence BBA");
    let y = agent(&pool).await;
    for &claim in &[a, b, c] {
        bba(
            &pool,
            claim,
            binary,
            y,
            None,
            None,
            json!({"1": 0.8, "0,1": 0.2}),
        )
        .await;
    }

    let (_, after) = build(&pool, &system, map, &[a, b, c]).await;
    assert_eq!(
        proxy(&after),
        proxy(&before),
        "a proxy weight moved with a belief"
    );
    // Calibration: the rebuild re-read the rows.
    assert_eq!(
        swb(find(&after, ev, a, "supports")),
        (1, 0.97, FlowBasis::Exact)
    );
}

// ===========================================================================
// Exact masses
// ===========================================================================

/// Exact masses on a fixture with known BBAs: the mass on the singleton the
/// edge names, the claim's own hypothesis index honoured, the largest of
/// several live rows, a retracted row and a row on a three-hypothesis frame
/// ignored even though larger, and a cached fold row (no evidence) ignored.
#[sqlx::test(migrations = "../../migrations")]
async fn exact_masses_on_a_fixture_with_known_bbas(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let f = agent(&pool).await;
    let (x, y, z) = (agent(&pool).await, agent(&pool).await, agent(&pool).await);
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);
    let binary = frame(&pool, 2).await;
    let flipped = frame(&pool, 2).await;
    let ternary = frame(&pool, 3).await;

    let a = claim(&pool, f, "group", t).await;
    let b = claim(&pool, f, "group", t).await;
    // On `flipped`, the claim is hypothesis 1: supported is {1}.
    claim_frame(&pool, a, flipped, 1).await;
    claim_frame(&pool, a, ternary, 1).await;

    let e1 = evidence_row(&pool, a).await;
    evidence_edge(&pool, e1, a, "supports").await;
    for (agent_id, masses) in [
        (x, json!({"1": 0.63, "0": 0.1, "0,1": 0.27})),
        (y, json!({"1": 0.41, "0,1": 0.59})),
    ] {
        bba(&pool, a, flipped, agent_id, None, Some(e1), masses).await;
    }
    let retracted = bba(
        &pool,
        a,
        flipped,
        z,
        None,
        Some(e1),
        json!({"1": 0.95, "0,1": 0.05}),
    )
    .await;
    retract_bba(&pool, retracted, z).await;
    bba(
        &pool,
        a,
        ternary,
        x,
        None,
        Some(e1),
        json!({"1": 0.99, "0,1,2": 0.01}),
    )
    .await;

    let e2 = evidence_row(&pool, b).await;
    evidence_edge(&pool, e2, b, "refutes").await;
    bba(
        &pool,
        b,
        binary,
        x,
        None,
        Some(e2),
        json!({"1": 0.27, "0,1": 0.73}),
    )
    .await;
    // A cached fold row on b: no evidence, never an evidence mass.
    bba(
        &pool,
        b,
        binary,
        y,
        None,
        None,
        json!({"1": 0.99, "0,1": 0.01}),
    )
    .await;

    let (_, edges) = build(&pool, &system, map, &[a, b]).await;
    assert_eq!(
        swb(find(&edges, e1, a, "supports")),
        (1, 0.63, FlowBasis::Exact)
    );
    assert_eq!(
        swb(find(&edges, e2, b, "refutes")),
        (-1, 0.27, FlowBasis::Exact)
    );
}

// ===========================================================================
// Audience
// ===========================================================================

/// A mass row the map's audience cannot read never contributes. A public
/// claim, a public evidence row and a public edge are on every map; team U's
/// writer-owned BBA (0.9) and team T's (0.4) hang on them. The public map
/// reads neither (the edge has no usable mass: `none`), T's map reads T's
/// only, U's map U's only, and a viewer in both teams building T's map is
/// still held to T's rows by the map predicate.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mass_row_the_audience_cannot_read_does_not_contribute(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let u = team(&pool, "flow-u").await;
    let world = fixture::world_group(&pool).await;
    let f = agent(&pool).await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let (_scoped, system) = fixture::bypass(&pool).await;
    let binary = frame(&pool, 2).await;

    let p = claim(&pool, f, "public", world).await;
    let ev = evidence_row(&pool, p).await;
    force_evidence_public(&pool, ev, world).await;
    evidence_edge(&pool, ev, p, "supports").await;
    let of_u = bba(
        &pool,
        p,
        binary,
        x,
        None,
        Some(ev),
        json!({"0": 0.9, "0,1": 0.1}),
    )
    .await;
    force_bba_owner(&pool, of_u, u).await;
    let of_t = bba(
        &pool,
        p,
        binary,
        y,
        None,
        Some(ev),
        json!({"0": 0.4, "0,1": 0.6}),
    )
    .await;
    force_bba_owner(&pool, of_t, t).await;

    let (_, public) = build(&pool, &system, AtlasMap::Public, &[p]).await;
    assert_eq!(
        swb(find(&public, ev, p, "supports")),
        (0, 0.0, FlowBasis::None)
    );
    let (_, on_t) = build(&pool, &system, AtlasMap::Team(t), &[p]).await;
    assert_eq!(
        swb(find(&on_t, ev, p, "supports")),
        (1, 0.4, FlowBasis::Exact)
    );
    let (_, on_u) = build(&pool, &system, AtlasMap::Team(u), &[p]).await;
    assert_eq!(
        swb(find(&on_u, ev, p, "supports")),
        (1, 0.9, FlowBasis::Exact)
    );

    let m = agent(&pool).await;
    add_member(&pool, t, m).await;
    add_member(&pool, u, m).await;
    let both = Viewer::resolve(&pool, m).await.expect("viewer");
    let (_, scoped_t) = build(&pool, &both, AtlasMap::Team(t), &[p]).await;
    assert_eq!(
        swb(find(&scoped_t, ev, p, "supports")),
        (1, 0.4, FlowBasis::Exact)
    );
}

/// The frame and the hypothesis index an exact mass is read through are held
/// to the map's audience too. On a public claim with public evidence: a
/// public BBA on a public frame (0.7 on hypothesis 0, 0.2 on 1), team U's
/// index row saying the claim is hypothesis 1 of that frame, and a second
/// public BBA (0.95 on hypothesis 0) on a frame team U owns. The public map
/// and T's map read neither of U's rows: index 0, U's frame ignored, 0.7
/// (reading U's index would give 0.2, reading U's frame 0.95). U's map reads
/// both, and the larger is 0.95.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_or_hypothesis_index_the_audience_cannot_read_is_not_used(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let u = team(&pool, "flow-u").await;
    let world = fixture::world_group(&pool).await;
    let f = agent(&pool).await;
    let x = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let binary = frame(&pool, 2).await;
    let of_u = frame(&pool, 2).await;
    let n =
        sqlx::query("UPDATE frames SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
            .bind(of_u)
            .bind(u)
            .execute(&pool)
            .await
            .expect("force frame owner")
            .rows_affected();
    assert_eq!(n, 1);

    let p = claim(&pool, f, "public", world).await;
    let ev = evidence_row(&pool, p).await;
    force_evidence_public(&pool, ev, world).await;
    evidence_edge(&pool, ev, p, "supports").await;
    claim_frame(&pool, p, binary, 1).await;
    let n = sqlx::query(
        "UPDATE claim_frames SET visibility = 'group', owner_group_id = $3 \
         WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(p)
    .bind(binary)
    .bind(u)
    .execute(&pool)
    .await
    .expect("force claim_frames owner")
    .rows_affected();
    assert_eq!(n, 1);
    bba(
        &pool,
        p,
        binary,
        x,
        None,
        Some(ev),
        json!({"0": 0.7, "1": 0.2, "0,1": 0.1}),
    )
    .await;
    bba(
        &pool,
        p,
        of_u,
        x,
        None,
        Some(ev),
        json!({"0": 0.95, "0,1": 0.05}),
    )
    .await;
    let stamps: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM mass_functions WHERE claim_id = $1",
    )
    .bind(p)
    .fetch_all(&pool)
    .await
    .expect("read bba stamps");
    assert!(stamps.iter().all(|(v, _)| v == "public"), "{stamps:?}");

    for map in [AtlasMap::Public, AtlasMap::Team(t)] {
        let (_, edges) = build(&pool, &system, map, &[p]).await;
        assert_eq!(
            swb(find(&edges, ev, p, "supports")),
            (1, 0.7, FlowBasis::Exact),
            "{map:?}"
        );
    }
    let (_, on_u) = build(&pool, &system, AtlasMap::Team(u), &[p]).await;
    assert_eq!(
        swb(find(&on_u, ev, p, "supports")),
        (1, 0.95, FlowBasis::Exact)
    );
}

// ===========================================================================
// Signs, cites, spellings
// ===========================================================================

/// Contradicting and refuting links come out with sign -1 and the belief
/// engine's own factor (contradicts 0.90, refutes 0.80; the SQL factor table
/// gives both 0), in either spelling; a refuting evidence edge with -1 too.
#[sqlx::test(migrations = "../../migrations")]
async fn contradicts_and_refutes_carry_negative_sign_and_the_engine_factor(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let f = agent(&pool).await;
    let x = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let binary = frame(&pool, 2).await;
    let (a, b, c) = (
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
    );
    claim_edge(&pool, a, b, "contradicts", json!({})).await;
    claim_edge(&pool, b, c, "REFUTES", json!({})).await;
    claim_edge(&pool, c, a, "CONTRADICTS", json!({})).await;
    let ev = evidence_row(&pool, a).await;
    evidence_edge(&pool, ev, a, "REFUTES").await;
    bba(
        &pool,
        a,
        binary,
        x,
        None,
        Some(ev),
        json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;

    let (_, edges) = build(&pool, &system, AtlasMap::Team(t), &[a, b, c]).await;
    assert_eq!(
        swb(find(&edges, a, b, "contradicts")),
        (-1, 0.90, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&edges, b, c, "refutes")),
        (-1, 0.80, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&edges, c, a, "contradicts")),
        (-1, 0.90, FlowBasis::Proxy)
    );
    assert_eq!(
        swb(find(&edges, ev, a, "refutes")),
        (-1, 0.7, FlowBasis::Exact)
    );
}

/// `cites` has no belief direction: sign 0 and weight 0, even when its edge
/// row stores a strength (a weight there would carry a value the link does
/// not transmit). A supports link with the same stored strength shows it.
#[sqlx::test(migrations = "../../migrations")]
async fn cites_weighs_zero_even_with_a_stored_strength(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let f = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let (a, b) = (
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
    );
    claim_edge(&pool, a, b, "cites", json!({"strength": 0.8})).await;
    claim_edge(&pool, b, a, "CITES", json!({})).await;
    claim_edge(&pool, b, a, "supports", json!({"strength": 0.8})).await;

    let (_, edges) = build(&pool, &system, AtlasMap::Team(t), &[a, b]).await;
    assert_eq!(swb(find(&edges, a, b, "cites")), (0, 0.0, FlowBasis::Proxy));
    assert_eq!(swb(find(&edges, b, a, "cites")), (0, 0.0, FlowBasis::Proxy));
    assert_eq!(
        swb(find(&edges, b, a, "supports")),
        (1, 0.8, FlowBasis::Proxy)
    );
}

/// Both spellings of one link collapse into one lower-cased edge carrying
/// the largest weight among the rows the map's audience may read: two of T's
/// rows (0.3 spelled `SUPPORTS`, 0.6 spelled `supports`) give 0.6, and U's row between
/// the same claims (0.9) is not read, so it cannot win the collapse. Two
/// evidence edges, `supports` and `SUPPORTS`, collapse the same way.
#[sqlx::test(migrations = "../../migrations")]
async fn both_spellings_collapse_into_one_lower_cased_edge(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let u = team(&pool, "flow-u").await;
    let f = agent(&pool).await;
    let x = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let binary = frame(&pool, 2).await;
    let (a, b) = (
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
    );
    // The larger weight sorts last (`SUPPORTS` < `supports`), so keeping the
    // first edge of a collapse would show.
    claim_edge(&pool, a, b, "SUPPORTS", json!({"strength": 0.3})).await;
    claim_edge(&pool, a, b, "supports", json!({"strength": 0.6})).await;
    let foreign = claim_edge(&pool, a, b, "supports", json!({"strength": 0.9})).await;
    force_edge_owner(&pool, foreign, u).await;
    let ev = evidence_row(&pool, a).await;
    evidence_edge(&pool, ev, a, "supports").await;
    evidence_edge(&pool, ev, a, "SUPPORTS").await;
    bba(
        &pool,
        a,
        binary,
        x,
        None,
        Some(ev),
        json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;

    let (set, edges) = build(&pool, &system, AtlasMap::Team(t), &[a, b]).await;
    // Calibration: W3 hands over both spellings as separate edges.
    assert_eq!(
        set.edges
            .iter()
            .filter(|e| e.source.id == a && e.target.id == b)
            .count(),
        2
    );
    let ab: Vec<&Edge> = edges
        .iter()
        .filter(|e| e.source == a && e.target == b)
        .collect();
    assert_eq!(ab.len(), 1, "{ab:#?}");
    assert_eq!(ab[0].relationship, "supports");
    assert_eq!(ab[0].flow_weight, 0.6);
    let evs: Vec<&Edge> = edges.iter().filter(|e| e.source == ev).collect();
    assert_eq!(evs.len(), 1, "{evs:#?}");
    assert_eq!(swb(evs[0]), (1, 0.5, FlowBasis::Exact));
}

// ===========================================================================
// The contract
// ===========================================================================

/// Every leaf edge carries a weight and a basis that pass the v1 contract's
/// validation: claim-to-claim links (stored strength, fallback, both signs,
/// cites), evidence edges with masses (both spellings), an authorship edge,
/// the derived filer edge, and a stored claim-to-evidence provenance row
/// (`none`, not re-oriented). Every W3 edge is in the output under its
/// lower-cased name.
#[sqlx::test(migrations = "../../migrations")]
async fn every_weighted_edge_passes_contract_validation(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let f = agent(&pool).await;
    let (x, author) = (agent(&pool).await, agent(&pool).await);
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);
    let binary = frame(&pool, 2).await;
    let (a, b, c) = (
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
    );
    claim_edge(&pool, a, b, "supports", json!({"strength": 0.4})).await;
    claim_edge(&pool, b, c, "contradicts", json!({})).await;
    claim_edge(&pool, c, a, "cites", json!({})).await;
    claim_edge(&pool, a, c, "decomposes_to", json!({})).await;
    edge(
        &pool,
        ("agent", author),
        ("claim", a),
        "AUTHORED",
        json!({}),
    )
    .await;
    let e1 = evidence_row(&pool, a).await;
    evidence_edge(&pool, e1, a, "SUPPORTS").await;
    bba(
        &pool,
        a,
        binary,
        x,
        None,
        Some(e1),
        json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    let e2 = evidence_row(&pool, b).await;
    evidence_edge(&pool, e2, b, "refutes").await;
    edge(
        &pool,
        ("claim", b),
        ("evidence", e2),
        "derived_from",
        json!({}),
    )
    .await;
    bba(
        &pool,
        b,
        binary,
        x,
        None,
        Some(e2),
        json!({"1": 0.2, "0,1": 0.8}),
    )
    .await;

    let (set, edges) = build(&pool, &system, map, &[a, b, c]).await;
    for e in &set.edges {
        let rel = e.relationship.to_ascii_lowercase();
        assert!(
            edges.iter().any(|w| w.source == e.source.id
                && w.target == e.target.id
                && w.relationship == rel),
            "W3 edge {e:?} has no weighted edge"
        );
    }
    assert!(edges.iter().all(|e| (0.0..=1.0).contains(&e.flow_weight)));
    assert_eq!(
        swb(find(&edges, b, e2, "derived_from")),
        (0, 0.0, FlowBasis::None)
    );
    assert_eq!(
        swb(find(&edges, author, a, "authored")),
        (0, 0.0, FlowBasis::None)
    );
    assert_eq!(
        swb(find(&edges, f, a, "asserts")),
        (0, 0.0, FlowBasis::None)
    );
    assert_eq!(
        swb(find(&edges, a, c, "decomposes_to")),
        (0, 0.0, FlowBasis::Proxy)
    );
    let doc = document(&set, edges, map);
    doc.validate()
        .expect("every weighted edge passes the contract");
}

/// An evidence-to-claim edge whose evidence has no mass row the audience can
/// read is `none` (weight 0, sign 0): no mass is invented. The v1 contract
/// refuses that basis for an evidence-to-claim pair, and this pins exactly
/// the rule that would have to change (or W10 must drop the edge).
#[sqlx::test(migrations = "../../migrations")]
async fn an_evidence_edge_with_no_readable_mass_is_none_and_the_contract_refuses_it(pool: PgPool) {
    let t = team(&pool, "flow-t").await;
    let f = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;
    let map = AtlasMap::Team(t);
    let a = claim(&pool, f, "group", t).await;
    let ev = evidence_row(&pool, a).await;
    evidence_edge(&pool, ev, a, "supports").await;

    let (set, edges) = build(&pool, &system, map, &[a]).await;
    assert_eq!(
        swb(find(&edges, ev, a, "supports")),
        (0, 0.0, FlowBasis::None)
    );
    let index = edges
        .iter()
        .position(|e| e.source == ev)
        .expect("the evidence edge");
    let doc = document(&set, edges, map);
    let err = doc
        .validate()
        .expect_err("the contract refuses none for evidence to claim");
    assert_eq!(
        err.0,
        vec![format!(
            "/edges/{index}/flow_basis: an edge from Evidence to Claim has basis Exact, not None"
        )]
    );
}

/// Force a co-owned edge: owner `owner`, co-owner `co_owner`.
async fn force_edge_co_owned(pool: &PgPool, id: Uuid, owner: Uuid, co_owner: Uuid) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .bind(co_owner)
    .execute(pool)
    .await
    .expect("force edge co-owner")
    .rows_affected();
    assert_eq!(n, 1);
}

/// `read_flow_inputs` on `map` for `set` plus one extra claim-to-claim edge
/// `a -> b` carrying the stored row ids `extra`, on a fresh snapshot.
async fn read_with_extra_edge(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    ids: &[Uuid],
    (a, b): (Uuid, Uuid),
    extra: &[Uuid],
) -> Result<epigraph_db::repos::atlas_flow::FlowInputs, DbError> {
    let mut tx = pool.begin().await.expect("begin the build");
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .expect("begin_build_snapshot");
    let mut set = match AtlasLeafRepository::build_leaf(&mut tx, viewer, map, ids, CAP)
        .await
        .expect("build_leaf")
    {
        LeafOutcome::Fits(set) => set,
        other => panic!("expected Fits, got {other:?}"),
    };
    if !extra.is_empty() {
        set.edges.push(LeafEdge {
            source: LeafNode::claim(a),
            target: LeafNode::claim(b),
            relationship: "supports".into(),
            origin: LeafEdgeOrigin::Stored {
                edge_ids: extra.to_vec(),
            },
        });
    }
    let out = AtlasFlowRepository::read_flow_inputs(&mut tx, viewer, map, &set).await;
    tx.rollback().await.expect("rollback");
    out
}

/// The strength read re-applies the leaf's edge rule on its own: a stored
/// claim-to-claim row id the map's audience cannot read is an error, never a
/// strength. W3 never hands it such an id, so the set is built by W3 and then
/// given one: a row another team owns, a row the map's team owns with a
/// co-owner (readable only by members of both, so never baked into one
/// team's map), and, on the public map, a row a team owns. A readable id
/// beside them still reads, so the error is the hidden id's alone.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_link_row_the_map_cannot_read_is_an_error_not_a_strength(pool: PgPool) {
    let world = fixture::world_group(&pool).await;
    let t = team(&pool, "flow-t").await;
    let u = team(&pool, "flow-u").await;
    let f = agent(&pool).await;
    let (_scoped, system) = fixture::bypass(&pool).await;

    // T's map: two of T's claims and one readable link.
    let (a, b) = (
        claim(&pool, f, "group", t).await,
        claim(&pool, f, "group", t).await,
    );
    let readable = claim_edge(&pool, a, b, "supports", json!({"strength": 0.4})).await;
    force_edge_owner(&pool, readable, t).await;
    let other_team = claim_edge(&pool, a, b, "supports", json!({"strength": 0.9})).await;
    force_edge_owner(&pool, other_team, u).await;
    let co_owned = claim_edge(&pool, a, b, "supports", json!({"strength": 0.9})).await;
    force_edge_co_owned(&pool, co_owned, t, u).await;

    let team_map = AtlasMap::Team(t);
    let control = read_with_extra_edge(&pool, &system, team_map, &[a, b], (a, b), &[])
        .await
        .expect("the unmodified leaf reads");
    assert_eq!(
        control.link_strengths.get(&readable),
        Some(&Some(json!(0.4)))
    );
    assert!(!control.link_strengths.contains_key(&other_team));
    assert!(!control.link_strengths.contains_key(&co_owned));
    read_with_extra_edge(&pool, &system, team_map, &[a, b], (a, b), &[readable])
        .await
        .expect("a readable extra id reads");
    for (what, hidden) in [("another team's", other_team), ("a co-owned", co_owned)] {
        let got = read_with_extra_edge(
            &pool,
            &system,
            team_map,
            &[a, b],
            (a, b),
            &[readable, hidden],
        )
        .await;
        assert!(
            matches!(got, Err(DbError::InvalidData { .. })),
            "{what} row on T's map: {got:?}"
        );
    }

    // The public map: two public claims, a public link, and T's row.
    let (c, d) = (
        claim(&pool, f, "public", world).await,
        claim(&pool, f, "public", world).await,
    );
    let public = claim_edge(&pool, c, d, "supports", json!({"strength": 0.4})).await;
    let teams = claim_edge(&pool, c, d, "supports", json!({"strength": 0.9})).await;
    force_edge_owner(&pool, teams, t).await;
    let control = read_with_extra_edge(&pool, &system, AtlasMap::Public, &[c, d], (c, d), &[])
        .await
        .expect("the unmodified public leaf reads");
    assert!(control.link_strengths.contains_key(&public));
    assert!(!control.link_strengths.contains_key(&teams));
    let got =
        read_with_extra_edge(&pool, &system, AtlasMap::Public, &[c, d], (c, d), &[teams]).await;
    assert!(
        matches!(got, Err(DbError::InvalidData { .. })),
        "a team's row on the public map: {got:?}"
    );
}

#![cfg(feature = "db")]
//! The per-team Atlas maps' nested-level routes (Atlas W10, backlog 083c97b9):
//! `GET /api/v1/atlas/maps`, `/maps/:map/themes`,
//! `/maps/:map/:hierarchy/levels/:id` and
//! `/maps/:map/:hierarchy/claims/:claim_id/leaf`.
//!
//! Hermetic `#[sqlx::test]` on a fresh database. `AppState` is built with
//! `with_scoped_pool` on a pool downgraded to the `epigraph_app` role (see
//! [`router`]), so every read runs on a viewer-stamped connection under row
//! security. Runs are written on the
//! superuser pool with a bypass viewer, the nightly's maintenance stand-in.
//!
//! # The world ([`World::seed`])
//!
//! Team A with member M (writer); team B with no member of A; stranger S, in
//! no team. Theme T holds A's claims X1 and X2, the public claim P, and B's
//! claim Z. Evidence E backs X1 (inheriting A's tenancy); M authored X1.
//!
//! A's run holds both hierarchies of T: meaning root RM (group) over meaning
//! leaf LM, and links root RL (group) over links leaf LL; each level's switch
//! leads to its counterpart. LM draws X1, X2, P, Z, the agent M and the
//! evidence E, with edges E->X1, M->X1, X1->X2 and Z->X1. Z is B's: a node A's
//! members cannot read, stored as a builder fault would store it, so the
//! per-viewer filter is what keeps it out. The public run holds PRM over PLM
//! and PRL over PLL, each drawing P.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_atlas_contract::check::{
    assert_indistinguishable, check_claim_leaf_body, check_claim_leaf_not_found, check_level_body,
    check_not_found, ClaimLeafExpected, Expected, Side,
};
use epigraph_atlas_contract::{
    Breadcrumb, Child, ChildKind, ClaimNode, Edge, FlowBasis, GroupLevel, Hierarchy, LeafLevel,
    LevelDocument, MapScope, Node, PlainNode, Switch, BUDGET_GZIP_BYTES, SCHEMA_VERSION,
};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc, NewMapRun};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AtlasMapRepository, AtlasServeRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// ---- plumbing ---------------------------------------------------------------------

/// The kernel as production runs it: a `ScopedPool` whose every connection
/// is downgraded to `epigraph_app`, so the row policies filter each read as
/// well as the in-query viewer predicate. (`fixture::scoped_pool` would run
/// on the superuser DSN `#[sqlx::test]` hands out, where no policy is
/// evaluated.)
async fn router(pool: &PgPool) -> Router {
    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("an epigraph_app ScopedPool");
    let role: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(scoped.inner())
        .await
        .expect("the pool's role");
    assert_eq!(
        role, "epigraph_app",
        "the kernel must read as the application role"
    );
    create_router(AppState::with_scoped_pool(scoped, ApiConfig::default()))
}

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(&["claims:read"], agent)
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn get(router: &Router, path: &str, agent: Uuid) -> Answer {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("authorization", format!("Bearer {}", token(agent)))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Answer {
        status,
        headers,
        body,
    }
}

fn seg(map: AtlasMap) -> String {
    match map {
        AtlasMap::Public => "public".into(),
        AtlasMap::Team(g) => g.to_string(),
    }
}

fn level_path(map: AtlasMap, h: &str, id: Uuid) -> String {
    format!("/api/v1/atlas/maps/{}/{h}/levels/{id}", seg(map))
}

fn leaf_path(map: AtlasMap, h: &str, claim: Uuid) -> String {
    format!("/api/v1/atlas/maps/{}/{h}/claims/{claim}/leaf", seg(map))
}

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

async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('atlas route theme') RETURNING id")
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

async fn set_theme(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
}

/// Re-tenant `ids` in one statement on the superuser pool.
async fn retenant(pool: &PgPool, ids: &[Uuid], owner: Uuid) {
    let n = sqlx::query(
        "UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = ANY($1)",
    )
    .bind(ids)
    .bind(owner)
    .execute(pool)
    .await
    .expect("re-tenant")
    .rows_affected();
    assert_eq!(n, ids.len() as u64);
}

/// One stored level: its hierarchy, parent and document.
struct Stored {
    hierarchy: AtlasHierarchy,
    parent: Option<Uuid>,
    doc: LevelDocument,
}

/// Build and finish one run of `map` holding `levels(run_id)`, on the
/// superuser pool at the epochs a build snapshot reads now.
async fn build_run(pool: &PgPool, map: AtlasMap, levels: impl FnOnce(Uuid) -> Vec<Stored>) -> Uuid {
    let (_scoped, system) = fixture::bypass(pool).await;
    let mut conn = pool.begin().await.expect("begin the build");
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut conn, &system, map)
        .await
        .expect("snapshot");
    let run = AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map,
            algo: "w10-test".into(),
            params: serde_json::json!({}),
            epochs,
        },
    )
    .await
    .expect("write_run");
    for s in levels(run) {
        let (id, theme, depth) = match &s.doc {
            LevelDocument::Group(g) => (g.level_id, g.theme_id, g.depth),
            LevelDocument::Leaf(l) => (l.level_id, l.theme_id, l.depth),
        };
        s.doc
            .validate()
            .expect("a test level is a valid v1 document");
        AtlasMapRepository::put_level(
            &mut conn,
            run,
            &LevelDoc {
                hierarchy: s.hierarchy,
                group_id: id,
                parent_group_id: s.parent,
                theme_id: theme,
                level: i32::from(depth),
                schema_version: 1,
                payload: serde_json::to_value(&s.doc).unwrap(),
            },
        )
        .await
        .expect("put_level");
    }
    AtlasMapRepository::finish_run(&mut conn, run)
        .await
        .expect("finish_run");
    conn.commit().await.expect("commit the build");
    run
}

fn scope_of(map: AtlasMap) -> (MapScope, Option<Uuid>) {
    match map {
        AtlasMap::Public => (MapScope::Public, None),
        AtlasMap::Team(g) => (MapScope::Team, Some(g)),
    }
}

fn h_of(h: AtlasHierarchy) -> Hierarchy {
    match h {
        AtlasHierarchy::Meaning => Hierarchy::Meaning,
        AtlasHierarchy::Links => Hierarchy::Links,
    }
}

struct Ctx {
    map: AtlasMap,
    theme: Uuid,
    run: Uuid,
}

/// A root group level (depth 0) with one leaf child.
fn root(
    c: &Ctx,
    h: AtlasHierarchy,
    id: Uuid,
    name: &str,
    leaf: Uuid,
    claims: u32,
    other: Uuid,
) -> Stored {
    let (map_scope, map_group_id) = scope_of(c.map);
    Stored {
        hierarchy: h,
        parent: None,
        doc: LevelDocument::Group(GroupLevel {
            schema_version: SCHEMA_VERSION,
            map_scope,
            map_group_id,
            hierarchy: h_of(h),
            theme_id: c.theme,
            run_id: c.run,
            level_id: id,
            depth: 0,
            name: Some(name.into()),
            needs_naming: false,
            breadcrumbs: vec![],
            switch: Switch {
                hierarchy: h_of(h).other(),
                level_id: other,
            },
            children: vec![Child {
                id: leaf,
                kind: ChildKind::Leaf,
                name: Some(format!("{name} leaf")),
                needs_naming: false,
                claim_count: claims,
                x: 0.0,
                y: 0.0,
                r: 0.5,
            }],
            bundles: vec![],
            targets: vec![],
        }),
    }
}

fn claim_node(id: Uuid, label: &str, x: f64) -> Node {
    Node::Claim(ClaimNode {
        id,
        label: label.into(),
        x,
        y: 0.1,
        truth_value: Some(0.5),
    })
}

fn edge(source: Uuid, target: Uuid, rel: &str, basis: FlowBasis) -> Edge {
    let (sign, w) = if basis == FlowBasis::Proxy {
        (1, 0.5)
    } else {
        (0, 0.0)
    };
    Edge {
        source,
        target,
        relationship: rel.into(),
        sign,
        flow_weight: w,
        flow_basis: basis,
    }
}

/// A leaf at depth 1 under `parent`.
#[allow(clippy::too_many_arguments)]
fn leaf(
    c: &Ctx,
    h: AtlasHierarchy,
    id: Uuid,
    parent: Uuid,
    other: Uuid,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
) -> Stored {
    let (map_scope, map_group_id) = scope_of(c.map);
    Stored {
        hierarchy: h,
        parent: Some(parent),
        doc: LevelDocument::Leaf(LeafLevel {
            schema_version: SCHEMA_VERSION,
            map_scope,
            map_group_id,
            hierarchy: h_of(h),
            theme_id: c.theme,
            run_id: c.run,
            level_id: id,
            depth: 1,
            name: Some("a leaf".into()),
            needs_naming: false,
            breadcrumbs: vec![Breadcrumb {
                level_id: parent,
                name: Some("root".into()),
                depth: 0,
            }],
            switch: Switch {
                hierarchy: h_of(h).other(),
                level_id: other,
            },
            nodes,
            edges,
            outgoing: vec![],
        }),
    }
}

struct World {
    a: Uuid,
    b: Uuid,
    m: Uuid,
    s: Uuid,
    theme: Uuid,
    x1: Uuid,
    x2: Uuid,
    p: Uuid,
    z: Uuid,
    e: Uuid,
    rm: Uuid,
    lm: Uuid,
    rl: Uuid,
    ll: Uuid,
    prm: Uuid,
    plm: Uuid,
    prl: Uuid,
    pll: Uuid,
    team_run: Uuid,
}

impl World {
    async fn seed(pool: &PgPool) -> World {
        let a = team(pool, "Alpha team").await;
        let b = team(pool, "Beta team").await;
        let (m, _) = fixture::seed_agent_with_group(pool, "atlas-member").await;
        let (s, _) = fixture::seed_agent_with_group(pool, "atlas-stranger").await;
        let (bm, _) = fixture::seed_agent_with_group(pool, "beta-member").await;
        add_member(pool, a, m, "writer").await;
        add_member(pool, b, bm, "writer").await;
        let theme = seed_theme(pool).await;
        let x1 = fixture::seed_group_claim(pool, m, a, "alpha claim one").await;
        let x2 = fixture::seed_group_claim(pool, m, a, "alpha claim two").await;
        let p = fixture::seed_public_claim(pool, m, "a public claim").await;
        let z = fixture::seed_group_claim(pool, bm, b, "beta claim").await;
        for c in [x1, x2, p, z] {
            set_theme(pool, c, theme).await;
        }
        let e = fixture::seed_evidence(pool, x1, "document").await;
        let (rm, lm, rl, ll) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let team_map = AtlasMap::Team(a);
        let team_run = build_run(pool, team_map, |run| {
            let c = Ctx {
                map: team_map,
                theme,
                run,
            };
            vec![
                root(&c, AtlasHierarchy::Meaning, rm, "Alpha meaning", lm, 4, rl),
                leaf(
                    &c,
                    AtlasHierarchy::Meaning,
                    lm,
                    rm,
                    ll,
                    vec![
                        claim_node(x1, "alpha claim one", -0.5),
                        claim_node(x2, "alpha claim two", -0.2),
                        claim_node(p, "a public claim", 0.2),
                        claim_node(z, "beta claim", 0.5),
                        Node::Agent(PlainNode {
                            id: m,
                            label: "an agent".into(),
                            x: 0.0,
                            y: 0.8,
                        }),
                        Node::Evidence(PlainNode {
                            id: e,
                            label: "a measurement".into(),
                            x: 0.0,
                            y: -0.8,
                        }),
                    ],
                    vec![
                        edge(e, x1, "supports", FlowBasis::None),
                        edge(m, x1, "authored", FlowBasis::None),
                        edge(x1, x2, "supports", FlowBasis::Proxy),
                        edge(z, x1, "supports", FlowBasis::Proxy),
                    ],
                ),
                root(&c, AtlasHierarchy::Links, rl, "Alpha links", ll, 3, rm),
                leaf(
                    &c,
                    AtlasHierarchy::Links,
                    ll,
                    rl,
                    lm,
                    vec![
                        claim_node(x1, "alpha claim one", -0.5),
                        claim_node(x2, "alpha claim two", 0.0),
                        claim_node(p, "a public claim", 0.5),
                    ],
                    vec![edge(x1, x2, "supports", FlowBasis::Proxy)],
                ),
            ]
        })
        .await;
        let (prm, plm, prl, pll) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        build_run(pool, AtlasMap::Public, |run| {
            let c = Ctx {
                map: AtlasMap::Public,
                theme,
                run,
            };
            vec![
                root(
                    &c,
                    AtlasHierarchy::Meaning,
                    prm,
                    "Public meaning",
                    plm,
                    1,
                    prl,
                ),
                leaf(
                    &c,
                    AtlasHierarchy::Meaning,
                    plm,
                    prm,
                    pll,
                    vec![claim_node(p, "a public claim", 0.0)],
                    vec![],
                ),
                root(&c, AtlasHierarchy::Links, prl, "Public links", pll, 1, prm),
                leaf(
                    &c,
                    AtlasHierarchy::Links,
                    pll,
                    prl,
                    plm,
                    vec![claim_node(p, "a public claim", 0.0)],
                    vec![],
                ),
            ]
        })
        .await;
        World {
            a,
            b,
            m,
            s,
            theme,
            x1,
            x2,
            p,
            z,
            e,
            rm,
            lm,
            rl,
            ll,
            prm,
            plm,
            prl,
            pll,
            team_run,
        }
    }

    fn team(&self) -> AtlasMap {
        AtlasMap::Team(self.a)
    }
}

fn node_ids(doc: &LevelDocument) -> Vec<Uuid> {
    match doc {
        LevelDocument::Leaf(l) => l.nodes.iter().map(Node::id).collect(),
        LevelDocument::Group(g) => g.children.iter().map(|c| c.id).collect(),
    }
}

fn assert_private(a: &Answer, what: &str) {
    assert_eq!(
        a.headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("private, no-store"),
        "{what}"
    );
}

// ---- the team, public and non-member cases ----------------------------------------

/// A member gets the team map's root and leaf, each a valid v1 document of
/// exactly the map and level asked for, privately.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_gets_the_team_level_and_it_passes_the_contract(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    for id in [w.rm, w.lm] {
        let got = get(&r, &level_path(w.team(), "meaning", id), w.m).await;
        assert_eq!(got.status, StatusCode::OK, "{}", got.text());
        assert_private(&got, "a team level");
        let doc = check_level_body(&got.body, &Expected::team(w.a, id))
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        match doc {
            LevelDocument::Group(g) => {
                assert_eq!(g.run_id, w.team_run);
                assert_eq!(g.children[0].id, w.lm);
            }
            LevelDocument::Leaf(l) => {
                let ids: Vec<Uuid> = l.nodes.iter().map(Node::id).collect();
                for want in [w.x1, w.x2, w.p, w.m, w.e] {
                    assert!(ids.contains(&want), "the leaf draws {want}");
                }
            }
        }
    }
}

/// A non-member (a stranger, and a member of another team) gets the
/// contract's not-found body for every level of the team map, byte for byte
/// the answer for a level that does not exist, and for a map or hierarchy
/// segment that names nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_gets_the_body_of_an_unknown_id(pool: PgPool) {
    let w = World::seed(&pool).await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "beta-outsider").await;
    add_member(&pool, w.b, outsider, "writer").await;
    let r = router(&pool).await;
    for id in [w.rm, w.lm, w.rl, w.ll] {
        let h = if id == w.rm || id == w.lm {
            "meaning"
        } else {
            "links"
        };
        let none = if h == "meaning" { "links" } else { "meaning" };
        let missing = get(&r, &level_path(w.team(), none, id), w.m).await;
        check_not_found(
            Side::Kernel,
            missing.status.as_u16(),
            &missing.body,
            &id.to_string(),
        )
        .unwrap_or_else(|e| panic!("absent {id}: {e:?}"));
        for who in [w.s, outsider] {
            let got = get(&r, &level_path(w.team(), h, id), who).await;
            check_not_found(
                Side::Kernel,
                got.status.as_u16(),
                &got.body,
                &id.to_string(),
            )
            .unwrap_or_else(|e| panic!("non-member {id}: {e:?}"));
            assert_indistinguishable(
                (got.status.as_u16(), &got.body),
                (missing.status.as_u16(), &missing.body),
            );
        }
        for path in [
            format!("/api/v1/atlas/maps/nope/{h}/levels/{id}"),
            format!("/api/v1/atlas/maps/{}/Meaning/levels/{id}", w.a),
            level_path(AtlasMap::Team(w.b), h, id),
        ] {
            let got = get(&r, &path, w.m).await;
            assert_indistinguishable(
                (got.status.as_u16(), &got.body),
                (missing.status.as_u16(), &missing.body),
            );
        }
    }
}

/// The public map is served to a viewer in no team, and to a member, as a
/// public document; its leaf draws the public claim.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_map_is_served_to_a_viewer_with_no_team(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    for who in [w.s, w.m] {
        for (h, id) in [
            ("meaning", w.prm),
            ("meaning", w.plm),
            ("links", w.prl),
            ("links", w.pll),
        ] {
            let got = get(&r, &level_path(AtlasMap::Public, h, id), who).await;
            assert_eq!(got.status, StatusCode::OK, "{}", got.text());
            let doc = check_level_body(&got.body, &Expected::public(id))
                .unwrap_or_else(|e| panic!("{id}: {e:?}"));
            if id == w.plm || id == w.pll {
                assert_eq!(node_ids(&doc), vec![w.p]);
            }
        }
    }
    // A team level asked for under the public map is absent there.
    let got = get(&r, &level_path(AtlasMap::Public, "meaning", w.rm), w.m).await;
    check_not_found(
        Side::Kernel,
        got.status.as_u16(),
        &got.body,
        &w.rm.to_string(),
    )
    .unwrap();
}

/// The switch of every team level leads to the other hierarchy's level for
/// the same theme, and that level is served under the other hierarchy.
#[sqlx::test(migrations = "../../migrations")]
async fn the_switch_leads_to_the_other_hierarchy_of_the_same_theme(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    for (h, id, want) in [
        ("meaning", w.rm, w.rl),
        ("meaning", w.lm, w.ll),
        ("links", w.rl, w.rm),
        ("links", w.ll, w.lm),
    ] {
        let got = get(&r, &level_path(w.team(), h, id), w.m).await;
        let doc = check_level_body(&got.body, &Expected::team(w.a, id)).unwrap();
        let (switch, theme, hierarchy) = match &doc {
            LevelDocument::Group(g) => (g.switch.clone(), g.theme_id, g.hierarchy),
            LevelDocument::Leaf(l) => (l.switch.clone(), l.theme_id, l.hierarchy),
        };
        assert_eq!(switch.level_id, want);
        assert_eq!(switch.hierarchy, hierarchy.other());
        let other_seg = match switch.hierarchy {
            Hierarchy::Meaning => "meaning",
            Hierarchy::Links => "links",
        };
        let other = get(&r, &level_path(w.team(), other_seg, switch.level_id), w.m).await;
        assert_eq!(other.status, StatusCode::OK, "{}", other.text());
        let other = check_level_body(&other.body, &Expected::team(w.a, want)).unwrap();
        let (o_theme, o_h) = match &other {
            LevelDocument::Group(g) => (g.theme_id, g.hierarchy),
            LevelDocument::Leaf(l) => (l.theme_id, l.hierarchy),
        };
        assert_eq!(o_h, hierarchy.other(), "the switch flips the hierarchy");
        assert_eq!(o_theme, theme, "for the same theme");
        assert_eq!(o_theme, w.theme);
    }
}

// ---- staleness ----------------------------------------------------------------------

/// A claim ARRIVING in team A after the build (from M's personal group)
/// leaves the run not current but with nothing left: it is still served.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stale_run_with_nothing_left_is_served(pool: PgPool) {
    let w = World::seed(&pool).await;
    let home: Uuid = sqlx::query_scalar(
        "SELECT g.id FROM groups g JOIN group_memberships gm ON gm.group_id = g.id \
          WHERE gm.agent_id = $1 AND g.kind = 'personal'",
    )
    .bind(w.m)
    .fetch_one(&pool)
    .await
    .unwrap();
    let arrival = fixture::seed_group_claim(&pool, w.m, home, "a new draft").await;
    retenant(&pool, &[arrival], w.a).await;
    // Calibration: the run is now not current and nothing left.
    let (map_epoch, map_left): (i64, i64) =
        sqlx::query_as("SELECT map_epoch, map_left_epoch FROM atlas_map_runs WHERE id = $1")
            .bind(w.team_run)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (n, left_n): (i64, i64) =
        sqlx::query_as("SELECT n, left_n FROM atlas_map_epochs WHERE owner_group_id = $1")
            .bind(w.a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(n > map_epoch, "calibration: the run is not current");
    assert_eq!(left_n, map_left, "calibration: nothing left the map");

    let r = router(&pool).await;
    for (h, id) in [("meaning", w.rm), ("meaning", w.lm), ("links", w.ll)] {
        let got = get(&r, &level_path(w.team(), h, id), w.m).await;
        assert_eq!(got.status, StatusCode::OK, "{id}: {}", got.text());
        check_level_body(&got.body, &Expected::team(w.a, id)).unwrap();
    }
    let maps = get(&r, "/api/v1/atlas/maps", w.m).await.json();
    assert_eq!(maps["maps"].as_array().unwrap().len(), 2, "{maps}");
}

/// A claim LEAVING team A after the build refuses every level of A's map
/// with the not-found body, removes the map from the list and its themes,
/// and the claim-to-leaf answers for it; the public map is unaffected.
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_a_claim_left_is_refused_with_the_not_found_body(pool: PgPool) {
    let w = World::seed(&pool).await;
    retenant(&pool, &[w.x2], w.b).await;
    let r = router(&pool).await;
    for (h, id) in [
        ("meaning", w.rm),
        ("meaning", w.lm),
        ("links", w.rl),
        ("links", w.ll),
    ] {
        let got = get(&r, &level_path(w.team(), h, id), w.m).await;
        check_not_found(
            Side::Kernel,
            got.status.as_u16(),
            &got.body,
            &id.to_string(),
        )
        .unwrap_or_else(|e| panic!("{id}: {e:?} {}", got.text()));
        let other = if h == "meaning" { "links" } else { "meaning" };
        let missing = get(&r, &level_path(w.team(), other, id), w.m).await;
        assert_indistinguishable(
            (got.status.as_u16(), &got.body),
            (missing.status.as_u16(), &missing.body),
        );
        assert!(
            !got.text().contains("left") && !got.text().contains("epoch"),
            "no staleness hint: {}",
            got.text()
        );
    }
    let maps = get(&r, "/api/v1/atlas/maps", w.m).await.json();
    let scopes: Vec<&str> = maps["maps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["scope"].as_str().unwrap())
        .collect();
    assert_eq!(scopes, vec!["public"], "{maps}");
    let themes = get(&r, &format!("/api/v1/atlas/maps/{}/themes", w.a), w.m).await;
    assert_eq!(themes.status, StatusCode::NOT_FOUND);
    let cl = get(&r, &leaf_path(w.team(), "meaning", w.x1), w.m).await;
    check_claim_leaf_not_found(
        Side::Kernel,
        cl.status.as_u16(),
        &cl.body,
        &w.x1.to_string(),
    )
    .unwrap();
    let public = get(&r, &level_path(AtlasMap::Public, "meaning", w.plm), w.m).await;
    assert_eq!(public.status, StatusCode::OK);
}

// ---- the per-viewer filter ----------------------------------------------------------

/// The stored team leaf draws B's claim Z, which A's members cannot read: a
/// member is served the leaf without Z and without its edge, and the result
/// is still a valid document.
#[sqlx::test(migrations = "../../migrations")]
async fn a_leaf_node_the_session_cannot_read_is_not_served(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    let got = get(&r, &level_path(w.team(), "meaning", w.lm), w.m).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let doc = check_level_body(&got.body, &Expected::team(w.a, w.lm)).unwrap();
    let LevelDocument::Leaf(l) = doc else {
        panic!("a leaf")
    };
    assert!(!l.nodes.iter().any(|n| n.id() == w.z), "Z is not served");
    assert!(
        !l.edges.iter().any(|e| e.source == w.z || e.target == w.z),
        "nor is its edge"
    );
    assert!(
        !got.text().contains(&w.z.to_string()) && !got.text().contains("beta claim"),
        "no trace of Z in the body"
    );
    assert_eq!(l.edges.len(), 3, "the other edges stay");
}

// ---- claim to leaf ------------------------------------------------------------------

/// The claim-to-leaf lookup answers with the leaf of the served run, only for
/// a claim the viewer can read on a map the viewer can read, and with one
/// not-found body otherwise.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_to_leaf_returns_only_leaves_the_viewer_can_read(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    let expect = |map: AtlasMap, h: Hierarchy, claim: Uuid| {
        let (map_scope, map_group_id) = scope_of(map);
        ClaimLeafExpected {
            map_scope,
            map_group_id,
            hierarchy: h,
            claim_id: claim,
        }
    };
    for (who, map, h, claim, want) in [
        (w.m, w.team(), "meaning", w.x1, w.lm),
        (w.m, w.team(), "links", w.x2, w.ll),
        (w.m, w.team(), "meaning", w.p, w.lm),
        (w.m, AtlasMap::Public, "meaning", w.p, w.plm),
        (w.s, AtlasMap::Public, "links", w.p, w.pll),
    ] {
        let got = get(&r, &leaf_path(map, h, claim), who).await;
        assert_eq!(got.status, StatusCode::OK, "{}", got.text());
        let hier = if h == "meaning" {
            Hierarchy::Meaning
        } else {
            Hierarchy::Links
        };
        let ans = check_claim_leaf_body(&got.body, &expect(map, hier, claim))
            .unwrap_or_else(|e| panic!("{claim}: {e:?}"));
        assert_eq!(ans.level_id, want);
        assert_eq!(ans.theme_id, w.theme);
        assert_private(&got, "claim to leaf");
    }
    // Refusals, all one body per claim id: Z is on A's stored leaf but A's
    // member cannot read it; a stranger is no member of A; a claim on no
    // leaf (the evidence id is no claim) and a claim asked for under the
    // public map, where it is on no leaf.
    let absent_x1 = get(&r, &leaf_path(AtlasMap::Team(w.b), "meaning", w.x1), w.m).await;
    for (who, map, claim) in [
        (w.m, w.team(), w.z),
        (w.s, w.team(), w.x1),
        (w.m, w.team(), w.e),
        (w.m, AtlasMap::Public, w.x1),
    ] {
        let got = get(&r, &leaf_path(map, "meaning", claim), who).await;
        check_claim_leaf_not_found(
            Side::Kernel,
            got.status.as_u16(),
            &got.body,
            &claim.to_string(),
        )
        .unwrap_or_else(|e| panic!("{claim}: {e:?} {}", got.text()));
        if claim == w.x1 {
            assert_indistinguishable(
                (got.status.as_u16(), &got.body),
                (absent_x1.status.as_u16(), &absent_x1.body),
            );
        }
    }
}

/// `AtlasServeRepository::leaves_of_claim` refuses on its own in-query
/// predicates, with no row policy behind them. The route re-reads the leaf
/// through the per-viewer filter before it answers, and under `epigraph_app`
/// the row policies hide the same rows, so neither the route test above nor
/// the role would notice a lookup that skipped the claim's or the level's
/// visibility predicate. Here the lookup runs on the superuser connection
/// `#[sqlx::test]` hands out (row security bypassed, asserted below), with
/// a member's and a stranger's resolved viewers.
///
/// - M reads X1 and the public P: both are found on LM (the positive control,
///   so "nothing found" cannot pass vacuously).
/// - Z is on A's stored LM, but it is B's: the claim predicate must refuse it.
/// - S reads P, but S is no member of A: the level predicate must refuse A's
///   leaf of it.
#[sqlx::test(migrations = "../../migrations")]
async fn leaves_of_claim_refuses_on_its_own_predicates(pool: PgPool) {
    let w = World::seed(&pool).await;
    let mut conn = pool.acquire().await.expect("a connection");
    let bypasses: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("the session's role");
    assert!(
        bypasses,
        "this arm needs a session no row policy filters, so the in-query predicates are the only guard"
    );
    let m = Viewer::resolve(&pool, w.m).await.expect("M's viewer");
    let s = Viewer::resolve(&pool, w.s).await.expect("S's viewer");
    async fn lookup(pool: &PgPool, w: &World, viewer: &Viewer, claim: Uuid) -> Vec<(Uuid, Uuid)> {
        let mut conn = pool.acquire().await.expect("a connection");
        AtlasServeRepository::leaves_of_claim(
            &mut conn,
            viewer,
            w.team(),
            w.team_run,
            AtlasHierarchy::Meaning,
            claim,
        )
        .await
        .expect("the lookup")
    }
    assert_eq!(
        lookup(&pool, &w, &m, w.x1).await,
        vec![(w.theme, w.lm)],
        "M reads X1"
    );
    assert_eq!(
        lookup(&pool, &w, &m, w.p).await,
        vec![(w.theme, w.lm)],
        "M reads P"
    );
    assert_eq!(
        lookup(&pool, &w, &m, w.z).await,
        Vec::<(Uuid, Uuid)>::new(),
        "B's claim Z is on A's stored leaf; M cannot read Z"
    );
    assert_eq!(
        lookup(&pool, &w, &s, w.p).await,
        Vec::<(Uuid, Uuid)>::new(),
        "S reads P but no level of A's map"
    );
}

// ---- maps and theme roots -----------------------------------------------------------

/// The map list holds exactly the maps the viewer's session reads (team maps
/// first, then the public map); a map's themes carry its root per hierarchy,
/// its root's name and count; a non-member gets the map's not-found body.
#[sqlx::test(migrations = "../../migrations")]
async fn maps_and_themes_list_only_what_the_viewer_reads(pool: PgPool) {
    let w = World::seed(&pool).await;
    let r = router(&pool).await;
    let m = get(&r, "/api/v1/atlas/maps", w.m).await;
    assert_private(&m, "maps");
    let m = m.json();
    let maps = m["maps"].as_array().unwrap();
    assert_eq!(maps.len(), 2, "{m}");
    assert_eq!(maps[0]["scope"], "team");
    assert_eq!(maps[0]["group_id"], w.a.to_string());
    assert_eq!(maps[0]["map"], w.a.to_string());
    assert_eq!(maps[0]["label"], "Alpha team");
    assert_eq!(maps[0]["run_id"], w.team_run.to_string());
    assert_eq!(maps[1]["scope"], "public");
    assert_eq!(maps[1]["group_id"], Value::Null);
    assert_eq!(maps[1]["map"], "public");
    assert!(!m.to_string().contains("epoch") && !m.to_string().contains("nothing_left"));

    let s = get(&r, "/api/v1/atlas/maps", w.s).await.json();
    let scopes: Vec<&str> = s["maps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["scope"].as_str().unwrap())
        .collect();
    assert_eq!(scopes, vec!["public"], "{s}");

    let t = get(&r, &format!("/api/v1/atlas/maps/{}/themes", w.a), w.m).await;
    assert_eq!(t.status, StatusCode::OK, "{}", t.text());
    let t = t.json();
    // `claim_count` is 4 although M cannot read B's claim Z: a theme's count,
    // like a group level's counts, is served as the builder stored it (the
    // `atlas_level` contract's design; the builder's audience rule guards it).
    // Only leaf rows are filtered per viewer. What this test locks in is which
    // MAPS and THEMES a viewer is told about, not a per-viewer count.
    assert_eq!(
        t["themes"],
        serde_json::json!([{
            "theme_id": w.theme,
            "label": "Alpha meaning",
            "claim_count": 4,
            "roots": {"meaning": w.rm, "links": w.rl},
        }])
    );
    let pt = get(&r, "/api/v1/atlas/maps/public/themes", w.s)
        .await
        .json();
    assert_eq!(pt["themes"][0]["roots"]["meaning"], w.prm.to_string());
    assert_eq!(pt["themes"][0]["roots"]["links"], w.prl.to_string());

    // A map the viewer may not read, a group with no map (B) and an id that
    // was never a group: byte for byte the same body once the id asked for
    // is normalised, so a refusal says nothing a missing map would not.
    let never = Uuid::new_v4();
    let denied = get(&r, &format!("/api/v1/atlas/maps/{}/themes", w.a), w.s).await;
    let no_map = get(&r, &format!("/api/v1/atlas/maps/{}/themes", w.b), w.s).await;
    let unknown = get(&r, &format!("/api/v1/atlas/maps/{never}/themes"), w.s).await;
    for (name, a) in [
        ("denied", &denied),
        ("no map", &no_map),
        ("unknown", &unknown),
    ] {
        assert_eq!(a.status, StatusCode::NOT_FOUND, "{name}: {}", a.text());
    }
    assert_eq!(denied.json()["details"]["entity"], "atlas_map");
    assert_eq!(denied.json()["details"]["id"], w.a.to_string());
    let normalised = |a: &Answer, id: Uuid| a.text().replace(&id.to_string(), "<map>");
    assert_eq!(normalised(&denied, w.a), normalised(&no_map, w.b));
    assert_eq!(normalised(&denied, w.a), normalised(&unknown, never));
}

// ---- budget -------------------------------------------------------------------------

/// The largest documents the contract's caps allow, stored for team A with
/// real rows (the worst-case leaf's 100 claim nodes are A's claims, so the
/// per-viewer filter keeps them all), are served whole and within the gzip
/// budget as served.
///
/// This is a calibration, not a guard on the routes: the kernel re-serialises
/// what the builder stored, so its size is set by the contract's caps, and no
/// route change short of padding the body can turn it red. The guard on the
/// bytes on the wire is the Explorer's
/// `a_level_is_compressed_within_budget_when_gzip_is_accepted`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_largest_documents_are_served_within_budget(pool: PgPool) {
    use epigraph_atlas_contract::fixtures::{worst_case_group, worst_case_leaf};
    use std::collections::HashMap;

    let a = team(&pool, "Budget team").await;
    let (m, _) = fixture::seed_agent_with_group(&pool, "budget-member").await;
    add_member(&pool, a, m, "reader").await;
    let theme = seed_theme(&pool).await;

    let mut leaf = worst_case_leaf();
    let mut group = worst_case_group();
    let LevelDocument::Leaf(l) = &mut leaf else {
        unreachable!()
    };
    let mut remap: HashMap<Uuid, Uuid> = HashMap::new();
    for (i, n) in l.nodes.iter().enumerate() {
        let real = fixture::seed_group_claim(&pool, m, a, &format!("budget claim {i}")).await;
        remap.insert(n.id(), real);
    }
    let leaf_id = l.level_id;
    let group_id = match &group {
        LevelDocument::Group(g) => g.level_id,
        LevelDocument::Leaf(_) => unreachable!(),
    };
    let map = AtlasMap::Team(a);
    let run = build_run(&pool, map, |run| {
        let LevelDocument::Leaf(l) = &mut leaf else {
            unreachable!()
        };
        for n in &mut l.nodes {
            if let Node::Claim(c) = n {
                c.id = remap[&c.id];
            }
        }
        for e in &mut l.edges {
            e.source = remap[&e.source];
            e.target = remap[&e.target];
        }
        for o in &mut l.outgoing {
            for s in &mut o.sources {
                *s = remap[s];
            }
        }
        l.map_group_id = Some(a);
        l.theme_id = theme;
        l.run_id = run;
        let LevelDocument::Group(g) = &mut group else {
            unreachable!()
        };
        g.map_group_id = Some(a);
        g.theme_id = theme;
        g.run_id = run;
        let leaf_parent = l.breadcrumbs.last().map(|b| b.level_id);
        let group_parent = g.breadcrumbs.last().map(|b| b.level_id);
        vec![
            Stored {
                hierarchy: AtlasHierarchy::Meaning,
                parent: leaf_parent,
                doc: leaf.clone(),
            },
            Stored {
                hierarchy: AtlasHierarchy::Meaning,
                parent: group_parent,
                doc: group.clone(),
            },
        ]
    })
    .await;
    assert!(!run.is_nil());
    let r = router(&pool).await;
    for (id, nodes) in [(leaf_id, 100usize), (group_id, 128usize)] {
        let got = get(&r, &level_path(map, "meaning", id), m).await;
        assert_eq!(got.status, StatusCode::OK, "{}", got.text());
        let doc = check_level_body(&got.body, &Expected::team(a, id))
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(node_ids(&doc).len(), nodes, "served whole");
        let gz = epigraph_atlas_contract::gzip_len(&got.body);
        assert!(gz <= BUDGET_GZIP_BYTES, "{gz} gzip bytes");
        // Not a trivially small body: the budget is actually exercised.
        assert!(
            gz > BUDGET_GZIP_BYTES / 4,
            "{gz} gzip bytes is not near the budget"
        );
    }
}

// ---- the co-owned overlay (backlog ff3b6046) --------------------------------------

/// A stored edge, tenancy as 070/072's trigger stamps it from the endpoints,
/// with `props` as its properties.
async fn insert_edge(
    pool: &PgPool,
    source: (&str, Uuid),
    target: (&str, Uuid),
    rel: &str,
    props: Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(source.1)
    .bind(source.0)
    .bind(target.1)
    .bind(target.0)
    .bind(rel)
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

/// Force an edge co-owned by `owner` and `co_owner` (as 072's meet stamps an
/// edge across two groups, or a regroup leaves one).
async fn force_co_owned(pool: &PgPool, id: Uuid, owner: Uuid, co_owner: Uuid) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .bind(co_owner)
    .execute(pool)
    .await
    .expect("force co-owned edge")
    .rows_affected();
    assert_eq!(n, 1);
}

/// A public frame of two hypotheses, `claim` at index 0 on it.
async fn binary_frame(pool: &PgPool, claim: Uuid) -> Uuid {
    let frame: Uuid =
        sqlx::query_scalar("INSERT INTO frames (name, hypotheses) VALUES ($1, $2) RETURNING id")
            .bind(format!("atlas-overlay-{}", Uuid::new_v4()))
            .bind(vec!["h0".to_string(), "h1".to_string()])
            .fetch_one(pool)
            .await
            .expect("seed frame");
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim_frames");
    frame
}

/// An evidence-keyed mass row on `claim`; tenancy inherited from the claim.
async fn evidence_mass(pool: &PgPool, claim: Uuid, ev: Uuid, agent: Uuid, masses: Value) -> Uuid {
    let frame = binary_frame(pool, claim).await;
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, evidence_id, \
                                     source_strength) \
         VALUES ($1, $2, $3, $4, $5, 0.5) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(masses)
    .bind(ev)
    .fetch_one(pool)
    .await
    .expect("seed mass row")
}

/// The overlay's world. Teams A, B and C; MA is in A, MB in B, DUAL in A and
/// B, TRI in A, B and C. Public claims P1 and P2 and public evidence EV1 (on
/// P1) and EV2 (on P2) are drawn by one meaning leaf on A's map (LA), on B's
/// map (LB) and on the public map (LP), each storing the same three edges a
/// whole audience reads.
///
/// In the database (all seeded before the runs are built):
/// * `co_ab`  P1 -contradicts-> P2, strength 0.7, owner A, co-owner B;
/// * `co_ba`  P2 -SUPPORTS-> P1, no strength, owner B, co-owner A;
/// * `co_bc`  P1 -corroborates-> P2, owner B, co-owner C (not A's);
/// * `gone`   P2 -refutes-> P1, owner A, co-owner B, retracted;
/// * `ev1e`   EV1 -supports-> P1, owner A, co-owner B, with a public mass
///   row (m({h0}) = 0.6);
/// * `ev2e`   EV2 -refutes-> P2, owner A, co-owner B, whose only mass row
///   (m({h1}) = 0.5) is C's.
struct Overlay {
    a: Uuid,
    b: Uuid,
    ma: Uuid,
    mb: Uuid,
    dual: Uuid,
    tri: Uuid,
    p1: Uuid,
    p2: Uuid,
    ev1: Uuid,
    ev2: Uuid,
    co_ab: Uuid,
    co_ba: Uuid,
    co_bc: Uuid,
    gone: Uuid,
    ev1e: Uuid,
    ev2e: Uuid,
    la: Uuid,
    lb: Uuid,
    lp: Uuid,
    stored: Vec<Edge>,
}

impl Overlay {
    async fn seed(pool: &PgPool) -> Overlay {
        let a = team(pool, "Overlay A").await;
        let b = team(pool, "Overlay B").await;
        let c = team(pool, "Overlay C").await;
        let mut members = Vec::new();
        for (label, groups) in [
            ("overlay-a", vec![a]),
            ("overlay-b", vec![b]),
            ("overlay-ab", vec![a, b]),
            ("overlay-abc", vec![a, b, c]),
        ] {
            let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
            for g in groups {
                add_member(pool, g, agent, "writer").await;
            }
            members.push(agent);
        }
        let (ma, mb, dual, tri) = (members[0], members[1], members[2], members[3]);
        let world = fixture::world_group(pool).await;
        let theme = seed_theme(pool).await;
        let p1 = fixture::seed_public_claim(pool, ma, "overlay public one").await;
        let p2 = fixture::seed_public_claim(pool, ma, "overlay public two").await;
        for p in [p1, p2] {
            set_theme(pool, p, theme).await;
        }
        let ev1 = fixture::seed_evidence(pool, p1, "document").await;
        let ev2 = fixture::seed_evidence(pool, p2, "observation").await;

        let co_ab = insert_edge(
            pool,
            ("claim", p1),
            ("claim", p2),
            "contradicts",
            serde_json::json!({"strength": 0.7}),
        )
        .await;
        force_co_owned(pool, co_ab, a, b).await;
        let co_ba = insert_edge(
            pool,
            ("claim", p2),
            ("claim", p1),
            "SUPPORTS",
            serde_json::json!({}),
        )
        .await;
        force_co_owned(pool, co_ba, b, a).await;
        let co_bc = insert_edge(
            pool,
            ("claim", p1),
            ("claim", p2),
            "corroborates",
            serde_json::json!({}),
        )
        .await;
        force_co_owned(pool, co_bc, b, c).await;
        let gone = insert_edge(
            pool,
            ("claim", p2),
            ("claim", p1),
            "refutes",
            serde_json::json!({}),
        )
        .await;
        force_co_owned(pool, gone, a, b).await;
        let n = sqlx::query(
            "UPDATE edges SET valid_from = now() - interval '2 hours', \
                              valid_to = now() - interval '1 hour' WHERE id = $1",
        )
        .bind(gone)
        .execute(pool)
        .await
        .expect("retract")
        .rows_affected();
        assert_eq!(n, 1);
        let ev1e = insert_edge(
            pool,
            ("evidence", ev1),
            ("claim", p1),
            "supports",
            serde_json::json!({}),
        )
        .await;
        force_co_owned(pool, ev1e, a, b).await;
        let ev2e = insert_edge(
            pool,
            ("evidence", ev2),
            ("claim", p2),
            "refutes",
            serde_json::json!({}),
        )
        .await;
        force_co_owned(pool, ev2e, a, b).await;
        evidence_mass(
            pool,
            p1,
            ev1,
            ma,
            serde_json::json!({"0": 0.6, "1": 0.1, "0,1": 0.3}),
        )
        .await;
        let m2 = evidence_mass(
            pool,
            p2,
            ev2,
            ma,
            serde_json::json!({"0": 0.2, "1": 0.5, "0,1": 0.3}),
        )
        .await;
        let n = sqlx::query(
            "UPDATE mass_functions SET visibility = 'group', owner_group_id = $2, \
                                       writer_owned = true WHERE id = $1",
        )
        .bind(m2)
        .bind(c)
        .execute(pool)
        .await
        .expect("force the mass row to C")
        .rows_affected();
        assert_eq!(n, 1);

        // Calibration: the stamps the test rests on.
        let stamps: Vec<(Uuid, String, Uuid, Option<Uuid>, bool)> = sqlx::query_as(
            "SELECT id, visibility::text, owner_group_id, co_owner_group_id, \
                    (valid_to IS NULL OR valid_to > now()) \
               FROM edges WHERE id = ANY($1) ORDER BY id",
        )
        .bind(vec![co_ab, co_ba, co_bc, gone, ev1e, ev2e])
        .fetch_all(pool)
        .await
        .expect("edge stamps");
        assert_eq!(stamps.len(), 6);
        for (id, vis, owner, co, live) in stamps {
            let want = if id == co_ba {
                (b, Some(a))
            } else if id == co_bc {
                (b, Some(c))
            } else {
                (a, Some(b))
            };
            assert_eq!(vis, "group", "edge {id}");
            assert_eq!((owner, co), want, "edge {id}");
            assert_eq!(live, id != gone, "edge {id}");
        }
        let public: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT visibility::text, owner_group_id FROM claims WHERE id = ANY($1) \
             UNION ALL \
             SELECT visibility::text, owner_group_id FROM evidence WHERE id = ANY($2) \
             UNION ALL \
             SELECT visibility::text, owner_group_id FROM mass_functions \
              WHERE evidence_id = $3",
        )
        .bind(vec![p1, p2])
        .bind(vec![ev1, ev2])
        .bind(ev1)
        .fetch_all(pool)
        .await
        .expect("node stamps");
        assert_eq!(public.len(), 5);
        for (vis, owner) in public {
            assert_eq!((vis.as_str(), owner), ("public", world));
        }

        let stored = vec![
            edge(ev1, p1, "cites", FlowBasis::None),
            edge(ev2, p2, "cites", FlowBasis::None),
            edge(p1, p2, "supports", FlowBasis::Proxy),
        ];
        let nodes = vec![
            claim_node(p1, "overlay public one", -0.5),
            claim_node(p2, "overlay public two", 0.5),
            Node::Evidence(PlainNode {
                id: ev1,
                label: "evidence one".into(),
                x: -0.5,
                y: -0.5,
            }),
            Node::Evidence(PlainNode {
                id: ev2,
                label: "evidence two".into(),
                x: 0.5,
                y: -0.5,
            }),
        ];
        let mut leaves = Vec::new();
        for map in [AtlasMap::Team(a), AtlasMap::Team(b), AtlasMap::Public] {
            let (root_id, leaf_id) = (Uuid::new_v4(), Uuid::new_v4());
            let other = Uuid::new_v4();
            build_run(pool, map, |run| {
                let ctx = Ctx { map, theme, run };
                vec![
                    root(
                        &ctx,
                        AtlasHierarchy::Meaning,
                        root_id,
                        "Overlay",
                        leaf_id,
                        2,
                        other,
                    ),
                    leaf(
                        &ctx,
                        AtlasHierarchy::Meaning,
                        leaf_id,
                        root_id,
                        other,
                        nodes.clone(),
                        stored.clone(),
                    ),
                ]
            })
            .await;
            leaves.push(leaf_id);
        }
        Overlay {
            a,
            b,
            ma,
            mb,
            dual,
            tri,
            p1,
            p2,
            ev1,
            ev2,
            co_ab,
            co_ba,
            co_bc,
            gone,
            ev1e,
            ev2e,
            la: leaves[0],
            lb: leaves[1],
            lp: leaves[2],
            stored,
        }
    }
}

fn flow(
    source: Uuid,
    target: Uuid,
    rel: &str,
    sign: i8,
    flow_weight: f64,
    flow_basis: FlowBasis,
) -> Edge {
    Edge {
        source,
        target,
        relationship: rel.into(),
        sign,
        flow_weight,
        flow_basis,
    }
}

fn sorted(mut edges: Vec<Edge>) -> Vec<Edge> {
    edges.sort_by(|x, y| {
        (x.source, x.target, &x.relationship).cmp(&(y.source, y.target, &y.relationship))
    });
    edges
}

/// The edges of a leaf the route serves `who`: every stored edge first, in
/// stored order, then what the overlay added, sorted.
async fn served_edges(r: &Router, o: &Overlay, map: AtlasMap, leaf: Uuid, who: Uuid) -> Vec<Edge> {
    let got = get(r, &level_path(map, "meaning", leaf), who).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_private(&got, "an overlaid leaf");
    let want = match map {
        AtlasMap::Team(g) => Expected::team(g, leaf),
        AtlasMap::Public => Expected::public(leaf),
    };
    let doc = check_level_body(&got.body, &want).unwrap_or_else(|e| panic!("{leaf}: {e:?}"));
    let LevelDocument::Leaf(l) = doc else {
        panic!("a leaf")
    };
    assert_eq!(
        node_ids(&LevelDocument::Leaf(l.clone())),
        vec![o.p1, o.p2, o.ev1, o.ev2],
        "the overlay adds no node"
    );
    assert_eq!(
        &l.edges[..o.stored.len()],
        &o.stored[..],
        "stored edges first, unchanged"
    );
    sorted(l.edges[o.stored.len()..].to_vec())
}

/// DONE for backlog ff3b6046: a member of BOTH teams that co-own an edge sees
/// it on the leaf, on either team's map, weighed as the nightly weighs a
/// leaf's edges; a member of only one team does not. An edge of two other
/// teams stays off a map, even for a member of all three; a retracted
/// co-owned edge is never drawn; the public map gets nothing; an evidence
/// edge whose mass the viewer cannot read is served `none`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_co_owned_edge_is_drawn_for_a_member_of_both_teams_only(pool: PgPool) {
    use epigraph_engine::atlas_flow::link_strength;
    let o = Overlay::seed(&pool).await;
    let r = router(&pool).await;
    let (a, b) = (AtlasMap::Team(o.a), AtlasMap::Team(o.b));

    let co_ab = flow(o.p1, o.p2, "contradicts", -1, 0.7, FlowBasis::Proxy);
    let co_ba = flow(
        o.p2,
        o.p1,
        "supports",
        1,
        link_strength(None, "supports"),
        FlowBasis::Proxy,
    );
    let co_bc = flow(
        o.p1,
        o.p2,
        "corroborates",
        1,
        link_strength(None, "corroborates"),
        FlowBasis::Proxy,
    );
    let ev1 = flow(o.ev1, o.p1, "supports", 1, 0.6, FlowBasis::Exact);
    let ev2_hidden = flow(o.ev2, o.p2, "refutes", 0, 0.0, FlowBasis::None);
    let ev2_read = flow(o.ev2, o.p2, "refutes", -1, 0.5, FlowBasis::Exact);
    assert!(co_ba.flow_weight > 0.0 && co_bc.flow_weight > 0.0);

    // One team only: the leaf as stored.
    assert_eq!(
        served_edges(&r, &o, a, o.la, o.ma).await,
        vec![],
        "A alone, A's map"
    );
    assert_eq!(
        served_edges(&r, &o, b, o.lb, o.mb).await,
        vec![],
        "B alone, B's map"
    );

    // Both teams: the co-owned edges, on either team's map.
    let both = sorted(vec![co_ab.clone(), co_ba.clone(), ev1.clone(), ev2_hidden]);
    assert_eq!(
        served_edges(&r, &o, a, o.la, o.dual).await,
        both,
        "A and B, A's map"
    );
    assert_eq!(
        served_edges(&r, &o, b, o.lb, o.dual).await,
        both,
        "A and B, B's map"
    );

    // All three teams: B and C's edge is on B's map only; C's mass row is read.
    let on_a = sorted(vec![
        co_ab.clone(),
        co_ba.clone(),
        ev1.clone(),
        ev2_read.clone(),
    ]);
    assert_eq!(
        served_edges(&r, &o, a, o.la, o.tri).await,
        on_a,
        "A, B and C, A's map"
    );
    let on_b = sorted(vec![co_ab, co_ba, co_bc, ev1, ev2_read]);
    assert_eq!(
        served_edges(&r, &o, b, o.lb, o.tri).await,
        on_b,
        "A, B and C, B's map"
    );

    // The public map draws public edges only, whoever asks.
    for who in [o.ma, o.dual, o.tri] {
        assert_eq!(
            served_edges(&r, &o, AtlasMap::Public, o.lp, who).await,
            vec![],
            "the public map"
        );
    }
}

/// `AtlasServeRepository::co_owned_leaf_edges` refuses on its own in-query
/// predicates, with no row policy behind them (the superuser connection
/// `#[sqlx::test]` hands out, asserted below), so the route test above cannot
/// pass on row security alone:
/// - a member of both teams gets exactly the live co-owned edges of team A
///   among the nodes (the positive control), with C's mass row left out;
/// - a member of A alone gets none (the edge splice);
/// - a member of all three does not get B and C's edge on A's map (the team
///   clause), and nobody gets the retracted edge (the in-force clause);
/// - an end matched by id under another kind is no match.
#[sqlx::test(migrations = "../../migrations")]
async fn co_owned_leaf_edges_refuses_on_its_own_predicates(pool: PgPool) {
    use epigraph_db::repos::atlas_leaf::LeafNode;
    let o = Overlay::seed(&pool).await;
    let mut conn = pool.acquire().await.expect("a connection");
    let bypasses: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("the session's role");
    assert!(bypasses, "this arm needs a session no row policy filters");
    let nodes = vec![
        LeafNode::claim(o.p1),
        LeafNode::claim(o.p2),
        LeafNode::evidence(o.ev1),
        LeafNode::evidence(o.ev2),
    ];
    async fn ids(
        conn: &mut sqlx::PgConnection,
        pool: &PgPool,
        who: Uuid,
        team: Uuid,
        nodes: &[LeafNode],
    ) -> (Vec<Uuid>, usize) {
        let viewer = Viewer::resolve(pool, who).await.expect("a viewer");
        let got = AtlasServeRepository::co_owned_leaf_edges(conn, &viewer, team, nodes)
            .await
            .expect("the overlay read");
        let mut ids: Vec<Uuid> = got
            .set
            .edges
            .iter()
            .flat_map(|e| match &e.origin {
                epigraph_db::repos::atlas_leaf::LeafEdgeOrigin::Stored { edge_ids } => {
                    edge_ids.clone()
                }
                other => panic!("an overlay edge is stored, not {other:?}"),
            })
            .collect();
        ids.sort_unstable();
        (ids, got.inputs.evidence_masses.len())
    }
    let mut want = vec![o.co_ab, o.co_ba, o.ev1e, o.ev2e];
    want.sort_unstable();
    assert_eq!(
        ids(&mut conn, &pool, o.dual, o.a, &nodes).await,
        (want.clone(), 1),
        "A and B: A's live co-owned edges; EV1's public mass row only"
    );
    assert_eq!(
        ids(&mut conn, &pool, o.ma, o.a, &nodes).await,
        (vec![], 0),
        "A alone reads no co-owned edge"
    );
    let (tri_a, tri_mass) = ids(&mut conn, &pool, o.tri, o.a, &nodes).await;
    assert_eq!((tri_a, tri_mass), (want, 2), "A, B and C on A's map");
    let (tri_b, _) = ids(&mut conn, &pool, o.tri, o.b, &nodes).await;
    assert!(tri_b.contains(&o.co_bc), "B and C's edge is on B's map");
    assert!(!tri_b.contains(&o.gone), "the retracted edge is never read");
    // P1 named as an agent: no edge at P1 matches.
    let wrong_kind = vec![
        LeafNode::agent(o.p1),
        LeafNode::claim(o.p2),
        LeafNode::evidence(o.ev1),
        LeafNode::evidence(o.ev2),
    ];
    assert_eq!(
        ids(&mut conn, &pool, o.tri, o.a, &wrong_kind).await,
        (vec![o.ev2e], 1),
        "an id under another kind is no match"
    );
}

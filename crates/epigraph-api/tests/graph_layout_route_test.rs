#![cfg(feature = "db")]
//! `GET /api/v1/graph/themes/layout`, `GET /api/v1/graph/links` and the
//! `layout` block of `GET /api/v1/claims/:id/placement` (Atlas P3a,
//! migration 197).
//!
//! Hermetic `#[sqlx::test]`. `AppState` is built with `with_scoped_pool`, so
//! every handler reads on a viewer-stamped connection. Layout rows are written
//! AFTER every claim and edge, at the current epoch: forcing a row from public
//! to private is a narrowing and would invalidate an earlier run.
//!
//! # The world
//!
//! Owner O with group G; stranger S with no groups. Themes T1 and T2 sit in
//! regions RA (centroid e0) and RB (e1). T3 has no layout row: its only
//! member is O's private Y (embedding e0), so it is viewer-placed into RA for
//! O and absent for S. Public P1 (T1) `supports` public P2 (T2), strength 0.8;
//! O's private X (T1) `contradicts` P2. Region RC holds T5, whose only member
//! is superseded, so nobody sees RC. Layout links: T1-T2 `supports: 1` and
//! `decomposes_to: 1`.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::repos::atlas_layout::{
    LayoutBuild, LayoutLinkOut, LayoutRegionOut, LayoutThemeOut,
};
use epigraph_db::AtlasLayoutRepository;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DIM: usize = 1536;

async fn router(pool: &PgPool) -> Router {
    create_router(AppState::with_scoped_pool(
        fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(&["claims:read"], agent)
}

async fn raw(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder().method(Method::GET).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).into())
}

async fn get(router: &Router, path: &str, bearer: &str) -> (StatusCode, Value, String) {
    let (status, _, text) = raw(router, path, Some(bearer)).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

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

async fn claim_in(
    pool: &PgPool,
    agent: Uuid,
    group: Option<Uuid>,
    theme: Uuid,
    content: &str,
    axis: Option<usize>,
) -> Uuid {
    let id = match group {
        None => fixture::seed_public_claim(pool, agent, content).await,
        Some(g) => fixture::seed_group_claim(pool, agent, g, content).await,
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

async fn edge_with(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    properties: Value,
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
    .expect("seed edge");
    id
}

/// A layout run at the current epoch: `regions` are `(id, axis)` 300 apart;
/// `themes` are `(theme, region)`, ranked in the order given per region.
async fn write_layout(
    pool: &PgPool,
    regions: &[(Uuid, usize)],
    themes: &[(Uuid, Uuid)],
    links: &[(Uuid, Uuid, &str, i64)],
) -> Uuid {
    let epoch: i64 = sqlx::query_scalar("SELECT n FROM atlas_layout_epoch")
        .fetch_one(pool)
        .await
        .unwrap();
    let mut ranks = std::collections::BTreeMap::<Uuid, i32>::new();
    let build = LayoutBuild {
        algo: "pca2-ward-v1".into(),
        params: serde_json::json!({}),
        cluster_run_id: None,
        visibility_epoch: epoch,
        public_claim_count: 0,
        public_link_count: 0,
        theme_set_digest: "0".repeat(64),
        regions: regions
            .iter()
            .enumerate()
            .map(|(i, (id, axis))| LayoutRegionOut {
                id: *id,
                ordinal: i32::try_from(i).unwrap(),
                label: format!("Region {i}"),
                x: -300.0 + 300.0 * i as f64,
                y: 12.5,
                r: 120.0,
                centroid: basis_f32(*axis),
            })
            .collect(),
        themes: themes
            .iter()
            .map(|(t, r)| {
                let k = ranks.entry(*r).or_insert(0);
                let out = LayoutThemeOut {
                    theme_id: *t,
                    region_id: *r,
                    rank_in_region: *k,
                    x: -290.5 + f64::from(*k),
                    y: 20.25,
                    public_member_count: 1,
                };
                *k += 1;
                out
            })
            .collect(),
        theme_links: links
            .iter()
            .map(|(a, b, rel, n)| LayoutLinkOut {
                theme_a: *a.min(b),
                theme_b: *a.max(b),
                relationship: (*rel).to_string(),
                link_count: *n,
            })
            .collect(),
    };
    let mut conn = pool.acquire().await.unwrap();
    AtlasLayoutRepository::write_run(&mut conn, &build)
        .await
        .expect("write run")
}

struct World {
    owner: Uuid,
    group: Uuid,
    t1: Uuid,
    t2: Uuid,
    t3: Uuid,
    t6: Option<Uuid>,
    p1: Uuid,
    p2: Uuid,
    x: Uuid,
    y: Uuid,
    ra: Uuid,
    rb: Uuid,
    rc: Uuid,
}

async fn atlas_world(pool: &PgPool, with_t6: bool) -> World {
    let (owner, group) = fixture::seed_agent_with_group(pool, "atlas-owner").await;
    let t1 = seed_theme(pool, "Stern capacitance").await;
    let t2 = seed_theme(pool, "Double layers").await;
    let t3 = seed_theme(pool, "My lab notes").await;
    let t5 = seed_theme(pool, "Retired theme").await;
    let p1 = claim_in(pool, owner, None, t1, "public claim one", Some(0)).await;
    let p2 = claim_in(pool, owner, None, t2, "public claim two", Some(1)).await;
    let x = claim_in(pool, owner, Some(group), t1, "private claim x", Some(0)).await;
    let y = claim_in(pool, owner, Some(group), t3, "private claim y", Some(0)).await;
    let gone = claim_in(pool, owner, None, t5, "superseded claim", Some(2)).await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(gone)
        .execute(pool)
        .await
        .unwrap();
    edge_with(
        pool,
        p1,
        p2,
        "supports",
        serde_json::json!({"strength": 0.8}),
    )
    .await;
    edge_with(pool, x, p2, "contradicts", serde_json::json!({})).await;
    let t6 = if with_t6 {
        let t6 = seed_theme(pool, "Hidden theme").await;
        claim_in(pool, owner, Some(group), t6, "private claim in t6", Some(0)).await;
        Some(t6)
    } else {
        None
    };
    let (ra, rb, rc) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut themes = vec![(t1, ra), (t2, rb), (t5, rc)];
    if let Some(t6) = t6 {
        themes.push((t6, ra));
    }
    write_layout(
        pool,
        &[(ra, 0), (rb, 1), (rc, 2)],
        &themes,
        &[(t1, t2, "supports", 1), (t1, t2, "decomposes_to", 1)],
    )
    .await;
    World {
        owner,
        group,
        t1,
        t2,
        t3,
        t6,
        p1,
        p2,
        x,
        y,
        ra,
        rb,
        rc,
    }
}

fn region<'a>(body: &'a Value, id: Uuid) -> &'a Value {
    body["regions"]
        .as_array()
        .expect("regions")
        .iter()
        .find(|r| r["id"] == id.to_string())
        .unwrap_or_else(|| panic!("region {id} missing from {body}"))
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_str().expect("id").to_string())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn both_routes_require_a_bearer(pool: PgPool) {
    let app = router(&pool).await;
    for path in [
        "/api/v1/graph/themes/layout".to_string(),
        format!(
            "/api/v1/graph/links?from={}&to={}",
            Uuid::new_v4(),
            Uuid::new_v4()
        ),
    ] {
        let (status, _, _) = raw(&app, &path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_layout_run_is_an_empty_200(pool: PgPool) {
    let app = router(&pool).await;
    let (status, body, _) = get(&app, "/api/v1/graph/themes/layout", &token(Uuid::new_v4())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["run"], Value::Null);
    assert_eq!(body["status"], "no_layout_run");
    assert_eq!(body["regions"], serde_json::json!([]));
    assert_eq!(body["next"]["themes"], Value::Null);
    let (status, _, _) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?run_id={}", Uuid::new_v4()),
        &token(Uuid::new_v4()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an explicit unknown run_id");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_narrowed_row_turns_the_layout_off(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(w.p2)
        .bind(w.group)
        .execute(&pool)
        .await
        .unwrap();
    let app = router(&pool).await;
    let (s, o) = (token(Uuid::new_v4()), token(w.owner));
    for t in [&s, &o] {
        for path in [
            "/api/v1/graph/themes/layout".to_string(),
            format!("/api/v1/graph/themes/layout?region_id={}", w.ra),
        ] {
            let (status, body, _) = get(&app, &path, t).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["status"], "layout_invalidated", "{body}");
            assert_eq!(body["run"], Value::Null);
            assert_eq!(body["regions"], serde_json::json!([]));
            assert_eq!(body["next"]["themes"], Value::Null);
            assert!(body.get("counts").is_none());
        }
        let (status, body, _) = get(
            &app,
            &format!("/api/v1/graph/links?from={}&to={}", w.ra, w.rb),
            t,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "layout_invalidated");
        assert_eq!(body["items"], serde_json::json!([]));
    }
    // Theme-to-theme drill-downs need no run and are served live. O reads
    // both members; S can no longer read any member of T2, which is the
    // ordinary 404.
    let (status, body, _) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t2),
        &o,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], Value::Null);
    assert_eq!(body["total"], 2);
    let (status, _, _) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t2),
        &s,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn responses_are_private_and_uncacheable(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let t = token(w.owner);
    for path in [
        "/api/v1/graph/themes/layout".to_string(),
        format!("/api/v1/graph/themes/layout?region_id={}", w.ra),
        format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t2),
    ] {
        let (status, headers, body) = raw(&app, &path, Some(&t)).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(headers["cache-control"], "private, no-store", "{path}");
        assert_eq!(headers["vary"], "Authorization", "{path}");
        assert!(headers.get("etag").is_none(), "{path}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn default_relationships_exclude_structure_and_flags_add_it(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let t = token(w.owner);
    let bundle = |body: &Value| -> Value {
        body["links"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["kind"] == "region")
            .map(|l| l["counts"].clone())
            .unwrap_or(Value::Null)
    };
    let (_, body, _) = get(&app, "/api/v1/graph/themes/layout", &t).await;
    assert_eq!(bundle(&body), serde_json::json!({"supports": 1}));
    assert!(!ids(&body["relationships"]).contains(&"decomposes_to".to_string()));
    for q in ["include_structure=true", "rel=*"] {
        let (_, body, _) = get(&app, &format!("/api/v1/graph/themes/layout?{q}"), &t).await;
        assert_eq!(
            bundle(&body),
            serde_json::json!({"decomposes_to": 1, "supports": 1}),
            "{q}: {body}"
        );
    }
    let (status, _, _) = get(&app, "/api/v1/graph/themes/layout?rel=a;b", &t).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The tenancy test: two viewers in different groups, a private claim
/// invisible to the outsider, and no count, id, label or existence signal
/// leaking across groups through either route.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_sees_no_private_claim_no_private_id_and_no_revealing_count(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let s = token(Uuid::new_v4());
    let o = token(w.owner);

    // 1. Top level.
    let (st, top, top_text) = get(&app, "/api/v1/graph/themes/layout", &s).await;
    assert_eq!(st, StatusCode::OK, "{top}");
    let ra = region(&top, w.ra);
    assert_eq!(ra["member_count"], 1, "{top}");
    assert_eq!(ra["theme_count"], 1);
    assert_eq!(ids(&ra["theme_ids"]), vec![w.t1.to_string()]);
    assert_eq!(top["unplaced_theme_count"], 0);
    assert_eq!(
        top["regions"].as_array().unwrap().len(),
        2,
        "RC is nobody's"
    );
    let links = top["links"].as_array().unwrap();
    assert_eq!(links.len(), 1, "{top}");
    assert_eq!(links[0]["counts"], serde_json::json!({"supports": 1}));
    assert_eq!(links[0]["total"], 1);
    // For contrast, O.
    let (_, otop, _) = get(&app, "/api/v1/graph/themes/layout", &o).await;
    let ora = region(&otop, w.ra);
    assert_eq!(ora["member_count"], 3, "P1, X and Y: {otop}");
    assert_eq!(ora["theme_count"], 2);
    assert_eq!(
        ids(&ora["theme_ids"]),
        vec![w.t1.to_string(), w.t3.to_string()]
    );

    // 2. Unplaced.
    let (st, unplaced, unplaced_text) =
        get(&app, "/api/v1/graph/themes/layout?region_id=unplaced", &s).await;
    assert_eq!(st, StatusCode::OK, "{unplaced}");
    assert_eq!(unplaced["themes"], serde_json::json!([]));
    assert_eq!(unplaced["region"], Value::Null);

    // 3. Region RA.
    let (st, ra_page, ra_text) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={}", w.ra),
        &s,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{ra_page}");
    let themes = ra_page["themes"].as_array().unwrap();
    assert_eq!(themes.len(), 1, "{ra_page}");
    assert_eq!(themes[0]["id"], w.t1.to_string());
    assert_eq!(themes[0]["member_count"], 1);
    assert_eq!(themes[0]["placement"], "shared");

    // 4. The drill-down.
    let (st, drill, drill_text) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t2),
        &s,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{drill}");
    let items = drill["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["source"]["id"], w.p1.to_string());
    assert_eq!(items[0]["target"]["id"], w.p2.to_string());
    assert_eq!(items[0]["direction"], "from_to");
    assert_eq!(items[0]["strength"], 0.8);
    assert_eq!(drill["counts"], serde_json::json!({"supports": 1}));
    assert_eq!(drill["total"], 1);

    // 5. A hidden theme is the same 404 as a random id.
    let (st5, _, body5) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t3, w.t1),
        &s,
    )
    .await;
    let random = Uuid::new_v4();
    let (st_r, _, body_random) = get(
        &app,
        &format!("/api/v1/graph/links?from={random}&to={}", w.t1),
        &s,
    )
    .await;
    assert_eq!(st5, StatusCode::NOT_FOUND, "{body5}");
    assert_eq!(st_r, StatusCode::NOT_FOUND);
    assert_eq!(
        body5.replace(&w.t3.to_string(), "<id>"),
        body_random.replace(&random.to_string(), "<id>")
    );

    // 6. Substring scan.
    for (name, text) in [
        ("top", &top_text),
        ("unplaced", &unplaced_text),
        ("region", &ra_text),
        ("links", &drill_text),
        ("404", &body5),
    ] {
        assert!(!text.contains(&w.x.to_string()), "{name} names X: {text}");
        assert!(!text.contains(&w.y.to_string()), "{name} names Y: {text}");
        assert!(!text.contains("private claim"), "{name}: {text}");
        assert!(!text.contains("My lab notes"), "{name}: {text}");
        if name != "404" {
            assert!(!text.contains(&w.t3.to_string()), "{name} names T3: {text}");
            assert!(!text.contains(&w.rc.to_string()), "{name} names RC: {text}");
        }
    }

    // Then O.
    let (_, odrill, _) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t2),
        &o,
    )
    .await;
    assert_eq!(odrill["items"].as_array().unwrap().len(), 2, "{odrill}");
    assert_eq!(odrill["counts"]["contradicts"], 1);
    assert_eq!(odrill["total"], 2);
    let (_, ora_page, _) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={}", w.ra),
        &o,
    )
    .await;
    let othemes = ora_page["themes"].as_array().unwrap();
    assert_eq!(othemes.len(), 2, "{ora_page}");
    assert_eq!(othemes[1]["id"], w.t3.to_string());
    assert_eq!(othemes[1]["placement"], "viewer");
}

#[sqlx::test(migrations = "../../migrations")]
async fn positions_are_identical_for_every_viewer(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let (_, s, _) = get(&app, "/api/v1/graph/themes/layout", &token(Uuid::new_v4())).await;
    let (_, o, _) = get(&app, "/api/v1/graph/themes/layout", &token(w.owner)).await;
    for r in [w.ra, w.rb] {
        let (a, b) = (region(&s, r), region(&o, r));
        for k in ["x", "y", "r", "label"] {
            assert_eq!(a[k], b[k], "{k}");
        }
    }
    assert_eq!(s["run"], o["run"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn viewer_placed_theme_reaches_only_its_reader(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let path = format!("/api/v1/graph/themes/layout?region_id={}", w.ra);
    let (_, o, _) = get(&app, &path, &token(w.owner)).await;
    let t3 = o["themes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == w.t3.to_string())
        .expect("T3 for O");
    assert_eq!(t3["placement"], "viewer");
    assert_eq!(t3["x"], Value::Null);
    assert_eq!(t3["y"], Value::Null);
    assert_eq!(t3["region_id"], w.ra.to_string());

    let (_, s, s_text) = get(&app, &path, &token(Uuid::new_v4())).await;
    assert!(!s_text.contains(&w.t3.to_string()));
    assert_eq!(s["region"]["theme_count"], 1);
    assert_eq!(s["region"]["member_count"], 1);

    let (status, place, _) = get(
        &app,
        &format!("/api/v1/claims/{}/placement", w.y),
        &token(w.owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{place}");
    assert_eq!(place["layout"]["placement"], "viewer");
    assert_eq!(place["layout"]["region_id"], w.ra.to_string());
    assert_eq!(place["layout"]["x"], Value::Null);
}

#[sqlx::test(migrations = "../../migrations")]
async fn region_404_is_the_same_for_unknown_and_invisible(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let s = token(Uuid::new_v4());
    let random = Uuid::new_v4();
    let (st_rc, _, body_rc) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={}", w.rc),
        &s,
    )
    .await;
    let (st_r, _, body_r) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={random}"),
        &s,
    )
    .await;
    assert_eq!(st_rc, StatusCode::NOT_FOUND, "{body_rc}");
    assert_eq!(st_r, StatusCode::NOT_FOUND);
    assert_eq!(
        body_rc.replace(&w.rc.to_string(), "<id>"),
        body_r.replace(&random.to_string(), "<id>")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_route_hidden_theme_against_its_region_is_the_plain_404(pool: PgPool) {
    let w = atlas_world(&pool, true).await;
    let t6 = w.t6.expect("T6");
    let app = router(&pool).await;
    let s = token(Uuid::new_v4());
    let (st, _, body) = get(
        &app,
        &format!("/api/v1/graph/links?from={t6}&to={}", w.ra),
        &s,
    )
    .await;
    let random = Uuid::new_v4();
    let (st_r, _, body_r) = get(
        &app,
        &format!("/api/v1/graph/links?from={random}&to={}", w.ra),
        &s,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "not the overlap 400: {body}");
    assert_eq!(st_r, StatusCode::NOT_FOUND);
    assert_eq!(
        body.replace(&t6.to_string(), "<id>"),
        body_r.replace(&random.to_string(), "<id>")
    );
    let (st_o, _, body_o) = get(
        &app,
        &format!("/api/v1/graph/links?from={t6}&to={}", w.ra),
        &token(w.owner),
    )
    .await;
    assert_eq!(st_o, StatusCode::BAD_REQUEST, "overlap for O: {body_o}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn layout_lists_cap_at_200_and_page_by_cursor(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "atlas-cap").await;
    let ra = Uuid::new_v4();
    let mut themes = Vec::new();
    for i in 0..205 {
        let t = seed_theme(&pool, &format!("Theme {i:03}")).await;
        claim_in(&pool, agent, None, t, &format!("cap claim {i}"), None).await;
        themes.push((t, ra));
    }
    write_layout(&pool, &[(ra, 0)], &themes, &[]).await;
    let app = router(&pool).await;
    let s = token(Uuid::new_v4());
    let (_, top, _) = get(&app, "/api/v1/graph/themes/layout", &s).await;
    let r = region(&top, ra);
    assert_eq!(r["theme_ids"].as_array().unwrap().len(), 200);
    assert_eq!(r["theme_count"], 205);

    let (_, p1, _) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={ra}"),
        &s,
    )
    .await;
    assert_eq!(p1["themes"].as_array().unwrap().len(), 200);
    let next = p1["next"]["themes"].as_str().expect("a cursor").to_string();
    let (st, p2, _) = get(
        &app,
        &format!("/api/v1/graph/themes/layout?region_id={ra}&themes_after={next}"),
        &s,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{p2}");
    assert_eq!(p2["themes"].as_array().unwrap().len(), 5);
    assert_eq!(p2["next"]["themes"], Value::Null);
    let mut seen: std::collections::BTreeSet<String> = ids(&p1["themes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].clone())
        .collect::<Value>())
    .into_iter()
    .collect();
    for t in p2["themes"].as_array().unwrap() {
        assert!(seen.insert(t["id"].as_str().unwrap().to_string()));
    }
    assert_eq!(seen.len(), 205);

    for bad in [
        format!(
            "/api/v1/graph/themes/layout?region_id={ra}&themes_after={next}&links_after={next}"
        ),
        format!("/api/v1/graph/themes/layout?region_id={ra}&themes_after=garbage"),
        "/api/v1/graph/themes/layout?themes_after=lt2.1.00000000000000000000000000000000"
            .to_string(),
        "/api/v1/graph/themes/layout?limit=abc".to_string(),
        "/api/v1/graph/themes/layout?region_id=nope".to_string(),
    ] {
        let (st, _, _) = raw(&app, &bad, Some(&s)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_route_rejects_same_side(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let (st, _, _) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}", w.t1, w.t1),
        &token(w.owner),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _, _) = get(&app, "/api/v1/graph/links", &token(w.owner)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_route_caps_and_walks(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    edge_with(&pool, w.p2, w.p1, "cites", serde_json::json!({})).await;
    let app = router(&pool).await;
    let o = token(w.owner);
    let (st, all, _) = get(
        &app,
        &format!("/api/v1/graph/links?from={}&to={}&limit=500", w.t1, w.t2),
        &o,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{all}");
    assert_eq!(all["items"].as_array().unwrap().len(), 3);
    assert!(all["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["direction"] == "to_from"));

    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    let mut page_no = 0;
    loop {
        let mut path = format!("/api/v1/graph/links?from={}&to={}&limit=1", w.t1, w.t2);
        if let Some(a) = &after {
            path.push_str(&format!("&after={a}"));
        }
        let (st, page, _) = get(&app, &path, &o).await;
        assert_eq!(st, StatusCode::OK, "{page}");
        if page_no == 0 {
            assert_eq!(
                page["counts"],
                serde_json::json!({"cites": 1, "contradicts": 1, "supports": 1})
            );
        } else {
            assert_eq!(page["counts"], Value::Null, "counts on page 1 only");
        }
        assert_eq!(page["total"], 3, "total on every page");
        for i in page["items"].as_array().unwrap() {
            seen.push(i["edge_id"].as_str().unwrap().to_string());
        }
        page_no += 1;
        match page["next"].as_str() {
            Some(n) => after = Some(n.to_string()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 3);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "each edge once");
}

#[sqlx::test(migrations = "../../migrations")]
async fn bodies_stay_under_two_megabytes_at_the_cap(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "atlas-big").await;
    let t7 = seed_theme(&pool, "Big source").await;
    let t8 = seed_theme(&pool, "Big target").await;
    for i in 0..200 {
        let a = claim_in(
            &pool,
            agent,
            None,
            t7,
            &format!("{i} {}", "a".repeat(20_000)),
            None,
        )
        .await;
        let b = claim_in(
            &pool,
            agent,
            None,
            t8,
            &format!("{i} {}", "b".repeat(20_000)),
            None,
        )
        .await;
        edge_with(&pool, a, b, "supports", serde_json::json!({})).await;
    }
    let app = router(&pool).await;
    let (st, _, text) = raw(
        &app,
        &format!("/api/v1/graph/links?from={t7}&to={t8}&limit=200"),
        Some(&token(Uuid::new_v4())),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 200);
    assert!(text.len() < 2 * 1024 * 1024, "{} bytes", text.len());
    let label = body["items"][0]["source"]["label"].as_str().unwrap();
    assert!(label.chars().count() <= 160);
}

#[sqlx::test(migrations = "../../migrations")]
async fn placement_carries_the_layout_position(pool: PgPool) {
    let w = atlas_world(&pool, false).await;
    let app = router(&pool).await;
    let s = token(Uuid::new_v4());
    let (st, body, _) = get(&app, &format!("/api/v1/claims/{}/placement", w.p1), &s).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["layout"]["placement"], "shared");
    assert_eq!(body["layout"]["region_id"], w.ra.to_string());
    assert_eq!(body["layout"]["x"], -290.5);
    assert_eq!(body["layout"]["y"], 20.25);
    let (st, _, _) = get(&app, &format!("/api/v1/claims/{}/placement", w.y), &s).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(w.p2)
        .bind(w.group)
        .execute(&pool)
        .await
        .unwrap();
    let (st, body, _) = get(&app, &format!("/api/v1/claims/{}/placement", w.p1), &s).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body["layout"],
        Value::Null,
        "an invalidated run places nothing"
    );
}

//! The Atlas fixture preview (`--atlas-fixture-preview`, backlog W11): off by
//! default, loopback only, serving the committed synthetic levels byte for
//! byte by map, hierarchy and id, and mounting nothing that reaches the API.
//! Also the `data-atlas-maps` helper W10's page tests use.

mod common;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use common::atlas_contract::{check_level_body, check_not_found, fixture_value, Expected, Side};
use common::atlas_maps::{attr_value, check_atlas_maps_attr};
use epigraph_explorer::atlas_maps::{level_path, AtlasMaps};
use epigraph_explorer::atlas_preview::{
    self, check_bind, parse_bind, preview_bind, PreviewError, PreviewStore, FLAG, MAPS_PREFIX,
    PAGE_PATH, PREVIEW_HEADER, PREVIEW_HEADER_VALUE,
};
use epigraph_explorer::upstream::atlas_level::{Hierarchy, MapScope};
use epigraph_explorer::AppState;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const PREVIEW_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/contract/atlas_level/v1/preview"
);

fn preview_router() -> Router {
    let addr: SocketAddr = "127.0.0.1:8097".parse().unwrap();
    let config = atlas_preview::config(addr).expect("the preview config is valid");
    let state = AppState::new(config).expect("state builds");
    atlas_preview::router(state, Arc::new(PreviewStore::embedded()))
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

async fn get(router: &Router, path: &str) -> Res {
    let resp = router
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 16 << 20).await.unwrap().to_vec();
    Res {
        status,
        headers,
        body,
    }
}

/// The committed preview lines, by level id, as bytes.
fn committed_lines() -> BTreeMap<Uuid, String> {
    let raw = std::fs::read_to_string(format!("{PREVIEW_DIR}/levels.jsonl")).unwrap();
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (
                Uuid::parse_str(v["level_id"].as_str().unwrap()).unwrap(),
                l.to_string(),
            )
        })
        .collect()
}

fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{PREVIEW_DIR}/manifest.json")).unwrap())
        .unwrap()
}

/// The map list the preview page carries, checked with the W10 helper.
async fn page_maps(router: &Router) -> AtlasMaps {
    let page = get(router, PAGE_PATH).await;
    assert_eq!(page.status, StatusCode::OK);
    let raw = attr_value(&page.text(), "data-atlas-maps").expect("the page carries the map list");
    check_atlas_maps_attr(&raw).unwrap_or_else(|e| panic!("data-atlas-maps: {e:#?}"))
}

fn hierarchy(v: &Value) -> Hierarchy {
    serde_json::from_value(v.clone()).unwrap()
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

// ---- off by default --------------------------------------------------------------

#[tokio::test]
async fn the_preview_is_off_by_default() {
    // No flag, or other arguments only: the normal Explorer.
    assert_eq!(preview_bind(&args(&[])), Ok(None));
    assert_eq!(preview_bind(&args(&["--port", "8097"])), Ok(None));
    assert_eq!(
        preview_bind(&args(&["--atlas-fixture-previewx", "8097"])),
        Ok(None)
    );

    // The normal app never serves a preview route, even for an id the preview
    // itself serves.
    let preview = preview_router();
    let (id, _) = committed_lines().into_iter().next().unwrap();
    let level = PreviewStore::embedded().path_of(id).unwrap();
    assert_eq!(get(&preview, &level).await.status, StatusCode::OK);
    assert_eq!(get(&preview, PAGE_PATH).await.status, StatusCode::OK);

    let app = common::spawn().await;
    let sid = app.sign_in("tok");
    for path in [
        level.clone(),
        format!("/explorer{level}"),
        PAGE_PATH.to_string(),
        format!("/explorer{PAGE_PATH}"),
    ] {
        for res in [app.get(&path).await, app.get_as(&path, &sid).await] {
            assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}: {}", res.body);
            assert!(res.header(PREVIEW_HEADER).is_none(), "{path}");
            assert!(!res.body.contains("\"schema_version\""), "{path}");
        }
    }
    // And the real Atlas page carries no preview data.
    let page = app.get_as("/explorer/atlas", &sid).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("data-atlas-maps"));
    assert!(!page.body.contains("data-level-prefix"));
    assert!(!page.body.contains("atlas-preview-banner"));
}

// ---- loopback only ---------------------------------------------------------------

#[test]
fn the_preview_refuses_a_non_loopback_bind() {
    for bad in [
        "0.0.0.0:8097",
        "[::]:8097",
        "192.168.1.20:8097",
        "10.0.0.1:8097",
        "172.17.0.1:8097",
        "100.64.0.1:8097",
        "[fe80::1]:8097",
        "[::ffff:10.0.0.1]:8097",
    ] {
        assert!(
            matches!(parse_bind(bad), Err(PreviewError::NotLoopback(_))),
            "{bad} must be refused: {:?}",
            parse_bind(bad)
        );
    }
    for bad in [
        "localhost:8097",
        "example.com:80",
        "0.0.0.0",
        "8097x",
        "70000",
        "127.0.0.1",
    ] {
        assert!(
            matches!(parse_bind(bad), Err(PreviewError::BadAddress(_))),
            "{bad}: {:?}",
            parse_bind(bad)
        );
    }
    assert!(matches!(parse_bind("0"), Err(PreviewError::PortZero(_))));
    assert!(matches!(
        parse_bind("127.0.0.1:0"),
        Err(PreviewError::PortZero(_))
    ));
    assert_eq!(parse_bind(""), Err(PreviewError::MissingAddress));

    let ok = |s: &str| parse_bind(s).unwrap();
    assert_eq!(ok("8097"), "127.0.0.1:8097".parse().unwrap());
    assert_eq!(ok("127.0.0.1:8097"), "127.0.0.1:8097".parse().unwrap());
    assert_eq!(ok("127.0.0.2:9000"), "127.0.0.2:9000".parse().unwrap());
    assert_eq!(ok("[::1]:8097"), "[::1]:8097".parse().unwrap());

    // Through the command line, both spellings, and a missing value.
    assert_eq!(
        preview_bind(&args(&[FLAG, "8097"])),
        Ok(Some("127.0.0.1:8097".parse().unwrap()))
    );
    assert_eq!(
        preview_bind(&args(&[&format!("{FLAG}=[::1]:8097")])),
        Ok(Some("[::1]:8097".parse().unwrap()))
    );
    assert!(matches!(
        preview_bind(&args(&[FLAG, "0.0.0.0:8097"])),
        Err(PreviewError::NotLoopback(_))
    ));
    assert!(matches!(
        preview_bind(&args(&[&format!("{FLAG}=0.0.0.0:8097")])),
        Err(PreviewError::NotLoopback(_))
    ));
    assert_eq!(
        preview_bind(&args(&[FLAG])),
        Err(PreviewError::MissingAddress)
    );
    assert_eq!(
        preview_bind(&args(&[FLAG, "--other"])),
        Err(PreviewError::MissingAddress)
    );

    // The configuration it runs with points at no API and is plain-http
    // loopback; nothing comes from the environment.
    let c = atlas_preview::config("127.0.0.1:8097".parse().unwrap()).unwrap();
    assert_eq!(c.public_base_url.as_str(), "http://127.0.0.1:8097/");
    assert_eq!(c.api_url.host_str(), Some("127.0.0.1"));
    assert_eq!(c.api_url.port(), Some(9));
    assert!(c.dev_bearer.is_none() && c.client_id.is_none());
}

/// `serve` itself refuses a non-loopback or port-0 address before it binds,
/// whatever its caller parsed: the guard is not only in argument parsing.
#[tokio::test]
async fn serve_refuses_a_non_loopback_address_before_binding() {
    for bad in [
        "0.0.0.0:8097",
        "[::]:8097",
        "192.168.1.20:8097",
        "127.0.0.1:0",
    ] {
        let addr: SocketAddr = bad.parse().unwrap();
        assert!(check_bind(addr).is_err(), "{bad}");
        // A shutdown that never fires: had it bound, this would serve forever.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            atlas_preview::serve(addr, std::future::pending()),
        )
        .await
        .unwrap_or_else(|_| panic!("{bad}: serve bound and ran instead of refusing"));
        let err = res.expect_err(bad);
        let e = err
            .downcast_ref::<PreviewError>()
            .unwrap_or_else(|| panic!("{bad}: {err:#}"));
        assert!(
            matches!(e, PreviewError::NotLoopback(_) | PreviewError::PortZero(_)),
            "{bad}: {e}"
        );
    }
    assert!(check_bind("127.0.0.1:8097".parse().unwrap()).is_ok());
    assert!(check_bind("[::1]:8097".parse().unwrap()).is_ok());
}

// ---- serving ---------------------------------------------------------------------

/// Walk the preview from the manifest's theme roots through every child,
/// switch, bundle target and outgoing target, fetching each level from the
/// preview route: every level is reachable, served byte for byte as
/// committed, and passes the contract for its map.
#[tokio::test]
async fn the_preview_serves_every_reachable_level_byte_for_byte_and_valid() {
    let router = preview_router();
    let lines = committed_lines();
    // Driven by the page's own map list, as the client is: each map's
    // level_url, the hierarchy the client knows, and the level id.
    let maps = page_maps(&router).await;
    let mut queue: VecDeque<(String, Hierarchy, Uuid, Expected)> = VecDeque::new();
    for map in &maps.maps {
        for t in &map.themes {
            for (h, id) in [
                (Hierarchy::Meaning, t.roots.meaning),
                (Hierarchy::Links, t.roots.links),
            ] {
                let want = match map.group_id {
                    Some(g) => Expected::team(g, id),
                    None => Expected::public(id),
                };
                queue.push_back((map.level_url.clone(), h, id, want));
            }
        }
    }
    let mut seen = BTreeSet::new();
    while let Some((url, h, id, want)) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let res = get(&router, &level_path(&url, h, id)).await;
        assert_eq!(res.status, StatusCode::OK, "{id}");
        assert_eq!(res.header("content-type"), Some("application/json"));
        assert_eq!(res.header(PREVIEW_HEADER), Some(PREVIEW_HEADER_VALUE));
        assert_eq!(
            res.text(),
            lines[&id],
            "{id} is served exactly as committed"
        );
        if let Err(e) = check_level_body(&res.body, &want) {
            panic!("{id}: {e:#?}");
        }
        let v: Value = serde_json::from_slice(&res.body).unwrap();
        assert_eq!(
            hierarchy(&v["hierarchy"]),
            h,
            "{id} is in the hierarchy asked for"
        );
        let next = |s: &str| Expected {
            level_id: Uuid::parse_str(s).unwrap(),
            ..want
        };
        // The switch names its own hierarchy; everything else stays in this one.
        let sw = next(v["switch"]["level_id"].as_str().unwrap());
        queue.push_back((
            url.clone(),
            hierarchy(&v["switch"]["hierarchy"]),
            sw.level_id,
            sw,
        ));
        let mut ids: Vec<&str> = Vec::new();
        for c in v["children"].as_array().into_iter().flatten() {
            ids.push(c["id"].as_str().unwrap());
        }
        for t in v["targets"].as_array().into_iter().flatten() {
            ids.push(t["level_id"].as_str().unwrap());
        }
        for o in v["outgoing"].as_array().into_iter().flatten() {
            ids.push(o["target"]["level_id"].as_str().unwrap());
        }
        for s in ids {
            let e = next(s);
            queue.push_back((url.clone(), h, e.level_id, e));
        }
    }
    assert_eq!(
        seen.len(),
        lines.len(),
        "every preview level is reachable from a theme root"
    );
}

#[tokio::test]
async fn the_preview_serves_the_contract_fixtures_under_their_map_and_hierarchy() {
    let router = preview_router();
    for stem in [
        "team_theme_root",
        "team_group_deep",
        "team_leaf_dense",
        "public_leaf",
    ] {
        let v = fixture_value(stem);
        let id = Uuid::parse_str(v["level_id"].as_str().unwrap()).unwrap();
        let map = if v["map_scope"] == "public" {
            "public"
        } else {
            "team"
        };
        let url = format!("{MAPS_PREFIX}{map}/");
        let res = get(&router, &level_path(&url, hierarchy(&v["hierarchy"]), id)).await;
        assert_eq!(res.status, StatusCode::OK, "{stem}");
        let committed = std::fs::read_to_string(format!(
            "{}/contract/atlas_level/v1/fixtures/{stem}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert_eq!(res.text(), committed, "{stem} is served as committed");
    }
}

#[tokio::test]
async fn the_preview_404s_an_unknown_id_with_the_contract_body() {
    let router = preview_router();
    let want = fixture_value("non_member_bff");
    let mut bodies = Vec::new();
    // A real level of each map, asked for under the other map or the other
    // hierarchy, is not found: the preview tells (map, hierarchy, id) apart
    // as the real route must, though its ids happen to be unique.
    let store = PreviewStore::embedded();
    let lines = committed_lines();
    let mut misaddressed = Vec::new();
    for scope in [MapScope::Team, MapScope::Public] {
        let (id, line) = lines
            .iter()
            .find(|(_, l)| {
                let v: Value = serde_json::from_str(l).unwrap();
                v["map_scope"] == serde_json::to_value(scope).unwrap()
            })
            .unwrap();
        let v: Value = serde_json::from_str(line).unwrap();
        let (own, other) = if scope == MapScope::Team {
            ("team", "public")
        } else {
            ("public", "team")
        };
        let h = hierarchy(&v["hierarchy"]);
        let other_h = match h {
            Hierarchy::Meaning => Hierarchy::Links,
            Hierarchy::Links => Hierarchy::Meaning,
        };
        let right = level_path(&format!("{MAPS_PREFIX}{own}/"), h, *id);
        assert_eq!(store.path_of(*id).as_deref(), Some(right.as_str()));
        assert_eq!(get(&router, &right).await.status, StatusCode::OK, "{right}");
        misaddressed.push((
            id.to_string(),
            level_path(&format!("{MAPS_PREFIX}{other}/"), h, *id),
        ));
        misaddressed.push((
            id.to_string(),
            level_path(&format!("{MAPS_PREFIX}{own}/"), other_h, *id),
        ));
        misaddressed.push((id.to_string(), format!("{MAPS_PREFIX}nomap/meaning/{id}")));
        misaddressed.push((id.to_string(), format!("{MAPS_PREFIX}{own}/Meaning/{id}")));
    }
    let mut cases: Vec<(String, String)> = [
        Uuid::new_v4().to_string(),
        "not-a-uuid".to_string(),
        "..%2F..%2Fetc".to_string(),
    ]
    .into_iter()
    .map(|id| (id.clone(), format!("{MAPS_PREFIX}team/meaning/{id}")))
    .collect();
    cases.extend(misaddressed);
    for (id, path) in cases {
        let res = get(&router, &path).await;
        if let Err(e) = check_not_found(Side::Bff, res.status.as_u16(), &res.body, &id) {
            panic!("{path}: {e:#?}");
        }
        let body: Value = serde_json::from_slice(&res.body).unwrap();
        assert_eq!(body, want["body"], "{path}");
        assert_eq!(res.header(PREVIEW_HEADER), Some(PREVIEW_HEADER_VALUE));
        bodies.push(res.body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "one body for every miss"
    );
}

#[tokio::test]
async fn the_preview_page_carries_the_banner_and_no_inline_script() {
    let router = preview_router();
    let res = get(&router, PAGE_PATH).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header(PREVIEW_HEADER), Some(PREVIEW_HEADER_VALUE));
    let body = res.text();
    assert!(body.contains("class=\"atlas-preview-banner\""), "{body}");
    assert!(body.contains("Preview: synthetic fixture data."));
    assert!(body.contains("data-atlas-mode=\"preview\""));
    // No page-wide level prefix: a level is fetched through its map's URL.
    assert!(!body.contains("data-level-prefix"));
    // The map list rides in an attribute (escaped), not in a script, and
    // passes the helper W10's page must pass, with one URL per map.
    let maps = page_maps(&router).await;
    let m = manifest();
    assert_eq!(maps.maps.len(), m["maps"].as_array().unwrap().len());
    for (got, want) in maps.maps.iter().zip(m["maps"].as_array().unwrap()) {
        assert_eq!(got.key, want["key"].as_str().unwrap());
        assert_eq!(got.level_url, format!("{MAPS_PREFIX}{}/", got.key));
        assert_eq!(
            serde_json::to_value(&got.themes).unwrap(),
            want["themes"],
            "the themes are the manifest's"
        );
    }
    for (i, _) in body.match_indices("<script") {
        let tag = &body[i..i + body[i..].find('>').unwrap()];
        assert!(tag.contains(" src=\"") && tag.contains(" defer"), "{tag}");
    }
    assert!(!body.contains("style="));
    let nested = body.find("static/atlas_nested.js").unwrap();
    let main = body.find("static/atlas.js").unwrap();
    assert!(nested < main, "the rules load before the canvas");
    // No sign-in, search or other Explorer link: none of them is served here.
    assert!(!body.contains("/auth/login"));
    assert!(!body.contains("/search"));

    // `/` leads to the page; health and static assets answer with the mark.
    let home = get(&router, "/").await;
    assert!(home.status.is_redirection());
    assert_eq!(home.header("location"), Some(PAGE_PATH));
    for path in ["/health", "/static/atlas.js", "/static/atlas_nested.js"] {
        let r = get(&router, path).await;
        assert_eq!(r.status, StatusCode::OK, "{path}");
        assert_eq!(
            r.header(PREVIEW_HEADER),
            Some(PREVIEW_HEADER_VALUE),
            "{path}"
        );
    }
}

/// The leaf legend keys the massless evidence line, apart from the solid
/// exact flow and the dashed estimate, with a style the stylesheet defines.
#[tokio::test]
async fn the_leaf_legend_keys_evidence_with_no_stored_mass() {
    let router = preview_router();
    let body = get(&router, PAGE_PATH).await.text();
    let at = body
        .find(r#"data-role="leaf-legend""#)
        .expect("the leaf legend is in the page");
    let legend = &body[at..at + body[at..].find("</div>").unwrap()];
    let keys: Vec<&str> = legend
        .split(r#"<span class="atlas__key">"#)
        .skip(1)
        .collect();
    let nomass = keys
        .iter()
        .find(|k| k.contains("evidence, no stored mass"))
        .expect("a legend entry for evidence with no stored mass");
    assert!(nomass.contains("atlas__line--nomass"), "{nomass}");
    for other in ["atlas__line--exact", "atlas__line--proxy"] {
        assert!(!nomass.contains(other), "{nomass}");
        assert!(legend.contains(other), "the {other} key stays");
    }
    let css = get(&router, "/static/atlas.css").await.text();
    assert!(
        css.contains(".atlas__line--nomass {"),
        "styled in atlas.css"
    );
}

/// The preview mounts no route that reaches the API: every Explorer page and
/// BFF route is absent, so a preview on a host with a live API cannot read it.
#[tokio::test]
async fn the_preview_mounts_no_upstream_route() {
    let router = preview_router();
    let id = Uuid::new_v4();
    for path in [
        "/atlas".to_string(),
        "/bff/atlas/layout".to_string(),
        format!("/bff/atlas/claim/{id}"),
        "/bff/atlas/search?q=x".to_string(),
        "/bff/themes".to_string(),
        format!("/claim/{id}"),
        "/search?q=x".to_string(),
        "/auth/login".to_string(),
        "/auth/callback?code=x&state=y".to_string(),
    ] {
        let r = get(&router, &path).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            r.header(PREVIEW_HEADER),
            Some(PREVIEW_HEADER_VALUE),
            "{path}"
        );
    }
}

// ---- the data-atlas-maps helper (what W10's page must pass) ----------------------

type Mutate = Box<dyn Fn(&mut Value)>;

/// The map list helper accepts the preview page's list and refuses every list
/// a client could not address unambiguously or read safely.
#[tokio::test]
async fn the_map_list_helper_refuses_an_ambiguous_or_unsafe_list() {
    let router = preview_router();
    let good: Value = serde_json::to_value(page_maps(&router).await).unwrap();
    assert!(check_atlas_maps_attr(&good.to_string()).is_ok());
    assert_eq!(good["maps"].as_array().unwrap().len(), 2);

    let bad = |f: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        f(&mut v);
        check_atlas_maps_attr(&v.to_string())
    };
    let cases: Vec<(&str, Mutate)> = vec![
        (
            "no level_url",
            Box::new(|v| {
                v["maps"][0].as_object_mut().unwrap().remove("level_url");
            }),
        ),
        (
            "a page-wide prefix field",
            Box::new(|v| v["level_prefix"] = "/x/".into()),
        ),
        (
            "an absolute level_url",
            Box::new(|v| v["maps"][0]["level_url"] = "https://evil.example/".into()),
        ),
        (
            "a protocol-relative level_url",
            Box::new(|v| v["maps"][0]["level_url"] = "//evil.example/".into()),
        ),
        (
            "a level_url with a query",
            Box::new(|v| v["maps"][0]["level_url"] = "/a?b=/".into()),
        ),
        (
            "a level_url with no trailing slash",
            Box::new(|v| v["maps"][0]["level_url"] = "/a".into()),
        ),
        (
            "two maps on one level_url",
            Box::new(|v| {
                v["maps"][1]["level_url"] = v["maps"][0]["level_url"].clone();
            }),
        ),
        (
            "a repeated key",
            Box::new(|v| v["maps"][1]["key"] = v["maps"][0]["key"].clone()),
        ),
        (
            "a team map with no group",
            Box::new(|v| v["maps"][0]["group_id"] = Value::Null),
        ),
        (
            "a public map with a group",
            Box::new(|v| {
                v["maps"][1]["group_id"] = v["maps"][0]["group_id"].clone();
            }),
        ),
        (
            "two public maps",
            Box::new(|v| {
                let mut p = v["maps"][1].clone();
                p["key"] = "public2".into();
                p["level_url"] = "/p2/".into();
                v["maps"].as_array_mut().unwrap().push(p);
            }),
        ),
        (
            "two maps for one team",
            Box::new(|v| {
                let mut t = v["maps"][0].clone();
                t["key"] = "team2".into();
                t["level_url"] = "/t2/".into();
                v["maps"].as_array_mut().unwrap().push(t);
            }),
        ),
        (
            "a theme listed twice",
            Box::new(|v| {
                let t = v["maps"][0]["themes"][0].clone();
                v["maps"][0]["themes"].as_array_mut().unwrap().push(t);
            }),
        ),
        (
            "one root for both hierarchies",
            Box::new(|v| {
                v["maps"][0]["themes"][0]["roots"]["links"] =
                    v["maps"][0]["themes"][0]["roots"]["meaning"].clone();
            }),
        ),
        (
            "another version",
            Box::new(|v| v["schema_version"] = 2.into()),
        ),
        (
            "a belief key",
            Box::new(|v| v["maps"][0]["themes"][0]["betp"] = 0.5.into()),
        ),
    ];
    for (what, f) in cases {
        assert!(bad(&*f).is_err(), "{what} must be refused");
    }
    // A theme named on no map yet is allowed (null label).
    assert!(bad(&|v| v["maps"][0]["themes"][0]["label"] = Value::Null).is_ok());
}

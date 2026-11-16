//! The per-team Atlas maps on the Explorer (backlog W10): the `/atlas` page's
//! `data-atlas-maps` and `data-atlas-claim-leaf-url`, the level proxy
//! `/bff/atlas/maps/{key}/{hierarchy}/{id}` and the claim-to-leaf proxy
//! `/bff/atlas/claim-leaf/{key}/{hierarchy}/{claim}`, against a wiremock
//! kernel.

mod common;

use std::io::Read as _;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use common::atlas_claim_leaf::{
    check_claim_leaf_body, check_claim_leaf_not_found, ClaimLeafExpected,
};
use common::atlas_contract::{
    assert_indistinguishable, check_level_body, check_not_found, fixture, fixture_value, Expected,
    Side, FIXTURE_TEAM_GROUP_ID,
};
use common::atlas_maps::{attr_value, check_atlas_maps_attr};
use common::{spawn, TestApp};
use epigraph_explorer::auth::SessionId;
use epigraph_explorer::upstream::atlas_level::{
    Hierarchy, MapScope, ATLAS_LEVEL_BUDGET_GZIP_BYTES,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

const G: Uuid = FIXTURE_TEAM_GROUP_ID;

/// One answer with its raw bytes (the shared harness keeps a lossy string).
struct Raw {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

async fn get_raw(app: &TestApp, uri: &str, sid: Option<&SessionId>, extra: &[(&str, &str)]) -> Raw {
    let mut req = Request::get(uri);
    if let Some(sid) = sid {
        req = req.header("cookie", TestApp::cookie(sid));
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = app
        .router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    Raw {
        status,
        headers,
        body,
    }
}

fn gunzip(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b)
        .read_to_end(&mut out)
        .expect("a gzip body");
    out
}

fn unbrotli(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::Decompressor::new(b, 4096)
        .read_to_end(&mut out)
        .expect("a br body");
    out
}

/// The dense team leaf fixture: its bytes, level id and hierarchy segment.
fn dense() -> (Vec<u8>, Uuid, &'static str) {
    let v = fixture_value("team_leaf_dense");
    assert_eq!(v["hierarchy"], "meaning");
    assert_eq!(v["map_group_id"], G.to_string());
    let id: Uuid = v["level_id"].as_str().unwrap().parse().unwrap();
    (fixture("team_leaf_dense"), id, "meaning")
}

fn team_key() -> String {
    format!("team-{}", G.simple())
}

fn kernel_level(map: &str, h: &str, id: Uuid) -> String {
    format!("/api/v1/atlas/maps/{map}/{h}/levels/{id}")
}

fn bff_level(key: &str, h: &str, id: Uuid) -> String {
    format!("/explorer/bff/atlas/maps/{key}/{h}/{id}")
}

async fn mount_level(app: &TestApp, kernel_path: &str, token: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(kernel_path.to_string()))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(&app.upstream)
        .await;
}

fn kernel_not_found(id: Uuid) -> Value {
    json!({
        "error": "NotFound",
        "message": format!("atlas_level with ID {id} not found"),
        "details": {"entity": "atlas_level", "id": id.to_string()},
    })
}

// ---- the /atlas page ----------------------------------------------------------------

/// The page renders the kernel's maps as a `data-atlas-maps` list that passes
/// the `atlas_maps` v1 checker: team maps first, each with its own level URL
/// under the BFF route, and the claim-to-leaf prefix beside it. The calls
/// carry the viewer's own bearer.
#[tokio::test]
async fn the_atlas_page_carries_a_valid_map_list() {
    let app = spawn().await;
    let sid = app.sign_in("tok-m");
    let (t1, t2) = (Uuid::from_u128(0x71), Uuid::from_u128(0x72));
    let roots =
        |a: u128, b: u128| json!({"meaning": Uuid::from_u128(a), "links": Uuid::from_u128(b)});
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps"))
        .and(header("authorization", "Bearer tok-m"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"maps": [
            {"scope": "team", "group_id": G, "map": G.to_string(), "label": "Alpha team",
             "run_id": Uuid::from_u128(1)},
            {"scope": "public", "group_id": null, "map": "public", "label": "Public map",
             "run_id": Uuid::from_u128(2)},
        ]})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/atlas/maps/{G}/themes")))
        .and(header("authorization", "Bearer tok-m"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scope": "team", "group_id": G, "run_id": Uuid::from_u128(1),
            "themes": [
                {"theme_id": t1, "label": "Kinetics", "claim_count": 12, "roots": roots(0xa1, 0xa2)},
                {"theme_id": t2, "label": null, "claim_count": 3, "roots": roots(0xb1, 0xb2)},
                // a theme whose two roots coincide is left out
                {"theme_id": Uuid::from_u128(0x73), "label": "x", "claim_count": 1, "roots": roots(0xc1, 0xc1)},
            ]})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps/public/themes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scope": "public", "group_id": null, "run_id": Uuid::from_u128(2),
            "themes": [{"theme_id": t1, "label": "Kinetics (public)", "claim_count": 2,
                        "roots": roots(0xd1, 0xd2)}]})))
        .mount(&app.upstream)
        .await;

    let res = app.get_as("/explorer/atlas", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let raw = attr_value(&res.body, "data-atlas-maps").expect("the page carries the map list");
    let maps = check_atlas_maps_attr(&raw).unwrap_or_else(|e| panic!("{e:?}\n{raw}"));
    let keys: Vec<&str> = maps.maps.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(keys, vec![team_key().as_str(), "public"]);
    let team = &maps.maps[0];
    assert_eq!(team.scope, MapScope::Team);
    assert_eq!(team.group_id, Some(G));
    assert_eq!(team.label, "Alpha team");
    assert_eq!(
        team.level_url,
        format!("/explorer/bff/atlas/maps/{}/", team_key())
    );
    let ids: Vec<Uuid> = team.themes.iter().map(|t| t.theme_id).collect();
    assert_eq!(ids, vec![t1, t2]);
    assert_eq!(team.themes[1].label, None);
    assert_eq!(maps.maps[1].level_url, "/explorer/bff/atlas/maps/public/");
    assert_eq!(
        maps.maps[1].themes[0].label.as_deref(),
        Some("Kinetics (public)")
    );
    assert_eq!(
        attr_value(&res.body, "data-atlas-claim-leaf-url").as_deref(),
        Some("/explorer/bff/atlas/claim-leaf/")
    );
}

/// No map, a failed map list, or a map whose themes cannot be read: the
/// attribute (or that map) is left out and the page still renders.
#[tokio::test]
async fn the_atlas_page_omits_the_map_list_when_the_kernel_lists_none() {
    // No mock at all: the kernel answers 404.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/atlas", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("data-atlas-maps"));
    assert!(res.body.contains("data-atlas-claim-leaf-url"));

    // An empty list.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"maps": []})))
        .mount(&app.upstream)
        .await;
    let res = app.get_as("/explorer/atlas", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("data-atlas-maps"));

    // Two maps, the team map's themes failing: only the public map is listed.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"maps": [
            {"scope": "team", "group_id": G, "map": G.to_string(), "label": "Alpha", "run_id": Uuid::nil()},
            {"scope": "public", "group_id": null, "map": "public", "label": "Public map", "run_id": Uuid::nil()},
        ]})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/atlas/maps/{G}/themes")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps/public/themes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scope": "public", "group_id": null, "run_id": Uuid::nil(), "themes": []})))
        .mount(&app.upstream)
        .await;
    let res = app.get_as("/explorer/atlas", &sid).await;
    let raw = attr_value(&res.body, "data-atlas-maps").expect("the public map is listed");
    let maps = check_atlas_maps_attr(&raw).unwrap();
    assert_eq!(maps.maps.len(), 1);
    assert_eq!(maps.maps[0].key, "public");
}

/// A hung API costs the page one budget (a third of the 2 s test upstream
/// timeout), not one upstream timeout per stage: whether the map list itself
/// hangs or the list answers and a map's themes hang, the shell renders
/// without `data-atlas-maps` well inside one upstream timeout.
#[tokio::test]
async fn a_hung_api_delays_the_atlas_page_by_the_budget_only() {
    let hang = || ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30));

    // The map list hangs.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps"))
        .respond_with(hang().set_body_json(json!({"maps": []})))
        .mount(&app.upstream)
        .await;
    let started = std::time::Instant::now();
    let res = app.get_as("/explorer/atlas", &sid).await;
    let took = started.elapsed();
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("data-atlas-maps"));
    assert!(
        took < std::time::Duration::from_millis(1_500),
        "the page waited {took:?} on a hung map list"
    );

    // The list answers; the map's themes hang.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"maps": [
            {"scope": "public", "group_id": null, "map": "public", "label": "Public map", "run_id": Uuid::nil()},
        ]})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/atlas/maps/public/themes"))
        .respond_with(hang().set_body_json(json!({
            "scope": "public", "group_id": null, "run_id": Uuid::nil(), "themes": []})))
        .mount(&app.upstream)
        .await;
    let started = std::time::Instant::now();
    let res = app.get_as("/explorer/atlas", &sid).await;
    let took = started.elapsed();
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("data-atlas-maps"));
    assert!(
        took < std::time::Duration::from_millis(1_500),
        "the page waited {took:?} on hung themes"
    );
}

// ---- the level proxy ----------------------------------------------------------------

/// The kernel's bytes are served unchanged, pass the contract, and carry
/// `private, no-cache` and an ETag.
#[tokio::test]
async fn the_level_proxy_serves_the_kernel_bytes_and_passes_the_contract() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (body, id, h) = dense();
    mount_level(
        &app,
        &kernel_level(&G.to_string(), h, id),
        "tok",
        body.clone(),
    )
    .await;
    let got = get_raw(&app, &bff_level(&team_key(), h, id), Some(&sid), &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(
        got.header("content-encoding"),
        None,
        "no encoding was asked for"
    );
    assert_eq!(got.body, body, "the kernel's bytes, unchanged");
    check_level_body(&got.body, &Expected::team(G, id)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(got.header("cache-control"), Some("private, no-cache"));
    assert_eq!(got.header("content-type"), Some("application/json"));
    let etag = got.header("etag").expect("an etag");
    assert!(etag.starts_with("W/\""), "{etag}");
    assert!(etag.contains(&id.to_string()), "{etag}");
}

/// With gzip accepted the level is gzip-compressed and within the 150 KB
/// budget on the wire, though the uncompressed bytes are over it; br is
/// served when only br is accepted. Both decode to the kernel's bytes.
#[tokio::test]
async fn a_level_is_compressed_within_budget_when_gzip_is_accepted() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (body, id, h) = dense();
    assert!(
        body.len() > ATLAS_LEVEL_BUDGET_GZIP_BYTES,
        "calibration: the fixture is over the budget uncompressed ({} bytes)",
        body.len()
    );
    mount_level(
        &app,
        &kernel_level(&G.to_string(), h, id),
        "tok",
        body.clone(),
    )
    .await;
    let uri = bff_level(&team_key(), h, id);

    let gz = get_raw(&app, &uri, Some(&sid), &[("accept-encoding", "gzip")]).await;
    assert_eq!(gz.status, StatusCode::OK);
    assert_eq!(gz.header("content-encoding"), Some("gzip"));
    assert!(
        gz.body.len() <= ATLAS_LEVEL_BUDGET_GZIP_BYTES,
        "{} gzip bytes on the wire",
        gz.body.len()
    );
    let plain = gunzip(&gz.body);
    assert_eq!(plain, body);
    check_level_body(&plain, &Expected::team(G, id)).unwrap();
    assert_eq!(gz.header("cache-control"), Some("private, no-cache"));
    let vary: Vec<String> = gz
        .headers
        .get_all("vary")
        .iter()
        .map(|v| v.to_str().unwrap().to_ascii_lowercase())
        .collect();
    assert!(
        vary.iter().any(|v| v.contains("accept-encoding")),
        "{vary:?}"
    );
    assert!(vary.iter().any(|v| v.contains("cookie")), "{vary:?}");

    let br = get_raw(&app, &uri, Some(&sid), &[("accept-encoding", "br")]).await;
    assert_eq!(br.header("content-encoding"), Some("br"));
    assert!(br.body.len() <= ATLAS_LEVEL_BUDGET_GZIP_BYTES);
    assert_eq!(unbrotli(&br.body), body);
}

/// A matching `If-None-Match` gets a 304 with no body and the same validator,
/// and only after the kernel answered: the kernel is asked both times.
#[tokio::test]
async fn a_level_is_private_and_revalidated_by_etag() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (body, id, h) = dense();
    mount_level(&app, &kernel_level(&G.to_string(), h, id), "tok", body).await;
    let uri = bff_level(&team_key(), h, id);
    let first = get_raw(&app, &uri, Some(&sid), &[]).await;
    let etag = first.header("etag").unwrap().to_string();
    // Sent as a browser would, accepting gzip: the 304 passes through the
    // compression layer with no body and no encoding.
    let again = get_raw(
        &app,
        &uri,
        Some(&sid),
        &[("if-none-match", &etag), ("accept-encoding", "gzip, br")],
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    assert!(again.body.is_empty(), "{} body bytes", again.body.len());
    assert_eq!(again.header("content-encoding"), None);
    assert_eq!(again.header("etag"), Some(etag.as_str()));
    assert_eq!(again.header("cache-control"), Some("private, no-cache"));
    let other = get_raw(
        &app,
        &uri,
        Some(&sid),
        &[("if-none-match", "W/\"elsewhere\"")],
    )
    .await;
    assert_eq!(other.status, StatusCode::OK);
    assert_eq!(app.upstream.received_requests().await.unwrap().len(), 3);
}

/// A member who cached a level and then lost access revalidates with the old
/// ETag: the kernel now answers 404, and so does the BFF, never 304.
#[tokio::test]
async fn a_revoked_member_gets_not_found_not_304() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (body, id, h) = dense();
    let kernel = kernel_level(&G.to_string(), h, id);
    mount_level(&app, &kernel, "tok", body).await;
    let uri = bff_level(&team_key(), h, id);
    let etag = get_raw(&app, &uri, Some(&sid), &[])
        .await
        .header("etag")
        .unwrap()
        .to_string();
    app.upstream.reset().await;
    Mock::given(method("GET"))
        .and(path(kernel))
        .respond_with(ResponseTemplate::new(404).set_body_json(kernel_not_found(id)))
        .mount(&app.upstream)
        .await;
    let got = get_raw(&app, &uri, Some(&sid), &[("if-none-match", &etag)]).await;
    check_not_found(Side::Bff, got.status.as_u16(), &got.body, &id.to_string())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(got.header("etag"), None);
}

/// Two viewers whose kernel answers for one (run, level) differ (the kernel
/// filtered a node out for the second) get different validators, so the
/// first viewer's ETag never earns the second a 304.
#[tokio::test]
async fn two_viewers_with_different_bodies_get_different_etags() {
    let app = spawn().await;
    let (a, b) = (app.sign_in("tok-a"), app.sign_in("tok-b"));
    let (body, id, h) = dense();
    // B's answer: A's leaf with its last node dropped, as for_viewer would.
    let mut v: Value = serde_json::from_slice(&body).unwrap();
    let gone = v["nodes"].as_array_mut().unwrap().pop().unwrap()["id"].clone();
    v["edges"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["source"] != gone && e["target"] != gone);
    for o in v["outgoing"].as_array_mut().unwrap() {
        o["sources"].as_array_mut().unwrap().retain(|s| *s != gone);
    }
    v["outgoing"]
        .as_array_mut()
        .unwrap()
        .retain(|o| !o["sources"].as_array().unwrap().is_empty());
    let b_body = serde_json::to_vec(&v).unwrap();
    let kernel = kernel_level(&G.to_string(), h, id);
    mount_level(&app, &kernel, "tok-a", body).await;
    mount_level(&app, &kernel, "tok-b", b_body.clone()).await;
    let uri = bff_level(&team_key(), h, id);
    let ea = get_raw(&app, &uri, Some(&a), &[])
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let gb = get_raw(&app, &uri, Some(&b), &[("if-none-match", &ea)]).await;
    assert_eq!(gb.status, StatusCode::OK, "A's validator is not B's");
    assert_eq!(gb.body, b_body);
    check_level_body(&gb.body, &Expected::team(G, id)).unwrap();
    assert_ne!(gb.header("etag"), Some(ea.as_str()));
}

/// The kernel's 404 (and 403) becomes the contract's BFF not-found body,
/// uncompressed even when gzip is accepted, byte for byte the answer for a
/// key, hierarchy or id that names nothing.
#[tokio::test]
async fn a_kernel_not_found_is_the_bff_not_found_body_even_compressed() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let id = Uuid::from_u128(0xdead);
    let gone = Uuid::from_u128(0xbeef);
    Mock::given(method("GET"))
        .and(path(kernel_level(&G.to_string(), "meaning", id)))
        .respond_with(ResponseTemplate::new(404).set_body_json(kernel_not_found(id)))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(kernel_level("public", "links", gone)))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .mount(&app.upstream)
        .await;
    let gzip = [("accept-encoding", "gzip")];
    let base = get_raw(
        &app,
        &bff_level(&team_key(), "meaning", id),
        Some(&sid),
        &gzip,
    )
    .await;
    check_not_found(Side::Bff, base.status.as_u16(), &base.body, &id.to_string())
        .unwrap_or_else(|e| panic!("{e:?}: {:?}", base.body));
    assert_eq!(base.header("content-encoding"), None);
    let want = fixture_value("non_member_bff");
    assert_eq!(
        serde_json::from_slice::<Value>(&base.body).unwrap(),
        want["body"]
    );
    let simple = G.simple().to_string();
    for uri in [
        bff_level("public", "links", gone),
        bff_level("nope", "meaning", id),
        bff_level(&format!("team-{}", simple.to_uppercase()), "meaning", id),
        bff_level(&G.to_string(), "meaning", id),
        bff_level(&team_key(), "Meaning", id),
        format!("/explorer/bff/atlas/maps/{}/meaning/not-a-uuid", team_key()),
    ] {
        let got = get_raw(&app, &uri, Some(&sid), &gzip).await;
        assert_indistinguishable(
            (got.status.as_u16(), &got.body),
            (base.status.as_u16(), &base.body),
        );
    }
}

/// A kernel answer for another level, hierarchy or map is not served.
#[tokio::test]
async fn a_body_for_another_level_is_refused() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (body, id, _) = dense();
    let other = Uuid::from_u128(0x0123);
    for (kernel, bff) in [
        (
            kernel_level(&G.to_string(), "meaning", other),
            bff_level(&team_key(), "meaning", other),
        ),
        (
            kernel_level(&G.to_string(), "links", id),
            bff_level(&team_key(), "links", id),
        ),
        (
            kernel_level("public", "meaning", id),
            bff_level("public", "meaning", id),
        ),
    ] {
        mount_level(&app, &kernel, "tok", body.clone()).await;
        let got = get_raw(&app, &bff, Some(&sid), &[]).await;
        assert_eq!(got.status, StatusCode::BAD_GATEWAY, "{bff}");
    }
}

/// Both proxies need a session and call nothing without one.
#[tokio::test]
async fn the_nested_routes_need_a_session() {
    let app = spawn().await;
    let id = Uuid::from_u128(5);
    for uri in [
        bff_level(&team_key(), "meaning", id),
        format!("/explorer/bff/atlas/claim-leaf/public/meaning/{id}"),
    ] {
        let got = get_raw(&app, &uri, None, &[]).await;
        assert_eq!(got.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

// ---- the claim-to-leaf proxy ---------------------------------------------------------

/// The lookup passes its contract; a refusal is its BFF not-found body; an
/// answer for another claim or map is not served; it is never cached.
#[tokio::test]
async fn claim_leaf_proxy_passes_its_contract() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let (claim, theme, leaf) = (
        Uuid::from_u128(0xc1),
        Uuid::from_u128(0x71),
        Uuid::from_u128(0x1f),
    );
    let answer = |claim: Uuid| {
        json!({"schema_version": 1, "claim_id": claim, "map_scope": "team", "map_group_id": G,
               "hierarchy": "links", "theme_id": theme, "level_id": leaf})
    };
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/atlas/maps/{G}/links/claims/{claim}/leaf"
        )))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer(claim)))
        .mount(&app.upstream)
        .await;
    let uri = |c: Uuid| format!("/explorer/bff/atlas/claim-leaf/{}/links/{c}", team_key());
    let got = get_raw(&app, &uri(claim), Some(&sid), &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    let leaf_ans = check_claim_leaf_body(
        &got.body,
        &ClaimLeafExpected {
            map_scope: MapScope::Team,
            map_group_id: Some(G),
            hierarchy: Hierarchy::Links,
            claim_id: claim,
        },
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(leaf_ans.level_id, leaf);
    assert_eq!(got.header("cache-control"), Some("private, no-store"));

    // The kernel refuses: one body.
    let refused = Uuid::from_u128(0xc2);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/atlas/maps/{G}/links/claims/{refused}/leaf"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "NotFound"})))
        .mount(&app.upstream)
        .await;
    let nf = get_raw(&app, &uri(refused), Some(&sid), &[]).await;
    check_claim_leaf_not_found(nf.status.as_u16(), &nf.body).unwrap_or_else(|e| panic!("{e:?}"));
    let bad = get_raw(
        &app,
        "/explorer/bff/atlas/claim-leaf/nope/links/x",
        Some(&sid),
        &[],
    )
    .await;
    assert_indistinguishable(
        (bad.status.as_u16(), &bad.body),
        (nf.status.as_u16(), &nf.body),
    );

    // An answer naming another claim.
    let liar = Uuid::from_u128(0xc3);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/atlas/maps/{G}/links/claims/{liar}/leaf"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(answer(claim)))
        .mount(&app.upstream)
        .await;
    let got = get_raw(&app, &uri(liar), Some(&sid), &[]).await;
    assert_eq!(got.status, StatusCode::BAD_GATEWAY);
}

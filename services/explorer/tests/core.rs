//! Core area against a wiremock upstream: the landing page, search in all
//! three modes, the composed claim page (grouped outlinks, evidence,
//! redaction short-circuit, degraded sections, OG), anonymous unfurls, and
//! the `/bff/claim` ETag. Upstream JSON is shaped exactly like the mapping
//! reports (`claims-endpoints.md`, `search-overview-endpoints.md`, plan
//! §2.2–§2.4), including omitted optional fields.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, TestApp};
use epigraph_explorer::config::{
    ENV_DEV_BEARER, ENV_PUBLIC_BASE_URL, ENV_PUBLIC_UNFURL, ENV_UPSTREAM_TIMEOUT_MS,
};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const CLAIM: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
/// A claim the centre supports.
const SUPPORTED: &str = "2a2a2a2a-0000-4000-8000-000000000002";
/// A claim that supports the centre.
const SUPPORTER: &str = "3b3b3b3b-0000-4000-8000-000000000003";
/// A superseded claim that contradicts the centre.
const CONTRADICTOR: &str = "4c4c4c4c-0000-4000-8000-000000000004";
const PAPER: &str = "5d5d5d5d-0000-4000-8000-000000000005";
const AUTHOR: &str = "6e6e6e6e-0000-4000-8000-000000000006";
const EVIDENCE: &str = "7f7f7f7f-0000-4000-8000-000000000007";
const SIBLING: &str = "8a8a8a8a-0000-4000-8000-000000000008";
const THEME: &str = "9b9b9b9b-0000-4000-8000-000000000009";
const CLUSTER: &str = "aaaaaaaa-0000-4000-8000-00000000000a";
const NEIGHBORHOOD: &str = "bbbbbbbb-0000-4000-8000-00000000000b";

const CONTENT: &str = "Water boils at 100 °C at sea level.";

// ---- fixtures -------------------------------------------------------------------

/// `GET /claims/:id` with `labels` omitted when empty (claims.rs:108-109)
/// and every other skip_serializing_if field omitted.
fn claim_json(content: &str, labels: &[&str]) -> Value {
    let mut v = json!({
        "id": CLAIM,
        "content": content,
        "truth_value": 0.8,
        "agent_id": AGENT,
        "trace_id": null,
        "created_at": "2026-01-02T03:04:05Z",
        "updated_at": "2026-01-03T03:04:05.123456Z"
    });
    if !labels.is_empty() {
        v["labels"] = json!(labels);
    }
    v
}

fn belief_json() -> Value {
    json!({
        "claim_id": CLAIM, "belief": 0.6, "plausibility": 0.9, "ignorance": 0.3,
        "mass_on_conflict": null, "mass_on_missing": null,
        "pignistic_prob": 0.75, "mass_function_count": 2
    })
}

fn ego_node(id: &str, entity_type: &str, label: &str) -> Value {
    let mut n = json!({"id": id, "entity_type": entity_type, "label": label, "redacted": false});
    if entity_type == "claim" {
        n["content"] = json!(label);
        n["truth_value"] = json!(0.5);
        n["labels"] = json!([]);
        n["is_current"] = json!(true);
    }
    n
}

fn ego_edge(n: u8, source: (&str, &str), target: (&str, &str), rel: &str, dir: &str) -> Value {
    json!({
        "id": format!("e0000000-0000-4000-8000-0000000000{n:02}"),
        "source_id": source.0, "target_id": target.0,
        "source_type": source.1, "target_type": target.1,
        "relationship": rel, "direction": dir
    })
}

/// Plan §2.2 shape: mixed-case relationships, an inbound paper edge, an
/// outbound agent edge, and a degree cap that truncated 57 edges to 7.
fn ego_json() -> Value {
    let mut contradictor = ego_node(CONTRADICTOR, "claim", "Water boils at 90 °C at sea level.");
    contradictor["is_current"] = json!(false);
    json!({
        "center": ego_node(CLAIM, "claim", CONTENT),
        "nodes": [
            ego_node(SUPPORTED, "claim", "Pasta cooks faster at sea level."),
            ego_node(SUPPORTER, "claim", "Measured boiling point: 99.97 °C."),
            contradictor,
            ego_node(PAPER, "paper", "paper"),
            ego_node(AUTHOR, "agent", "Ada Example"),
            ego_node(EVIDENCE, "evidence", "Thermometer log"),
            ego_node(SIBLING, "claim", "Sibling paragraph."),
        ],
        "edges": [
            ego_edge(1, (CLAIM, "claim"), (SUPPORTED, "claim"), "SUPPORTS", "out"),
            ego_edge(2, (SUPPORTER, "claim"), (CLAIM, "claim"), "supports", "in"),
            ego_edge(3, (CONTRADICTOR, "claim"), (CLAIM, "claim"), "CONTRADICTS", "in"),
            ego_edge(4, (PAPER, "paper"), (CLAIM, "claim"), "asserts", "in"),
            ego_edge(5, (CLAIM, "claim"), (AUTHOR, "agent"), "ATTRIBUTED_TO", "out"),
            ego_edge(6, (EVIDENCE, "evidence"), (CLAIM, "claim"), "provides_evidence", "in"),
            ego_edge(7, (CLAIM, "claim"), (SIBLING, "claim"), "same_source", "out"),
        ],
        "total_edges": 57,
        "truncated": true
    })
}

/// Bare array; ids as strings; `+00:00` timestamps; bare DOI in source_url.
fn evidence_json() -> Value {
    json!([
        {"id": EVIDENCE, "claim_id": CLAIM, "content": "Boiling point table, p. 12",
         "content_hash": "ab12", "source_url": "10.1038/nature12373",
         "evidence_type": "analytical", "created_at": "2026-01-02T03:04:05.123+00:00"},
        {"id": "7f7f7f7f-0000-4000-8000-000000000017", "claim_id": CLAIM,
         "content": "Interview with a chemist", "content_hash": "cd34",
         "source_url": "Dr. Example", "evidence_type": "testimonial",
         "created_at": "2026-01-02T03:04:05+00:00"},
        {"id": "7f7f7f7f-0000-4000-8000-000000000027", "claim_id": CLAIM,
         "content": "", "content_hash": "ef56", "source_url": null,
         "evidence_type": "empirical", "created_at": "2026-01-02T03:04:05+00:00"}
    ])
}

fn edge_evidence_json(relationship: &str, content: Option<&str>) -> Value {
    let evidence: Vec<Value> = content
        .map(|c| {
            vec![json!({
                "edge_id": "c0000000-0000-4000-8000-000000000001",
                "evidence_id": "d0000000-0000-4000-8000-000000000001",
                "evidence_content": c, "strength": 0.9,
                "created_at": "2026-01-02T03:04:05+00:00"
            })]
        })
        .unwrap_or_default();
    json!({"claim_id": CLAIM, "relationship": relationship, "total": evidence.len(), "evidence": evidence})
}

fn challenges_json() -> Value {
    json!({
        "challenges": [{
            "id": "f0000000-0000-4000-8000-000000000001", "claim_id": CLAIM,
            "challenger_id": "00000000-0000-0000-0000-000000000000",
            "challenge_type": "factual_error",
            "explanation": "Altitude matters more than stated.",
            "state": "pending", "created_at": "2026-02-01T00:00:00Z"
        }],
        "total": 1
    })
}

/// `source_doi`/`source_url` omitted on the first chain.
fn provenance_json() -> Value {
    json!({
        "claim_id": CLAIM,
        "chains": [
            {"path": [
                {"id": CLAIM, "entity_type": "claim", "label": "Water boils at 100 °C at sea level."},
                {"id": "f1000000-0000-4000-8000-000000000001", "entity_type": "trace",
                 "label": "deductive (0.90)"}
            ]},
            {"path": [
                {"id": CLAIM, "entity_type": "claim", "label": "Water boils at 100 °C at sea level."},
                {"id": EVIDENCE, "entity_type": "evidence", "label": "analytical: 10.1038/nature12373"}
            ],
             "source_doi": "10.1038/nature12373",
             "source_url": "https://doi.org/10.1038/nature12373"}
        ]
    })
}

fn placement_json() -> Value {
    json!({
        "claim_id": CLAIM, "theme_id": THEME, "cluster_run_id": "cccccccc-0000-4000-8000-00000000000c",
        "cluster_id": CLUSTER, "neighborhood_id": NEIGHBORHOOD,
        "run_completed_at": "2026-09-01T12:00:00Z"
    })
}

fn claim_path(suffix: &str) -> String {
    format!("/api/v1/claims/{CLAIM}{suffix}")
}

async fn mount_get(app: &TestApp, p: &str, status: u16, body: Value, times: u64) {
    Mock::given(method("GET"))
        .and(path(p))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(times)
        .mount(&app.upstream)
        .await;
}

/// Every claim-page sub-call, each expected exactly `times` times.
async fn mount_claim_page(app: &TestApp, times: u64) {
    mount_get(
        app,
        &claim_path(""),
        200,
        claim_json(CONTENT, &["physics", "chemistry", "textbook", "fourth"]),
        times,
    )
    .await;
    mount_sub_calls(app, times).await;
}

async fn mount_sub_calls(app: &TestApp, times: u64) {
    mount_get(app, &claim_path("/belief"), 200, belief_json(), times).await;
    mount_get(app, &claim_path("/ego"), 200, ego_json(), times).await;
    mount_get(app, &claim_path("/evidence"), 200, evidence_json(), times).await;
    mount_get(
        app,
        &claim_path("/supporting-evidence"),
        200,
        edge_evidence_json("SUPPORTS", Some("Packet evidence for")),
        times,
    )
    .await;
    mount_get(
        app,
        &claim_path("/contradicting-evidence"),
        200,
        edge_evidence_json("CONTRADICTS", None),
        times,
    )
    .await;
    mount_get(
        app,
        &claim_path("/challenges"),
        200,
        challenges_json(),
        times,
    )
    .await;
    mount_get(
        app,
        &claim_path("/provenance"),
        200,
        provenance_json(),
        times,
    )
    .await;
    mount_get(app, &claim_path("/placement"), 200, placement_json(), times).await;
}

async fn upstream_paths(app: &TestApp) -> Vec<String> {
    app.upstream
        .received_requests()
        .await
        .expect("request recording is on")
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

// ---- mounting -------------------------------------------------------------------------

#[tokio::test]
async fn core_routes_are_mounted_and_built() {
    // No upstream mocks: wiremock answers 404 to everything.
    let app = spawn().await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("id=\"landing-title\""));
    assert!(!res.body.contains("not built yet"));

    let res = app.get_as("/explorer/search?q=x", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Search failed."), "{}", res.body);

    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));

    let res = app
        .get_as(&format!("/explorer/bff/claim/{CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["error"], "not_found");

    let res = app.get_as("/explorer/bff/search?q=x", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["results"]["status"], "unavailable");
}

// ---- /claim/:id -----------------------------------------------------------------------

#[tokio::test]
async fn claim_page_groups_outlinks_by_family_and_direction() {
    let app = spawn().await;
    mount_claim_page(&app, 1).await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;
    assert!(body.contains(&format!(
        "<blockquote class=\"claim-text claim__content\">{CONTENT}</blockquote>"
    )));
    assert!(body.contains("<li class=\"label\">physics</li>"));

    // Families in display order; case-folded SUPPORTS/supports merge into
    // one family with a heading per direction.
    let support = body
        .find("Support and corroboration")
        .expect("support family");
    let refute = body
        .find("Contradiction and challenge")
        .expect("contradiction family");
    let other = body.find(">Other</h3>").expect("other family");
    assert!(support < refute && refute < other);
    let out = body.find("Supports →").expect("outgoing heading");
    let inbound = body.find("← Supported by").expect("backlink heading");
    assert!(out < inbound, "outgoing before incoming");
    assert!(body.contains("← Contradicted by"));
    assert!(body.contains("← Asserted by"));
    assert!(body.contains("← Evidence from"));
    assert!(body.contains("same source →"), "non-allowlisted → Other");
    assert!(body.contains("attributed to →"));

    // Each neighbour under the right heading, linked by entity type.
    let supported_link = body
        .find(&format!(
            "<a href=\"/explorer/claim/{SUPPORTED}\">Pasta cooks faster"
        ))
        .expect("outgoing neighbour links to its claim");
    let supporter_link = body
        .find(&format!(
            "<a href=\"/explorer/claim/{SUPPORTER}\">Measured boiling point"
        ))
        .expect("backlink neighbour is the edge source");
    assert!(out < supported_link && supported_link < inbound && inbound < supporter_link);
    assert!(body.contains(&format!(
        "<a href=\"/explorer/agent/{AUTHOR}\">Ada Example</a>"
    )));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/evidence/{EVIDENCE}\">Thermometer log</a>"
    )));
    assert!(
        body.contains("<span class=\"outlinks__plain\">paper 5d5d5d5d</span>"),
        "papers have no page: plain text"
    );
    assert!(!body.contains(&format!("/paper/{PAPER}")));
    assert!(body.contains("claim · superseded"));

    // Truncation notice with the graph link. The fixture sets upstream's
    // `truncated: true`, so this is the degree cap talking.
    assert!(
        body.contains("This claim has 57 connections; the connection limit cut the list to 7."),
        "{body}"
    );
    assert!(body.contains(&format!(
        "<a href=\"/explorer/claim/{CLAIM}/graph\">Open the graph view</a>"
    )));
}

/// Fewer edges than `total_edges` is not, on its own, truncation: `/ego`
/// subtracts redaction-dropped edges from `total_edges` and reserves
/// `truncated` for its degree cap. Raising the notice anyway offered a dead
/// link (the graph view reads the same `/ego`) and published a count of the
/// neighbours the viewer may not see.
#[tokio::test]
async fn short_edge_list_without_upstream_truncation_shows_no_notice() {
    let app = spawn().await;
    mount_get(
        &app,
        &claim_path(""),
        200,
        claim_json(CONTENT, &["physics"]),
        1,
    )
    .await;
    // Upstream's own `truncated` is false while `total_edges` (57) exceeds
    // the seven edges it returned — the shape a redacted neighbourhood has.
    // Every other sub-call is unmounted and degrades, which the page allows.
    let mut ego = ego_json();
    ego["truncated"] = json!(false);
    mount_get(&app, &claim_path("/ego"), 200, ego, 1).await;

    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        !res.body.contains("connection limit cut the list"),
        "no truncation notice when upstream did not truncate"
    );
    assert!(
        !res.body.contains("57 connections"),
        "and no count of what is missing: {}",
        res.body
    );
    // The connections that did come back are still rendered.
    assert!(res.body.contains("Supports →"));
}

#[tokio::test]
async fn claim_page_renders_evidence_challenges_provenance_and_placement() {
    let app = spawn().await;
    mount_claim_page(&app, 1).await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    let body = &res.body;

    // Evidence: vocabularies normalised, a bare DOI becomes doi.org, a
    // testimony source stays text.
    assert!(body.contains("<span class=\"label\">Literature</span>"));
    assert!(body.contains("<span class=\"label\">Testimony</span>"));
    assert!(body.contains("<span class=\"label\">Document or observation</span>"));
    assert!(body.contains("<a href=\"https://doi.org/10.1038/nature12373\" rel=\"noopener noreferrer nofollow\">10.1038/nature12373</a>"));
    assert!(body.contains("Source: Dr. Example"));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/evidence/{EVIDENCE}\">Evidence details</a>"
    )));
    assert!(body.contains("Packet evidence for"));
    assert!(body.contains("strength 0.90"));
    assert!(body.contains("None linked."), "empty contradicting list");

    // Challenges: the nil challenger is not an agent link.
    assert!(body.contains("factual error"));
    assert!(body.contains("Altitude matters more than stated."));
    assert!(body.contains("Unknown challenger"));
    assert!(!body.contains("/explorer/agent/00000000-0000-0000-0000-000000000000"));

    // Provenance summary plus links to the full chain and history pages.
    assert!(body.contains("deductive (0.90)"));
    assert!(body.contains(&format!("href=\"/explorer/claim/{CLAIM}/provenance\"")));
    assert!(body.contains(&format!("href=\"/explorer/claim/{CLAIM}/history\"")));

    // Belief panel.
    assert!(body.contains("<meter class=\"claim-meter\" min=\"0\" max=\"1\" value=\"0.75\">"));
    assert!(body.contains("<span class=\"num\">0.80</span>"));
    assert!(body.contains("<dt>Plausibility</dt><dd class=\"num\">0.90</dd>"));

    // Placement links, flagged as not permalinks. Each carries `?claim=` so
    // the theme / community / neighbourhood view it opens can render its share
    // button, whose target is this claim's URL — the only durable one of the
    // four (`links::with_centre_claim`).
    assert!(body.contains(&format!(
        "<a href=\"/explorer/theme/{THEME}?claim={CLAIM}\">Theme</a>"
    )));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/community/{CLUSTER}?claim={CLAIM}\">Community</a>"
    )));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/neighborhood/{NEIGHBORHOOD}?claim={CLAIM}\">Neighborhood</a>"
    )));
    assert!(body.contains("not permalinks"));
    assert!(body.contains(&format!("<a href=\"/explorer/agent/{AGENT}\">Agent</a>")));

    // OG/Twitter: content title, truth + BetP + first three labels, and an
    // absolute og:url from PUBLIC_BASE_URL.
    assert!(body.contains(&format!(
        "<meta property=\"og:title\" content=\"{CONTENT}\">"
    )));
    assert!(body.contains(
        "<meta property=\"og:description\" content=\"Truth value 0.80 · Belief (BetP) 0.75 · Labels: physics, chemistry, textbook\">"
    ));
    assert!(body.contains(&format!(
        "<meta property=\"og:url\" content=\"https://explorer.example.com/explorer/claim/{CLAIM}\">"
    )));
    assert!(body.contains(&format!(
        "<meta name=\"twitter:title\" content=\"{CONTENT}\">"
    )));
}

/// Cross-area: follow the claim page's own theme link into the graph area and
/// land on a view that can still be shared.
///
/// The two areas were built in separate worktrees and each was right alone —
/// the graph pages read `?claim=` and the claim page emitted placement links —
/// but the claim page emitted them bare, so every theme, community and
/// neighbourhood view reached from a claim silently lost its share button.
/// Nothing either area tested could see that, because neither test followed a
/// link the other area had produced. This one does.
#[tokio::test]
async fn placement_links_from_the_claim_page_open_a_shareable_view() {
    let app = spawn().await;
    mount_claim_page(&app, 1).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "theme_id": THEME, "truncated": false,
            "neighborhoods": [{"id": NEIGHBORHOOD, "label": "n-1", "size": 4}],
            "neighborhood_edges": []
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let claim_page = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(claim_page.status, StatusCode::OK);

    // Take the href the page actually rendered, not one rebuilt here.
    let marker = "<li><a href=\"";
    let start = claim_page
        .body
        .find(&format!("{marker}/explorer/theme/"))
        .expect("theme link on the claim page")
        + marker.len();
    let href: String = claim_page.body[start..]
        .split('"')
        .next()
        .expect("quoted href")
        .to_string();

    let theme_page = app.get_as(&href, &sid).await;
    assert_eq!(theme_page.status, StatusCode::OK, "{}", theme_page.body);
    assert!(
        theme_page.body.contains(&format!(
            "data-share-url=\"https://explorer.example.com/explorer/claim/{CLAIM}\""
        )),
        "the theme view reached from {href} must know its centre claim"
    );
    app.upstream.verify().await;
}

#[tokio::test]
async fn redacted_claim_skips_every_other_sub_call() {
    let app = spawn().await;
    mount_get(
        &app,
        &claim_path(""),
        200,
        claim_json("[REDACTED]", &["secret-project"]),
        2,
    )
    .await;
    mount_sub_calls(&app, 0).await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res
        .body
        .contains("You cannot see the content of this claim."));
    assert!(
        !res.body.contains("[REDACTED]"),
        "the marker is never shown"
    );
    assert!(
        !res.body.contains("secret-project"),
        "labels stay out of the page and OG"
    );
    assert!(res
        .body
        .contains("<meta property=\"og:title\" content=\"A claim in EpiGraph\">"));
    assert!(!res.body.contains("Connections"), "no sections rendered");

    let res = app
        .get_as(&format!("/explorer/bff/claim/{CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let v = res.json();
    assert_eq!(v["redacted"], true);
    for section in [
        "belief",
        "outlinks",
        "evidence",
        "supporting",
        "contradicting",
        "challenges",
        "provenance",
        "placement",
    ] {
        assert_eq!(v[section]["status"], "unavailable", "{section}");
    }

    let calls = upstream_paths(&app).await;
    assert_eq!(
        calls,
        vec![claim_path(""), claim_path("")],
        "only GET /claims/:id was called"
    );
}

#[tokio::test]
async fn failing_or_slow_sub_calls_degrade_only_their_section() {
    let app = spawn_with(&[(ENV_UPSTREAM_TIMEOUT_MS, "500")], Router::new()).await;
    mount_get(&app, &claim_path(""), 200, claim_json(CONTENT, &[]), 1).await;
    mount_get(
        &app,
        &claim_path("/belief"),
        500,
        json!({"error": "DatabaseError", "message": "pool timed out: secret detail"}),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(claim_path("/evidence")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(evidence_json())
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&app.upstream)
        .await;
    // axum's text/plain 400 (plan §3.4 "Deserialization").
    Mock::given(method("GET"))
        .and(path(claim_path("/provenance")))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "text/plain; charset=utf-8")
                .set_body_string("Invalid URL: UUID parsing failed"),
        )
        .mount(&app.upstream)
        .await;
    mount_get(&app, &claim_path("/ego"), 200, ego_json(), 1).await;
    mount_get(
        &app,
        &claim_path("/supporting-evidence"),
        200,
        edge_evidence_json("SUPPORTS", None),
        1,
    )
    .await;
    mount_get(
        &app,
        &claim_path("/contradicting-evidence"),
        200,
        edge_evidence_json("CONTRADICTS", None),
        1,
    )
    .await;
    mount_get(
        &app,
        &claim_path("/challenges"),
        200,
        json!({"challenges": [], "total": 0}),
        1,
    )
    .await;
    mount_get(&app, &claim_path("/placement"), 200, json!({"claim_id": CLAIM, "theme_id": null, "cluster_run_id": null, "cluster_id": null, "neighborhood_id": null, "run_completed_at": null}), 1).await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;
    assert!(body.contains(CONTENT));
    assert!(
        body.contains(
            "<p class=\"section-unavailable\">The EpiGraph API is unavailable right now.</p>"
        ),
        "belief 500"
    );
    assert!(
        body.contains(
            "<p class=\"section-unavailable\">The EpiGraph API took too long to answer.</p>"
        ),
        "evidence timeout"
    );
    assert!(
        body.contains(
            "<p class=\"section-unavailable\">The EpiGraph API rejected this request.</p>"
        ),
        "provenance 400"
    );
    assert!(
        !body.contains("secret detail"),
        "upstream detail is logged, not shown"
    );
    // The other sections still render.
    assert!(body.contains("Supports →"));
    assert!(body.contains("Nobody has challenged this claim."));
    assert!(body.contains("This claim is not placed in the latest clustering run."));
    // Without a BetP the OG description falls back to the truth value.
    assert!(body.contains("<meta property=\"og:description\" content=\"Truth value 0.80\">"));
}

#[tokio::test]
async fn bad_or_unknown_claim_ids_are_404_pages() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    for uri in [
        "/explorer/claim/not-a-uuid",
        "/claim/1234",
        "/explorer/bff/claim/not-a-uuid",
    ] {
        let res = app.get_as(uri, &sid).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{uri}");
    }
    let res = app.get("/explorer/claim/not-a-uuid").await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "anonymous too");
    assert!(res.body.contains("We could not find that claim."));
    assert!(
        upstream_paths(&app).await.is_empty(),
        "no upstream call for a malformed id"
    );

    mount_get(
        &app,
        &claim_path(""),
        404,
        json!({"error": "NotFound", "message": format!("Claim with ID {CLAIM} not found"),
               "details": {"entity": "Claim", "id": CLAIM}}),
        1,
    )
    .await;
    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));
}

// ---- anonymous /claim/:id and OG ----------------------------------------------------------

#[tokio::test]
async fn anonymous_claim_gets_a_generic_card_without_public_unfurl() {
    let app = spawn().await;
    let res = app.get(&format!("/explorer/claim/{CLAIM}")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Sign in to read this claim"));
    assert!(res.body.contains(&format!(
        "href=\"/explorer/auth/login?return_to=%2Fexplorer%2Fclaim%2F{CLAIM}\""
    )));
    assert!(res
        .body
        .contains("<meta property=\"og:title\" content=\"A claim in EpiGraph\">"));
    assert!(res.body.contains(&format!(
        "<meta property=\"og:url\" content=\"https://explorer.example.com/explorer/claim/{CLAIM}\">"
    )));
    assert!(
        upstream_paths(&app).await.is_empty(),
        "no upstream call at all"
    );
}

#[tokio::test]
async fn anonymous_claim_unfurls_from_an_anonymous_read_when_enabled() {
    let app = spawn_with(&[(ENV_PUBLIC_UNFURL, "true")], Router::new()).await;
    Mock::given(method("GET"))
        .and(path(claim_path("")))
        .and(|req: &wiremock::Request| !req.headers.contains_key("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(claim_json(CONTENT, &["physics"])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let res = app.get(&format!("/explorer/claim/{CLAIM}")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Sign in to read this claim"));
    assert!(res.body.contains(&format!(
        "<meta property=\"og:title\" content=\"{CONTENT}\">"
    )));
    assert!(res.body.contains(
        "<meta property=\"og:description\" content=\"Truth value 0.80 · Labels: physics\">"
    ));
    assert_eq!(
        upstream_paths(&app).await,
        vec![claim_path("")],
        "no content-bearing sub-calls"
    );
}

#[tokio::test]
async fn anonymous_unfurl_of_a_redacted_or_failing_read_is_generic() {
    let app = spawn_with(&[(ENV_PUBLIC_UNFURL, "true")], Router::new()).await;
    Mock::given(method("GET"))
        .and(path(claim_path("")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(claim_json("[REDACTED]", &["secret-project"])),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(claim_path("")))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&app.upstream)
        .await;
    for _ in 0..2 {
        let res = app.get(&format!("/explorer/claim/{CLAIM}")).await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(res
            .body
            .contains("<meta property=\"og:title\" content=\"A claim in EpiGraph\">"));
        assert!(!res.body.contains("REDACTED") && !res.body.contains("secret-project"));
    }
}

#[tokio::test]
async fn og_tags_escape_hostile_content_and_cut_multibyte_text_safely() {
    let hostile = "\"><script>alert(1)</script><meta x=\"";
    let app = spawn_with(&[(ENV_PUBLIC_UNFURL, "true")], Router::new()).await;
    mount_get(
        &app,
        &claim_path(""),
        200,
        claim_json(hostile, &["<b>l</b>", "a\"b"]),
        1,
    )
    .await;
    mount_sub_calls(&app, 1).await;
    let sid = app.sign_in("tok");

    for res in [
        app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await,
        {
            // The anonymous unfurl path renders the same text into OG.
            Mock::given(method("GET"))
                .and(path(claim_path("")))
                .and(|req: &wiremock::Request| !req.headers.contains_key("authorization"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(claim_json(hostile, &["<b>l</b>"])),
                )
                .mount(&app.upstream)
                .await;
            app.get(&format!("/explorer/claim/{CLAIM}")).await
        },
    ] {
        assert_eq!(res.status, StatusCode::OK);
        assert!(!res.body.contains("<script>alert(1)"), "content is escaped");
        assert!(!res.body.contains("<b>l</b>"), "labels are escaped");
        assert!(!res.body.contains("<meta x="), "no attribute breakout");
        assert!(res.body.contains(
            "<meta property=\"og:title\" content=\"&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;&#60;meta x=&#34;\">"
        ));
    }

    // Multi-byte text is cut on a char boundary (100 chars + …).
    let app = spawn().await;
    let long = format!("{}{}", "μ".repeat(99), "😀 tail that is cut");
    mount_get(&app, &claim_path(""), 200, claim_json(&long, &[]), 1).await;
    mount_sub_calls(&app, 1).await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    let expected = format!("{}😀…", "μ".repeat(99));
    assert!(res.body.contains(&format!(
        "<meta property=\"og:title\" content=\"{expected}\">"
    )));
    assert!(res
        .body
        .contains(&format!("<title>{expected} · EpiGraph Explorer</title>")));
    assert!(
        res.body.contains(&long),
        "the page itself shows the full text"
    );
}

// ---- /bff/claim/:id ------------------------------------------------------------------------

#[tokio::test]
async fn bff_claim_carries_a_weak_etag_and_answers_304() {
    let app = spawn().await;
    mount_get(&app, &claim_path(""), 200, claim_json(CONTENT, &[]), 3).await;
    for (p, body) in [
        ("/belief", belief_json()),
        ("/ego", ego_json()),
        ("/evidence", evidence_json()),
        ("/supporting-evidence", edge_evidence_json("SUPPORTS", None)),
        (
            "/contradicting-evidence",
            edge_evidence_json("CONTRADICTS", None),
        ),
        ("/provenance", provenance_json()),
        ("/placement", placement_json()),
    ] {
        mount_get(&app, &claim_path(p), 200, body, 3).await;
    }
    // A challenge appears between the second and third request; the claim
    // row (and its updated_at) does not change.
    Mock::given(method("GET"))
        .and(path(claim_path("/challenges")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"challenges": [], "total": 0})),
        )
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&app.upstream)
        .await;
    mount_get(&app, &claim_path("/challenges"), 200, challenges_json(), 1).await;
    let sid = app.sign_in("tok");
    let uri = format!("/explorer/bff/claim/{CLAIM}");

    let first = app.get_as(&uri, &sid).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first
        .header("content-type")
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(first.header("cache-control"), Some("private, no-cache"));
    let etag = first.header("etag").expect("etag").to_string();
    assert!(etag.starts_with("W/\""), "{etag}");
    let v = first.json();
    assert_eq!(v["id"], CLAIM);
    assert_eq!(v["claim"]["content"], CONTENT);
    assert_eq!(v["belief"]["status"], "ok");
    assert_eq!(v["belief"]["data"]["pignistic_prob"], 0.75);
    assert_eq!(v["outlinks"]["data"]["families"][0]["family"], "support");
    assert_eq!(
        v["outlinks"]["data"]["families"][0]["groups"][0]["heading"],
        "Supports →"
    );
    assert_eq!(v["outlinks"]["data"]["total_edges"], 57);
    assert_eq!(
        v["evidence"]["data"][0]["source"]["href"],
        "https://doi.org/10.1038/nature12373"
    );
    assert_eq!(v["urls"]["graph"], format!("/explorer/claim/{CLAIM}/graph"));

    let cookie = TestApp::cookie(&sid);
    let second = app
        .get_with(&uri, &[("cookie", &cookie), ("if-none-match", &etag)])
        .await;
    assert_eq!(second.status, StatusCode::NOT_MODIFIED);
    assert!(second.body.is_empty());
    assert_eq!(second.header("etag"), Some(etag.as_str()));

    let third = app
        .get_with(&uri, &[("cookie", &cookie), ("if-none-match", &etag)])
        .await;
    assert_eq!(
        third.status,
        StatusCode::OK,
        "a new challenge changes the ETag"
    );
    assert_ne!(third.header("etag"), Some(etag.as_str()));
    assert_eq!(third.json()["challenges"]["data"][0]["state"], "pending");
}

#[tokio::test]
async fn bff_claim_requires_sign_in() {
    let app = spawn().await;
    let res = app.get(&format!("/explorer/bff/claim/{CLAIM}")).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "unauthorized");
    assert!(upstream_paths(&app).await.is_empty());
}

// ---- /search ---------------------------------------------------------------------------------

fn semantic_hit(id: &str, statement: &str, similarity: f64) -> Value {
    json!({
        "claim_id": id, "statement": statement, "similarity": similarity,
        "epistemic": {"belief": 0.6, "plausibility": 0.9, "ignorance": 0.3, "truth_value": 0.8},
        "agent_id": AGENT
    })
}

#[tokio::test]
async fn semantic_search_posts_the_query_and_links_results() {
    let app = spawn().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/search/semantic"))
        .and(header("authorization", "Bearer tok"))
        .and(body_json(json!({"query": "water boils", "limit": 50})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                semantic_hit(CLAIM, CONTENT, 0.923),
                semantic_hit(SUPPORTED, "[REDACTED]", 0.5)
            ],
            "total": 2, "query_time_ms": 12
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as("/explorer/search?q=water+boils&page=3", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;
    assert!(body.contains(&format!(
        "<a href=\"/explorer/claim/{CLAIM}\">{CONTENT}</a>"
    )));
    assert!(body.contains("92% match"));
    assert!(body.contains("truth 0.80"));
    assert!(body.contains("belief [0.60, 0.90]"));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/claim/{SUPPORTED}\" class=\"result__hidden\">Content hidden</a>"
    )));
    assert!(!body.contains("[REDACTED]"));
    assert!(
        body.contains("the EpiGraph API cannot page further"),
        "unpaged mode says so"
    );
    assert!(!body.contains("rel=\"next\"") && !body.contains("rel=\"prev\""));
    assert!(body.contains("value=\"water boils\""), "query prefilled");
    assert!(body.contains("value=\"semantic\" checked"));
}

#[tokio::test]
async fn label_search_pages_by_offset_while_pages_are_full() {
    let app = spawn().await;
    let hit = |i: usize| {
        json!({
            "id": format!("0000000{}-0000-4000-8000-{:012}", i % 10, i),
            "content": format!("Labelled claim {i}"), "truth_value": 0.5, "agent_id": AGENT,
            "created_at": "2026-01-02T03:04:05+00:00", "labels": ["a", "b"],
            "is_current": i != 1, "supersedes": null
        })
    };
    for (offset, n) in [("0", 20usize), ("20", 3)] {
        Mock::given(method("GET"))
            .and(path("/api/v1/claims/by-labels"))
            .and(query_param("labels", "a,b"))
            .and(query_param("current_only", "true"))
            .and(query_param("limit", "20"))
            .and(query_param("offset", offset))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Value::Array((0..n).map(hit).collect())),
            )
            .expect(1)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");

    let res = app
        .get_as("/explorer/search?q=a%2C+b&mode=label", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("Labelled claim 19"));
    assert!(res.body.contains("page 1"));
    assert!(res
        .body
        .contains("href=\"/explorer/search?q=a%2C+b&#38;mode=label&#38;page=2\" rel=\"next\""));
    assert!(!res.body.contains("rel=\"prev\""));
    assert!(res
        .body
        .contains("<span class=\"result__superseded\">superseded</span>"));
    assert!(res.body.contains("2026-01-02"));

    let res = app
        .get_as("/explorer/search?q=a%2C+b&mode=label&page=2", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Labelled claim 2"));
    assert!(res
        .body
        .contains("href=\"/explorer/search?q=a%2C+b&#38;mode=label&#38;page=1\" rel=\"prev\""));
    assert!(
        !res.body.contains("rel=\"next\""),
        "a short page is the last"
    );
    assert!(!res.body.contains("cannot page further"));
}

#[tokio::test]
async fn evidence_search_links_evidence_and_its_claim() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/search/evidence"))
        .and(query_param("query", "boiling point"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"evidence_id": EVIDENCE, "claim_id": CLAIM, "raw_content": "Table of boiling points",
                 "evidence_type": "document", "similarity": 0.81},
                {"evidence_id": "7f7f7f7f-0000-4000-8000-000000000017", "claim_id": SUPPORTED,
                 "raw_content": null, "evidence_type": "testimony", "similarity": 0.4}
            ],
            "count": 2
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as("/explorer/search?q=boiling+point&mode=evidence", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(&format!(
        "<a href=\"/explorer/claim/{CLAIM}\">Table of boiling points</a>"
    )));
    assert!(res.body.contains(&format!(
        "<a href=\"/explorer/evidence/{EVIDENCE}\">Evidence details</a>"
    )));
    assert!(res.body.contains("<span class=\"label\">Document</span>"));
    assert!(res.body.contains("<span class=\"label\">Testimony</span>"));
    assert!(res.body.contains("(no text)"));
    assert!(res.body.contains("81% match"));
}

#[tokio::test]
async fn search_empty_results_blank_queries_and_failures() {
    let app = spawn().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/search/semantic"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results": [], "total": 0, "query_time_ms": 1})),
        )
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/search/evidence"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": "InternalError", "message": "sqlx: secret"})),
        )
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/search?q=nothing+matches", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("No results for “nothing matches”."));

    let res = app.get_as("/explorer/search?q=x&mode=evidence", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res
        .body
        .contains("Search failed. The EpiGraph API is unavailable right now."));
    assert!(!res.body.contains("secret"));

    // Nothing to search for: the form only, no upstream call.
    for uri in [
        "/explorer/search",
        "/explorer/search?q=++&mode=label",
        "/explorer/search?q=%2C+%2C&mode=label",
    ] {
        let res = app.get_as(uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(!res.body.contains("id=\"results-title\""), "{uri}");
    }
    let res = app.get_as("/explorer/search?q=%2C&mode=label", &sid).await;
    assert!(res.body.contains("Enter one or more labels"));
    let long = "q".repeat(1001);
    let res = app
        .get_as(&format!("/explorer/search?q={long}"), &sid)
        .await;
    assert!(res.body.contains("That search is too long."));

    assert_eq!(
        upstream_paths(&app).await.len(),
        2,
        "only the two real searches"
    );
}

#[tokio::test]
async fn bff_search_returns_the_normalised_outcome() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/claims/by-labels"))
        .and(query_param("labels", "physics"))
        .and(query_param("offset", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": CLAIM, "content": CONTENT, "truth_value": 0.8, "agent_id": AGENT,
            "created_at": "2026-01-02T03:04:05+00:00", "labels": ["physics"],
            "is_current": true, "supersedes": null
        }])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as("/explorer/bff/search?q=physics&mode=label&page=2", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v = res.json();
    assert_eq!(v["mode"], "label");
    assert_eq!(v["page"], 2);
    assert_eq!(v["paging_supported"], true);
    assert_eq!(v["results"]["status"], "ok");
    assert_eq!(
        v["results"]["data"][0]["claim_url"],
        format!("/explorer/claim/{CLAIM}")
    );
    assert_eq!(v["results"]["data"][0]["text"], CONTENT);
    assert_eq!(
        v["prev_url"],
        "/explorer/search?q=physics&mode=label&page=1"
    );
    assert_eq!(v["next_url"], Value::Null);

    let res = app.get_as("/explorer/bff/search?q=+", &sid).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json()["error"], "bad_request");
    let res = app.get("/explorer/bff/search?q=x").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

// ---- / -----------------------------------------------------------------------------------

fn stats_json() -> Value {
    json!({"claims": 343000, "edges": 1200000, "evidence": 5000, "embeddings": 340000,
           "agents": 42, "frames": 7, "workflows": 3, "computed_at": "2026-09-15T00:00:00Z"})
}

fn themes_json() -> Value {
    json!({"themes": [
        {"id": THEME, "label": "Thermodynamics", "claim_count": 40},
        {"id": "9b9b9b9b-0000-4000-8000-000000000019", "label": "Optics", "claim_count": 12}
    ]})
}

fn communities_json() -> Value {
    json!({
        "run_id": "cccccccc-0000-4000-8000-00000000000c",
        "generated_at": "2026-09-01T12:00:00Z",
        "degraded": false,
        "supernodes": [
            {"cluster_id": "aaaaaaaa-0000-4000-8000-000000000001", "label": "cluster-1", "size": 5,
             "mean_betp": null, "dominant_type": null, "dominant_frame_id": null},
            {"cluster_id": CLUSTER, "label": "cluster-2", "size": 30, "mean_betp": 0.61,
             "dominant_type": "factual", "dominant_frame_id": null}
        ],
        "cluster_edges": [{"a": CLUSTER, "b": "aaaaaaaa-0000-4000-8000-000000000001", "weight": 3}]
    })
}

#[tokio::test]
async fn landing_shows_stats_themes_and_communities() {
    let app = spawn().await;
    mount_get(&app, "/api/v1/stats", 200, stats_json(), 1).await;
    mount_get(&app, "/api/v1/graph/themes/overview", 200, themes_json(), 1).await;
    mount_get(
        &app,
        "/api/v1/graph/communities/overview",
        200,
        communities_json(),
        1,
    )
    .await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;
    assert!(body.contains("<dt>Claims</dt><dd class=\"num\">343,000</dd>"));
    assert!(body.contains("<dt>Edges</dt><dd class=\"num\">1,200,000</dd>"));
    assert!(body.contains(&format!("<a href=\"/explorer/theme/{THEME}\">Thermodynamics</a> <span class=\"muted small\">40 claims</span>")));
    let big = body
        .find(&format!(
            "<a href=\"/explorer/community/{CLUSTER}\">cluster-2</a>"
        ))
        .expect("largest community");
    let small = body.find("cluster-1</a>").expect("smaller community");
    assert!(big < small, "communities sorted by size");
    assert!(body.contains("30 claims · mean BetP 0.61"));
    assert!(body.contains("action=\"/explorer/search\""));
    assert!(body.contains("<option value=\"evidence\">"));

    // Cached per viewer for 60 s: a second view makes no upstream calls
    // (each mock expects exactly one hit).
    let res = app.get_as("/explorer/", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(upstream_paths(&app).await.len(), 3);
}

#[tokio::test]
async fn landing_degrades_each_overview_independently() {
    // Dev bearer (localhost): a 401 on the protected overview is a plain
    // Unauthorized, so the section degrades instead of ending a session.
    let app = spawn_with(
        &[
            (ENV_PUBLIC_BASE_URL, "http://localhost:8096/explorer"),
            (ENV_DEV_BEARER, "dev-token"),
        ],
        Router::new(),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_json()))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/themes/overview"))
        .and(header("authorization", "Bearer dev-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/communities/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "run_id": null, "generated_at": null, "degraded": false,
            "status": "no_clusters_computed", "supernodes": [], "cluster_edges": []
        })))
        .mount(&app.upstream)
        .await;

    let res = app.get("/explorer/").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("343,000"), "stats still render");
    assert!(res
        .body
        .contains("<p class=\"section-unavailable\">Sign in to see this.</p>"));
    assert!(res
        .body
        .contains("No clustering run has been computed yet."));

    // A session whose protected overview fails with a 5xx degrades too.
    let app = spawn().await;
    mount_get(&app, "/api/v1/stats", 200, stats_json(), 1).await;
    mount_get(&app, "/api/v1/graph/themes/overview", 200, themes_json(), 1).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/communities/overview"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/plain")
                .set_body_string("error returned from database: secret"),
        )
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Thermodynamics"));
    assert!(res.body.contains(
        "<p class=\"section-unavailable\">The EpiGraph API is unavailable right now.</p>"
    ));
    assert!(!res.body.contains("secret"));
}

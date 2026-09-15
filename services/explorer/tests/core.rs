//! Core area against a wiremock upstream: the composed claim page (grouped
//! outlinks, evidence, redaction short-circuit, degraded sections, OG),
//! anonymous unfurls, and the `/bff/claim` ETag. Upstream JSON is shaped exactly like the mapping
//! reports (`claims-endpoints.md`, `search-overview-endpoints.md`, plan
//! §2.2–§2.4), including omitted optional fields.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, TestApp};
use epigraph_explorer::config::{ENV_PUBLIC_UNFURL, ENV_UPSTREAM_TIMEOUT_MS};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
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

    let res = app.get_as(&format!("/explorer/claim/{CLAIM}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));

    let res = app
        .get_as(&format!("/explorer/bff/claim/{CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["error"], "not_found");
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

    // Truncation notice with the graph link.
    assert!(body.contains("Showing 7 of 57 connections."));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/claim/{CLAIM}/graph\">Open the graph view</a>"
    )));
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

    // Placement links, flagged as not permalinks.
    assert!(body.contains(&format!("<a href=\"/explorer/theme/{THEME}\">Theme</a>")));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/community/{CLUSTER}\">Community</a>"
    )));
    assert!(body.contains(&format!(
        "<a href=\"/explorer/neighborhood/{NEIGHBORHOOD}\">Neighborhood</a>"
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

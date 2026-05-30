#![cfg(feature = "db")]
//! A3 read-path authorization: a private claim must be redacted for anyone
//! who is not the authenticated owner — and the spoofable ?agent_id wire
//! value must be ignored. Tests go through spawn_app → build_app_for_tests →
//! create_router (the production middleware layering); a handler-unit test
//! that hand-passes auth_ctx cannot catch this bug (spec §7.3).
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (sqlx::PgPool, std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    // get_claim unconditionally queries `claim_encryption` (an out-of-tree
    // table no migration creates). Without it the handler 500s before reaching
    // the redaction branch, silently turning this regression guard RED on the
    // standard epigraph_db_repo_test DB. Provision it so the suite is runnable.
    common::ensure_claim_encryption_table(&pool).await;
    // frame_claims_sorted's frame-existence check (FrameRepository::get_by_id)
    // SELECTs frames.properties (migration 044). The shared test DB may predate
    // it; provision the column so that handler reaches its redaction branch
    // instead of 500ing.
    common::ensure_frame_properties_column(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// Extract the `content` field from a get_claim JSON response.
fn content_of(v: &serde_json::Value) -> String {
    v.get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("<missing>")
        .to_string()
}

/// DISCRIMINATING REGRESSION: no token + ?agent_id=<owner_uuid> (spoof) must
/// redact. Pre-fix: handler trusts params.agent_id == owner → returns full
/// content. Post-fix: requester is None (no auth) → Redacted.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={owner}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "private claim still returns 200, just redacted");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        content_of(&body),
        "[REDACTED]",
        "no-token spoof of owner agent_id must NOT reveal private content"
    );
}

/// Stranger token + spoofed ?agent_id=<owner> → still redacted.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let stranger_token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={owner}"))
        .bearer_auth(&stranger_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(content_of(&body), "[REDACTED]");
}

/// Owner token, even with a RANDOM spoofed ?agent_id, sees full content —
/// proving the decision uses the token's agent_id, not the wire param.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_owner_token_ignores_wire_param_and_sees_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={random}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        content_of(&body),
        "TOP SECRET private claim body",
        "owner token must see full content even with a spoofed wire agent_id"
    );
}

/// Non-regression: anonymous GET of a public / ownership-less claim returns
/// 200 + full content (optional-bearer did not turn public reads into 401s).
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_anonymous_public_claim_is_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let claim_id = common::seed_claim(&pool, "public ownership-less claim body").await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(content_of(&body), "public ownership-less claim body");
}

/// Invalid Bearer token on a public read → 401 (spec §7.4 default).
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_invalid_token_is_401() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let claim_id = common::seed_claim(&pool, "public claim for invalid-token test").await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}"))
        .bearer_auth("not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "present-but-invalid Bearer must 401 even on a public read");
}

/// list_claims (GET /claims) must redact a private claim's content for a
/// no-token caller spoofing ?agent_id=<owner>. We constrain the page with
/// `search` so the freshly-seeded claim is the only match, avoiding paging
/// flakiness on a shared test DB.
#[tokio::test(flavor = "multi_thread")]
async fn list_claims_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let secret = format!("LIST private secret body {}", Uuid::new_v4());
    let claim_id = common::seed_claim_with_agent(&pool, &secret, owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims"))
        .query(&[
            ("limit", "100"),
            ("agent_id", owner.to_string().as_str()),
            ("search", secret.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let items = body.get("items").and_then(|i| i.as_array()).expect("items array");
    let found = items
        .iter()
        .find(|it| it.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str()))
        .expect("seeded claim present in first page");
    assert_eq!(
        content_of(found),
        "[REDACTED]",
        "no-token spoof must not reveal private content in list_claims"
    );
}

/// claims_by_belief (GET /api/v1/claims/by-belief) must redact a private claim
/// for a no-token caller spoofing ?agent_id=<owner>. We seed the claim into a
/// fresh frame and pass ?frame_id=<frame> so the seeded claim is the only row
/// in the page — avoiding paging flakiness on the shared test DB (the query is
/// ORDER BY belief DESC LIMIT 100, and belief=0.5 can fall outside the top 100
/// on a populated DB). The belief predicate (c.belief >= min AND c.plausibility
/// <= max) still applies even with frame_id narrowing, and NULL >= 0.0 is
/// falsy, so we must set belief/plausibility explicitly for the row to return.
#[tokio::test(flavor = "multi_thread")]
async fn claims_by_belief_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "BELIEF private secret body", owner).await;
    sqlx::query("UPDATE claims SET belief = 0.5, plausibility = 0.9 WHERE id = $1")
        .bind(claim_id)
        .execute(&pool)
        .await
        .unwrap();
    let frame_id = common::seed_frame_with_claim(&pool, claim_id).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/by-belief?min_belief=0.0&max_plausibility=1.0&limit=100&frame_id={frame_id}&agent_id={owner}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    let arr = rows.as_array().expect("array of belief rows");
    let found = arr
        .iter()
        .find(|it| it.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str()))
        .expect("seeded claim present");
    assert_eq!(
        content_of(found),
        "[REDACTED]",
        "no-token spoof of owner agent_id must NOT reveal private content in claims_by_belief"
    );
}

/// OTHER DIRECTION for claims_by_belief: the OWNER token — even with a RANDOM
/// spoofed ?agent_id — must see full content. Mirrors
/// get_claim_owner_token_ignores_wire_param_and_sees_full: proves the decision
/// is token-driven, not param-driven, AND guards against an over-redaction
/// regression (unconditional redact, or a requester derivation that never
/// resolves to the owner) that the stranger-only test cannot catch.
#[tokio::test(flavor = "multi_thread")]
async fn claims_by_belief_owner_token_ignores_wire_param_and_sees_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "BELIEF private secret body", owner).await;
    sqlx::query("UPDATE claims SET belief = 0.5, plausibility = 0.9 WHERE id = $1")
        .bind(claim_id)
        .execute(&pool)
        .await
        .unwrap();
    let frame_id = common::seed_frame_with_claim(&pool, claim_id).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/by-belief?min_belief=0.0&max_plausibility=1.0&limit=100&frame_id={frame_id}&agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    let arr = rows.as_array().expect("array of belief rows");
    let found = arr
        .iter()
        .find(|it| it.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str()))
        .expect("seeded claim present");
    assert_eq!(
        content_of(found),
        "BELIEF private secret body",
        "owner token must see full content in claims_by_belief even with a spoofed wire agent_id"
    );
}

/// frame_claims_sorted (GET /api/v1/frames/:id/claims) is a SEPARATE handler
/// with its own redaction loop that, pre-A3, independently trusted
/// params.agent_id. A no-token caller spoofing ?agent_id=<owner> must still be
/// redacted. Without this guard the exact spoof bypass could be reintroduced in
/// frame_claims_sorted and nothing would catch it.
#[tokio::test(flavor = "multi_thread")]
async fn frame_claims_sorted_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "FRAME private secret body", owner).await;
    let frame_id = common::seed_frame_with_claim(&pool, claim_id).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/frames/{frame_id}/claims?limit=100&agent_id={owner}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let arr: serde_json::Value = resp.json().await.unwrap();
    let rows = arr.as_array().expect("array of frame claim rows");
    let found = rows
        .iter()
        .find(|it| {
            it.get("claim_id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str())
        })
        .expect("seeded claim present in frame");
    assert_eq!(
        content_of(found),
        "[REDACTED]",
        "no-token spoof of owner agent_id must NOT reveal private content in frame_claims_sorted"
    );
}

/// OTHER DIRECTION for frame_claims_sorted: the OWNER token — even with a RANDOM
/// spoofed ?agent_id — must see full content. Guards over-redaction in the
/// separate frame handler.
#[tokio::test(flavor = "multi_thread")]
async fn frame_claims_sorted_owner_token_ignores_wire_param_and_sees_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "FRAME private secret body", owner).await;
    let frame_id = common::seed_frame_with_claim(&pool, claim_id).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/frames/{frame_id}/claims?limit=100&agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let arr: serde_json::Value = resp.json().await.unwrap();
    let rows = arr.as_array().expect("array of frame claim rows");
    let found = rows
        .iter()
        .find(|it| {
            it.get("claim_id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str())
        })
        .expect("seeded claim present in frame");
    assert_eq!(
        content_of(found),
        "FRAME private secret body",
        "owner token must see full content in frame_claims_sorted even with a spoofed wire agent_id"
    );
}

/// claim_provenance (GET /api/v1/claims/:id/provenance) labels the claim step
/// "[REDACTED]" when the requester lacks access. No-token spoof of the owner
/// agent_id must still redact.
#[tokio::test(flavor = "multi_thread")]
async fn claim_provenance_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "PROV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Force a provenance chain so the claim step is emitted and the label is
    // asserted (otherwise the redaction path is exercised but no chain is
    // returned). Insert an evidence row + DERIVED_FROM edge directly.
    // NOT-NULL `evidence_type` and `claim_id` columns are required by the
    // schema (\d evidence on epigraph_db_repo_test) in addition to the
    // properties.evidence_type/doi read by build_evidence_chains.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, properties) \
         VALUES ($1, 'ev', $2, 'document', $3, '{\"evidence_type\":\"document\",\"doi\":\"10.1/x\"}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    common::insert_edge(&pool, claim_id, evidence_id, "claim", "evidence", "DERIVED_FROM").await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/{claim_id}/provenance?agent_id={owner}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // The first step in the first chain is the claim step; its label is the
    // (truncated) content or "[REDACTED]". With no chains, the response has
    // an empty `chains` array but the claim is still redacted via the same
    // check, so assert no chain leaks the secret and that if a claim step is
    // present it is redacted.
    let chains = body.get("chains").and_then(|c| c.as_array()).expect("chains array");
    for chain in chains {
        if let Some(path) = chain.get("path").and_then(|p| p.as_array()) {
            for step in path {
                let label = step.get("label").and_then(|l| l.as_str()).unwrap_or("");
                assert!(
                    !label.contains("PROV private secret body"),
                    "private claim content leaked into provenance label: {label}"
                );
            }
        }
    }
    // Stronger: the claim step label must be exactly "[REDACTED]". Find a
    // step whose entity_type == "claim".
    let mut saw_claim_step = false;
    for chain in chains {
        if let Some(path) = chain.get("path").and_then(|p| p.as_array()) {
            for step in path {
                if step.get("entity_type").and_then(|t| t.as_str()) == Some("claim") {
                    saw_claim_step = true;
                    assert_eq!(step.get("label").and_then(|l| l.as_str()), Some("[REDACTED]"));
                }
            }
        }
    }
    // If there are no chains (claim has no trace/evidence), the redaction
    // still ran on `claim_label`; the no-leak assertion above is the
    // discriminating guard. saw_claim_step may be false in that case.
    let _ = saw_claim_step;
}

/// OTHER DIRECTION for claim_provenance: the OWNER token — even with a RANDOM
/// spoofed ?agent_id — must see the FULL claim content in the claim step label.
/// Mirrors the owner-full counterparts for claims_by_belief / frame_claims_sorted:
/// proves the decision is token-driven, not param-driven, AND guards against a
/// "redact for everyone" over-redaction regression that the no-token test alone
/// cannot catch (per the task bar: owner-sees-full AND stranger-sees-REDACTED
/// must both be asserted). The same DERIVED_FROM evidence chain is seeded so the
/// claim step is actually emitted (chains.is_empty() branch in claim_provenance),
/// and saw_claim_step is asserted true so this test cannot pass vacuously.
#[tokio::test(flavor = "multi_thread")]
async fn claim_provenance_owner_token_ignores_wire_param_and_sees_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "PROV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Same chain seeding as the redacted test so a claim-typed step is emitted.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, properties) \
         VALUES ($1, 'ev', $2, 'document', $3, '{\"evidence_type\":\"document\",\"doi\":\"10.1/x\"}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    common::insert_edge(&pool, claim_id, evidence_id, "claim", "evidence", "DERIVED_FROM").await;

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/{claim_id}/provenance?agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let chains = body.get("chains").and_then(|c| c.as_array()).expect("chains array");
    // The claim step label is the (un-truncated, < 60 char) content for an
    // owner. Find a claim-typed step and assert it shows the secret in full.
    let mut saw_claim_step = false;
    for chain in chains {
        if let Some(path) = chain.get("path").and_then(|p| p.as_array()) {
            for step in path {
                if step.get("entity_type").and_then(|t| t.as_str()) == Some("claim") {
                    saw_claim_step = true;
                    assert_eq!(
                        step.get("label").and_then(|l| l.as_str()),
                        Some("PROV private secret body"),
                        "owner token must see full content in provenance claim label even with a spoofed wire agent_id"
                    );
                }
            }
        }
    }
    assert!(
        saw_claim_step,
        "expected a claim-typed provenance step (chain seeding failed); test would be vacuous without it"
    );
}

/// list_edges (GET /api/v1/edges) OMITS an edge whose source/target claim is
/// redacted for the requester. This is the edges-level regression guard for the
/// shared `requester = auth_ctx...agent_id.or(client_id)` wiring (the six other
/// edges handlers route through the identical pattern). No-token caller spoofing
/// ?agent_id=<owner> must NOT see the edge (source claim is private); the owner
/// token (even with a random wire agent_id) must see it. The two halves together
/// prove the decision is token-driven, not wire-param-driven.
#[tokio::test(flavor = "multi_thread")]
async fn list_edges_no_token_spoofed_owner_omits_private_edge() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "EDGE private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // An edge whose source is the private claim. When the source claim is
    // redacted for the requester, list_edges drops the whole edge.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, properties) \
         VALUES ($1, 'ev', $2, 'document', $3, '{}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    let edge_id =
        common::insert_edge(&pool, claim_id, evidence_id, "claim", "evidence", "DERIVED_FROM").await;

    let url = format!(
        "http://{addr}/api/v1/edges?source_id={claim_id}&source_type=claim&agent_id={owner}"
    );

    // No-token spoof of the owner agent_id: source claim is redacted → edge omitted.
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let edges: serde_json::Value = resp.json().await.unwrap();
    let arr = edges.as_array().expect("array of edges");
    assert!(
        !arr.iter()
            .any(|e| e.get("id").and_then(|v| v.as_str()) == Some(edge_id.to_string().as_str())),
        "no-token spoof of owner agent_id must NOT see an edge whose source claim is private"
    );

    // Owner token (with a RANDOM spoofed wire agent_id) → source claim is Full → edge present.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let owner_url = format!(
        "http://{addr}/api/v1/edges?source_id={claim_id}&source_type=claim&agent_id={random}"
    );
    let resp = reqwest::Client::new()
        .get(&owner_url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let edges: serde_json::Value = resp.json().await.unwrap();
    let arr = edges.as_array().expect("array of edges");
    assert!(
        arr.iter()
            .any(|e| e.get("id").and_then(|v| v.as_str()) == Some(edge_id.to_string().as_str())),
        "owner token must see the edge even with a spoofed wire agent_id"
    );
}

/// evidence_by_relationship (GET /api/v1/claims/:id/supporting-evidence) — the
/// explicitly-named Task-7 deliverable. The handler early-returns an EMPTY list
/// when the claim itself is redacted for the requester (`check_content_access`
/// on the claim), and the full evidence list otherwise. Pre-A3 it trusted the
/// spoofable params.agent_id; the wiring now derives the requester from the
/// token. DISCRIMINATING PAIR: a no-token caller spoofing ?agent_id=<owner>
/// must get total==0 (empty), while the owner token (even with a random wire
/// agent_id) must get total==1. The owner half de-vacuums the stranger half:
/// the SUPPORTS edge here is evidence->claim (source_type='evidence',
/// target_type='claim'), which is the OPPOSITE direction from the provenance
/// test's claim->evidence DERIVED_FROM edge — so this seeding is what makes the
/// query return a row at all.
#[tokio::test(flavor = "multi_thread")]
async fn supporting_evidence_no_token_spoofed_owner_sees_empty_owner_sees_evidence() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "SUPEV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // SUPPORTS edge: evidence (source) -> claim (target). This is the shape the
    // evidence_by_relationship JOIN requires (ev.id = e.source_id,
    // e.target_id = claim, e.source_type='evidence', e.relationship='SUPPORTS').
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, properties) \
         VALUES ($1, 'supporting evidence body', $2, 'document', $3, '{}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    common::insert_edge(&pool, evidence_id, claim_id, "evidence", "claim", "SUPPORTS").await;

    // No-token spoof of the owner agent_id: claim is redacted → empty list.
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/{claim_id}/supporting-evidence?agent_id={owner}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("total").and_then(|t| t.as_u64()),
        Some(0),
        "no-token spoof of owner agent_id must NOT see evidence for a private claim"
    );
    let ev = body.get("evidence").and_then(|e| e.as_array()).expect("evidence array");
    assert!(ev.is_empty(), "evidence list must be empty for a redacted claim");

    // Owner token (with a RANDOM spoofed wire agent_id): claim is Full → the
    // evidence is returned. total==1 also proves the stranger half above was
    // not vacuously empty due to a wrong edge direction.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/{claim_id}/supporting-evidence?agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("total").and_then(|t| t.as_u64()),
        Some(1),
        "owner token must see the supporting evidence even with a spoofed wire agent_id"
    );
    let ev = body.get("evidence").and_then(|e| e.as_array()).expect("evidence array");
    assert!(
        ev.iter().any(|e| e.get("evidence_id").and_then(|v| v.as_str())
            == Some(evidence_id.to_string().as_str())),
        "owner must see the seeded evidence_id"
    );
}

/// get_evidence (GET /api/v1/evidence/:id) blanks the evidence `content` —
/// AND, per the A3 Task-7 field-level hardening, the free-form `caption` and
/// identifying `source_url` — when the linked claim is private and the
/// requester lacks access. DISCRIMINATING PAIR: a no-token caller spoofing
/// ?agent_id=<owner> sees content=="[REDACTED]" and NO caption / source_url,
/// while the owner token (random wire agent_id) sees the real content, caption
/// and source_url. The edge here is claim->evidence (the get_evidence
/// claim-link query wants target_type='evidence', source_type='claim'). The
/// caption/source_url assertions are the ones that fail on pre-fix code (which
/// emitted them ungated) — the owner half proves they are present to begin with.
#[tokio::test(flavor = "multi_thread")]
async fn get_evidence_no_token_spoofed_owner_redacts_content_caption_and_url() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "GETEV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Evidence with a non-null source_url column AND a caption in properties so
    // the field-gating assertions are not vacuous (None == None).
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, source_url, properties) \
         VALUES ($1, 'evidence body text', $2, 'figure', $3, 'https://secret.example/leak', \
                 '{\"evidence_type\":\"figure\",\"caption\":\"SECRET CAPTION substance\"}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    // claim -> evidence link edge (get_evidence reads source_type='claim',
    // target_type='evidence' to find the linked claim for the access check).
    common::insert_edge(&pool, claim_id, evidence_id, "claim", "evidence", "DERIVED_FROM").await;

    // No-token spoof of the owner agent_id: claim redacted → content, caption,
    // and source_url all gated.
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/evidence/{evidence_id}?agent_id={owner}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("content").and_then(|c| c.as_str()),
        Some("[REDACTED]"),
        "no-token spoof must not reveal evidence content for a private claim"
    );
    assert!(
        body.get("caption").and_then(|c| c.as_str()).is_none(),
        "caption must be gated when the linked claim is redacted (leaked: {:?})",
        body.get("caption")
    );
    assert!(
        body.get("source_url").and_then(|c| c.as_str()).is_none(),
        "source_url must be gated when the linked claim is redacted (leaked: {:?})",
        body.get("source_url")
    );

    // Owner token (random wire agent_id): full content, caption, source_url.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/evidence/{evidence_id}?agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("content").and_then(|c| c.as_str()),
        Some("evidence body text"),
        "owner must see full evidence content even with a spoofed wire agent_id"
    );
    assert_eq!(
        body.get("caption").and_then(|c| c.as_str()),
        Some("SECRET CAPTION substance"),
        "owner must see the caption (proves the gated test above was non-vacuous)"
    );
    assert_eq!(
        body.get("source_url").and_then(|c| c.as_str()),
        Some("https://secret.example/leak"),
        "owner must see the source_url (proves the gated test above was non-vacuous)"
    );
}

/// graph_full (GET /api/v1/graph/full) labels a private claim node "[REDACTED]"
/// when the requester lacks access — its own per-node redaction branch,
/// independent of list_edges. DISCRIMINATING PAIR: a no-token caller spoofing
/// ?agent_id=<owner> sees label=="[REDACTED]", while the owner token (random
/// wire agent_id) sees the real label. The owner half doubles as the
/// "node is actually present" proof (graph_full pulls nodes from the 2000 most
/// recent edges, so a freshly-seeded edge guarantees inclusion).
#[tokio::test(flavor = "multi_thread")]
async fn graph_full_no_token_spoofed_owner_redacts_node_label() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "GRAPHFULL private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // An edge incident to the private claim so it surfaces as a graph node.
    let other = common::seed_claim_with_agent(&pool, "GRAPHFULL public neighbor", owner).await;
    common::insert_edge(&pool, claim_id, other, "claim", "claim", "RELATES_TO").await;

    let find_node = |body: &serde_json::Value| -> Option<String> {
        body.get("nodes")
            .and_then(|n| n.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|n| n.get("id").and_then(|v| v.as_str())
                        == Some(claim_id.to_string().as_str()))
                    .and_then(|n| n.get("label").and_then(|l| l.as_str()))
                    .map(|s| s.to_string())
            })
    };

    // No-token spoof of the owner agent_id: node label redacted.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/full?agent_id={owner}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // The node may or may not be in the 2000-edge window on a busy DB, but when
    // present it MUST be redacted. The owner half below asserts presence.
    if let Some(label) = find_node(&body) {
        assert_eq!(
            label, "[REDACTED]",
            "no-token spoof of owner agent_id must redact the private node label in graph_full"
        );
        assert!(
            !label.contains("GRAPHFULL private secret body"),
            "private claim content leaked into graph_full node label: {label}"
        );
    }

    // Owner token (random wire agent_id): node present AND label is the real
    // content (proves the redaction is token-driven and the node is in-window).
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/full?agent_id={random}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let label = find_node(&body).expect("private claim node present in graph_full for owner");
    assert_eq!(
        label, "GRAPHFULL private secret body",
        "owner token must see the full node label even with a spoofed wire agent_id"
    );
}

/// execute_graph_query (POST /api/v1/graph/query) reads agent_id from the
/// JSON body. DISCRIMINATING PAIR (mirrors graph_full): a no-token caller with
/// body agent_id == owner (spoof) sees label == "[REDACTED]", while the owner
/// token (random spoofed body agent_id) sees the real label. The owner half
/// proves the redaction is token-driven — not "graph_query always redacts" or
/// "the body agent_id is still trusted" — and doubles as the presence proof.
#[tokio::test(flavor = "multi_thread")]
async fn graph_query_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "GQL private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let find_node_label = |body: &serde_json::Value| -> Option<String> {
        body.get("nodes")
            .and_then(|n| n.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|n| n.get("id").and_then(|v| v.as_str())
                        == Some(claim_id.to_string().as_str()))
                    .and_then(|n| n.get("label").and_then(|l| l.as_str()))
                    .map(|s| s.to_string())
            })
    };

    // No-token spoof of the owner agent_id in the body: node label redacted.
    // MATCH (n:claim) RETURN * with no WHERE returns all claims (capped). The
    // shared test DB holds >200 claims and the handler default LIMIT is 200
    // with no ORDER BY, so raise the explicit limit to the handler cap (1000)
    // to guarantee the freshly-seeded claim is in the result window.
    let body = serde_json::json!({
        "query": "MATCH (n:claim) RETURN * LIMIT 1000",
        "agent_id": owner.to_string()
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/graph/query"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "graph query returns 200");
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    // graph_query redacts into the node `label` field, not `content`. The cap
    // (1000) must include our just-seeded claim; absence means the test can't
    // discriminate, so require presence here too.
    let label = find_node_label(&resp_body)
        .expect("seeded claim not present in graph query result; widen the match");
    assert_eq!(
        label, "[REDACTED]",
        "private claim node label must be redacted under no-token spoof"
    );

    // Owner token with a RANDOM (spoofed) body agent_id: node present AND label
    // is the real content. Proves redaction is token-driven and that the body
    // agent_id field is no longer trusted for access.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owner_body = serde_json::json!({
        "query": "MATCH (n:claim) RETURN * LIMIT 1000",
        "agent_id": Uuid::new_v4().to_string()
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/graph/query"))
        .bearer_auth(&owner_token)
        .json(&owner_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "graph query returns 200 for owner");
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    let label = find_node_label(&resp_body)
        .expect("private claim node present in graph query result for owner");
    assert_eq!(
        label, "GQL private secret body",
        "owner token must see the full node label even with a spoofed body agent_id"
    );
}

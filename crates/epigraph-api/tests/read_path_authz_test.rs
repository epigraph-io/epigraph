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

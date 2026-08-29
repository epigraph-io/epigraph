#![cfg(feature = "db")]
//! A3 read-path authorization: a private claim must be redacted for anyone
//! who is not the authenticated owner — and the spoofable ?agent_id wire
//! value must be ignored. Tests go through spawn_app → build_app_for_tests →
//! create_router (the production middleware layering); a handler-unit test
//! that hand-passes auth_ctx cannot catch this bug (spec §7.3).
//!
//! # PR-03: the anonymous halves became 401 halves, and did NOT just disappear
//!
//! Every route this file exercises moved from the anonymous `public` router to
//! `protected`, so an unauthenticated request now 401s before it reaches a
//! handler. The `*_no_token_spoofed_owner_*` tests were written to prove that a
//! caller passing `?agent_id=<owner>` cannot thereby read the owner's private
//! content — and that property still has to hold, for a caller who IS
//! authenticated as somebody else.
//!
//! So each of those tests was converted rather than deleted: it now asserts
//! BOTH that the anonymous request is refused (401 + an RFC 6750 challenge) AND
//! that a STRANGER'S token with the same spoofed `?agent_id` still gets
//! `[REDACTED]`. Replacing the anonymous request with nothing would have
//! removed the only coverage of partition redaction on nine routes; replacing
//! it with an owner token would have inverted the assertion it was making.
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    // This file connects to the shared $DATABASE_URL and does NOT migrate:
    // neither `pool_and_app` nor `build_app_for_tests` calls `run_migrations`,
    // and calling it here is not an option — the local dev database is
    // provisioned with psql and carries no `_sqlx_migrations` row at all, so a
    // migrator run would restart from 001 and die.
    //
    // The claim_encryption stand-in that `common::ensure_claim_encryption_table`
    // used to create is deleted in this PR (migration 060 creates the real
    // table), which removes the self-healing that hid an unmigrated database.
    // Fail LOUDLY on the precondition instead: without 060 every case below
    // fails as an unexplained 500 from get_claim's unconditional
    // ClaimEncryptionRepository::get_by_claim_id_conn.
    let has_060: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.claim_encryption')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass lookup");
    assert!(
        has_060.is_some(),
        "DATABASE_URL points at a database without migration 060 \
         (public.claim_encryption is missing). Apply migrations first: \
         `cargo run -p epigraph-api --bin epigraph-migrate`."
    );
    // frame_claims_sorted's frame-existence check (FrameRepository::get_by_id)
    // SELECTs frames.properties (migration 044). The shared test DB may predate
    // it; provision the column so that handler reaches its redaction branch
    // instead of 500ing.
    common::ensure_frame_properties_column(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// Assert a response is the PR-03 refusal: 401 plus the RFC 6750 challenge a
/// client needs in order to discover where to authenticate.
async fn assert_401_with_challenge(resp: reqwest::Response, what: &str) {
    assert_eq!(
        resp.status(),
        401,
        "{what}: this route moved to the protected router in PR-03; an \
         unauthenticated request must be refused"
    );
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .unwrap_or_else(|| panic!("{what}: 401 with no WWW-Authenticate header"))
        .to_str()
        .expect("challenge is ASCII")
        .to_string();
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "{what}: challenge lacks error=\"invalid_token\": {challenge}"
    );
}

/// Anonymous GET of `url` must be refused.
async fn assert_anonymous_get_401(url: &str) {
    let resp = reqwest::Client::new().get(url).send().await.unwrap();
    assert_401_with_challenge(resp, url).await;
}

/// A token for somebody who is NOT the owner. This is what the
/// `*_no_token_spoofed_owner_*` tests use now: the spoof they guard against is
/// still reachable, just by an authenticated stranger rather than by nobody.
fn stranger_token() -> String {
    common::mint_token_with_agent(&["claims:read"], Uuid::new_v4())
}

/// Extract the `content` field from a get_claim JSON response.
fn content_of(v: &serde_json::Value) -> String {
    v.get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("<missing>")
        .to_string()
}

/// PR-03: the spoof is no longer reachable without a credential at all — the
/// route left the anonymous router. The spoof-redaction property itself is
/// still asserted, one test below, against a STRANGER'S token.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_anonymous_spoofed_owner_is_401() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    assert_anonymous_get_401(&format!("http://{addr}/claims/{claim_id}?agent_id={owner}")).await;
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

/// PR-05: the `community` partition arm, over HTTP.
///
/// Every fixture in this file — all fifteen `seed_private_ownership` calls —
/// writes `'private'`. `ownership.partition_type` admits three values and this
/// crate's read path had never exercised the third, so the whole two-hop
/// `community_members ⋈ perspectives` branch of `check_content_access` was
/// reached by no `epigraph-api` test at all. PR-05 rewrites that branch
/// (migration 068 moves the gate from the overloaded `encryption_key_id` text
/// column into a typed `ownership.community_id`), and
/// `crates/epigraph-mcp/tests/community_partition.rs` covers it at the MCP
/// surface. This is the HTTP half: same decision function, different handler,
/// and it goes through the production middleware stack rather than calling a
/// tool directly.
///
/// Both dispositions in one test on purpose — a redaction assertion alone
/// cannot distinguish "redacted" from "fixture never worked".
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_community_member_sees_content_and_outsider_does_not() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let member = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "COMMUNITY-GATED claim body", owner).await;
    let community = common::seed_community_with_member(&pool, member).await;
    common::seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let member_resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}"))
        .bearer_auth(common::mint_token_with_agent(&["claims:read"], member))
        .send()
        .await
        .unwrap();
    assert_eq!(member_resp.status(), 200);
    let member_body: serde_json::Value = member_resp.json().await.unwrap();
    assert_eq!(
        content_of(&member_body),
        "COMMUNITY-GATED claim body",
        "an agent owning a perspective in the gating community must see the content \
         over HTTP, not only through the MCP tool"
    );

    // A stranger who is authenticated, and who spoofs ?agent_id=<member> for
    // good measure: the decision must come from the token, and membership must
    // be the whole test.
    let outsider_resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={member}"))
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(outsider_resp.status(), 200);
    let outsider_body: serde_json::Value = outsider_resp.json().await.unwrap();
    assert_eq!(
        content_of(&outsider_body),
        "[REDACTED]",
        "a non-member must be redacted, and a spoofed ?agent_id must not launder them \
         into the community"
    );
}

/// PR-03 INVERSION. This test used to assert the opposite: that an anonymous
/// GET of an ownership-less claim returned 200 with full content, on the
/// grounds that a claim nobody has claimed is a claim anybody may read.
///
/// That reasoning does not survive contact with the corpus. "No `ownership`
/// row" is the default state of a claim, not a declaration that it is public —
/// the overwhelming majority of rows are in it by omission, not by intent. An
/// anonymous reader who could enumerate them had the corpus.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_anonymous_is_401() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let claim_id = common::seed_claim(&pool, "ownership-less claim body").await;

    assert_anonymous_get_401(&format!("http://{addr}/claims/{claim_id}")).await;
}

/// Present-but-invalid Bearer token → 401. Unchanged by PR-03:
/// `bearer_auth_middleware` rejects a malformed token in exactly the same place
/// `optional_bearer_auth_middleware` did, so this asserts the same thing it
/// always did — only the reason a credential-less request also 401s has moved.
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
    assert_eq!(resp.status(), 401, "present-but-invalid Bearer must 401");
}

/// list_claims (GET /claims) must redact a private claim's content for a
/// no-token caller spoofing ?agent_id=<owner>. We constrain the page with
/// `search` so the freshly-seeded claim is the only match, avoiding paging
/// flakiness on a shared test DB.
#[tokio::test(flavor = "multi_thread")]
async fn list_claims_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let secret = format!("LIST private secret body {}", Uuid::new_v4());
    let claim_id = common::seed_claim_with_agent(&pool, &secret, owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Anonymous: refused outright.
    let anon = reqwest::Client::new()
        .get(format!("http://{addr}/claims"))
        .query(&[("limit", "100"), ("search", secret.as_str())])
        .send()
        .await
        .unwrap();
    assert_401_with_challenge(anon, "GET /claims").await;

    // Authenticated stranger spoofing ?agent_id=<owner>: reaches the handler,
    // and must still be redacted.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims"))
        .query(&[
            ("limit", "100"),
            ("agent_id", owner.to_string().as_str()),
            ("search", secret.as_str()),
        ])
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let items = body
        .get("items")
        .and_then(|i| i.as_array())
        .expect("items array");
    let found = items
        .iter()
        .find(|it| it.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str()))
        .expect("seeded claim present in first page");
    assert_eq!(
        content_of(found),
        "[REDACTED]",
        "stranger token spoofing ?agent_id=<owner> must not reveal private content in list_claims"
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
async fn claims_by_belief_stranger_token_spoofed_owner_is_redacted() {
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

    let url = format!(
        "http://{addr}/api/v1/claims/by-belief?min_belief=0.0&max_plausibility=1.0&limit=100&frame_id={frame_id}&agent_id={owner}"
    );
    assert_anonymous_get_401(&url).await;

    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
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
        "stranger token spoofing ?agent_id=<owner> must NOT reveal private content in claims_by_belief"
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
async fn frame_claims_sorted_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "FRAME private secret body", owner).await;
    let frame_id = common::seed_frame_with_claim(&pool, claim_id).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let url = format!("http://{addr}/api/v1/frames/{frame_id}/claims?limit=100&agent_id={owner}");
    assert_anonymous_get_401(&url).await;

    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
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
        "stranger token spoofing ?agent_id=<owner> must NOT reveal private content in frame_claims_sorted"
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
async fn claim_provenance_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "PROV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Force a provenance chain so the claim step is emitted and the label is
    // asserted (otherwise the redaction path is exercised but no chain is
    // returned). Insert an evidence row + DERIVED_FROM edge directly.
    // NOT-NULL `evidence_type` and `claim_id` columns are required by the
    // schema (\d evidence on epigraph_db_repo_test) in addition to the
    // properties.evidence_type/doi read by build_evidence_chains.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
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
    common::insert_edge(
        &pool,
        claim_id,
        evidence_id,
        "claim",
        "evidence",
        "DERIVED_FROM",
    )
    .await;

    let url = format!("http://{addr}/api/v1/claims/{claim_id}/provenance?agent_id={owner}");
    assert_anonymous_get_401(&url).await;

    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
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
    let chains = body
        .get("chains")
        .and_then(|c| c.as_array())
        .expect("chains array");
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
                    assert_eq!(
                        step.get("label").and_then(|l| l.as_str()),
                        Some("[REDACTED]")
                    );
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
    let claim_id = common::seed_claim_with_agent(&pool, "PROV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Same chain seeding as the redacted test so a claim-typed step is emitted.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
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
    common::insert_edge(
        &pool,
        claim_id,
        evidence_id,
        "claim",
        "evidence",
        "DERIVED_FROM",
    )
    .await;

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
    let chains = body
        .get("chains")
        .and_then(|c| c.as_array())
        .expect("chains array");
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
async fn list_edges_stranger_token_spoofed_owner_omits_private_edge() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "EDGE private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // An edge whose source is the private claim. When the source claim is
    // redacted for the requester, list_edges drops the whole edge.
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
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
    let edge_id = common::insert_edge(
        &pool,
        claim_id,
        evidence_id,
        "claim",
        "evidence",
        "DERIVED_FROM",
    )
    .await;

    let url = format!(
        "http://{addr}/api/v1/edges?source_id={claim_id}&source_type=claim&agent_id={owner}"
    );

    // Anonymous: refused before the handler runs.
    assert_anonymous_get_401(&url).await;

    // Stranger token spoofing the owner agent_id: source claim is redacted →
    // edge omitted.
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let edges: serde_json::Value = resp.json().await.unwrap();
    let arr = edges.as_array().expect("array of edges");
    assert!(
        !arr.iter()
            .any(|e| e.get("id").and_then(|v| v.as_str()) == Some(edge_id.to_string().as_str())),
        "stranger token spoofing ?agent_id=<owner> must NOT see an edge whose source claim is private"
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
async fn supporting_evidence_stranger_token_spoofed_owner_sees_empty_owner_sees_evidence() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "SUPEV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // SUPPORTS edge: evidence (source) -> claim (target). This is the shape the
    // evidence_by_relationship JOIN requires (ev.id = e.source_id,
    // e.target_id = claim, e.source_type='evidence', e.relationship='SUPPORTS').
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
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
    common::insert_edge(
        &pool,
        evidence_id,
        claim_id,
        "evidence",
        "claim",
        "SUPPORTS",
    )
    .await;

    let url =
        format!("http://{addr}/api/v1/claims/{claim_id}/supporting-evidence?agent_id={owner}");
    assert_anonymous_get_401(&url).await;

    // Stranger token spoofing the owner agent_id: claim is redacted → empty list.
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("total").and_then(|t| t.as_u64()),
        Some(0),
        "stranger token spoofing ?agent_id=<owner> must NOT see evidence for a private claim"
    );
    let ev = body
        .get("evidence")
        .and_then(|e| e.as_array())
        .expect("evidence array");
    assert!(
        ev.is_empty(),
        "evidence list must be empty for a redacted claim"
    );

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
    let ev = body
        .get("evidence")
        .and_then(|e| e.as_array())
        .expect("evidence array");
    assert!(
        ev.iter()
            .any(|e| e.get("evidence_id").and_then(|v| v.as_str())
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
async fn get_evidence_stranger_token_spoofed_owner_redacts_content_caption_and_url() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(&pool, "GETEV private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // Evidence with a non-null source_url column AND a caption in properties so
    // the field-gating assertions are not vacuous (None == None).
    let evidence_id = uuid::Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
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
    common::insert_edge(
        &pool,
        claim_id,
        evidence_id,
        "claim",
        "evidence",
        "DERIVED_FROM",
    )
    .await;

    let url = format!("http://{addr}/api/v1/evidence/{evidence_id}?agent_id={owner}");
    assert_anonymous_get_401(&url).await;

    // Stranger token spoofing the owner agent_id: claim redacted → content,
    // caption, and source_url all gated.
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body.get("content").and_then(|c| c.as_str()),
        Some("[REDACTED]"),
        "stranger token spoofing ?agent_id=<owner> must not reveal evidence content for a private claim"
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
async fn graph_full_stranger_token_spoofed_owner_redacts_node_label() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "GRAPHFULL private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    // An edge incident to the private claim so it surfaces as a graph node.
    let other = common::seed_claim_with_agent(&pool, "GRAPHFULL public neighbor", owner).await;
    common::insert_edge(&pool, claim_id, other, "claim", "claim", "RELATES_TO").await;

    let find_node = |body: &serde_json::Value| -> Option<String> {
        body.get("nodes")
            .and_then(|n| n.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|n| {
                        n.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str())
                    })
                    .and_then(|n| n.get("label").and_then(|l| l.as_str()))
                    .map(|s| s.to_string())
            })
    };

    let url = format!("http://{addr}/api/v1/graph/full?agent_id={owner}");
    assert_anonymous_get_401(&url).await;

    // Stranger token spoofing the owner agent_id: node label redacted.
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(stranger_token())
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
            "stranger token spoofing ?agent_id=<owner> must redact the private node label in graph_full"
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
async fn graph_query_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let (claim_id, probe) =
        common::seed_probe_claim_with_agent(&pool, "GQL private secret body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let find_node_label = |body: &serde_json::Value| -> Option<String> {
        body.get("nodes")
            .and_then(|n| n.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|n| {
                        n.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str())
                    })
                    .and_then(|n| n.get("label").and_then(|l| l.as_str()))
                    .map(|s| s.to_string())
            })
    };

    // Select EXACTLY the seeded claim, by the unique `properties->>'probe'`
    // key `seed_probe_claim_with_agent` wrote.
    //
    // This used to be `MATCH (n:claim) RETURN * LIMIT 1000` — match everything,
    // and trust the seeded row to be inside the window. `graph_query.rs` emits
    // `SELECT id FROM claims <where> LIMIT <n>` with **no ORDER BY**, so which
    // 1000 rows come back is whatever the plan yields; once the shared test
    // database passed ~2500 claims the freshly-seeded row started falling
    // outside it and the test failed with "seeded claim not present", i.e. a
    // false failure that says nothing about redaction. A one-row match makes
    // the assertion about redaction and nothing else.
    let query = format!("MATCH (n:claim) WHERE n.probe = '{probe}' RETURN *");
    let body = serde_json::json!({
        "query": query,
        "agent_id": owner.to_string()
    });
    let anon = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/graph/query"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_401_with_challenge(anon, "POST /api/v1/graph/query").await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/graph/query"))
        .bearer_auth(stranger_token())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "graph query returns 200");
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    // graph_query redacts into the node `label` field, not `content`. The
    // WHERE selects exactly one row, so absence here is a real failure — the
    // node vanished from the response — not a windowing accident.
    let label = find_node_label(&resp_body)
        .expect("the probe-selected claim must be present in the graph query result");
    assert_eq!(
        label, "[REDACTED]",
        "private claim node label must be redacted for a stranger token spoofing the owner"
    );

    // Owner token with a RANDOM (spoofed) body agent_id: node present AND label
    // is the real content. Proves redaction is token-driven and that the body
    // agent_id field is no longer trusted for access.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owner_body = serde_json::json!({
        "query": query,
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

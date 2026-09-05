#![cfg(feature = "db")]
//! A3 read-path authorization: a private claim must be INVISIBLE to anyone who
//! is not the authenticated owner — and the spoofable ?agent_id wire value must
//! be ignored.
//!
//! # PR-14: "redacted" became "absent", and the file's vocabulary followed
//!
//! Through PR-13 these routes answered a non-owner with a 200 whose content had
//! been overwritten by a placeholder. PR-14 deleted that pass: the reads filter
//! on a `Viewer`, so a row the caller may not see is not returned at all. Three
//! assertions here changed as a direct consequence (`get_claim`,
//! `claim_provenance`, `get_evidence`), and the tests named `..._is_redacted`
//! were renamed rather than left describing a behaviour the code no longer has. Tests go through spawn_app → build_app_for_tests →
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
//! that a STRANGER'S token with the same spoofed `?agent_id` is still denied
//! the content (since PR-14: by absence). Replacing the anonymous request with
//! nothing would have removed the only coverage of partition enforcement on
//! nine routes; replacing it with an owner token would have inverted the
//! assertion it was making.
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

/// THE PR-14 ACCEPTANCE CRITERION (plan §8.4 N15, §8.5).
///
/// *"`get_claim(private_id)` and `get_claim(random_uuid)` produce byte-identical
/// responses for a non-member."* This is the assertion that stops the endpoint
/// being a confirmation oracle, and it is the reason redaction had to be
/// deleted rather than tightened: a `[REDACTED]` body and a 404 are trivially
/// distinguishable, so a caller could enumerate which uuids name real private
/// claims without ever reading one.
///
/// The test was named `..._is_redacted` and asserted only a STATUS CODE. A
/// status-only assertion passes while the oracle stands — two 404s whose bodies
/// differ still separate "exists but hidden" from "never existed" — so the
/// whole-body comparison below is the load-bearing half.
///
/// # Why "byte-identical" is asserted modulo the echoed uuid
///
/// `ApiError::NotFound` serialises `{"entity":..,"id":<the uuid you asked
/// for>}`, so the two bodies necessarily differ in the one value the caller
/// itself supplied and therefore already knows. Normalising that id away and
/// requiring equality of everything else is the strongest form of the criterion
/// that is true; the alternative — making the not-found body id-free — would
/// touch every `ApiError::NotFound` in the API for no gain in secrecy.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_private_and_nonexistent_are_indistinguishable_to_a_stranger() {
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
    // PR-12 TIGHTENING. Before migration 071, `seed_private_ownership` wrote an
    // ACL row that ONLY `check_content_access` consulted: every claim was still
    // `visibility='public'`, so the viewer predicate returned the row and the
    // handler blanked its content to "[REDACTED]".
    //
    // The 071 compat shim now TRANSCRIBES that row into the tenancy columns, so
    // the claim is genuinely ('group', <owner's personal group>) and the
    // stranger's viewer predicate excludes it outright. The row is ABSENT, not
    // blanked.
    //
    // That is strictly less disclosure — a stranger no longer learns the claim
    // exists — and it is the end state plan PR-14 names: "delete redaction; a
    // non-visible row is absent, not blanked". progress.json's Q6 records
    // `check_content_access` retention as `gated_on: "PR-12 transcription
    // completing"`; this is that gate discharging.
    assert_eq!(
        resp.status(),
        404,
        "a transcribed private claim must be ABSENT to a stranger, not returned \
         with blanked content"
    );
    let private_status = resp.status();
    let private_headers = resp.headers().clone();
    let private_body = resp.text().await.unwrap();

    // The same request against a uuid that names nothing at all.
    let absent = Uuid::new_v4();
    let resp2 = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{absent}?agent_id={owner}"))
        .bearer_auth(&stranger_token)
        .send()
        .await
        .unwrap();
    let absent_status = resp2.status();
    let absent_headers = resp2.headers().clone();
    let absent_body = resp2.text().await.unwrap();

    assert_eq!(
        private_status, absent_status,
        "status must not discriminate"
    );
    assert_eq!(
        private_headers.get("content-type"),
        absent_headers.get("content-type"),
        "content-type must not discriminate"
    );
    assert_eq!(
        private_body.replace(&claim_id.to_string(), "<ID>"),
        absent_body.replace(&absent.to_string(), "<ID>"),
        "a private claim and a nonexistent uuid must be byte-identical to a \
         non-member once the echoed id is normalised (plan §8.4 N15). \
         private={private_body}  absent={absent_body}"
    );
    assert!(
        !private_body.contains("TOP SECRET private claim body")
            && !private_body.contains("[REDACTED]"),
        "the not-found body must carry neither the content nor a placeholder \
         announcing that content exists: {private_body}"
    );
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
    let claim_id = common::seed_claim_with_agent(&pool, "COMMUNITY-GATED claim body", owner).await;
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
    // PR-12 TIGHTENING. Migration 071's shim transcribes the community ownership
    // row into ('group', <the community's projected group>), so a non-member's
    // viewer predicate excludes the claim outright rather than the handler
    // blanking its content. A spoofed ?agent_id still does not launder anyone
    // into the community — that half of the property is unchanged and is what
    // the 404 now demonstrates.
    assert_eq!(
        outsider_resp.status(),
        404,
        "a non-member must not see the community-gated claim AT ALL, and a spoofed \
         ?agent_id must not launder them into the community"
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
async fn list_claims_stranger_token_spoofed_owner_omits_the_private_claim() {
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
    // PR-12 TIGHTENING. Before migration 071, `seed_private_ownership` wrote an
    // ACL row that ONLY `check_content_access` consulted: every claim was still
    // `visibility='public'`, so the viewer predicate returned the row and the
    // handler blanked its content to "[REDACTED]".
    //
    // The 071 compat shim now TRANSCRIBES that row into the tenancy columns, so
    // the claim is genuinely ('group', <owner's personal group>) and the
    // stranger's viewer predicate excludes it outright. The row is ABSENT, not
    // blanked.
    //
    // That is strictly less disclosure — a stranger no longer learns the claim
    // exists — and it is the end state plan PR-14 names: "delete redaction; a
    // non-visible row is absent, not blanked". progress.json's Q6 records
    // `check_content_access` retention as `gated_on: "PR-12 transcription
    // completing"`; this is that gate discharging.
    assert!(
        items
            .iter()
            .all(|it| it.get("id").and_then(|v| v.as_str()) != Some(claim_id.to_string().as_str())),
        "stranger token spoofing ?agent_id=<owner> must not see the transcribed \
         private claim AT ALL in list_claims; got {items:?}"
    );
}

/// claims_by_belief (GET /api/v1/claims/by-belief) must OMIT a private claim
/// for a stranger's token spoofing ?agent_id=<owner>. We seed the claim into a
/// fresh frame and pass ?frame_id=<frame> so the seeded claim is the only row
/// in the page — avoiding paging flakiness on the shared test DB (the query is
/// ORDER BY belief DESC LIMIT 100, and belief=0.5 can fall outside the top 100
/// on a populated DB). The belief predicate (c.belief >= min AND c.plausibility
/// <= max) still applies even with frame_id narrowing, and NULL >= 0.0 is
/// falsy, so we must set belief/plausibility explicitly for the row to return.
#[tokio::test(flavor = "multi_thread")]
async fn claims_by_belief_stranger_token_spoofed_owner_omits_the_private_claim() {
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
    // PR-12 TIGHTENING. Before migration 071, `seed_private_ownership` wrote an
    // ACL row that ONLY `check_content_access` consulted: every claim was still
    // `visibility='public'`, so the viewer predicate returned the row and the
    // handler blanked its content to "[REDACTED]".
    //
    // The 071 compat shim now TRANSCRIBES that row into the tenancy columns, so
    // the claim is genuinely ('group', <owner's personal group>) and the
    // stranger's viewer predicate excludes it outright. The row is ABSENT, not
    // blanked.
    //
    // That is strictly less disclosure — a stranger no longer learns the claim
    // exists — and it is the end state plan PR-14 names: "delete redaction; a
    // non-visible row is absent, not blanked". progress.json's Q6 records
    // `check_content_access` retention as `gated_on: "PR-12 transcription
    // completing"`; this is that gate discharging.
    assert!(
        arr.iter()
            .all(|it| it.get("id").and_then(|v| v.as_str()) != Some(claim_id.to_string().as_str())),
        "stranger token spoofing ?agent_id=<owner> must not see the transcribed \
         private claim AT ALL in claims_by_belief; got {arr:?}"
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
async fn frame_claims_sorted_stranger_token_spoofed_owner_omits_the_private_claim() {
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
    // PR-12 TIGHTENING. Before migration 071, `seed_private_ownership` wrote an
    // ACL row that ONLY `check_content_access` consulted: every claim was still
    // `visibility='public'`, so the viewer predicate returned the row and the
    // handler blanked its content to "[REDACTED]".
    //
    // The 071 compat shim now TRANSCRIBES that row into the tenancy columns, so
    // the claim is genuinely ('group', <owner's personal group>) and the
    // stranger's viewer predicate excludes it outright. The row is ABSENT, not
    // blanked.
    //
    // That is strictly less disclosure — a stranger no longer learns the claim
    // exists — and it is the end state plan PR-14 names: "delete redaction; a
    // non-visible row is absent, not blanked". progress.json's Q6 records
    // `check_content_access` retention as `gated_on: "PR-12 transcription
    // completing"`; this is that gate discharging.
    assert!(
        rows.iter()
            .all(|it| it.get("claim_id").and_then(|v| v.as_str())
                != Some(claim_id.to_string().as_str())),
        "stranger token spoofing ?agent_id=<owner> must not see the transcribed \
         private claim AT ALL in frame_claims_sorted; got {rows:?}"
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

/// claim_provenance (GET /api/v1/claims/:id/provenance) treats a claim this
/// viewer cannot read as ABSENT. Before PR-14 it returned 200 with the claim
/// step labelled "[REDACTED]" — a body that confirms the id names a real,
/// private claim. It now returns the identical 404 a nonexistent id returns.
///
/// The paired `..._returns_the_same_404_as_a_random_uuid` test below is what
/// makes that equality load-bearing; this test pins the status and the absence
/// of the secret, and `claim_provenance_owner_token_ignores_wire_param_and_sees_full`
/// is the Class P half proving the route did not simply stop working.
#[tokio::test(flavor = "multi_thread")]
async fn claim_provenance_stranger_token_spoofed_owner_is_absent() {
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
    assert_eq!(
        resp.status(),
        404,
        "a claim this viewer cannot read must be absent, not blanked"
    );
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("PROV private secret body"),
        "private claim content leaked into the not-found body: {text}"
    );
    // And no placeholder either: the point of PR-14 is that there is no
    // response shape which says "a claim is here but you may not read it".
    assert!(
        !text.contains("[REDACTED]"),
        "the redacted response shape must no longer exist: {text}"
    );

    // The oracle assertion. The body for a claim that exists-but-is-invisible
    // must equal the body for a uuid that names nothing, once the echoed id —
    // which the caller supplied and therefore already knows — is normalised
    // away. Anything else (a distinct message, a different field set) re-opens
    // the confirmation oracle that returning "[REDACTED]" was.
    let absent = Uuid::new_v4();
    let resp2 = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/claims/{absent}/provenance?agent_id={owner}"
        ))
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 404);
    let text2 = resp2.text().await.unwrap();
    assert_eq!(
        text.replace(&claim_id.to_string(), "<ID>"),
        text2.replace(&absent.to_string(), "<ID>"),
        "an invisible claim and a nonexistent one must be indistinguishable"
    );
}

/// OTHER DIRECTION for claim_provenance: the OWNER token — even with a RANDOM
/// spoofed ?agent_id — must see the FULL claim content in the claim step label.
/// Mirrors the owner-full counterparts for claims_by_belief / frame_claims_sorted:
/// proves the decision is token-driven, not param-driven, AND guards against a
/// "redact for everyone" over-redaction regression that the no-token test alone
/// cannot catch. The task bar this was written against said "owner-sees-full AND
/// stranger-sees-REDACTED must both be asserted"; PR-14 deleted the redacted
/// disposition, so the surviving obligation is the DISCRIMINATING PAIR itself —
/// owner-sees-full and stranger-sees-nothing — which is what makes a viewer that
/// matches nothing fail instead of pass. The same DERIVED_FROM evidence chain is seeded so the
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
/// explicitly-named Task-7 deliverable.
///
/// **REWRITTEN FOR PR-14.** This doc used to say "the handler early-returns an
/// EMPTY list when the claim itself is redacted for the requester
/// (`check_content_access` on the claim)". There is no claim-level gate on this
/// endpoint any more, and no `check_content_access` anywhere in the tree. The
/// control is now inside the read: `EvidenceRepository::by_relationship_for_claim`
/// filters BOTH the edge (`{EDGE_VISIBILITY:ed}`) and the evidence row
/// (`{VISIBILITY:ev}`), so a stranger's viewer matches neither and the join
/// yields nothing.
///
/// The observable shape — an empty list rather than a 404 — is unchanged and is
/// kept deliberately: this endpoint has never had a claim-existence check, so a
/// claim the caller cannot see and a claim that never existed both return
/// `total: 0`. That is §8.5's indistinguishability requirement satisfied at the
/// bottom rather than at the top, and the reasoning is written out at
/// `routes/edges.rs::evidence_by_relationship`.
///
/// Pre-A3 it trusted the
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

/// get_evidence (GET /api/v1/evidence/:id) treats evidence whose parent claim
/// this viewer cannot read as ABSENT.
///
/// Before PR-14 this route fetched the row unconditionally and then nulled
/// `content`, `caption` and `source_url` field by field — a per-field decision
/// taken after the secret was already in memory, and one that had to be
/// repeated correctly at every field the response grew. It now filters at the
/// read: `evidence` carries its own tenancy columns, kept in step with the
/// parent claim by the inherit/propagate triggers, so the row simply does not
/// come back.
///
/// DISCRIMINATING PAIR: the stranger gets the same 404 a never-created
/// evidence id gets, while the owner (with a random spoofed wire ?agent_id)
/// still sees content, caption AND source_url. The owner half is what proves
/// the 404 above is a tenancy decision and not a broken route — it is the
/// Class P assertion, and without it a viewer that matched nothing would pass.
#[tokio::test(flavor = "multi_thread")]
async fn get_evidence_stranger_token_spoofed_owner_is_absent() {
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
    assert_eq!(
        resp.status(),
        404,
        "evidence hanging off a claim this viewer cannot read must be absent, not blanked"
    );
    let text = resp.text().await.unwrap();
    for secret in [
        "evidence body text",
        "SECRET CAPTION substance",
        "https://secret.example/leak",
        "[REDACTED]",
    ] {
        assert!(
            !text.contains(secret),
            "not-found body must carry neither the secret nor a placeholder \
             confirming one exists (found {secret:?} in {text})"
        );
    }

    // Oracle: indistinguishable from evidence that was never created.
    let absent = Uuid::new_v4();
    let resp2 = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/evidence/{absent}?agent_id={owner}"
        ))
        .bearer_auth(stranger_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 404);
    let text2 = resp2.text().await.unwrap();
    assert_eq!(
        text.replace(&evidence_id.to_string(), "<ID>"),
        text2.replace(&absent.to_string(), "<ID>"),
        "invisible evidence and nonexistent evidence must be indistinguishable"
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

/// graph_full (GET /api/v1/graph/full) OMITS a private claim node from a
/// stranger's result rather than including it with a blanked label.
///
/// # This assertion was VACUOUS and PR-14 had to fix that, not just flip it
///
/// The previous revision wrapped its check in `if let Some(label) =
/// find_node(&body)` and asserted `label == "[REDACTED]"` inside — hedging
/// against the node falling outside graph_full's 2000-edge window. Once PR-12
/// transcribed ownership into the tenancy columns the node became ABSENT for a
/// stranger, the `if let` stopped matching, and the test passed while asserting
/// nothing whatsoever. Simply changing the expected string would have left it
/// vacuous; the check has to move OUT of the conditional to mean anything.
///
/// DISCRIMINATING PAIR: the stranger must not see the node at all, and the
/// owner (with a random spoofed wire ?agent_id) must — the owner half is both
/// the Class P assertion and the proof that the seeded node is inside the
/// window, so the stranger's absence is a tenancy decision and not a paging
/// accident.
#[tokio::test(flavor = "multi_thread")]
async fn graph_full_stranger_token_spoofed_owner_omits_the_private_node() {
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
    // UNCONDITIONAL. The owner half below proves the node is inside the
    // 2000-edge window, so an absence here is a tenancy decision rather than
    // the paging accident the old `if let` was hedging against.
    assert_eq!(
        find_node(&body),
        None,
        "a private claim must be ABSENT from a stranger's graph_full, not \
         present with a blanked label; body was {body:?}"
    );

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

/// execute_graph_query (POST /api/v1/graph/query) reads agent_id from the JSON
/// body. DISCRIMINATING PAIR (mirrors graph_full): a stranger's token with body
/// agent_id == owner (spoof) must not see the node AT ALL, while the owner token
/// (random spoofed body agent_id) sees it with its real label. The owner half
/// proves the decision is token-driven — not "graph_query always hides" or "the
/// body agent_id is still trusted" — and doubles as the presence proof.
///
/// PR-14 renamed this from `..._is_redacted`. The assertion was already an
/// absence check (PR-12 tightened it); only the name still described blanking.
#[tokio::test(flavor = "multi_thread")]
async fn graph_query_stranger_token_spoofed_owner_omits_the_private_node() {
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
    // PR-12 TIGHTENING, completed by PR-14. graph_query used to blank the node
    // `label`, because `seed_private_ownership` wrote an ACL row that left the
    // claim `visibility='public'` and so still inside the viewer predicate.
    // Migration 071's shim transcribes it into the tenancy columns, so the node
    // is excluded from the result set entirely; PR-14 then deleted the blanking
    // branch (`apply_partition_filter`) that would have handled it.
    //
    // The WHERE clause selects exactly one row by its unique probe key, so
    // absence here is a real, specific measurement — not the windowing accident
    // the comment above this block was written to rule out.
    assert!(
        find_node_label(&resp_body).is_none(),
        "a transcribed private claim must be ABSENT from a stranger's graph query, \
         not present with a redacted label; got {resp_body:?}"
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

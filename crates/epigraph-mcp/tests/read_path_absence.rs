//! Consolidated MCP read-path redaction parity test (A3 §7.5, Task 12).
//!
//! NAME NOTE: this file was `read_path_redaction.rs` through PR-13. PR-14
//! deleted redaction outright, so the old name asserted a behaviour that no
//! longer exists. The MATRIX it covers is unchanged and still worth one place:
//! both transports (HTTP bearer vs. stdio fallback), owner vs. stranger, the
//! public non-regression, and the batch per-id path — every one of them now
//! expressed as presence-vs-ABSENCE rather than content-vs-placeholder.
//!
//! This file is the single discriminating regression that exercises the
//! WHOLE matrix the spec enumerates — both transports (HTTP bearer vs. stdio
//! fallback), owner vs. stranger, the public non-regression, and the batch
//! per-id path — in one place, so a future refactor that breaks redaction trips
//! exactly one obviously-named test.
//!
//! Each case runs against its own fresh `#[sqlx::test]` database: the seeded
//! claims are the ONLY rows, so the stranger assertion proves *redaction*, not
//! a missing/not-found row (INDEX §5 residual: a large seeded DB can make a
//! redaction test non-discriminating). `find_claim` / `.expect()` panic on
//! absence, which is the not-found guard.
//!
//! The stranger-via-MCP assertions FAIL on `origin/main` (which returned the
//! owner's content to any caller) and PASS on this branch — that is the
//! discriminating regression. This is a TEST-ONLY task; the redaction
//! implementation already landed in Task 11, so every assertion is GREEN on the
//! first run.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{Agent, ClaimId};
use epigraph_crypto::AgentSigner;
use epigraph_db::AgentRepository;
use epigraph_mcp::tools::claims::{get_claim, query_claims};
use epigraph_mcp::types::{GetClaimParams, QueryClaimsParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

// The `REDACTED` constant is GONE, and its absence is the point. Every
// assertion in this file that once read `content == "[REDACTED]"` is now an
// absence assertion: migration 071 transcribes `ownership` into the tenancy
// columns, so the Viewer predicate drops the row before any handler can blank
// it. Redaction on this path is not merely unused — it is unreachable.
//
// That is what plan PR-14 ("delete redaction; a non-visible row is absent, not
// blanked") formalises, and what `docs/tenancy/progress.json`'s Q6 means by
// `gated_on: "PR-12 transcription completing"`. PR-12 does not delete
// `check_content_access`; it makes its remaining branches unreachable.

// ── Case: owner (HTTP) sees full content; stranger (HTTP) is redacted ────────
//
// The HTTP transport derives the requester from the validated bearer identity.
// We model that here by passing `Some(agent)` directly to `get_claim` (exactly
// what `mcp_requester(Some(auth), _)` resolves a bearer to). The stranger
// assertion is the discriminating one: on `origin/main` it returned A's
// content. PR-12 tightened the required disposition from `"[REDACTED]"` to
// ABSENT — migration 071 puts the ownership row into the tenancy columns, so
// the stranger's Viewer excludes the claim rather than returning a blanked
// body. Strictly less disclosure: the stranger no longer learns it exists.
#[sqlx::test(migrations = "../../migrations")]
async fn http_owner_sees_content_stranger_sees_nothing(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());
    seed_private_ownership(&pool, claim_id, owner).await;

    let server = build_test_server(pool.clone());

    // Owner (HTTP) → real content.
    let owner_body = get_claim_as(&server, &pool, claim_id, Some(owner)).await;
    assert_eq!(
        owner_body["content"].as_str().unwrap(),
        expected,
        "owner must see the full private content"
    );

    // Stranger (HTTP), B ≠ A. PR-12 TIGHTENING: absent, not blanked — migration
    // 071 made the claim genuinely ('group', <owner's personal group>), so the
    // stranger's Viewer excludes it and it never reaches the redaction step.
    // Still the discriminating assertion, and now a stronger one: the stranger
    // does not even learn the claim exists.
    let stranger = Uuid::new_v4();
    assert_claim_absent_for(&server, &pool, claim_id, Some(stranger)).await;
}

// ── Case: stdio fallback resolves the requester to server.agent_id() ─────────
//
// On the stdio transport there is no `AuthContext`, so the principal falls back
// to the server's own signer identity. PR-14 deleted `mcp_requester`, which used
// to compute that alongside a separate viewer; the derivation now happens ONCE,
// in `tools::viewer::request_viewer`'s `None` arm, and feeds the Viewer that
// filters the read.
//
// THE VIEWER UNDER TEST IS THE ONE THE PRODUCTION ARM PRODUCES. We call
// `request_viewer(&server, None)` — the real function, the real `None` arm —
// rather than resolving a viewer from the literal `server.agent_id()`. The
// literal form was tried and rejected: it constructs the fixture from the same
// value it then confirms, so it would keep passing if the stdio arm stopped
// resolving to the server agent, which is the only thing this case exists to
// check. `request_viewer` was widened from `pub(crate)` to `pub` for exactly
// this, and for nothing else.
//
// The choice of ARM (stdio ⇒ `auth == None` and nothing else) is pinned
// separately, by `http_calls_cannot_reach_a_tool_without_an_auth_context.rs`:
// an HTTP call with no `AuthContext` is refused one frame up, at dispatch.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_fallback_uses_server_identity(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let server_agent = server_agent_id(&pool).await;

    // (a) Private claim OWNED BY the stdio server agent → real content, because
    // the stdio arm resolves the principal to server_agent == owner.
    let owned_id = seed_claim(&pool, server_agent).await;
    let owned_expected = format!("test claim {}", owned_id.as_uuid());
    seed_private_ownership(&pool, owned_id, server_agent).await;

    let stdio_viewer = epigraph_mcp::tools::viewer::request_viewer(&server, /* auth */ None)
        .await
        .expect("the stdio arm must establish the server's own agent row");

    let owned_body = get_claim_with(&server, &stdio_viewer, owned_id).await;
    assert_eq!(
        owned_body["content"].as_str().unwrap(),
        owned_expected,
        "the viewer `request_viewer(_, None)` returns must carry the server \
         agent's groups: it is what every claim the stdio process writes is \
         authored by. Seeing an absence here means the stdio arm resolved some \
         OTHER principal."
    );

    // (b) Private claim owned by a DIFFERENT agent. PR-12 TIGHTENING: absent,
    // not blanked — the claim is now ('group', <other_owner's personal group>),
    // which the stdio server agent is not in. This is the non-vacuity control:
    // without it, a `request_viewer` that returned an all-seeing viewer would
    // satisfy (a).
    let other_owner = seed_agent(&pool).await;
    let foreign_id = seed_claim(&pool, other_owner).await;
    seed_private_ownership(&pool, foreign_id, other_owner).await;

    assert_claim_absent_with(&server, &stdio_viewer, foreign_id).await;
}

// ── Case: public (ownership-less) non-regression for ANY requester ───────────
//
// A claim with no `ownership` row is public: `check_content_access` returns
// `Full` regardless of requester. The spec requires this hold "for any
// requester (including `None`)", so we assert all three: owner, stranger, and
// the anonymous stdio `None`. This guards against an over-eager redaction that
// fails closed on public rows.
#[sqlx::test(migrations = "../../migrations")]
async fn public_claim_is_never_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner).await; // no ownership row → public
    let expected = format!("test claim {}", claim_id.as_uuid());

    let server = build_test_server(pool.clone());

    for (label, requester) in [
        ("owner", Some(owner)),
        ("stranger", Some(Uuid::new_v4())),
        ("anonymous (stdio None)", None),
    ] {
        let body = get_claim_as(&server, &pool, claim_id, requester).await;
        assert_eq!(
            body["content"].as_str().unwrap(),
            expected,
            "public claim must show full content to {label}"
        );
    }
}

// ── Case: query_claims batch redacts only the rows the requester can't see ───
//
// `query_claims` uses `batch_check_content_access` + a per-id `access_map`
// lookup — a different code path from singular `get_claim`. Its distinctive
// failure mode is a *mispairing* (the access decision landing on the wrong
// claim), which cannot occur with a single claim. We seed a mixed result set
// (one public, one private-owned-by-a-stranger) and query as a non-owner: each
// row must get ITS OWN decision.
#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_hides_only_unauthorized_rows(pool: PgPool) {
    let public_owner = seed_agent(&pool).await;
    let private_owner = seed_agent(&pool).await;

    let public_id = seed_claim_with_truth(&pool, public_owner, 0.80).await;
    let public_content = format!("test claim {}", public_id.as_uuid());

    let private_id = seed_claim_with_truth(&pool, private_owner, 0.20).await;
    seed_private_ownership(&pool, private_id, private_owner).await;

    let server = build_test_server(pool.clone());

    // Query as a STRANGER (neither owner). Both claims appear; only the private
    // one is redacted.
    let stranger = Uuid::new_v4();
    let viewer = viewer_for(&pool, Some(stranger)).await;
    let result = query_claims(
        &server,
        &viewer,
        QueryClaimsParams {
            min_truth: Some(0.0),
            max_truth: Some(1.0),
            limit: Some(50),
        },
    )
    .await
    .expect("query_claims as stranger");
    let claims = parse_claims(&result);

    let public = find_claim(&claims, public_id);
    assert_eq!(
        public["content"].as_str().unwrap(),
        public_content,
        "public claim must show full content to a stranger in a batch query — \
         and it must NOT be collateral damage of the private one's exclusion"
    );

    // PR-12 TIGHTENING: the private claim is dropped by the Viewer predicate
    // rather than returned blanked. The per-id mispairing this case was written
    // to catch would now show up as the PUBLIC claim going missing instead,
    // which the assertion above still catches.
    assert!(
        claims
            .iter()
            .all(|c| c["id"].as_str() != Some(private_id.as_uuid().to_string().as_str())),
        "a private claim must be ABSENT for a stranger in a batch query, not \
         returned blanked; got {claims:?}"
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Resolve the server's own agent id the same way `EpiGraphMcpFull::agent_id`
/// does (which is `pub(crate)` and so not reachable from an integration test):
/// derive the signer's public key and get-or-create the agent. The signer bytes
/// MUST stay in lockstep with `build_test_server` in `common/mod.rs`
/// (`AgentSigner::from_bytes(&[0xA7u8; 32])`) — if that constant changes there,
/// change it here too, or this helper resolves a different agent than the server
/// uses and the stdio cases go silently non-discriminating.
async fn server_agent_id(pool: &PgPool) -> Uuid {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let pub_key = signer.public_key();
    if let Some(a) = AgentRepository::get_by_public_key(pool, &pub_key)
        .await
        .expect("get agent by public key")
    {
        return a.id.as_uuid();
    }
    let agent = Agent::new(pub_key, Some("mcp-agent".to_string()));
    AgentRepository::create(pool, &agent)
        .await
        .expect("create server agent");
    agent.id.as_uuid()
}

/// Resolve the Viewer for `requester`, or the public viewer when anonymous.
///
/// # Why the shared `public_viewer` no longer works here
///
/// These tests used to build ONE `public_viewer` (empty group set) and pass the
/// acting principal separately as the `requester` wire parameter. That was
/// faithful before PR-12, because `seed_private_ownership` wrote an ACL row that
/// only `check_content_access` consulted while every claim stayed
/// `visibility='public'` — so the Viewer predicate matched every row and the
/// requester decided everything.
///
/// Migration 071 transcribes `ownership` into the tenancy columns, so the Viewer
/// is now the FIRST filter. An empty-group viewer cannot see a private claim at
/// all — not even the OWNER'S. Keeping it would assert against a principal that
/// cannot exist in production, where `Viewer::resolve` runs on the authenticated
/// agent and viewer and requester are therefore the same principal.
async fn viewer_for(pool: &PgPool, requester: Option<Uuid>) -> epigraph_db::visibility::Viewer {
    match requester {
        Some(agent) => epigraph_db::visibility::Viewer::resolve(pool, agent)
            .await
            .expect("resolve viewer"),
        None => fixture::public_viewer(pool).await,
    }
}

async fn get_claim_as(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: ClaimId,
    requester: Option<Uuid>,
) -> Value {
    let viewer = viewer_for(pool, requester).await;
    get_claim_with(server, &viewer, claim_id).await
}

/// The same read, driven by a `Viewer` the caller already holds.
///
/// The stdio case obtains its viewer from `request_viewer` rather than by
/// resolving a principal it names itself, so it cannot go through
/// [`get_claim_as`]'s `Option<Uuid>` front door.
async fn get_claim_with(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: ClaimId,
) -> Value {
    let result = get_claim(
        server,
        viewer,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .expect("get_claim");
    parse_claim(&result)
}

/// Assert `requester` cannot see `claim_id` AT ALL.
///
/// After PR-12 a non-visible row is ABSENT, not blanked — strictly less
/// disclosure than the old `[REDACTED]` body, which told a stranger the claim
/// existed. This is the end state plan PR-14 formalises.
async fn assert_claim_absent_for(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: ClaimId,
    requester: Option<Uuid>,
) {
    let viewer = viewer_for(pool, requester).await;
    assert_claim_absent_with(server, &viewer, claim_id).await;
}

/// [`assert_claim_absent_for`], driven by a `Viewer` the caller already holds.
async fn assert_claim_absent_with(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: ClaimId,
) {
    let result = get_claim(
        server,
        viewer,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await;
    let hidden_err = match result {
        Err(e) => e.to_string(),
        Ok(ok) => panic!(
            "expected the claim to be ABSENT for this requester, but get_claim \
             returned a body: {:?}",
            parse_claim(&ok)
        ),
    };

    // THE ACCEPTANCE ORACLE (plan §8.4 N15), MCP half. "Not found" as a
    // SUBSTRING is not enough: a message that says "not found" but differs in
    // any other way from the one a never-created uuid produces still tells the
    // caller which uuids name real private claims, which is the whole defect
    // deleting redaction exists to close. Require the two to be identical once
    // the echoed uuid — which the caller supplied and already knows — is
    // normalised away.
    let absent = Uuid::new_v4();
    let absent_err = get_claim(
        server,
        viewer,
        GetClaimParams {
            claim_id: absent.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .expect_err("a uuid that names nothing must not return a claim")
    .to_string();

    assert_eq!(
        hidden_err.replace(&claim_id.as_uuid().to_string(), "<ID>"),
        absent_err.replace(&absent.to_string(), "<ID>"),
        "a claim outside the viewer's scope and a nonexistent uuid must be \
         indistinguishable. hidden={hidden_err}  absent={absent_err}"
    );
}

async fn seed_private_ownership(pool: &PgPool, claim_id: ClaimId, owner: Uuid) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim_id.as_uuid())
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed private ownership");
}

fn parse_claim(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

fn parse_claims(result: &CallToolResult) -> Vec<Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    parsed.as_array().expect("response is JSON array").clone()
}

fn find_claim(claims: &[Value], id: ClaimId) -> &Value {
    let id_str = id.as_uuid().to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Derive a unique public key from the agent id so seeding several agents in
    // one test doesn't collide on `agents_public_key_unique`.
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    seed_claim_with_truth(pool, agent_id, 0.5).await
}

async fn seed_claim_with_truth(pool: &PgPool, agent_id: Uuid, truth: f64) -> ClaimId {
    let id = Uuid::new_v4();
    // 16-byte UUID padded to a 32-byte content_hash. `repeat(0).take(16)` keeps
    // this MSRV-safe (avoids `iter::repeat_n`).
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current) \
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[], true)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    ClaimId::from_uuid(id)
}

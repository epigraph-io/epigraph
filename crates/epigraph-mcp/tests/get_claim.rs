//! Integration test for [`get_claim`] after Task 4 of the
//! backlog-retirement plan: surfaces `labels`/`is_current`/`supersedes` on
//! `ClaimResponse` for single-claim lookup (previously stubbed defaults).
//!
//! Seeds two claims directly via SQL (one open backlog claim, one superseded
//! pointing at the open one), then verifies the MCP `get_claim` handler
//! returns the new fields with real database state.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_mcp::tools::claims::get_claim;
use epigraph_mcp::types::GetClaimParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_returns_labels_and_retirement_state(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Claim 1: an open backlog claim (is_current=true, supersedes=None).
    let open_id = seed_claim(&pool, agent, &["backlog"], true, None).await;

    let server = build_test_server(pool.clone());

    let result = get_claim(
        &server,
        &viewer,
        GetClaimParams {
            claim_id: open_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        None,
    )
    .await
    .expect("get_claim open");
    let body = parse_claim(&result);

    assert_eq!(
        body["id"].as_str().unwrap(),
        open_id.as_uuid().to_string(),
        "id round-trips"
    );
    assert_eq!(body["labels"], serde_json::json!(["backlog"]));
    assert_eq!(body["is_current"], Value::Bool(true));
    assert!(
        body.get("supersedes").map(|v| v.is_null()).unwrap_or(true),
        "open claim should not include supersedes (None skips serialization): {body:?}"
    );

    // Claim 2: superseded, points at the open claim.
    let superseded_id = seed_claim(&pool, agent, &["backlog"], false, Some(open_id)).await;

    let result = get_claim(
        &server,
        &viewer,
        GetClaimParams {
            claim_id: superseded_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        None,
    )
    .await
    .expect("get_claim superseded");
    let body = parse_claim(&result);

    assert_eq!(body["is_current"], Value::Bool(false));
    assert_eq!(
        body["supersedes"].as_str().unwrap(),
        open_id.as_uuid().to_string(),
        "superseded.supersedes should point at open_id"
    );
}

/// Discriminating redaction regression (A3 §7.5, Task 11): a `private`-partition
/// claim must return its full content to the OWNER and be **absent** for a
/// stranger.
///
/// **The stranger disposition changed in PR-12 and this comment says so
/// deliberately.** It used to be `content == "[REDACTED]"` plus
/// `content_hash == ""`. Migration 071 now transcribes the `ownership` row into
/// the tenancy columns, so the stranger's `Viewer` excludes the row entirely
/// and `get_claim` reports not-found — which subsumes both old assertions and
/// leaks strictly less, because the stranger no longer learns the claim exists.
///
/// The blanking branch it used to exercise is NOT untested: see
/// [`get_claim_blanks_the_content_hash_when_it_redacts`] below for the live
/// path, and `epigraph-mcp/src/tools/redaction.rs::redact_content_blanks_hash_in_lockstep_with_content`
/// for the helper all eight call sites go through.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_redacts_private_content_for_strangers(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner, &[], true, None).await;
    let expected_content = format!("test claim {}", claim_id.as_uuid());

    // Mark the claim private, owned by `owner`.
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim_id.as_uuid())
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed private ownership");

    let server = build_test_server(pool.clone());

    // PR-12: the Viewer must be resolved for the acting principal, as it is in
    // production (`Viewer::resolve` runs on the authenticated agent). Migration
    // 071 transcribes the `ownership` row into the tenancy columns, so an
    // empty-group `public_viewer` can no longer see this claim AT ALL — not even
    // as its owner.
    let owner_viewer = epigraph_db::visibility::Viewer::resolve(&pool, owner)
        .await
        .expect("resolve owner viewer");

    // Owner requester → full content AND the real content_hash.
    let owner_body = parse_claim(
        &get_claim(
            &server,
            &owner_viewer,
            GetClaimParams {
                claim_id: claim_id.as_uuid().to_string(),
                frame_id: None,
                perspective_id: None,
            },
            Some(owner),
        )
        .await
        .expect("get_claim as owner"),
    );
    assert_eq!(
        owner_body["content"].as_str().unwrap(),
        expected_content,
        "owner must see the full private content"
    );
    assert!(
        !owner_body["content_hash"].as_str().unwrap().is_empty(),
        "owner must see the real content_hash (proves blanking is conditional, \
         not always-blank): {owner_body:?}"
    );

    // Stranger requester (a different, non-owner agent id) → content AND
    // content_hash both redacted. The hash assertion guards the
    // confirmation-oracle leak: content_hash = BLAKE3(content), so leaking it
    // for a redacted claim re-exposes the redacted field.
    //
    // PR-12 TIGHTENING: absent, not blanked. Migration 071 makes the claim
    // genuinely ('group', <owner's personal group>), so the stranger's Viewer
    // excludes it and `get_claim` reports not-found. That subsumes BOTH
    // assertions this case used to make — a row that is never returned leaks
    // neither `content` nor the `content_hash` confirmation oracle — and it
    // leaks strictly less, because the stranger no longer learns the claim
    // exists at all.
    let stranger = Uuid::new_v4();
    let stranger_viewer = epigraph_db::visibility::Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger viewer");
    let stranger_result = get_claim(
        &server,
        &stranger_viewer,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        Some(stranger),
    )
    .await;
    match stranger_result {
        Err(e) => assert!(
            e.to_string().contains("not found"),
            "expected not-found for a claim outside the stranger's scope, got: {e}"
        ),
        Ok(ok) => panic!(
            "a transcribed private claim must be ABSENT for a stranger, but \
             get_claim returned a body: {:?}",
            parse_claim(&ok)
        ),
    }
}

/// The `content_hash` confirmation oracle stays closed on the branch that still
/// BLANKS rather than hides.
///
/// # Why this test had to be written, not just kept
///
/// PR-12 rewrote three cases (`get_claim`, `query_claims_by_label`,
/// `query_claims_redaction`) from "content is `[REDACTED]` and content_hash is
/// `\"\"`" to "the row is absent". The absence disposition is strictly better —
/// but it removed every integration-level assertion on the HASH half, while the
/// blanking code stayed live behind eight `redact_content` call sites. A change
/// that stopped blanking `content_hash` on a path that still redacts would then
/// have been caught by nothing above the helper's own unit test.
///
/// # The shape, and why it is realistic rather than contrived
///
/// This is the LEGACY shape: an `ownership` row that predates migration 071 and
/// was therefore never transcribed. `check_content_access` reads `ownership`
/// and says Redacted; the tenancy columns still say public so the `Viewer`
/// admits the row; `get_claim` reaches the blanking branch. It is exactly the
/// population `epigraph-tenancy-backfill`'s `transcribe_legacy_ownership` arm
/// exists to clear, reproduced here by disabling the trigger for one INSERT.
///
/// `content_hash = BLAKE3(content)` — returning it for a redacted claim is a
/// confirmation oracle over the redacted field, which is why the hash must be
/// blanked in LOCKSTEP with the content and not in a separate branch.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_blanks_the_content_hash_when_it_redacts(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    // NOT `seed_agent` twice: it binds a FIXED public key and
    // `agents_public_key_unique` rejects the second call. A stranger needs no
    // `agents` row anyway — `Viewer::resolve` on an unknown principal yields a
    // correct, empty `Scoped` viewer, which is exactly what a stranger is.
    let stranger = Uuid::new_v4();
    let claim_id = seed_claim(&pool, owner, &[], true, None).await;

    // The legacy shape: an `ownership` row written while 071's trigger was not
    // there. The claim's tenancy columns stay ('public', world).
    sqlx::query("ALTER TABLE ownership DISABLE TRIGGER ownership_transcribe")
        .execute(&pool)
        .await
        .expect("disable the transcription trigger");
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim_id.as_uuid())
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed an untranscribed ownership row");
    sqlx::query("ALTER TABLE ownership ENABLE TRIGGER ownership_transcribe")
        .execute(&pool)
        .await
        .expect("re-enable the transcription trigger");

    let still_public: String =
        sqlx::query_scalar("SELECT visibility::text FROM claims WHERE id = $1")
            .bind(claim_id.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("read visibility");
    assert_eq!(
        still_public, "public",
        "precondition: the row must remain viewer-visible, or this test would be \
         asserting absence again instead of blanking"
    );

    let server = build_test_server(pool.clone());
    let stranger_viewer = epigraph_db::visibility::Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger viewer");

    let body = parse_claim(
        &get_claim(
            &server,
            &stranger_viewer,
            GetClaimParams {
                claim_id: claim_id.as_uuid().to_string(),
                frame_id: None,
                perspective_id: None,
            },
            Some(stranger),
        )
        .await
        .expect("the claim is viewer-visible, so get_claim must RETURN it"),
    );

    assert_eq!(
        body["content"].as_str().unwrap(),
        "[REDACTED]",
        "precondition: this must be the BLANKING branch, not the absence one — \
         if this fails the test is no longer covering what it claims to cover"
    );
    assert_eq!(
        body["content_hash"].as_str().unwrap(),
        "",
        "the content_hash must be blanked in lockstep with the content: \
         content_hash = BLAKE3(content) is a confirmation oracle for the \
         redacted field, so leaking it re-exposes what the redaction hid"
    );
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

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<ClaimId>,
) -> ClaimId {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes.map(|s| s.as_uuid()))
    .execute(pool)
    .await
    .expect("seed claim");
    ClaimId::from_uuid(id)
}

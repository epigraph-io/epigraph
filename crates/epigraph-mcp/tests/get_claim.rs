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
/// `content_hash == ""`. The claim is group-private in its own tenancy columns,
/// so the stranger's `Viewer` excludes the row entirely and `get_claim` reports
/// not-found — which subsumes both old assertions and leaks strictly less,
/// because the stranger no longer learns the claim exists.
///
/// The blanking branch it used to exercise is NOT untested: see
/// [`get_claim_blanks_the_content_hash_when_it_redacts`] below for the live
/// path, and `epigraph-mcp/src/tools/redaction.rs::redact_content_blanks_hash_in_lockstep_with_content`
/// for the helper all eight call sites go through.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_hides_private_content_from_strangers(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner, &[], true, None).await;
    let expected_content = format!("test claim {}", claim_id.as_uuid());

    // Mark the claim private, owned by `owner`.
    common::seed_private_tenancy(&pool, claim_id.as_uuid(), owner).await;

    let server = build_test_server(pool.clone());

    // PR-12: the Viewer must be resolved for the acting principal, as it is in
    // production (`Viewer::resolve` runs on the authenticated agent). The claim
    // is group-private, so an empty-group `public_viewer` cannot see it AT ALL —
    // not even as its owner.
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

// `the_read_path_does_not_consult_the_legacy_ownership_table` lived here until
// PR-22, and it is DELETED rather than ported.
//
// It manufactured a row whose legacy `ownership` record and whose tenancy
// columns DISAGREED — by suppressing migration 071's write-through trigger for a
// single INSERT — and asserted that the read path answered from the columns.
// Migration 084 removes the relation, so there is no second store left to
// disagree with and no way to construct the case. The property is now carried by
// the schema instead of by an assertion, and
// `epigraph-db/tests/retire_ownership_preflight.rs::the_ownership_relation_is_retired_at_head`
// is what pins the schema.
//
// The half that test also protected — that `content_hash` is an unsalted
// `BLAKE3(content)` and must never be returned beside a body the caller may not
// read — was already closed by construction in PR-14: no branch returns a claim
// WITHOUT its content, so the two fields cannot disagree in any response.
// `epigraph-api/tests/no_redaction_sentinel.rs` keeps it that way.
//
// The deploy-ordering constraint it was the only executable statement of —
// `D-PR14-transcription-is-a-deploy-prerequisite` — is now carried by migration
// 084's second pre-flight, which refuses to drop the table while any non-public
// row lacks a `tenancy_transcription_log` entry recording the partition that row
// currently holds. It runs on the database being deployed rather than on a
// fixture, which is the respect in which it is the better instrument.
//
// It is NOT a superset of what this test asserted, and the difference is stated
// rather than glossed. This test manufactured a DISAGREEMENT between an
// `ownership` row and the tenancy columns and asserted the read path ignored
// the former; after 084 there is one store, so there is nothing left to
// disagree with and the assertion has no subject. The pre-flight is a
// deploy-time guard, not a read-path assertion, and the remaining half of the
// deploy ordering — a non-public `ownership` row whose claim is still public —
// is carried by `docs/deploy.md` steps 1-2, not by the migration.

// ── helpers ──────────────────────────────────────────────────────────────────

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

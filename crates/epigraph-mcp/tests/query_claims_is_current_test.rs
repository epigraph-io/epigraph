//! Reproduction for backlog `a85ee585`: the `query_claims` MCP tool reports a
//! FABRICATED retirement state on every row it returns.
//!
//! `ClaimRepository::list_by_truth_range` selects only
//! `(id, content, truth_value, agent_id, trace_id, created_at, updated_at)` —
//! no `is_current`, no `supersedes` — and hands those columns to
//! `claim_from_row`, which builds the `Claim` through `Claim::with_id`. That
//! constructor hardcodes `supersedes: None, is_current: true`. The
//! `query_claims` handler then hardcodes the same two values a second time when
//! it builds each `ClaimResponse`.
//!
//! The result is that a retired claim and a live claim are INDISTINGUISHABLE on
//! the wire: both come back `"is_current": true` with `supersedes` omitted.
//! `get_claim` on the very same id reports the real values (it post-fixes the
//! `Claim` from a `SELECT` that includes both columns), so the two tools
//! actively contradict each other.
//!
//! This test drives the REAL retirement path — `ClaimRepository::supersede`,
//! which sets `is_current = false` on the old row and `supersedes = old.id` on
//! the new one — rather than hand-crafting the state, so it cannot pass by
//! accident against a fixture that merely looks superseded.
//!
//! Deliberately scoped to the *reporting* lie, NOT to whether superseded rows
//! should be in the page at all. `crates/epigraph-mcp/tests/query_claims_labels_test.rs`
//! locks in the no-`is_current`-filter behaviour on purpose (backlog
//! `babd5904`), and this test asserts nothing that contradicts it: it only
//! requires that whatever rows ARE returned describe themselves truthfully.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::repos::ClaimRepository;
use epigraph_mcp::tools::claims::query_claims;
use epigraph_mcp::types::QueryClaimsParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_test_server, seed_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_reports_real_retirement_state(pool: PgPool) {
    // A live claim, then a genuine supersession through the repo API.
    let original = seed_claim(&pool, "a85ee585 original statement", 0.40).await;

    // NOTE the tuple order: `supersede` returns `(new_uuid, old_uuid)`.
    let (replacement_id, retired_id) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(original),
        "a85ee585 replacement statement",
        TruthValue::new(0.60).expect("truth 0.60"),
        "a85ee585 reproduction",
    )
    .await
    .expect("supersede");

    // Ground truth straight from the table, so the assertions below are
    // compared against what the database actually holds.
    let (db_retired_is_current, db_replacement_supersedes) =
        db_state(&pool, retired_id, replacement_id).await;
    assert!(
        !db_retired_is_current,
        "precondition: supersede() must set is_current=false on the old row"
    );
    assert_eq!(
        db_replacement_supersedes,
        Some(retired_id),
        "precondition: supersede() must set supersedes on the new row"
    );

    let server = build_test_server(pool.clone());
    let result = query_claims(
        &server,
        QueryClaimsParams {
            min_truth: Some(0.0),
            max_truth: Some(1.0),
            current_only: false,
            limit: Some(50),
        },
        None,
    )
    .await
    .expect("query_claims");
    let claims = parse_claims(&result);

    // The retired row IS in the page — `list_by_truth_range` has no is_current
    // filter. That is the existing, deliberate contract (babd5904); this lookup
    // documents it rather than challenging it.
    let retired = find_claim(&claims, retired_id);
    let replacement_row = find_claim(&claims, replacement_id);

    // Dump both rows so a failure carries the whole wire payload, not just the
    // one field the first assertion happens to trip on.
    println!("retired row on the wire:     {retired}");
    println!("replacement row on the wire: {replacement_row}");

    // THE DEFECT. The row the DB marks `is_current = false` is reported as
    // live, because both `Claim::with_id` and the handler hardcode `true`.
    assert_eq!(
        retired["is_current"].as_bool(),
        Some(false),
        "retired claim {retired_id} is is_current=false in the database but \
         query_claims reported is_current={:?} — the handler hardcodes `true`, \
         so a superseded claim is indistinguishable from a live one on the wire",
        retired["is_current"]
    );

    // Same lie, other column: the replacement's `supersedes` link is dropped,
    // so a consumer cannot walk the retirement chain from a query page.
    let replacement = find_claim(&claims, replacement_id);
    let expected_supersedes = retired_id.to_string();
    assert_eq!(
        replacement["supersedes"].as_str(),
        Some(expected_supersedes.as_str()),
        "replacement claim {replacement_id} has supersedes={retired_id} in the \
         database but query_claims reported supersedes={:?} — the handler \
         hardcodes `None`",
        replacement.get("supersedes")
    );

    // And the live row must still read as live, so a fix that simply inverts
    // the hardcode is not mistaken for a correct one.
    assert_eq!(
        replacement["is_current"].as_bool(),
        Some(true),
        "replacement claim {replacement_id} must still report is_current=true"
    );
}

/// The same defect one layer down, so the implementer knows the handler fix is
/// not sufficient on its own. Even a handler that faithfully forwards
/// `c.is_current` / `c.supersedes` would still emit `true` / `None`, because
/// `list_by_truth_range`'s `SELECT` never asks for those two columns and
/// `claim_from_row` → `Claim::with_id` fills them with constants.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_truth_range_returns_default_retirement_state(pool: PgPool) {
    let original = seed_claim(&pool, "a85ee585 repo-layer original", 0.40).await;
    let (replacement_id, retired_id) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(original),
        "a85ee585 repo-layer replacement",
        TruthValue::new(0.60).expect("truth 0.60"),
        "a85ee585 reproduction",
    )
    .await
    .expect("supersede");

    let claims = ClaimRepository::list_by_truth_range(&pool, 0.0, 1.0, false, 50, 0)
        .await
        .expect("list_by_truth_range");

    let retired = claims
        .iter()
        .find(|c| c.id.as_uuid() == retired_id)
        .expect("retired claim is in the page — list_by_truth_range has no is_current filter");
    assert!(
        !retired.is_current,
        "list_by_truth_range returned the retired claim with is_current={} — the \
         SELECT omits the column and Claim::with_id defaults it to true",
        retired.is_current
    );

    let replacement = claims
        .iter()
        .find(|c| c.id.as_uuid() == replacement_id)
        .expect("replacement claim is in the page");
    assert_eq!(
        replacement.supersedes.map(|s| s.as_uuid()),
        Some(retired_id),
        "list_by_truth_range dropped the supersedes link — the SELECT omits the \
         column and Claim::with_id defaults it to None"
    );
}

async fn db_state(pool: &PgPool, retired: Uuid, replacement: Uuid) -> (bool, Option<Uuid>) {
    let is_current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(retired)
            .fetch_one(pool)
            .await
            .expect("read retired row");
    let supersedes: Option<Uuid> =
        sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
            .bind(replacement)
            .fetch_one(pool)
            .await
            .expect("read replacement row");
    (is_current, supersedes)
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

fn find_claim(claims: &[Value], id: Uuid) -> &Value {
    let id_str = id.to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

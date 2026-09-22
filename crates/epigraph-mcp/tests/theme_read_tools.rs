//! Integration tests for the read-side theme tools `list_themes` / `get_theme`
//! (backlog `c40689c9-a6c0-4c90-adfb-cf52e8a6b917`, umbrella
//! `ac4d02b9-d374-44ad-b7dd-b9bd0370509e`).
//!
//! ## Why every params struct here is built from `serde_json::from_value`
//!
//! Same discipline as `recall_temporal.rs`: the assertions must be behavioural,
//! not "it compiles". Building params from JSON also exercises the exact
//! deserialisation path an MCP client takes, including the `#[serde(default)]`
//! on every optional field.
//!
//! ## Shared-database discipline
//!
//! `test_pool_or_skip!` hands back a pool onto whatever `DATABASE_URL` names —
//! a SHARED scratch DB, unlike `epigraph-db`'s `#[sqlx::test]`, which gets a
//! throwaway. Two consequences shape every fixture below:
//!
//!  1. Each test mints a run-unique `label_prefix`, asserts only on its OWN
//!     rows, and never on a corpus-wide total or "the first theme".
//!  2. Themes are deleted on the way out. `theme_cluster_test`'s skip path and
//!     `recall_temporal`'s `no_leak_s6_diverse_themes` both depend on the
//!     corpus having few or no themes, so leaked theme rows would break
//!     siblings rather than this file.

#[macro_use]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::themes::{get_theme, list_themes, GetThemeParams, ListThemesParams};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Run-unique label prefix so concurrent siblings and leftovers from earlier
/// runs cannot enter this test's result set.
fn unique_prefix(tag: &str) -> String {
    format!("ttest-{tag}-{}", Uuid::new_v4().simple())
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'theme-read-tools', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// Theme with an explicitly WRONG `claim_count`, mirroring production: only
/// `update_count` maintains that column, and `assign_claim` / `bulk_assign`
/// never call it.
async fn seed_theme(pool: &PgPool, label: &str, stale_count: i32) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'seeded by theme_read_tools', $2) RETURNING id",
    )
    .bind(label)
    .bind(stale_count)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

async fn seed_member(pool: &PgPool, agent: Uuid, theme: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, theme_id) \
         VALUES ($1, $2, $3, $4, 0.7, true, $5)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(theme)
    .execute(pool)
    .await
    .expect("insert member");
    id
}

/// Drop this run's rows. Members first: `claims.theme_id` references
/// `claim_themes`.
async fn cleanup(pool: &PgPool, themes: &[Uuid]) {
    sqlx::query("DELETE FROM claims WHERE theme_id = ANY($1)")
        .bind(themes)
        .execute(pool)
        .await
        .expect("cleanup claims");
    sqlx::query("DELETE FROM claim_themes WHERE id = ANY($1)")
        .bind(themes)
        .execute(pool)
        .await
        .expect("cleanup themes");
}

fn themes_of(body: &Value) -> Vec<Value> {
    body.get("themes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[tokio::test]
async fn list_themes_reports_live_membership_and_pages_deterministically() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let prefix = unique_prefix("list");

    // `hot` has the small stale counter and MORE real members; `cold` has a
    // huge stale counter and fewer. Any implementation that reads
    // `claim_themes.claim_count` (i.e. any thin wrapper over the pre-existing
    // `ClaimThemeRepository::list`) orders these backwards and reports the
    // wrong counts.
    let hot = seed_theme(&pool, &format!("{prefix}-hot"), 1).await;
    let cold = seed_theme(&pool, &format!("{prefix}-cold"), 5000).await;
    for i in 0..3 {
        seed_member(&pool, agent, hot, &format!("{prefix} hot member {i}")).await;
    }
    seed_member(&pool, agent, cold, &format!("{prefix} cold member 0")).await;

    let params: ListThemesParams =
        serde_json::from_value(json!({ "label_prefix": prefix })).expect("params");
    let body = common::first_text(&list_themes(&server, &viewer, params).await.expect("list_themes"));

    let themes = themes_of(&body);
    assert_eq!(
        themes.len(),
        2,
        "the run-unique prefix must isolate exactly this test's two themes: {body}"
    );
    assert_eq!(
        body.get("total").and_then(Value::as_i64),
        Some(2),
        "total must apply the same label_prefix predicate as the page: {body}"
    );
    assert_eq!(
        body.get("has_more").and_then(Value::as_bool),
        Some(false),
        "a complete page must not claim there is more: {body}"
    );

    assert_eq!(
        themes[0].get("theme_id").and_then(Value::as_str),
        Some(hot.to_string().as_str()),
        "ordering must follow LIVE member_count (hot=3) not the stale claim_count \
         (cold=5000): {body}"
    );
    assert_eq!(
        themes[0].get("member_count").and_then(Value::as_i64),
        Some(3),
        "member_count must be the live COUNT(*) over claims.theme_id: {body}"
    );
    assert_eq!(
        themes[0].get("stored_claim_count").and_then(Value::as_i64),
        Some(1),
        "the stale column must still be surfaced verbatim so drift is visible: {body}"
    );
    assert!(
        themes[0].get("centroid_dim").is_some(),
        "centroid_dim must be present (null for an unfitted theme), since the backlog \
         asks for it and claim_themes has no such column to read directly: {body}"
    );

    // Page 2 of a size-1 walk must be the OTHER theme, not the same one.
    let p1: ListThemesParams =
        serde_json::from_value(json!({ "label_prefix": prefix, "limit": 1, "offset": 0 }))
            .expect("params");
    let p2: ListThemesParams =
        serde_json::from_value(json!({ "label_prefix": prefix, "limit": 1, "offset": 1 }))
            .expect("params");
    let page1 = common::first_text(&list_themes(&server, &viewer, p1).await.expect("page1"));
    let page2 = common::first_text(&list_themes(&server, &viewer, p2).await.expect("page2"));
    let id1 = themes_of(&page1)[0]["theme_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id2 = themes_of(&page2)[0]["theme_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(id1, id2, "offset paging returned the same theme twice");
    assert_eq!(
        page1.get("has_more").and_then(Value::as_bool),
        Some(true),
        "a short page with rows remaining must say has_more=true: {page1}"
    );

    cleanup(&pool, &[hot, cold]).await;
}

#[tokio::test]
async fn get_theme_returns_member_ids_without_content() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let prefix = unique_prefix("get");

    let theme = seed_theme(&pool, &format!("{prefix}-solo"), 0).await;
    let secret = "PRIVATE-ish member body that must not appear in get_theme output";
    let member = seed_member(&pool, agent, theme, secret).await;

    let params: GetThemeParams =
        serde_json::from_value(json!({ "theme_id": theme.to_string() })).expect("params");
    let body = common::first_text(&get_theme(&server, &viewer, params).await.expect("get_theme"));

    let members = body
        .get("members")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(members.len(), 1, "expected the one seeded member: {body}");
    assert_eq!(
        members[0].get("claim_id").and_then(Value::as_str),
        Some(member.to_string().as_str()),
        "member page must carry the claim id: {body}"
    );
    assert_eq!(
        body.get("members_total").and_then(Value::as_i64),
        Some(1),
        "members_total is the live count and is the walk's termination signal: {body}"
    );
    assert_eq!(
        body.get("theme")
            .and_then(|t| t.get("member_count"))
            .and_then(Value::as_i64),
        Some(1),
        "the embedded summary must agree with members_total: {body}"
    );

    // Content withholding is a redaction-surface decision, not an accident:
    // a membership listing with previews would bypass the PRIVATE-visibility
    // pass every other content-returning read applies.
    let serialised = body.to_string();
    assert!(
        !serialised.contains(secret),
        "get_theme leaked claim content; it must return ids only: {body}"
    );

    // `members_limit: 0` is the summary-only escape hatch.
    let summary_only: GetThemeParams =
        serde_json::from_value(json!({ "theme_id": theme.to_string(), "members_limit": 0 }))
            .expect("params");
    let body0 = common::first_text(
        &get_theme(&server, &viewer, summary_only)
            .await
            .expect("summary only"),
    );
    assert!(
        body0["members"].as_array().is_some_and(Vec::is_empty),
        "members_limit=0 must return no members: {body0}"
    );
    assert_eq!(
        body0.get("members_total").and_then(Value::as_i64),
        Some(1),
        "members_limit=0 must still report the true total: {body0}"
    );

    cleanup(&pool, &[theme]).await;
}

#[tokio::test]
async fn get_theme_rejects_ambiguous_and_unresolvable_selectors() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let prefix = unique_prefix("ambig");

    // TWO themes with the SAME label. `claim_themes` has no UNIQUE(label) and
    // `theme_cluster(wipe_first=false)` produces exactly this. An
    // implementation that resolved a label to "the first match" would silently
    // scope to one of two distinct themes.
    let dup_label = format!("{prefix}-dup");
    let a = seed_theme(&pool, &dup_label, 0).await;
    let b = seed_theme(&pool, &dup_label, 0).await;

    let dup: GetThemeParams =
        serde_json::from_value(json!({ "theme_label": dup_label })).expect("params");
    let err = get_theme(&server, &viewer, dup)
        .await
        .expect_err("duplicate label must be rejected, not silently disambiguated");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(&a.to_string()) && msg.contains(&b.to_string()),
        "the rejection must name every candidate so the caller can pick: {msg}"
    );

    // A label that matches nothing must ERROR, not degrade to "no filter".
    let missing: GetThemeParams = serde_json::from_value(json!({
        "theme_label": format!("{prefix}-does-not-exist")
    }))
    .expect("params");
    get_theme(&server, &viewer, missing)
        .await
        .expect_err("an unmatched theme_label must be rejected, not treated as unscoped");

    // A malformed UUID must ERROR rather than be dropped.
    let bad: GetThemeParams =
        serde_json::from_value(json!({ "theme_id": "not-a-uuid" })).expect("params");
    get_theme(&server, &viewer, bad)
        .await
        .expect_err("a malformed theme_id must be rejected, not ignored");

    // A well-formed but unknown UUID must ERROR.
    let unknown: GetThemeParams =
        serde_json::from_value(json!({ "theme_id": Uuid::new_v4().to_string() })).expect("params");
    get_theme(&server, &viewer, unknown)
        .await
        .expect_err("an unknown theme_id must be rejected");

    // Both selectors at once is ambiguous by construction.
    let both: GetThemeParams = serde_json::from_value(json!({
        "theme_id": a.to_string(),
        "theme_label": dup_label,
    }))
    .expect("params");
    get_theme(&server, &viewer, both)
        .await
        .expect_err("theme_id + theme_label together must be rejected");

    // Neither selector is a programming error the tool must name.
    let neither: GetThemeParams = serde_json::from_value(json!({})).expect("params");
    get_theme(&server, &viewer, neither)
        .await
        .expect_err("get_theme with no selector must be rejected");

    cleanup(&pool, &[a, b]).await;
}

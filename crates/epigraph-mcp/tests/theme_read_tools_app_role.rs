//! `list_themes` / `get_theme` (and the theme selector theme-scoped `recall`
//! shares) list only themes the caller can read a current member of, and count
//! only those members, measured on the APPLICATION ROLE (backlog 06f5c5b2).
//!
//! Before the fix both tools returned every `claim_themes` row: a caller could
//! enumerate themes made only of another team's private claims, read their
//! labels, and learn their stored size from `stored_claim_count`, which the
//! REST overview and expand routes already hide. `list_themes`' `total` also
//! counted every theme on the raw pool.
//!
//! The server is built the way `dedup_probes_app_role.rs` builds it: from ONE
//! `ScopedPool` logged in as `epigraph_app`, whose `inner()` is the plain pool,
//! as in `main.rs`. The superuser `pool` the harness hands each test only seeds
//! rows. A fresh `#[sqlx::test]` database per test, so totals are exact.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::themes::{get_theme, list_themes, GetThemeParams, ListThemesParams};
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A server built ONLY from a `ScopedPool` logged in as `epigraph_app`.
async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = scoped.inner().clone();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&plain)
        .await
        .expect("current_user");
    assert_eq!(
        role, "epigraph_app",
        "PREMISE: the server's plain pool must be the application role"
    );
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5eu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped)
}

fn json_of(result: &CallToolResult) -> Value {
    match result.content.first().expect("content") {
        ContentBlock::Text(t) => serde_json::from_str(&t.text).expect("json"),
        other => panic!("expected text, got {other:?}"),
    }
}

async fn seed_theme(pool: &PgPool, label: &str, stored_count: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'seeded by theme_read_tools_app_role', $2) RETURNING id",
    )
    .bind(label)
    .bind(stored_count)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

async fn assign(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
}

struct Corpus {
    member: Uuid,
    stranger: Uuid,
    /// One public member, stored count 0.
    open: Uuid,
    /// Two members private to the member's group, stored count 9999.
    hidden: Uuid,
    /// Same label as `open`, one private member.
    hidden_dup: Uuid,
    dup_label: &'static str,
    hidden_label: &'static str,
}

async fn seed(pool: &PgPool) -> Corpus {
    let (member, group) = fixture::seed_agent_with_group(pool, "themes-app-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "themes-app-stranger").await;

    let open = seed_theme(pool, "app-dup", 0).await;
    let hidden = seed_theme(pool, "app-hidden", 9999).await;
    let hidden_dup = seed_theme(pool, "app-dup", 0).await;

    let c = fixture::seed_public_claim(pool, member, "app theme open member").await;
    assign(pool, c, open).await;
    for i in 0..2 {
        let c = fixture::seed_group_claim(pool, member, group, &format!("app hidden m{i}")).await;
        assign(pool, c, hidden).await;
    }
    let c = fixture::seed_group_claim(pool, member, group, "app hidden dup member").await;
    assign(pool, c, hidden_dup).await;

    Corpus {
        member,
        stranger,
        open,
        hidden,
        hidden_dup,
        dup_label: "app-dup",
        hidden_label: "app-hidden",
    }
}

async fn viewer_of(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("viewer")
}

fn listed(body: &Value) -> Vec<(String, i64)> {
    let mut v: Vec<(String, i64)> = body["themes"]
        .as_array()
        .expect("themes array")
        .iter()
        .map(|t| {
            (
                t["theme_id"].as_str().expect("theme_id").to_string(),
                t["member_count"].as_i64().expect("member_count"),
            )
        })
        .collect();
    v.sort();
    v
}

fn ids(pairs: &[(Uuid, i64)]) -> Vec<(String, i64)> {
    let mut v: Vec<(String, i64)> = pairs.iter().map(|(u, n)| (u.to_string(), *n)).collect();
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_themes_hides_themes_the_caller_cannot_read_a_member_of(pool: PgPool) {
    let c = seed(&pool).await;
    let server = app_server(&pool).await;
    let params = || -> ListThemesParams { serde_json::from_value(json!({})).expect("params") };

    let stranger = json_of(
        &list_themes(&server, &viewer_of(&pool, c.stranger).await, params())
            .await
            .expect("list_themes as stranger"),
    );
    assert_eq!(
        listed(&stranger),
        ids(&[(c.open, 1)]),
        "the stranger must see only the theme with a public member, not the all-private \
         ones: {stranger}"
    );
    assert_eq!(
        stranger["total"].as_i64(),
        Some(1),
        "total must count only the themes the page can show: {stranger}"
    );
    assert_eq!(stranger["has_more"].as_bool(), Some(false));
    let text = stranger.to_string();
    for (what, hidden) in [("hidden", c.hidden), ("hidden_dup", c.hidden_dup)] {
        assert!(
            !text.contains(&hidden.to_string()),
            "the {what} theme's id leaked to the stranger: {stranger}"
        );
    }
    assert!(
        !text.contains("app-hidden") && !text.contains("9999"),
        "neither the hidden label nor its stored count may reach the stranger: {stranger}"
    );
    assert!(
        stranger["themes"][0].get("stored_claim_count").is_none(),
        "stored_claim_count is gone from the wire shape: {stranger}"
    );

    let member = json_of(
        &list_themes(&server, &viewer_of(&pool, c.member).await, params())
            .await
            .expect("list_themes as member"),
    );
    assert_eq!(
        listed(&member),
        ids(&[(c.open, 1), (c.hidden, 2), (c.hidden_dup, 1)]),
        "the member's stamped read must list its own private themes with live counts \
         (2, not the stored 9999): {member}"
    );
    assert_eq!(member["total"].as_i64(), Some(3), "{member}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_theme_does_not_resolve_or_name_a_hidden_theme(pool: PgPool) {
    let c = seed(&pool).await;
    let server = app_server(&pool).await;
    let stranger = viewer_of(&pool, c.stranger).await;
    let member = viewer_of(&pool, c.member).await;
    let p = |v: Value| -> GetThemeParams { serde_json::from_value(v).expect("params") };

    // By id: refused for the stranger, served for the member.
    let err = get_theme(
        &server,
        &stranger,
        p(json!({ "theme_id": c.hidden.to_string() })),
    )
    .await
    .expect_err("a hidden theme must not resolve by id");
    assert!(
        format!("{err:?}").contains("no theme with id"),
        "a hidden id gets the unknown-id answer: {err:?}"
    );
    let unknown = get_theme(
        &server,
        &stranger,
        p(json!({ "theme_id": Uuid::new_v4().to_string() })),
    )
    .await
    .expect_err("an unknown id is refused");
    assert_eq!(
        format!("{err:?}").replace(&c.hidden.to_string(), "<id>"),
        format!("{unknown:?}").replace(&unknown_id(&unknown), "<id>"),
        "hidden and unknown must be indistinguishable apart from the echoed id"
    );
    let body = json_of(
        &get_theme(
            &server,
            &member,
            p(json!({ "theme_id": c.hidden.to_string() })),
        )
        .await
        .expect("the member reads its own private theme"),
    );
    assert_eq!(body["theme"]["member_count"].as_i64(), Some(2), "{body}");
    assert_eq!(body["members_total"].as_i64(), Some(2), "{body}");

    // By label: a hidden-only label is a plain miss, and never names the id.
    let err = get_theme(
        &server,
        &stranger,
        p(json!({ "theme_label": c.hidden_label })),
    )
    .await
    .expect_err("a label whose only theme is hidden is a miss");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("no theme has label") && !msg.contains(&c.hidden.to_string()),
        "the label miss must not carry the hidden theme's id: {msg}"
    );

    // A duplicate label with one hidden theme resolves, for the stranger, to the
    // one it can see; the member sees the ambiguity and both candidates.
    let body = json_of(
        &get_theme(&server, &stranger, p(json!({ "theme_label": c.dup_label })))
            .await
            .expect("the stranger's only visible candidate resolves"),
    );
    assert_eq!(
        body["theme"]["theme_id"].as_str(),
        Some(c.open.to_string().as_str()),
        "{body}"
    );
    assert!(
        !body.to_string().contains(&c.hidden_dup.to_string()),
        "the hidden duplicate leaked: {body}"
    );
    let err = get_theme(&server, &member, p(json!({ "theme_label": c.dup_label })))
        .await
        .expect_err("the member sees two candidates, so the label is ambiguous");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(&c.open.to_string()) && msg.contains(&c.hidden_dup.to_string()),
        "the member's ambiguity error names both of its visible candidates: {msg}"
    );
}

/// The UUID the unknown-id refusal echoed back, so the two refusals can be
/// compared with their ids masked.
fn unknown_id(err: &impl std::fmt::Debug) -> String {
    let s = format!("{err:?}");
    let at = s.find("no theme with id ").expect("unknown-id refusal") + "no theme with id ".len();
    s[at..at + 36].to_string()
}
